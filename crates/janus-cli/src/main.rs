//! Terminal chat on `janus-client` through a development mailbox: the reference client.
//!
//! ```text
//! janus-mailbox 127.0.0.1:7000                   # writes mailbox.der, the certificate clients pin
//! JANUS_DIR=alice janus invite 127.0.0.1:7000
//! JANUS_DIR=bob janus join 127.0.0.1:7000        # within 10 minutes
//! JANUS_DIR=alice janus chat 127.0.0.1:7000      # later: back to the saved contacts
//! ```
//!
//! The inviter gets 6 words to read out and the joiner types them; then the joiner reads 3
//! safety words back, which the inviter types before either side can talk. Contacts and history
//! live in `JANUS_DIR` (default `janus-data`), so a client that quits or crashes comes back with
//! `chat` and finds what it missed waiting in the mailbox.

mod ui;

use std::cell::Cell;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs, process, thread};

use janus_client::{Client, Error, Event, Platform};
use janus_core::{Block, Interval, Key};
use janus_transport::{Direct, Transport};
use zeroize::Zeroizing;

/// How often to tick the client.
const POLL: Duration = Duration::from_millis(500);
const CERT_FILE: &str = "mailbox.der";
const DEFAULT_DIR: &str = "janus-data";
const KEY_FILE: &str = "storage.key";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Invite,
    Join,
    Chat,
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mode = match args.first() {
        Some(&"invite") => Some(Mode::Invite),
        Some(&"join") => Some(Mode::Join),
        Some(&"chat") => Some(Mode::Chat),
        _ => None,
    };
    let result = match (mode, &args[..]) {
        (Some(mode), [_, addr]) => chat(mode, addr, CERT_FILE),
        (Some(mode), [_, addr, cert]) => chat(mode, addr, cert),
        (None, ["ui"]) => ui::run("127.0.0.1:8080").map_err(Into::into),
        (None, ["ui", addr]) => ui::run(addr).map_err(Into::into),
        _ => {
            eprintln!(
                "usage: janus invite|join|chat <mailbox> [cert] | janus ui [addr]\n\
                 contacts live in $JANUS_DIR (default {DEFAULT_DIR})"
            );
            process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

struct Cli {
    dir: PathBuf,
    key: Zeroizing<Key>,
    /// Seconds `/skip` moved the clock ahead.
    skew: Rc<Cell<u64>>,
}

impl Platform for Cli {
    fn storage_key(&self) -> Zeroizing<Key> {
        self.key.clone()
    }

    // shortcut: the wall clock, since std has no clock that keeps counting during sleep; the
    // apps pass `mach_continuous_time` or `elapsedRealtime`.
    fn now(&self) -> u64 {
        now().saturating_add(self.skew.get())
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.clone()
    }
}

// shortcut: the key sits in a file next to the data it protects, so encryption at rest guards
// nothing here; the apps keep it in the OS keychain.
fn storage_key(dir: &PathBuf) -> io::Result<Zeroizing<Key>> {
    let path = dir.join(KEY_FILE);
    match fs::read(&path) {
        Ok(bytes) => Key::try_from(&bytes[..])
            .map(Zeroizing::new)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "storage key is not 32 bytes")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut key = Zeroizing::new(Key::default());
            getrandom::fill(key.as_mut()).map_err(io::Error::other)?;
            fs::create_dir_all(dir)?;
            fs::File::create_new(&path)?.write_all(&*key)?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

/// What the next line typed answers.
enum Waiting {
    Nothing,
    /// A: the 3 safety words B reads out.
    SafetyWords,
    /// B: Enter once A says the words match.
    Confirm(String),
}

fn chat(mode: Mode, addr: &str, cert: &str) -> Result<(), Box<dyn std::error::Error>> {
    let der = fs::read(cert)
        .map_err(|e| io::Error::new(e.kind(), format!("mailbox certificate {cert}: {e}")))?;
    let dir = PathBuf::from(env::var("JANUS_DIR").unwrap_or_else(|_| DEFAULT_DIR.into()));
    let skew = Rc::new(Cell::new(0));
    let platform = Cli {
        key: storage_key(&dir)?,
        dir,
        skew: Rc::clone(&skew),
    };
    let direct = Direct::new(addr, &der)?;
    let network = direct.network();
    let mut client = Client::open(platform, vec![direct])?;
    let mut name = String::new();
    if mode != Mode::Chat {
        name = ask("name for the new contact: ")?;
    }
    match mode {
        Mode::Invite => {
            let words = client.invite(&network, Interval::H1)?;
            println!("tell the other side these 6 words: {}", *words);
            println!("the invitation lives 10 minutes; waiting for the answer...");
        }
        Mode::Join => {
            client.join(&network, &ask("6 words: ")?)?;
            println!("looking for the invitation...");
        }
        Mode::Chat if client.contacts().is_empty() => {
            return Err("no contacts yet: invite or join first".into());
        }
        Mode::Chat => {}
    }
    let mut current = client.contacts().first().map(|c| c.id.clone());
    println!(
        "/to <name> picks who you write to, /contacts lists them, /history shows the current one, \
         /close ends it on both sides, /skip <hours> moves the clock, /quit leaves (come back \
         with `janus chat`)."
    );
    if mode == Mode::Chat {
        contacts(&client, current.as_deref());
    }

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in io::stdin().lock().lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
        let _ = tx.send("/quit".into());
    });

    let mut waiting = Waiting::Nothing;
    loop {
        match rx.recv_timeout(POLL) {
            Ok(line) => {
                let line = line.trim();
                match std::mem::replace(&mut waiting, Waiting::Nothing) {
                    Waiting::SafetyWords => match client.verify(line, &name) {
                        Ok(id) => {
                            println!("safety words match: connected to {name}");
                            current = Some(id);
                        }
                        Err(Error::Handshake(janus_core::Error::Rejected)) => {
                            println!(
                                "they do not match. Retype them; if they really differ, someone \
                                 is in the middle: stop here."
                            );
                            waiting = Waiting::SafetyWords;
                        }
                        Err(e) => println!("error: {e}"),
                    },
                    Waiting::Confirm(id) => {
                        client.confirm(&id, &name)?;
                        println!("connected to {name}");
                        history(&client, &id);
                        current = Some(id);
                    }
                    Waiting::Nothing => {
                        if !command(&mut client, &mut current, &skew, line) {
                            return Ok(());
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {}
        }
        let names: HashMap<String, String> = client
            .contacts()
            .into_iter()
            .map(|c| (c.id, c.name))
            .collect();
        let name_of = |id: &str| names.get(id).cloned().unwrap_or_default();
        let events = match client.tick() {
            Ok(events) => events,
            Err(e) => {
                println!("error: {e}");
                continue;
            }
        };
        for event in events {
            match event {
                Event::Answered => {
                    print!("answered. Type the 3 words the other side reads to you: ");
                    io::stdout().flush()?;
                    waiting = Waiting::SafetyWords;
                }
                Event::Joined {
                    contact,
                    safety_words,
                } => {
                    println!("read these 3 words to the other side: {safety_words}");
                    print!("press Enter once they say they match (Ctrl-C if they do not)...");
                    io::stdout().flush()?;
                    waiting = Waiting::Confirm(contact);
                }
                Event::Message { contact, data } => {
                    println!(
                        "<- {}: {}",
                        name_of(&contact),
                        String::from_utf8_lossy(&data)
                    );
                }
                Event::Closed { contact } => {
                    println!("{} closed the conversation", name_of(&contact));
                    if current.as_deref() == Some(&contact) {
                        current = None;
                    }
                }
                Event::Dormant { contact } => println!(
                    "{} is dormant: nothing heard for 360 days; any block wakes it, or /close it",
                    name_of(&contact)
                ),
                Event::Awake { contact } => println!("{} is awake again", name_of(&contact)),
            }
        }
    }
}

/// False on `/quit`.
fn command(
    client: &mut Client<Cli, Direct>,
    current: &mut Option<String>,
    skew: &Cell<u64>,
    line: &str,
) -> bool {
    let result = match line.split_whitespace().collect::<Vec<_>>()[..] {
        ["/quit"] => return false,
        ["/contacts"] => {
            contacts(client, current.as_deref());
            Ok(())
        }
        ["/to", name] => {
            match client.contacts().into_iter().find(|c| c.name == name) {
                Some(c) => *current = Some(c.id),
                None => println!("no contact named {name}"),
            }
            Ok(())
        }
        ["/history"] => {
            if let Some(id) = current.as_deref() {
                history(client, id);
            }
            Ok(())
        }
        ["/close"] => match current.take() {
            Some(id) => client.close(&id),
            None => Ok(()),
        },
        ["/skip", hours] => {
            match hours.parse::<u64>() {
                Ok(h) => {
                    skew.set(skew.get().saturating_add(h.saturating_mul(3600)));
                    println!("clock moved {h}h ahead");
                }
                Err(_) => println!("usage: /skip <hours>"),
            }
            Ok(())
        }
        [] => Ok(()),
        _ => match current.as_deref() {
            Some(id) => client.send(id, line.as_bytes()),
            None => {
                println!("nobody to write to: /to <name>");
                Ok(())
            }
        },
    };
    if let Err(e) = result {
        println!("error: {e}");
    }
    true
}

fn contacts(client: &Client<Cli, Direct>, current: Option<&str>) {
    for c in client.contacts() {
        let mut marks = String::new();
        if Some(c.id.as_str()) == current {
            marks.push_str(" (writing to)");
        }
        if !c.confirmed {
            marks.push_str(" (unconfirmed)");
        }
        if c.dormant {
            marks.push_str(" (dormant)");
        }
        println!("  {}{marks}", c.name);
    }
}

fn history(client: &Client<Cli, Direct>, id: &str) {
    let name = client
        .contacts()
        .into_iter()
        .find(|c| c.id == id)
        .map(|c| c.name)
        .unwrap_or_default();
    match client.history(id) {
        Ok(entries) => {
            for (mine, data) in entries {
                let who = if mine { "you" } else { &name };
                println!("   {who}: {}", String::from_utf8_lossy(&data));
            }
        }
        Err(e) => println!("error: {e}"),
    }
}

fn ask(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

/// Start of the queue id, which changes as the keys rotate.
fn qid(block: &Block) -> String {
    block[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs()
}
