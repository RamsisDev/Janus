//! The thread that owns the client. Every client call can wait on the network, so the window
//! only sends commands here and draws the updates that come back. It ticks once a second.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use janus_ffi::{Client, Contact, DevMailbox, Event, HistoryEntry, JanusError, NetworkInfo};

use crate::platform::DesktopPlatform;

const TICK: Duration = Duration::from_secs(1);

pub enum Command {
    Invite { network: String, hours: u8 },
    Join { network: String, words: String },
    Verify { typed: String, name: String },
    Confirm { contact: String, name: String },
    Send { contact: String, text: String },
    Close { contact: String },
    Install { profile: Vec<u8> },
    History { contact: String },
    SafetyWords { contact: String },
}

pub enum Update {
    /// The client could not open; nothing else will come.
    Fatal(String),
    Contacts(Vec<Contact>),
    Networks(Vec<NetworkInfo>),
    History(String, Vec<HistoryEntry>),
    /// A: the 6 words of the new invitation.
    Invited(String),
    /// A: the contact the safety words opened.
    Verified(String),
    Joining,
    Confirmed(String),
    SafetyWords(String, Option<String>),
    Event(Event),
    Failed(JanusError),
    /// Why the last tick failed, or `None` once one works again.
    Trouble(Option<String>),
}

struct Out {
    tx: Sender<Update>,
    ctx: eframe::egui::Context,
}

impl Out {
    fn send(&self, update: Update) {
        // The window is gone if this fails, and the thread ends with the next command.
        let _ = self.tx.send(update);
        self.ctx.request_repaint();
    }
}

pub fn spawn(ctx: eframe::egui::Context) -> (Sender<Command>, Receiver<Update>) {
    let (commands, rx) = mpsc::channel();
    let (tx, updates) = mpsc::channel();
    let out = Out { tx, ctx };
    thread::spawn(move || {
        let client = match open() {
            Ok(client) => client,
            Err(e) => return out.send(Update::Fatal(e)),
        };
        out.send(Update::Networks(client.networks()));
        out.send(Update::Contacts(client.contacts()));
        let mut next_tick = Instant::now();
        loop {
            match rx.recv_timeout(next_tick.saturating_duration_since(Instant::now())) {
                Ok(command) => run(&client, command, &out),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if Instant::now() >= next_tick {
                tick(&client, &out);
                next_tick = Instant::now() + TICK;
            }
        }
    });
    (commands, updates)
}

fn open() -> Result<Arc<Client>, String> {
    let platform = DesktopPlatform::new()?;
    Client::new(Arc::new(platform), dev_mailbox()).map_err(|e| format!("{e}"))
}

/// Debug builds reach the development mailbox at `JANUS_DEV_MAILBOX` (`host:port`), pinned to
/// the certificate in the file `JANUS_DEV_CERT`; `make desktop` sets both.
#[cfg(debug_assertions)]
fn dev_mailbox() -> Option<DevMailbox> {
    let address = std::env::var("JANUS_DEV_MAILBOX").ok()?;
    let cert = std::fs::read(std::env::var("JANUS_DEV_CERT").ok()?).ok()?;
    Some(DevMailbox { address, cert })
}

#[cfg(not(debug_assertions))]
fn dev_mailbox() -> Option<DevMailbox> {
    None
}

fn run(client: &Client, command: Command, out: &Out) {
    let result = match command {
        Command::Invite { network, hours } => client.invite(network, hours).map(Update::Invited),
        Command::Join { network, words } => client.join(network, words).map(|()| Update::Joining),
        Command::Verify { typed, name } => client.verify(typed, name).map(Update::Verified),
        Command::Confirm { contact, name } => client
            .confirm(contact.clone(), name)
            .map(|()| Update::Confirmed(contact)),
        Command::Send { contact, text } => client
            .send(contact.clone(), text.into_bytes())
            .and_then(|()| client.history(contact.clone()))
            .map(|h| Update::History(contact, h)),
        Command::Close { contact } => client
            .close(contact)
            .map(|()| Update::Contacts(client.contacts())),
        Command::Install { profile } => client
            .install_network(profile)
            .map(|_| Update::Networks(client.networks())),
        Command::History { contact } => client
            .history(contact.clone())
            .map(|h| Update::History(contact, h)),
        Command::SafetyWords { contact } => Ok(Update::SafetyWords(
            contact.clone(),
            client.safety_words(contact),
        )),
    };
    out.send(result.unwrap_or_else(Update::Failed));
    out.send(Update::Contacts(client.contacts()));
}

fn tick(client: &Client, out: &Out) {
    match client.tick() {
        Ok(events) => {
            out.send(Update::Trouble(None));
            let changed = !events.is_empty();
            for event in events {
                if let Event::Message { contact, .. } = &event
                    && let Ok(history) = client.history(contact.clone())
                {
                    out.send(Update::History(contact.clone(), history));
                }
                out.send(Update::Event(event));
            }
            if changed {
                out.send(Update::Contacts(client.contacts()));
            }
        }
        Err(e) => out.send(Update::Trouble(Some(format!("{e}")))),
    }
}
