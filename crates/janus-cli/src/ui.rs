//! `janus ui [addr]`: Alice (side a, the inviter) and Bob (side b) in one process, joined by an
//! in-memory relay, behind a tiny sequential HTTP server for a browser demo.
//!
//! ```text
//! GET  /              the page
//! GET  /state         state JSON
//! GET  /words         6 fresh invitation words (never part of the state)
//! POST /invite        body: 6 words (Alice)
//! POST /join          body: 6 words (Bob), runs the handshake up to Bob's safety words
//! POST /verify        body: the 3 safety words Bob shows (Alice); Bob then confirms
//! POST /send?from=a   body: text (or from=b)
//! POST /skip          clock +1h
//! POST /reset         fresh engines
//! ```
//!
//! Every POST replies with the state JSON; failed actions show up as `error` log entries.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

use janus_core::{
    BLOCK_LEN, Block, Engine, Error, Interval, MSG1_LEN, MSG2_LEN, MSG3_LEN, NetworkId, Received,
    SessionId, words,
};

use crate::{now, qid};

const PAGE: &str = include_str!("ui.html");
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;
const MAX_DRAIN: u64 = 1024 * 1024;
const INTERVAL: Interval = Interval::H1;
/// Both sides of the demo share one in-memory relay, so one network.
const NET: NetworkId = [0; 32];
/// Start of the sealed body: queue id 16 + sealed header 84 + nonce 24 (janus-core block.rs).
const BODY_AT: usize = 124;
/// Bytes shown when a message morphs between plaintext and ciphertext.
const PEEK: usize = 24;
const SIDES: [&str; 2] = ["a", "b"];

// The narration spells out these layouts; keep it honest if the handshake changes.
const _: () = assert!(MSG1_LEN == 48 + 32 + 32 + 1184);
const _: () = assert!(MSG2_LEN == 32 + 32 + 1088 + 32);
const _: () = assert!(MSG3_LEN == 64);

pub fn run(addr: &str) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("ui on http://{addr}");
    let mut state = State::default();
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        // Timeouts and resets from browsers are routine; the next connection goes on.
        let _ = serve(&mut stream, &mut state);
    }
    Ok(())
}

fn serve(stream: &mut TcpStream, state: &mut State) -> io::Result<()> {
    // One thread serves everything, so an idle preconnect must not hold it.
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = Vec::new();
    let mut chunk = [0; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return reply(
                stream,
                "431 Request Header Fields Too Large",
                "text/plain",
                "",
            );
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]);
    let mut lines = head.lines();
    let mut request = lines.next().unwrap_or_default().split(' ');
    let (method, target) = (
        request.next().unwrap_or_default(),
        request.next().unwrap_or_default(),
    );
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let len = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .map_or(Some(0), |(_, v)| v.trim().parse::<usize>().ok());
    let Some(len) = len else {
        return reply(
            stream,
            "400 Bad Request",
            "text/plain",
            "bad Content-Length",
        );
    };
    if len > MAX_BODY {
        reply(
            stream,
            "413 Payload Too Large",
            "text/plain",
            "body over 64 KiB",
        )?;
        // Closing with unread input resets the connection before the client reads the 413.
        stream.shutdown(Shutdown::Write)?;
        io::copy(&mut stream.take(MAX_DRAIN), &mut io::sink())?;
        return Ok(());
    }
    let mut body = buf[head_end + 4..].to_vec();
    let read = body.len();
    if read < len {
        body.resize(len, 0);
        stream.read_exact(&mut body[read..])?;
    }
    body.truncate(len);
    let text = String::from_utf8_lossy(&body);

    match (method, path, query) {
        ("GET", "/", _) => return reply(stream, "200 OK", "text/html; charset=utf-8", PAGE),
        ("GET", "/state", _) => {}
        ("GET", "/words", _) => return reply(stream, "200 OK", "text/plain", &words()),
        ("POST", "/invite", _) => state.invite(&text),
        ("POST", "/join", _) => state.join(&text),
        ("POST", "/verify", _) => state.verify(&text),
        ("POST", "/send", "from=a") => state.send(0, &text),
        ("POST", "/send", "from=b") => state.send(1, &text),
        ("POST", "/skip", _) => state.skip(),
        ("POST", "/reset", _) => *state = State::default(),
        _ => return reply(stream, "404 Not Found", "text/plain", "not found"),
    }
    if method == "POST" {
        state.pump();
    }
    reply(stream, "200 OK", "application/json", &state.json())
}

fn reply(stream: &mut TcpStream, status: &str, kind: &str, body: &str) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[derive(Default)]
struct Side {
    engine: Engine,
    session: Option<SessionId>,
    /// `(mine, text)`: sent and decrypted messages.
    chat: Vec<(bool, String)>,
    /// Full queue id of the last block sent, to spot DH ratchet steps.
    queue: Option<[u8; 16]>,
}

struct Entry {
    side: &'static str,
    kind: &'static str,
    text: String,
    morph: Option<(String, String)>,
}

#[derive(Default)]
struct State {
    sides: [Side; 2],
    /// msg1 waiting in the relay for Bob.
    msg1: Option<Block>,
    skew: u64,
    log: Vec<Entry>,
}

impl State {
    fn clock(&self) -> u64 {
        now().saturating_add(self.skew)
    }

    fn note(&mut self, side: &'static str, kind: &'static str, text: impl Into<String>) {
        let text = text.into();
        let morph = None;
        self.log.push(Entry {
            side,
            kind,
            text,
            morph,
        });
    }

    /// Plaintext/ciphertext animation for the last entry.
    fn morph(&mut self, from: String, to: String) {
        if let Some(e) = self.log.last_mut() {
            e.morph = Some((from, to));
        }
    }

    fn phase(&self) -> &'static str {
        if self.sides.iter().all(|s| s.session.is_some()) {
            "connected"
        } else if self.sides[1].session.is_some() {
            "verifying"
        } else if self.msg1.is_some() {
            "invited"
        } else {
            "idle"
        }
    }

    fn invite(&mut self, words: &str) {
        if matches!(self.phase(), "connected" | "verifying") {
            return self.note("a", "error", "already joined: reset first");
        }
        match self.sides[0]
            .engine
            .invite(words, &NET, INTERVAL, self.clock())
        {
            Ok(msg1) => {
                self.note(
                    "a",
                    "handshake",
                    format!(
                        "invitation created: msg1 {MSG1_LEN} B = CPace 48 + X25519 32 + \
                         commitment to the msg3 key and interval 32 + ML-KEM-768 key 1184, \
                         padded to {BLOCK_LEN} B"
                    ),
                );
                let text = format!(
                    "keeps msg1 on rendezvous queue {} (24 bits of the words)",
                    qid(&msg1)
                );
                self.note("relay", "handshake", text);
                self.msg1 = Some(msg1);
            }
            Err(e) => self.note(
                "a",
                "error",
                format!("invitation not created: {}", reason(&e)),
            ),
        }
    }

    fn join(&mut self, words: &str) {
        let Some(msg1) = self.msg1.take() else {
            return self.note(
                "b",
                "error",
                "no invitation in the relay: Alice must invite first",
            );
        };
        if let Err((side, e)) = self.handshake(words, &msg1) {
            for s in &mut self.sides {
                if let Some(id) = s.session.take() {
                    s.engine.remove(id);
                }
            }
            let text = format!("handshake failed: {}, invitation destroyed", reason(&e));
            self.note(side, "error", text);
        }
    }

    fn handshake(&mut self, words: &str, msg1: &Block) -> Result<(), (&'static str, Error)> {
        let clock = self.clock();
        let msg2 = self.sides[1]
            .engine
            .respond(words, &NET, msg1, clock)
            .map_err(|e| ("b", e))?;
        self.note(
            "b",
            "handshake",
            format!(
                "answered: msg2 {MSG2_LEN} B = CPace 32 + X25519 32 + ML-KEM-768 ciphertext 1088 \
                 + confirmation 32, padded to {BLOCK_LEN} B"
            ),
        );
        let text = format!("carries msg2 to queue {} (derived from msg1)", qid(&msg2));
        self.note("relay", "handshake", text);

        let msg3 = self.sides[0]
            .engine
            .finish_invite(&msg2, clock)
            .map_err(|e| ("a", e))?;
        self.note(
            "a",
            "handshake",
            format!(
                "words confirmed, root key = HKDF(CPace || X25519 || ML-KEM); msg3 {MSG3_LEN} B, \
                 padded to {BLOCK_LEN} B; the session opens once Bob's safety words are typed"
            ),
        );
        let text = format!("carries msg3 to queue {} (derived from msg2)", qid(&msg3));
        self.note("relay", "handshake", text);

        let id = self.sides[1]
            .engine
            .finish_response(&msg3, clock)
            .map_err(|e| ("b", e))?;
        self.sides[1].session = Some(id);
        self.note(
            "b",
            "handshake",
            "confirmation and commitment verified: reads the 3 safety words to Alice; sends \
             nothing until she says they match",
        );
        Ok(())
    }

    fn verify(&mut self, typed: &str) {
        let Some(id_b) = self.sides[1]
            .session
            .filter(|_| self.phase() == "verifying")
        else {
            return self.note("a", "error", "nothing to verify: Bob must join first");
        };
        match self.sides[0].engine.verify(typed, self.clock()) {
            Ok(id) => {
                self.sides[0].session = Some(id);
                self.sides[1].engine.confirm(id_b);
                self.note(
                    "a",
                    "handshake",
                    "safety words match: nobody sits in the middle, session open",
                );
                self.note("b", "handshake", "Alice says they match: confirmed");
                let text = "from now on blocks travel on queues only the two sides can compute";
                self.note("relay", "info", text);
            }
            Err(Error::Rejected) => self.note(
                "a",
                "error",
                "safety words do not match: a typo, or someone in the middle",
            ),
            Err(e) => self.note("a", "error", format!("verification failed: {}", reason(&e))),
        }
    }

    fn send(&mut self, from: usize, text: &str) {
        let side = &mut self.sides[from];
        let blocks = match side
            .session
            .map(|id| side.engine.encrypt(id, text.as_bytes()))
        {
            None => {
                return self.note(
                    SIDES[from],
                    "error",
                    "no session yet: invite and join first",
                );
            }
            Some(None) => return self.note(SIDES[from], "error", "message too large"),
            Some(Some(blocks)) => blocks,
        };
        side.chat.push((true, text.to_owned()));
        let sealed = format!(
            "sealed {} B of text into {} block(s) of {BLOCK_LEN} B -> queue {}",
            text.len(),
            blocks.len(),
            qid(&blocks[0])
        );
        self.note(SIDES[from], "block", sealed);
        self.morph(preview(text), ciphertext(&blocks[0]));
        for block in &blocks {
            self.deliver(from, block, false);
        }
    }

    fn skip(&mut self) {
        self.skew += 3600;
        let text = format!(
            "clock moved +1h (total +{}h): rotation interval ({}h) elapsed",
            self.skew / 3600,
            INTERVAL.secs() / 3600
        );
        self.note("clock", "info", text);
    }

    /// Delivers control blocks (forced rotation) both ways until both sides are quiet.
    fn pump(&mut self) {
        let clock = self.clock();
        for _ in 0..10 {
            let out = self.sides.each_mut().map(|s| s.engine.outgoing(clock));
            if out.iter().all(Vec::is_empty) {
                return;
            }
            for (from, blocks) in out.into_iter().enumerate() {
                for (_, block) in blocks {
                    let text = format!(
                        "forced key rotation: control block (ML-KEM offer / reply / ack) -> \
                         queue {}",
                        qid(&block)
                    );
                    self.note(SIDES[from], "rotation", text);
                    self.deliver(from, &block, true);
                }
            }
        }
    }

    fn deliver(&mut self, from: usize, block: &Block, control: bool) {
        let q = qid(block);
        let (queue, _) = block
            .split_first_chunk::<16>()
            .expect("blocks are BLOCK_LEN bytes");
        if self.sides[from]
            .queue
            .replace(*queue)
            .is_some_and(|old| old != *queue)
        {
            let text = format!("now sending on new queue {q} (DH ratchet stepped)");
            self.note(SIDES[from], "rotation", text);
        }
        let peek = &ciphertext(block)[..23];
        let text = format!("forwards {BLOCK_LEN} B to queue {q}, ciphertext {peek}... (opaque)");
        self.note("relay", "block", text);

        let clock = self.clock();
        let to = &mut self.sides[1 - from];
        let mut plain = None;
        let (kind, text) = match to.engine.receive(block, clock) {
            Some((_, Received::Message(m))) => {
                let text = String::from_utf8_lossy(&m).into_owned();
                plain = Some(preview(&text));
                to.chat.push((false, text));
                let text = format!("opened block from queue {q}: message ({} B)", m.len());
                ("block", text)
            }
            Some((_, Received::Nothing)) if control => (
                "rotation",
                format!("processed control block from queue {q}"),
            ),
            Some((_, Received::Nothing)) => (
                "block",
                format!("opened block from queue {q}: fragment, waiting for the rest"),
            ),
            Some((_, Received::Closed)) => {
                to.session = None;
                ("info", "peer closed the session".to_owned())
            }
            None => ("block", format!("dropped: no session opens it (queue {q})")),
        };
        self.note(SIDES[1 - from], kind, text);
        if let Some(plain) = plain {
            self.morph(ciphertext(block), plain);
        }
    }

    fn json(&self) -> String {
        let chat = |s: &Side| {
            let items: Vec<String> = s
                .chat
                .iter()
                .map(|(mine, text)| format!(r#"{{"mine":{mine},"text":{}}}"#, quote(text)))
                .collect();
            items.join(",")
        };
        let log: Vec<String> = self
            .log
            .iter()
            .map(|e| {
                let (side, kind, text) = (e.side, e.kind, quote(&e.text));
                let morph = e.morph.as_ref().map_or(String::new(), |(from, to)| {
                    format!(r#","from":{},"to":{}"#, quote(from), quote(to))
                });
                format!(r#"{{"side":"{side}","kind":"{kind}","text":{text}{morph}}}"#)
            })
            .collect();
        let safety = self.sides[1]
            .session
            .and_then(|id| self.sides[1].engine.safety_words(id))
            .unwrap_or_default();
        format!(
            r#"{{"phase":"{}","safety":{},"skew_hours":{},"chats":{{"a":[{}],"b":[{}]}},"log":[{}]}}"#,
            self.phase(),
            quote(&safety),
            self.skew / 3600,
            chat(&self.sides[0]),
            chat(&self.sides[1]),
            log.join(",")
        )
    }
}

fn reason(e: &Error) -> &'static str {
    match e {
        Error::Rejected => "Rejected (wrong words?)",
        Error::BadWords => "BadWords (exactly 6 words from the list needed)",
        Error::Expired => "Expired (invitation too old)",
    }
}

fn ciphertext(block: &Block) -> String {
    let bytes = &block[BODY_AT..BODY_AT + PEEK];
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn preview(text: &str) -> String {
    let cut: String = text.chars().take(PEEK * 3 - 3).collect();
    format!("\"{cut}\"")
}

/// A JSON string literal.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: &str = "alpha cable echo forest orbit velvet";

    #[test]
    fn wrong_words_stay_idle_then_right_words_connect_and_deliver() {
        let mut s = State::default();
        s.invite(WORDS);
        s.join("alpha cable echo forest orbit zoo");
        s.pump();
        assert_eq!(s.phase(), "idle");
        assert!(s.log.iter().any(|e| e.kind == "error"));

        s.invite(WORDS);
        s.join(WORDS);
        assert_eq!(s.phase(), "verifying");
        s.verify("abandon ability able");
        assert_eq!(s.phase(), "verifying");
        let shown = s.sides[1]
            .engine
            .safety_words(s.sides[1].session.unwrap())
            .unwrap();
        s.verify(&shown);
        s.send(0, "hola");
        s.pump();
        assert_eq!(s.phase(), "connected");
        assert_eq!(s.sides[1].chat, [(false, "hola".to_owned())]);
        let morphs: Vec<_> = s.log.iter().filter_map(|e| e.morph.clone()).collect();
        assert_eq!(morphs.len(), 2, "one encryption and one decryption");
        assert_eq!(
            (&morphs[0].0, &morphs[1].1),
            (&"\"hola\"".into(), &"\"hola\"".into())
        );
        assert_eq!(morphs[0].1, morphs[1].0, "both show the same ciphertext");
        assert_eq!(quote("a\"\\\n"), r#""a\"\\\u000a""#);
    }
}
