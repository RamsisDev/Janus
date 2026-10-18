//! Katzenpost's mix network wire protocol over one TCP connection, from `wire.md`: a one-byte
//! prologue, the pqXX handshake carrying an `AuthenticateMessage` each way, then commands, each
//! sent as two Noise transport messages followed by a rekey.
//!
//! ```text
//! AuthenticateMessage | ad_len 1 | additional data | zeros to 255 | unix_time 4
//! frame               | Noise(length 4) | Noise(command 1 | 0 | body length 4 | body | zeros)
//! ```
//!
//! The responder's `AuthenticateMessage` rides in handshake message 2, the initiator's in
//! message 3 (seen on the test network: message 2 is 2628 bytes).

use std::io::{self, Read, Write};
use std::net::TcpStream;

use super::noise::{Cipher, Handshake, SECRET_KEY_LEN, TAG_LEN};

pub const PROLOGUE: u8 = 3;
const AUTH_LEN: usize = 1 + 255 + 4;
/// The largest Noise message, raised from Noise's 65535 for Sphincs+ signatures.
pub const MAX_NOISE: usize = 1_300_000;
const HEADER_LEN: usize = 1 + 1 + 4;

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

fn authenticate_message(ad: &[u8], unix_time: u32) -> [u8; AUTH_LEN] {
    assert!(ad.len() <= 255, "additional data is at most 255 bytes");
    let mut m = [0; AUTH_LEN];
    m[0] = ad.len() as u8;
    m[1..1 + ad.len()].copy_from_slice(ad);
    m[256..].copy_from_slice(&unix_time.to_be_bytes());
    m
}

/// `(additional data, unix_time)` of an `AuthenticateMessage`.
fn parse_authenticate(m: &[u8]) -> Option<(Vec<u8>, u32)> {
    if m.len() != AUTH_LEN {
        return None;
    }
    let len = usize::from(m[0]);
    let time = u32::from_be_bytes(m[256..].try_into().expect("4 bytes"));
    Some((m[1..1 + len].to_vec(), time))
}

/// A command as it travels: its number and body. The wire pads it with zeros up to the
/// session's padded length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub command: u8,
    pub body: Vec<u8>,
}

/// An established connection to a node.
pub struct Session<S = TcpStream> {
    stream: S,
    send: Cipher,
    recv: Cipher,
    /// The peer's clock at the handshake, in seconds since 1970.
    pub peer_time: u32,
    /// Every frame we send is padded with zeros to at least this many bytes of command.
    pub pad_to: usize,
}

impl<S: Read + Write> Session<S> {
    /// Runs the handshake as initiator with our link key `secret`, accepting only a peer whose
    /// link key is `peer` and sending `ad` as our additional data.
    pub fn connect(
        mut stream: S,
        secret: &[u8; SECRET_KEY_LEN],
        peer: &[u8],
        ad: &[u8],
    ) -> io::Result<Session<S>> {
        let mut hs = Handshake::initiator(secret, &[PROLOGUE]);
        let mut first = vec![PROLOGUE];
        first.extend(hs.write(&[]));
        stream.write_all(&first)?;
        stream.flush()?;

        let mut m2 = vec![0; hs.message_len(AUTH_LEN)];
        stream.read_exact(&mut m2)?;
        let payload = hs.read(&m2).ok_or(invalid("handshake message 2"))?;
        if hs.remote_static().as_deref() != Some(peer) {
            return Err(invalid("unexpected link key"));
        }
        let (_, peer_time) = parse_authenticate(&payload).ok_or(invalid("authenticate"))?;

        let m3 = hs.write(&authenticate_message(ad, 0));
        stream.write_all(&m3)?;
        stream.flush()?;

        let mut m4 = vec![0; hs.message_len(0)];
        stream.read_exact(&mut m4)?;
        hs.read(&m4).ok_or(invalid("handshake message 4"))?;

        let t = hs.finish();
        Ok(Session {
            stream,
            send: t.send,
            recv: t.recv,
            peer_time,
            pad_to: 0,
        })
    }

    pub fn send(&mut self, frame: &Frame) -> io::Result<()> {
        let mut plain = Vec::with_capacity(HEADER_LEN + frame.body.len().max(self.pad_to));
        plain.push(frame.command);
        plain.push(0);
        plain.extend_from_slice(&(frame.body.len() as u32).to_be_bytes());
        plain.extend_from_slice(&frame.body);
        if plain.len() < self.pad_to {
            plain.resize(self.pad_to, 0);
        }
        if plain.len() + TAG_LEN > MAX_NOISE {
            return Err(invalid("command too long"));
        }
        let header = self
            .send
            .seal(&[], &((plain.len() + TAG_LEN) as u32).to_be_bytes());
        let body = self.send.seal(&[], &plain);
        self.send.rekey();
        self.stream.write_all(&header)?;
        self.stream.write_all(&body)?;
        self.stream.flush()
    }

    pub fn recv(&mut self) -> io::Result<Frame> {
        let mut header = [0; 4 + TAG_LEN];
        self.stream.read_exact(&mut header)?;
        let len = self
            .recv
            .open(&[], &header)
            .ok_or(invalid("frame header"))?;
        let len = u32::from_be_bytes(len[..].try_into().expect("4 bytes")) as usize;
        if !(HEADER_LEN + TAG_LEN..=MAX_NOISE).contains(&len) {
            return Err(invalid("frame length"));
        }
        let mut sealed = vec![0; len];
        self.stream.read_exact(&mut sealed)?;
        let plain = self.recv.open(&[], &sealed).ok_or(invalid("frame"))?;
        self.recv.rekey();
        let body_len = u32::from_be_bytes(plain[2..6].try_into().expect("4 bytes")) as usize;
        if plain[1] != 0 || HEADER_LEN + body_len > plain.len() {
            return Err(invalid("command"));
        }
        Ok(Frame {
            command: plain[0],
            body: plain[HEADER_LEN..HEADER_LEN + body_len].to_vec(),
        })
    }

    pub fn stream(&self) -> &S {
        &self.stream
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::thread;

    use super::super::noise::{generate, public_key};
    use super::*;

    /// A responder written from the same rules, for tests only.
    fn accept(mut s: UnixStream, secret: [u8; 32]) -> (Vec<u8>, Frame) {
        let mut hs = Handshake::responder(&secret, &[PROLOGUE]);
        let mut m1 = vec![0; 1 + hs.message_len(0)];
        s.read_exact(&mut m1).unwrap();
        assert_eq!(m1[0], PROLOGUE);
        hs.read(&m1[1..]).unwrap();
        s.write_all(&hs.write(&authenticate_message(b"", 1234)))
            .unwrap();
        let mut m3 = vec![0; hs.message_len(AUTH_LEN)];
        s.read_exact(&mut m3).unwrap();
        let (ad, _) = parse_authenticate(&hs.read(&m3).unwrap()).unwrap();
        s.write_all(&hs.write(&[])).unwrap();
        let t = hs.finish();
        let mut session = Session {
            stream: s,
            send: t.send,
            recv: t.recv,
            peer_time: 0,
            pad_to: 0,
        };
        let got = session.recv().unwrap();
        session.send(&got).unwrap();
        (ad, got)
    }

    #[test]
    fn a_session_carries_padded_commands_both_ways() {
        let server = generate();
        let server_pub = public_key(&server);
        let (a, b) = UnixStream::pair().unwrap();
        let secret = *server;
        let peer = thread::spawn(move || accept(b, secret));
        let mut s = Session::connect(a, &generate(), &server_pub, b"who").unwrap();
        assert_eq!(s.peer_time, 1234);
        s.pad_to = 100;
        let frame = Frame {
            command: 18,
            body: 7u64.to_be_bytes().to_vec(),
        };
        s.send(&frame).unwrap();
        assert_eq!(s.recv().unwrap(), frame);
        let (ad, got) = peer.join().unwrap();
        assert_eq!((ad, got), (b"who".to_vec(), frame));
    }

    #[test]
    fn a_peer_with_another_link_key_is_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        let server = generate();
        let secret = *server;
        thread::spawn(move || {
            let _ = std::panic::catch_unwind(|| accept(b, secret));
        });
        let other = public_key(&generate());
        let err = Session::connect(a, &generate(), &other, b"").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
