//! Store-and-forward mailbox for Janus blocks, keyed by the queue id in their first 16 bytes.
//!
//! [`Mailbox`] is the store: `put` keeps a block under its queue and `fetch` hands back the
//! oldest one, deleting it. Blocks expire after [`TTL`], each queue keeps at most
//! [`MAX_PER_QUEUE`] (oldest dropped first) and the whole mailbox at most [`MAX_BLOCKS`].
//! Nothing touches the disk, and there are no accounts: a queue id is all it knows.
//!
//! [`Mailbox::answer`] speaks the protocol, the same whether requests come over TLS or through
//! the mixnet, where replies travel back in single-use reply blocks:
//!
//! ```text
//! PUT   | block (16384 B)              ->  ACK   | 16384 random bytes
//! FETCH | queue id (16 B) | zeros      ->  BLOCK | the oldest block,  or  DECOY | 16384 random bytes
//! ```
//!
//! Every request and every reply has the same size, so neither tells a put from a fetch, nor
//! an empty queue from a busy one. With the `server` feature (on by default), [`serve`] runs a
//! mailbox over TLS 1.3 for the `Direct` transport. That one is for development: it sees client
//! addresses, though it never logs or stores them.

use std::collections::{HashMap, VecDeque};
#[cfg(feature = "server")]
use std::io::{self, Read, Write};
#[cfg(feature = "server")]
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "server")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "server")]
use std::thread;
#[cfg(feature = "server")]
use std::time::{Duration, Instant};

use janus_core::{BLOCK_LEN, Block, QueueId};
#[cfg(feature = "server")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
#[cfg(feature = "server")]
use rustls::{ServerConfig, ServerConnection, StreamOwned};

pub const PUT: u8 = 1;
pub const FETCH: u8 = 2;
pub const ACK: u8 = 1;
pub const BLOCK: u8 = 1;
pub const DECOY: u8 = 0;
/// An operation byte, then a block or a padded queue id.
pub const REQUEST_LEN: usize = 1 + BLOCK_LEN;
/// A status byte, then a block or random bytes.
pub const REPLY_LEN: usize = 1 + BLOCK_LEN;
pub type Request = [u8; REQUEST_LEN];
pub type Reply = [u8; REPLY_LEN];
const QUEUE_ID_LEN: usize = size_of::<QueueId>();
/// The only name in the mailbox's self-signed certificate; clients pin the certificate itself.
pub const SERVER_NAME: &str = "janus-mailbox";
/// How long a block waits to be fetched: the longest rotation backoff.
pub const TTL: u64 = 30 * 24 * 3600;
/// Blocks per queue: four messages of the core's largest size (1000 blocks).
pub const MAX_PER_QUEUE: usize = 4096;
/// Blocks in the whole mailbox, 1 GiB.
pub const MAX_BLOCKS: usize = 65536;
/// Seconds between sweeps of expired blocks on queues nobody fetches.
const SWEEP_EVERY: u64 = 60;
/// A connection silent this long is closed.
#[cfg(feature = "server")]
const IDLE: Duration = Duration::from_secs(120);

pub fn put_request(block: &Block) -> Box<Request> {
    let mut request = Box::new([0; REQUEST_LEN]);
    request[0] = PUT;
    request[1..].copy_from_slice(block);
    request
}

pub fn fetch_request(queue: &QueueId) -> Box<Request> {
    let mut request = Box::new([0; REQUEST_LEN]);
    request[0] = FETCH;
    request[1..=QUEUE_ID_LEN].copy_from_slice(queue);
    request
}

pub struct Mailbox {
    ttl: u64,
    per_queue: usize,
    max: usize,
    /// `(posted at, block)`, oldest first.
    queues: HashMap<QueueId, VecDeque<(u64, Box<Block>)>>,
    stored: usize,
    swept: u64,
}

impl Default for Mailbox {
    fn default() -> Self {
        Mailbox::new(TTL, MAX_PER_QUEUE, MAX_BLOCKS)
    }
}

impl Mailbox {
    pub fn new(ttl: u64, per_queue: usize, max: usize) -> Mailbox {
        Mailbox {
            ttl,
            per_queue,
            max,
            queues: HashMap::new(),
            stored: 0,
            swept: 0,
        }
    }

    /// Keeps `block` under its queue id; `now` is seconds from any fixed start. A full queue
    /// drops its oldest block; a full mailbox drops `block`.
    pub fn put(&mut self, block: &Block, now: u64) {
        self.sweep(now);
        let queue: &QueueId = block
            .first_chunk()
            .expect("a block starts with its queue id");
        let at_cap = self
            .queues
            .get(queue)
            .is_some_and(|blocks| blocks.len() >= self.per_queue);
        // shortcut: a full mailbox refuses new blocks until some expire, so a flood blocks
        // everyone; add abuse limits without accounts before the mailbox is public.
        if !at_cap && self.stored >= self.max {
            return;
        }
        let blocks = self.queues.entry(*queue).or_default();
        if at_cap {
            blocks.pop_front();
        } else {
            self.stored += 1;
        }
        blocks.push_back((now, Box::new(*block)));
    }

    /// The oldest unexpired block on `queue`, deleted from the mailbox.
    pub fn fetch(&mut self, queue: &QueueId, now: u64) -> Option<Box<Block>> {
        self.sweep(now);
        let blocks = self.queues.get_mut(queue)?;
        let mut found = None;
        while let Some((at, block)) = blocks.pop_front() {
            self.stored -= 1;
            if now.saturating_sub(at) < self.ttl {
                found = Some(block);
                break;
            }
        }
        if blocks.is_empty() {
            self.queues.remove(queue);
        }
        found
    }

    /// The reply to `request`; `None` for an unknown operation.
    pub fn answer(&mut self, request: &Request, now: u64) -> Option<Box<Reply>> {
        let mut reply = Box::new([0; REPLY_LEN]);
        let found = match request[0] {
            PUT => {
                self.put(request[1..].try_into().expect("REQUEST_LEN"), now);
                reply[0] = ACK;
                None
            }
            FETCH => {
                let queue = request[1..=QUEUE_ID_LEN].try_into().expect("REQUEST_LEN");
                self.fetch(queue, now)
            }
            _ => return None,
        };
        match found {
            Some(block) => {
                reply[0] = BLOCK;
                reply[1..].copy_from_slice(&*block);
            }
            None => getrandom::fill(&mut reply[1..]).expect("OS random generator unavailable"),
        }
        Some(reply)
    }

    fn sweep(&mut self, now: u64) {
        if now < self.swept.saturating_add(SWEEP_EVERY) {
            return;
        }
        self.swept = now;
        let (ttl, stored) = (self.ttl, &mut self.stored);
        self.queues.retain(|_, blocks| {
            while blocks
                .front()
                .is_some_and(|(at, _)| now.saturating_sub(*at) >= ttl)
            {
                blocks.pop_front();
                *stored -= 1;
            }
            !blocks.is_empty()
        });
    }
}

/// A fresh self-signed certificate for [`SERVER_NAME`], in DER, and its key.
#[cfg(feature = "server")]
pub fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let certified =
        rcgen::generate_simple_self_signed([SERVER_NAME.to_owned()]).expect("a fixed valid name");
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    (certified.cert.der().clone(), key.into())
}

/// Serves one in-memory [`Mailbox`] over TLS 1.3 with `cert` and `key`, forever.
#[cfg(feature = "server")]
pub fn serve(
    listener: TcpListener,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> io::Result<()> {
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(io::Error::other)?;
    let config = Arc::new(config);
    let mailbox = Arc::new(Mutex::new(Mailbox::default()));
    let start = Instant::now();
    for tcp in listener.incoming() {
        let Ok(tcp) = tcp else { continue };
        let (config, mailbox) = (Arc::clone(&config), Arc::clone(&mailbox));
        // shortcut: one thread per connection with no cap; bound it before the mailbox is public.
        // A client that leaves or misbehaves just ends its connection; nothing is logged.
        thread::spawn(move || connection(tcp, config, &mailbox, start));
    }
    Ok(())
}

#[cfg(feature = "server")]
fn connection(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
    mailbox: &Mutex<Mailbox>,
    start: Instant,
) -> io::Result<()> {
    tcp.set_read_timeout(Some(IDLE))?;
    tcp.set_write_timeout(Some(IDLE))?;
    tcp.set_nodelay(true)?;
    let conn = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, tcp);
    let mut request = Box::new([0; REQUEST_LEN]);
    loop {
        tls.read_exact(&mut *request)?;
        let now = start.elapsed().as_secs();
        let reply = mailbox.lock().unwrap().answer(&request, now);
        tls.write_all(&*reply.ok_or(io::ErrorKind::InvalidData)?)?;
        tls.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(queue: u8, n: u8) -> Block {
        let mut b = [n; BLOCK_LEN];
        b[..16].fill(queue);
        b
    }

    #[test]
    fn fetch_returns_oldest_first_and_deletes() {
        let mut m = Mailbox::default();
        m.put(&block(1, 10), 0);
        m.put(&block(1, 11), 0);
        m.put(&block(2, 20), 0);
        assert_eq!(*m.fetch(&[1; 16], 0).unwrap(), block(1, 10));
        assert_eq!(*m.fetch(&[1; 16], 0).unwrap(), block(1, 11));
        assert!(m.fetch(&[1; 16], 0).is_none());
        assert_eq!(*m.fetch(&[2; 16], 0).unwrap(), block(2, 20));
        assert_eq!((m.stored, m.queues.len()), (0, 0));
    }

    #[test]
    fn caps_drop_the_oldest_of_a_queue_and_refuse_when_full() {
        let mut m = Mailbox::new(TTL, 2, 3);
        for n in 0..3 {
            m.put(&block(1, n), 0);
        }
        m.put(&block(2, 20), 0);
        m.put(&block(3, 30), 0);
        assert!(m.fetch(&[3; 16], 0).is_none(), "mailbox full");
        assert_eq!(
            *m.fetch(&[1; 16], 0).unwrap(),
            block(1, 1),
            "oldest dropped"
        );
        assert_eq!(*m.fetch(&[1; 16], 0).unwrap(), block(1, 2));
        assert_eq!(*m.fetch(&[2; 16], 0).unwrap(), block(2, 20));
    }

    #[test]
    fn blocks_expire_on_fetch_and_on_sweep() {
        let mut m = Mailbox::new(100, 8, 1);
        m.put(&block(1, 10), 0);
        assert!(m.fetch(&[1; 16], 100).is_none());

        m.put(&block(1, 11), 100);
        m.put(&block(2, 20), 150);
        assert!(
            m.fetch(&[2; 16], 150).is_none(),
            "full until queue 1 expires"
        );
        m.put(&block(2, 21), 200);
        assert_eq!(*m.fetch(&[2; 16], 200).unwrap(), block(2, 21));
    }

    #[test]
    fn answers_have_one_size_and_unknown_requests_none() {
        let mut m = Mailbox::default();
        let ack = m.answer(&put_request(&block(1, 10)), 0).unwrap();
        assert_eq!(ack[0], ACK);
        let found = m.answer(&fetch_request(&[1; 16]), 0).unwrap();
        assert_eq!((found[0], &found[1..]), (BLOCK, &block(1, 10)[..]));
        let empty = m.answer(&fetch_request(&[1; 16]), 0).unwrap();
        assert_eq!(empty[0], DECOY);
        assert_ne!(&empty[1..], &[0; BLOCK_LEN][..], "decoys are random");
        assert!(m.answer(&[9; REQUEST_LEN], 0).is_none());
    }
}
