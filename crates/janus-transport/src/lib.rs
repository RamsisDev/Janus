//! How blocks travel, behind one [`Transport`] interface so a client never depends on a network.
//!
//! [`Mixnet`] is the app's transport: constant-rate requests to mailboxes through a mixnet
//! client, the [`Link`], with mailboxes and paths chosen from the network's [`Directory`]. Each
//! network is a pinned [`Network`] profile. [`Memory`] shares an in-process [`Mailbox`] for
//! tests. [`Direct`] talks to a `janus-mailbox` server over TLS 1.3 and pins its certificate; it
//! is for development only, since the mailbox sees client addresses.

mod directory;
pub mod katzenpost;
mod mixnet;
mod network;
#[cfg(any(test, feature = "sim"))]
pub mod sim;

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use janus_core::{Block, NetworkId, QueueId};
use janus_mailbox::{
    ACK, BLOCK, MAX_PER_QUEUE, Mailbox, REPLY_LEN, SERVER_NAME, fetch_request, put_request,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha2::{Digest, Sha256};

pub use directory::{Directory, Node};
pub use mixnet::{Link, Mixnet, REPLY_TIMEOUT, SLOT};
pub use network::{Authority, Network};

pub trait Transport {
    /// The network this transport reaches; the core binds it into handshakes run over it.
    fn network(&self) -> NetworkId;
    /// Sends a block to the mailbox serving its queue (the block's first 16 bytes).
    fn post(&mut self, block: &Block);
    /// The queues to fetch from now on; replaces the previous set.
    fn listen(&mut self, queues: &[QueueId]);
    /// Blocks waiting on the listened queues. The mailbox deletes what it hands out, so each
    /// block comes back once.
    fn poll(&mut self) -> Vec<Block>;
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn network(&self) -> NetworkId {
        (**self).network()
    }

    fn post(&mut self, block: &Block) {
        (**self).post(block);
    }

    fn listen(&mut self, queues: &[QueueId]) {
        (**self).listen(queues);
    }

    fn poll(&mut self) -> Vec<Block> {
        (**self).poll()
    }
}

/// Clones share one mailbox, like clients of one server, and one random network id. Blocks
/// never expire.
#[derive(Clone)]
pub struct Memory {
    mailbox: Arc<Mutex<Mailbox>>,
    network: NetworkId,
    queues: Vec<QueueId>,
}

impl Default for Memory {
    fn default() -> Memory {
        let mut network = NetworkId::default();
        getrandom::fill(&mut network).expect("OS random generator unavailable");
        Memory {
            mailbox: Arc::default(),
            network,
            queues: Vec::new(),
        }
    }
}

impl Transport for Memory {
    fn network(&self) -> NetworkId {
        self.network
    }

    fn post(&mut self, block: &Block) {
        self.mailbox.lock().unwrap().put(block, 0);
    }

    fn listen(&mut self, queues: &[QueueId]) {
        self.queues = queues.to_vec();
    }

    fn poll(&mut self) -> Vec<Block> {
        let mut mailbox = self.mailbox.lock().unwrap();
        let mut got = Vec::new();
        for queue in &self.queues {
            while let Some(block) = mailbox.fetch(queue, 0) {
                got.push(*block);
            }
        }
        got
    }
}

/// Bounds every connect, read and write, so a dead mailbox never stalls the client.
const TIMEOUT: Duration = Duration::from_secs(10);

type Tls = StreamOwned<ClientConnection, TcpStream>;

/// A `janus-mailbox` server over TLS 1.3. Connects on first use and again after any failure;
/// posted blocks wait in memory until the mailbox acknowledges them.
pub struct Direct {
    addr: String,
    config: Arc<ClientConfig>,
    network: NetworkId,
    tls: Option<Tls>,
    queues: Vec<QueueId>,
    outbox: VecDeque<Block>,
}

impl Direct {
    /// The mailbox at `addr` (`host:port`), trusted only if it shows `cert` (DER), the
    /// certificate it wrote at startup. That certificate also names the network.
    pub fn new(addr: &str, cert: &[u8]) -> io::Result<Direct> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert.to_vec()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Direct {
            addr: addr.to_owned(),
            config: Arc::new(config),
            network: Sha256::new()
                .chain_update(b"janus direct network")
                .chain_update(cert)
                .finalize()
                .into(),
            tls: None,
            queues: Vec::new(),
            outbox: VecDeque::new(),
        })
    }

    /// Whether the last exchange with the mailbox worked.
    pub fn connected(&self) -> bool {
        self.tls.is_some()
    }

    /// Sends the outbox, then fetches every listened queue into `got`, if given.
    fn exchange(&mut self, got: Option<&mut Vec<Block>>) -> io::Result<()> {
        if self.tls.is_none() {
            self.tls = Some(connect(&self.addr, &self.config)?);
        }
        let tls = self.tls.as_mut().expect("just connected");
        let mut reply = Box::new([0; REPLY_LEN]);
        while let Some(block) = self.outbox.front() {
            tls.write_all(&*put_request(block))?;
            tls.flush()?;
            tls.read_exact(&mut *reply)?;
            if reply[0] != ACK {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.outbox.pop_front();
        }
        let Some(got) = got else { return Ok(()) };
        for queue in &self.queues {
            // A mailbox never holds more than this per queue; a lying one cannot loop us.
            for _ in 0..MAX_PER_QUEUE {
                tls.write_all(&*fetch_request(queue))?;
                tls.flush()?;
                tls.read_exact(&mut *reply)?;
                if reply[0] != BLOCK {
                    break;
                }
                got.push(reply[1..].try_into().expect("REPLY_LEN"));
            }
        }
        Ok(())
    }
}

fn connect(addr: &str, config: &Arc<ClientConfig>) -> io::Result<Tls> {
    let tcp = addr
        .to_socket_addrs()?
        .find_map(|a| TcpStream::connect_timeout(&a, TIMEOUT).ok())
        .ok_or(io::ErrorKind::ConnectionRefused)?;
    tcp.set_read_timeout(Some(TIMEOUT))?;
    tcp.set_write_timeout(Some(TIMEOUT))?;
    tcp.set_nodelay(true)?;
    let name = ServerName::try_from(SERVER_NAME).expect("a valid DNS name");
    let conn = ClientConnection::new(Arc::clone(config), name).map_err(io::Error::other)?;
    Ok(StreamOwned::new(conn, tcp))
}

impl Transport for Direct {
    fn network(&self) -> NetworkId {
        self.network
    }

    fn post(&mut self, block: &Block) {
        self.outbox.push_back(*block);
        if self.exchange(None).is_err() {
            self.tls = None;
        }
    }

    fn listen(&mut self, queues: &[QueueId]) {
        self.queues = queues.to_vec();
    }

    fn poll(&mut self) -> Vec<Block> {
        let mut got = Vec::new();
        if self.exchange(Some(&mut got)).is_err() {
            self.tls = None;
        }
        got
    }
}

/// A uniformly random index below `n`, which must not be 0.
fn below(n: usize) -> usize {
    let mut r = [0; 8];
    getrandom::fill(&mut r).expect("OS random generator unavailable");
    // The bias of the modulo is under 2^-40 for any directory size.
    (u64::from_be_bytes(r) % n as u64) as usize
}

fn shuffle<T>(items: &mut [T]) {
    for i in (1..items.len()).rev() {
        items.swap(i, below(i + 1));
    }
}
