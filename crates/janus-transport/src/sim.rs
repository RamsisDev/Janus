//! A mixnet simulated in memory, for tests: packets cross every node at once, a killed node
//! drops what crosses it, and the directory changes only when an epoch is published: then it
//! lists every node not dead. Built for this crate's tests and with the `sim` feature.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use janus_mailbox::{Mailbox, Reply, Request};

use crate::{Directory, Link, Node};

/// One packet a client sent: when (milliseconds of the net's clock), from which link and
/// through which gateway. All packets have the same size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub at: u64,
    pub link: usize,
    pub gateway: String,
}

pub type Capture = Arc<Mutex<Vec<Sent>>>;

struct State {
    /// Every node, dead or alive.
    all: Directory,
    directory: Arc<Directory>,
    mailboxes: HashMap<String, Mailbox>,
    dead: HashSet<String>,
    links: usize,
}

/// Clones share one network.
#[derive(Clone)]
pub struct Net {
    state: Arc<Mutex<State>>,
    clock: Arc<AtomicU64>,
    capture: Capture,
}

impl Net {
    pub fn new(directory: Directory) -> Net {
        let mailboxes = directory
            .mailboxes
            .iter()
            .map(|m| (m.name.clone(), Mailbox::default()))
            .collect();
        Net {
            state: Arc::new(Mutex::new(State {
                all: directory.clone(),
                directory: Arc::new(directory),
                mailboxes,
                dead: HashSet::new(),
                links: 0,
            })),
            clock: Arc::new(AtomicU64::new(0)),
            capture: Capture::default(),
        }
    }

    /// A new client's connection to the network.
    pub fn link(&self) -> SimLink {
        let mut state = self.lock();
        state.links += 1;
        SimLink {
            net: self.clone(),
            id: state.links,
            replies: Vec::new(),
        }
    }

    /// Every packet sent so far, as an observer at the clients would see them.
    pub fn capture(&self) -> Capture {
        Arc::clone(&self.capture)
    }

    /// Milliseconds since the net started.
    pub fn clock(&self) -> impl Fn() -> u64 + Send + 'static {
        let clock = Arc::clone(&self.clock);
        move || clock.load(Ordering::Relaxed)
    }

    pub fn advance(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::Relaxed);
    }

    pub fn directory(&self) -> Arc<Directory> {
        Arc::clone(&self.lock().directory)
    }

    /// The node drops everything from now on, and a mailbox loses what it held.
    pub fn kill(&self, name: &str) {
        let mut state = self.lock();
        state.dead.insert(name.to_owned());
        if let Some(mailbox) = state.mailboxes.get_mut(name) {
            *mailbox = Mailbox::default();
        }
    }

    pub fn revive(&self, name: &str) {
        self.lock().dead.remove(name);
    }

    /// The next epoch, listing every node not dead.
    pub fn publish(&self) {
        let mut state = self.lock();
        let mut dir = state.all.clone();
        let dead = &state.dead;
        dir.epoch = state.directory.epoch + 1;
        dir.gateways.retain(|n| !dead.contains(&n.name));
        for layer in &mut dir.layers {
            layer.retain(|n| !dead.contains(&n.name));
        }
        dir.mailboxes.retain(|n| !dead.contains(&n.name));
        state.directory = Arc::new(dir);
    }

    /// One more mailbox, published at once.
    pub fn add_mailbox(&self, name: &str, operator: &str) {
        let mut state = self.lock();
        state.mailboxes.insert(name.to_owned(), Mailbox::default());
        state.all.mailboxes.push(node(name, operator));
        drop(state);
        self.publish();
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }
}

pub struct SimLink {
    net: Net,
    id: usize,
    replies: Vec<(u64, Box<Reply>)>,
}

impl Link for SimLink {
    fn directory(&mut self) -> Option<Arc<Directory>> {
        Some(self.net.directory())
    }

    fn send(&mut self, tag: u64, path: &[&Node], request: &Request) -> io::Result<()> {
        let at = self.net.clock.load(Ordering::Relaxed);
        let mut state = self.net.lock();
        let gateway = &path[0].name;
        if state.dead.contains(gateway) {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        self.net.capture.lock().unwrap().push(Sent {
            at,
            link: self.id,
            gateway: gateway.clone(),
        });
        if path.iter().any(|n| state.dead.contains(&n.name)) {
            return Ok(());
        }
        let mailbox = &path[path.len() - 1].name;
        if let Some(reply) = state
            .mailboxes
            .get_mut(mailbox)
            .and_then(|m| m.answer(request, at / 1000))
        {
            self.replies.push((tag, reply));
        }
        Ok(())
    }

    fn replies(&mut self) -> Vec<(u64, Box<Reply>)> {
        std::mem::take(&mut self.replies)
    }
}

/// A node named `name`, keyed by its name.
pub fn node(name: &str, operator: &str) -> Node {
    use sha2::{Digest, Sha256};
    Node {
        name: name.into(),
        operator: operator.into(),
        key: Sha256::digest(name.as_bytes()).to_vec(),
        addresses: vec![format!("{name}.example:4000")],
    }
}

/// 2 gateways, 3 layers of 2 mixes and 4 mailboxes, with paths for any gateway and mailbox.
pub fn test_directory() -> Directory {
    Directory {
        epoch: 1,
        gateways: vec![node("g1", "op5"), node("g2", "op6")],
        layers: vec![
            vec![node("m11", "op1"), node("m12", "op2")],
            vec![node("m21", "op2"), node("m22", "op3")],
            vec![node("m31", "op3"), node("m32", "op4")],
        ],
        mailboxes: vec![
            node("box1", "op7"),
            node("box2", "op8"),
            node("box3", "op7"),
            node("box4", "op8"),
        ],
    }
}
