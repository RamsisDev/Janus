//! The mixnet transport: constant-rate requests to mailboxes, through a mixnet client.
//!
//! Every packet is one mailbox request (`janus_mailbox`), sent along a fresh random path with a
//! single-use reply block for the answer, so the mailbox never learns who asks. One packet
//! leaves per slot whether the user writes or not: a slot carries a queued block, else a fetch
//! of one listened queue, else a decoy, which is a fetch of a random queue. Each fetch names a
//! single queue, so nothing on the path can group one person's queues. Puts and fetches take
//! turns, so a long message does not stall receiving.
//!
//! `post` only queues, and sending happens in `poll`; call it on a fixed timer, never in answer
//! to the user, or the moment a packet leaves tells when they wrote.
//!
//! Every request is answered, so every packet is also a loop that shows the path works. A put
//! whose acknowledgement is late is sent again (the core drops duplicates); a fetch whose reply
//! is lost loses the block it carried, as on any lossy network. After [`MAX_LOST`] lost replies
//! in a row, or when the gateway cannot be reached, the next gateway takes over.
//!
//! When a new directory arrives, each queue is fetched both at its mailbox under the new
//! directory and under the one before, so blocks posted just before the change are not lost.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::Arc;

use janus_core::{Block, NetworkId, QueueId};
use janus_mailbox::{ACK, BLOCK, Reply, Request, fetch_request, put_request};

use crate::{Directory, Node, Transport};

/// Milliseconds between packets: 8 KiB/s of requests while the app is active. A starting
/// value, to set per cover level from battery and data tests on phones.
pub const SLOT: u64 = 2000;
/// Milliseconds to wait for a reply; seconds of mixing delay at every hop, both ways.
pub const REPLY_TIMEOUT: u64 = 60_000;
/// Replies lost in a row before the gateway is dropped.
pub const MAX_LOST: u32 = 8;
/// Milliseconds a dropped gateway is not tried again, unless every other one failed too.
const GATEWAY_BACKOFF: u64 = 10 * 60_000;
/// Slots sent at once to catch up; after a longer pause the rate starts afresh.
const MAX_BURST: u64 = 4;
/// Random queues tried for a decoy until one has a path.
const DECOY_TRIES: usize = 8;

/// A mixnet client: our own Katzenpost client, or a simulation in tests.
pub trait Link {
    /// The latest directory, verified against the network's pinned authorities.
    fn directory(&mut self) -> Option<Arc<Directory>>;
    /// Sends `request` as one packet along `path` (gateway first, mailbox last), with a reply
    /// block that brings the answer back under `tag`. An error means the gateway is unreachable.
    fn send(&mut self, tag: u64, path: &[&Node], request: &Request) -> io::Result<()>;
    /// Replies that arrived since the last call.
    fn replies(&mut self) -> Vec<(u64, Box<Reply>)>;
}

enum Job {
    Put(Box<Block>),
    /// A queue and the name of the mailbox asked.
    Fetch(QueueId, String),
    Decoy,
}

pub struct Mixnet<L> {
    network: NetworkId,
    link: L,
    /// Milliseconds of a monotonic clock.
    clock: Box<dyn Fn() -> u64 + Send>,
    slot: u64,
    next_slot: Option<u64>,
    put_turn: bool,
    directory: Option<Arc<Directory>>,
    previous: Option<Arc<Directory>>,
    gateway: Option<String>,
    /// Dropped gateways and until when.
    failed: HashMap<String, u64>,
    lost: u32,
    outbox: VecDeque<Box<Block>>,
    queues: Vec<QueueId>,
    /// What is left of the current round over the listened queues.
    fetches: VecDeque<(QueueId, String)>,
    /// Requests waiting for their reply, and when they left.
    inflight: HashMap<u64, (Job, u64)>,
    last_tag: u64,
    got: Vec<Block>,
}

impl<L: Link> Mixnet<L> {
    /// The network of id `network` through `link`, one packet every `slot` milliseconds of
    /// `clock`.
    pub fn new(
        network: NetworkId,
        link: L,
        slot: u64,
        clock: impl Fn() -> u64 + Send + 'static,
    ) -> Mixnet<L> {
        Mixnet {
            network,
            link,
            clock: Box::new(clock),
            slot,
            next_slot: None,
            put_turn: false,
            directory: None,
            previous: None,
            gateway: None,
            failed: HashMap::new(),
            lost: 0,
            outbox: VecDeque::new(),
            queues: Vec::new(),
            fetches: VecDeque::new(),
            inflight: HashMap::new(),
            last_tag: 0,
            got: Vec::new(),
        }
    }

    /// The gateway in use, if any.
    pub fn gateway(&self) -> Option<&str> {
        self.gateway.as_deref()
    }

    fn run(&mut self) {
        let now = (self.clock)();
        self.refresh();
        for (tag, reply) in self.link.replies() {
            self.answered(tag, &reply);
        }
        self.expire(now);
        let mut next = self.next_slot.unwrap_or(now);
        if now.saturating_sub(next) >= MAX_BURST * self.slot {
            next = now;
        }
        while next <= now {
            self.send_slot(now);
            next += self.slot;
        }
        self.next_slot = Some(next);
    }

    fn refresh(&mut self) {
        let Some(dir) = self.link.directory() else {
            return;
        };
        if self
            .directory
            .as_ref()
            .is_some_and(|d| d.epoch == dir.epoch)
        {
            return;
        }
        if let Some(g) = &self.gateway
            && !dir.gateways.iter().any(|n| &n.name == g)
        {
            self.gateway = None;
        }
        self.previous = self.directory.replace(dir);
        self.fetches.clear();
    }

    fn answered(&mut self, tag: u64, reply: &Reply) {
        let Some((job, _)) = self.inflight.remove(&tag) else {
            return;
        };
        self.lost = 0;
        match job {
            Job::Put(block) if reply[0] != ACK => self.outbox.push_front(block),
            Job::Fetch(queue, mailbox) if reply[0] == BLOCK => {
                self.got.push(reply[1..].try_into().expect("REPLY_LEN"));
                self.fetches.push_front((queue, mailbox));
            }
            _ => {}
        }
    }

    fn expire(&mut self, now: u64) {
        let late: Vec<u64> = self
            .inflight
            .iter()
            .filter(|(_, (_, at))| now >= at.saturating_add(REPLY_TIMEOUT))
            .map(|(tag, _)| *tag)
            .collect();
        for tag in late {
            self.lost += 1;
            if let Some((Job::Put(block), _)) = self.inflight.remove(&tag) {
                self.outbox.push_front(block);
            }
        }
        if self.lost >= MAX_LOST {
            self.drop_gateway(now);
        }
    }

    fn drop_gateway(&mut self, now: u64) {
        self.lost = 0;
        if let Some(g) = self.gateway.take() {
            self.failed.insert(g, now.saturating_add(GATEWAY_BACKOFF));
        }
    }

    /// The gateway in use, or the first in the directory's order that did not fail lately,
    /// or, if all did, the one whose backoff ends first.
    fn pick_gateway<'a>(&mut self, dir: &'a Directory, now: u64) -> Option<&'a Node> {
        if let Some(g) = &self.gateway {
            return dir.gateways.iter().find(|n| &n.name == g);
        }
        self.failed.retain(|_, until| *until > now);
        let order = dir.gateways();
        let pick = match order.iter().find(|g| !self.failed.contains_key(&g.name)) {
            Some(g) => *g,
            None => *order.iter().min_by_key(|g| self.failed[&g.name])?,
        };
        self.gateway = Some(pick.name.clone());
        Some(pick)
    }

    fn send_slot(&mut self, now: u64) {
        let Some(dir) = self.directory.clone() else {
            return;
        };
        let Some(gateway) = self.pick_gateway(&dir, now) else {
            return;
        };
        self.put_turn = !self.put_turn;
        for put in [self.put_turn, !self.put_turn] {
            if put {
                if let Some(block) = self.outbox.pop_front() {
                    let queue = block.first_chunk().expect("a block starts with its queue");
                    if let Some(path) = dir.mailbox(queue).and_then(|m| dir.path(gateway, m)) {
                        let request = put_request(&block);
                        return self.transmit(Job::Put(block), &request, &path, now);
                    }
                    // No path to that mailbox from this gateway: retry once others went.
                    self.outbox.push_back(block);
                }
            } else {
                if self.fetches.is_empty() {
                    self.new_round(&dir);
                }
                while let Some((queue, mailbox)) = self.fetches.pop_front() {
                    if !self.queues.contains(&queue) {
                        continue;
                    }
                    if let Some(path) = dir.node(&mailbox).and_then(|m| dir.path(gateway, m)) {
                        let request = fetch_request(&queue);
                        return self.transmit(Job::Fetch(queue, mailbox), &request, &path, now);
                    }
                }
            }
        }
        for _ in 0..DECOY_TRIES {
            let mut queue = QueueId::default();
            getrandom::fill(&mut queue).expect("OS random generator unavailable");
            if let Some(path) = dir.mailbox(&queue).and_then(|m| dir.path(gateway, m)) {
                return self.transmit(Job::Decoy, &fetch_request(&queue), &path, now);
            }
        }
    }

    /// Every listened queue at its mailbox now and, after a directory change, at the one before.
    fn new_round(&mut self, dir: &Directory) {
        for queue in &self.queues {
            for d in [Some(dir), self.previous.as_deref()].into_iter().flatten() {
                if let Some(m) = d.mailbox(queue) {
                    let fetch = (*queue, m.name.clone());
                    if !self.fetches.contains(&fetch) {
                        self.fetches.push_back(fetch);
                    }
                }
            }
        }
    }

    fn transmit(&mut self, job: Job, request: &Request, path: &[&Node], now: u64) {
        self.last_tag += 1;
        match self.link.send(self.last_tag, path, request) {
            Ok(()) => {
                self.inflight.insert(self.last_tag, (job, now));
            }
            Err(_) => {
                self.drop_gateway(now);
                if let Job::Put(block) = job {
                    self.outbox.push_front(block);
                }
            }
        }
    }
}

impl<L: Link> Transport for Mixnet<L> {
    fn network(&self) -> NetworkId {
        self.network
    }

    fn post(&mut self, block: &Block) {
        self.outbox.push_back(Box::new(*block));
    }

    fn listen(&mut self, queues: &[QueueId]) {
        self.queues = queues.to_vec();
    }

    fn poll(&mut self) -> Vec<Block> {
        self.run();
        std::mem::take(&mut self.got)
    }
}

#[cfg(test)]
mod tests {
    use janus_core::BLOCK_LEN;

    use super::*;
    use crate::sim::{Net, test_directory};

    fn block(queue: u8, n: u8) -> Block {
        let mut b = [n; BLOCK_LEN];
        b[..16].fill(queue);
        b
    }

    fn mixnet(net: &Net) -> Mixnet<crate::sim::SimLink> {
        Mixnet::new([0; 32], net.link(), SLOT, net.clock())
    }

    /// Polls each of `ts` once per slot, `slots` times.
    fn run(net: &Net, ts: &mut [&mut Mixnet<crate::sim::SimLink>], slots: u64) -> Vec<Block> {
        let mut got = Vec::new();
        for _ in 0..slots {
            for t in ts.iter_mut() {
                got.extend(t.poll());
            }
            net.advance(SLOT);
        }
        got
    }

    #[test]
    fn blocks_reach_the_queue_owner_one_packet_per_slot() {
        let net = Net::new(test_directory());
        let (mut a, mut b) = (mixnet(&net), mixnet(&net));
        let capture = net.capture();
        b.listen(&[[1; 16]]);
        for n in 0..3 {
            a.post(&block(1, n));
        }
        assert!(capture.lock().unwrap().is_empty(), "post sent something");
        let got = run(&net, &mut [&mut a, &mut b], 10);
        assert_eq!(got, [block(1, 0), block(1, 1), block(1, 2)]);
        let sent = capture.lock().unwrap();
        assert_eq!(sent.len(), 20, "one packet per slot and client");
    }

    #[test]
    fn a_dead_gateway_is_replaced() {
        let net = Net::new(test_directory());
        let (mut a, mut b) = (mixnet(&net), mixnet(&net));
        b.listen(&[[1; 16]]);
        run(&net, &mut [&mut a, &mut b], 1);
        let first = a.gateway().unwrap().to_owned();
        net.kill(&first);
        a.post(&block(1, 7));
        let got = run(&net, &mut [&mut a, &mut b], 6);
        assert_ne!(a.gateway(), Some(first.as_str()));
        assert_eq!(got, [block(1, 7)]);
    }

    #[test]
    fn a_put_lost_on_the_way_is_sent_again() {
        let net = Net::new(test_directory());
        let (mut a, mut b) = (mixnet(&net), mixnet(&net));
        b.listen(&[[1; 16]]);
        for name in ["m11", "m12"] {
            net.kill(name);
        }
        a.post(&block(1, 7));
        assert!(run(&net, &mut [&mut a, &mut b], 4).is_empty());
        for name in ["m11", "m12"] {
            net.revive(name);
        }
        let late = REPLY_TIMEOUT / SLOT + 4;
        assert_eq!(run(&net, &mut [&mut a, &mut b], late), [block(1, 7)]);
    }

    #[test]
    fn blocks_left_under_the_old_directory_are_still_fetched() {
        let net = Net::new(test_directory());
        let (mut a, mut b) = (mixnet(&net), mixnet(&net));
        let queues: Vec<QueueId> = (0..32).map(|i| [i; 16]).collect();
        for q in &queues {
            a.post(&block(q[0], 1));
        }
        run(&net, &mut [&mut a, &mut b], 40);
        net.add_mailbox("box9", "op9");
        assert!(
            queues
                .iter()
                .any(|q| net.directory().mailbox(q).unwrap().name == "box9"),
            "box9 took no queue"
        );
        b.listen(&queues);
        let mut got = run(&net, &mut [&mut b], 120);
        got.sort();
        let all: Vec<Block> = queues.iter().map(|q| block(q[0], 1)).collect();
        assert_eq!(got, all);
    }
}
