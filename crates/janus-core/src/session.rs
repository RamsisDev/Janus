//! Sessions and the engine: the only way in and out of the core.
//!
//! Control frames travel in single-fragment `Kind::Control` blocks:
//!
//! ```text
//! Rekey      | 1 | offer id 4 | ml-kem key 1184 |
//! RekeyReply | 2 | offer id 4 | ml-kem ciphertext 1088 |
//! Ack        | 3 |
//! Close      | 4 |
//! Cover      | 5 |
//! ```
//!
//! Close ends the session on both sides. Cover is a decoy for cover traffic, dropped after
//! decryption.
//!
//! Forced rotation: when the interval elapses a side sends Rekey, the peer answers RekeyReply
//! and the offerer answers Ack. The ratchet's sending DH step is lazy (it runs only after a new
//! peer key arrives), so this round trip forces turn changes that rotate both DH keys. The
//! ML-KEM secret is mixed into the offerer's next new chain: usually the Ack's, but with
//! crossing traffic the Ack may land on an old chain. A side whose secret is still unmixed when
//! the interval elapses sends a bare Ack instead of a Rekey, forcing another turn change. Acks
//! are never answered.
//!
//! Rotating needs the peer, so while it stays silent each new attempt waits twice as long, up
//! to `MAX_BACKOFF`; any block from the peer restores the interval. A session that hears nothing
//! for `MAX_SILENCE` goes dormant: it sends and rotates nothing, but still opens blocks, and the
//! first one from the peer wakes it. Rotation traffic counts as hearing, so sessions between
//! live devices never go dormant on their own. Only the user deletes a dormant session: silence
//! can be forged (a cut network plus a forged clock), and deleting would force a new meeting to
//! exchange words.
//!
//! The clock passed in may be forged (spoofed NTP). Each session keeps its own: a clock moved
//! back counts as no time passing and never undoes elapsed time, so it cannot stall rotation or
//! keep skipped keys alive; and one call adds at most `MAX_SILENT_STEP` to the silence, so a
//! clock pushed forward cannot put sessions to sleep at once.

use std::collections::{BTreeMap, HashMap};

use zeroize::Zeroizing;

use crate::block::{
    self, BLOCK_LEN, Block, Fragment, Kind, MAX_CONTENT_LEN, QUEUE_ID_LEN, QueueId,
};
use crate::crypto::{self, Key, NONCE_LEN, TAG_LEN};
use crate::handshake::{
    self, Error, Established, Initiator, Interval, MSG1_LEN, MSG2_LEN, MSG3_LEN, NetworkId,
    Responder, SAFETY_LEN,
};
use crate::ratchet::{MAX_SKIP, Ratchet};

/// Equal to the skip window, so a full message still assembles when delivered in reverse.
const MAX_FRAGMENTS: usize = MAX_SKIP;
// shortcut: at most 8 messages stay partial per session (oldest evicted), within `MAX_PARTS`;
// stream fragments to the client when it needs more.
const MAX_PARTIALS: usize = 8;
/// Fragments held in partial messages across all sessions (~64 MB), so contacts together
/// cannot hold more than four full messages. A starting value, to tune.
const MAX_PARTS: usize = 4 * MAX_FRAGMENTS;
/// Control blocks kept for `outgoing`, oldest dropped first; lost control blocks are tolerated.
const MAX_OUTBOX: usize = 4;
/// Seconds (360 days) without any block from the peer after which a session goes dormant.
pub const MAX_SILENCE: u64 = 360 * 24 * 3600;
/// Most seconds one call adds to a session's silence. A device off for longer than this
/// counts only this much; its peer, whose clock kept running, goes dormant anyway.
const MAX_SILENT_STEP: u64 = 24 * 3600;
/// Longest wait between unanswered rotation attempts.
const MAX_BACKOFF: u64 = 30 * 24 * 3600;
/// Doublings counted; past them the wait is at `MAX_BACKOFF` anyway.
const MAX_DOUBLINGS: u8 = 16;
/// Wrong answers an invitation survives. Each is one online guess at the 42 bits of the words
/// the rendezvous queue does not reveal.
pub const MAX_ANSWERS: u8 = 64;
/// Invitations answered at once from one rendezvous queue: unrelated ones can share it, and B
/// cannot tell its peer's apart before the handshake ends. Each answer is one more guess for
/// whoever posted that invitation, so a guesser wins under 2^-35 of the time. A man in the
/// middle that already has the words completes only the answer whose safety words match the
/// other side's, at most 2^-31 of the time.
pub const MAX_REPLIES: usize = 4;

const REKEY: u8 = 1;
const REKEY_REPLY: u8 = 2;
const ACK: u8 = 3;
const CLOSE: u8 = 4;
const COVER: u8 = 5;

const STATE_AAD: &[u8] = b"janus session v3";

struct Partial {
    msg_id: u64,
    count: u32,
    parts: BTreeMap<u32, Zeroizing<Vec<u8>>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    Message(Zeroizing<Vec<u8>>),
    /// A fragment, control or cover block: nothing to show, but the state changed.
    Nothing,
    /// The peer closed the session; it is already gone. Delete its export.
    Closed,
}

pub struct Session {
    ratchet: Ratchet,
    interval: Interval,
    safety: [u8; SAFETY_LEN],
    /// The user vouched for the safety words; `Engine` sends nothing before.
    confirmed: bool,
    /// Last time passed in.
    wall: u64,
    /// Never goes back: advances only when `wall` does. Rotation and skipped keys age on it.
    clock: u64,
    last_rotation: u64,
    /// Seconds since the last block from the peer opened, at most `MAX_SILENT_STEP` per call.
    silence: u64,
    /// Rotation attempts sent since the peer was last heard.
    unanswered: u8,
    partial: Vec<Partial>,
    outbox: Vec<Block>,
}

impl Session {
    pub fn new(established: Established, now: u64) -> Session {
        let Established {
            initiator,
            root,
            our_dh,
            their_dh,
            interval,
            safety,
        } = established;
        Session {
            ratchet: Ratchet::new(initiator, &root, our_dh, &their_dh),
            interval,
            safety,
            // A gets its session only from `Engine::verify`, once the words were typed.
            confirmed: initiator,
            wall: now,
            clock: now,
            last_rotation: now,
            silence: 0,
            unanswered: 0,
            partial: Vec::new(),
            outbox: Vec::new(),
        }
    }

    /// Advances the session's clocks to `now` and returns `clock`.
    fn tick(&mut self, now: u64) -> u64 {
        let step = now.saturating_sub(self.wall);
        self.wall = now;
        self.clock = self.clock.saturating_add(step);
        self.silence = self.silence.saturating_add(step.min(MAX_SILENT_STEP));
        self.clock
    }

    pub fn dormant(&mut self, now: u64) -> bool {
        self.tick(now);
        self.silence > MAX_SILENCE
    }

    /// Drops skipped keys past their TTL; true if any went.
    pub fn purge(&mut self, now: u64) -> bool {
        let clock = self.tick(now);
        self.ratchet.purge(clock)
    }

    /// `None` when `data` is over `MAX_FRAGMENTS` blocks (~16 MB).
    pub fn encrypt(&mut self, data: &[u8]) -> Option<Vec<Block>> {
        // shortcut: no streaming; the client chunks bigger payloads into several messages.
        if data.len() > MAX_FRAGMENTS * MAX_CONTENT_LEN {
            return None;
        }
        let msg_id = u64::from_be_bytes(crypto::random());
        let bodies = block::split(Kind::Message, msg_id, data);
        Some(bodies.iter().map(|body| self.ratchet.seal(body)).collect())
    }

    /// `None` when the block is not for this session. A block that opens wakes a dormant one.
    pub fn decrypt(&mut self, block: &Block, now: u64) -> Option<Received> {
        let clock = self.tick(now);
        let body = self.ratchet.open(block, clock)?;
        self.silence = 0;
        self.unanswered = 0;
        Some(match block::parse(&body) {
            Some(f) if f.kind == Kind::Message => self
                .reassemble(&f)
                .map_or(Received::Nothing, Received::Message),
            Some(f) if f.count == 1 && f.content == [CLOSE] => Received::Closed,
            Some(f) if f.count == 1 => {
                self.control(f.content);
                Received::Nothing
            }
            _ => Received::Nothing,
        })
    }

    /// Pending control blocks, plus a Rekey (or an Ack, see the module doc) when the rotation
    /// wait has elapsed. Nothing while dormant.
    pub fn outgoing(&mut self, now: u64) -> Vec<Block> {
        if self.dormant(now) {
            return Vec::new();
        }
        let wait = (self.interval.secs() << self.unanswered).min(MAX_BACKOFF);
        if self.clock >= self.last_rotation.saturating_add(wait) {
            match self.ratchet.kem_offer() {
                Some((id, ek)) => self.queue(&[&[REKEY][..], &id.to_be_bytes(), &ek].concat()),
                None => self.queue(&[ACK]),
            }
            self.last_rotation = self.clock;
            self.unanswered = (self.unanswered + 1).min(MAX_DOUBLINGS);
        }
        std::mem::take(&mut self.outbox)
    }

    /// `nonce | ciphertext | tag` under `storage_key`.
    pub fn export(&self, storage_key: &Key) -> Vec<u8> {
        let ratchet = self.ratchet.to_bytes();
        let parts: usize = self
            .partial
            .iter()
            .flat_map(|p| p.parts.values())
            .map(|c| 6 + c.len())
            .sum();
        let len = 1 + SAFETY_LEN + 1 + 4 * 8 + 1 + 1 + 16 * self.partial.len() + parts + 4;
        let len = len + BLOCK_LEN * self.outbox.len() + ratchet.len();
        // Reserved up front: a reallocation would leave unzeroized copies of secrets behind.
        let mut w = Zeroizing::new(Vec::with_capacity(len));
        w.push(self.interval as u8);
        w.extend_from_slice(&self.safety);
        w.push(u8::from(self.confirmed));
        for t in [self.wall, self.clock, self.last_rotation, self.silence] {
            w.extend_from_slice(&t.to_be_bytes());
        }
        w.push(self.unanswered);
        w.push(self.partial.len() as u8);
        for p in &self.partial {
            w.extend_from_slice(&p.msg_id.to_be_bytes());
            w.extend_from_slice(&p.count.to_be_bytes());
            w.extend_from_slice(&(p.parts.len() as u32).to_be_bytes());
            for (index, content) in &p.parts {
                w.extend_from_slice(&index.to_be_bytes());
                w.extend_from_slice(&(content.len() as u16).to_be_bytes());
                w.extend_from_slice(content);
            }
        }
        w.extend_from_slice(&(self.outbox.len() as u32).to_be_bytes());
        for block in &self.outbox {
            w.extend_from_slice(block);
        }
        w.extend_from_slice(&ratchet);
        debug_assert_eq!(w.len(), len);
        let nonce = crypto::random::<NONCE_LEN>();
        let tag = crypto::seal(storage_key, &nonce, STATE_AAD, &mut w);
        [&nonce[..], &w, &tag].concat()
    }

    pub fn import(bytes: &[u8], storage_key: &Key) -> Option<Session> {
        let (nonce, rest) = bytes.split_first_chunk::<NONCE_LEN>()?;
        let (sealed, tag) = rest.split_last_chunk::<TAG_LEN>()?;
        let mut plain = Zeroizing::new(sealed.to_vec());
        crypto::open(storage_key, nonce, STATE_AAD, &mut plain, tag)?;
        let r = &mut &plain[..];
        let interval = Interval::from_byte(take::<1>(r)?[0])?;
        let safety = *take(r)?;
        let confirmed = match take::<1>(r)?[0] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let mut time = || take(r).map(|t| u64::from_be_bytes(*t));
        let (wall, clock, last_rotation, silence) = (time()?, time()?, time()?, time()?);
        let unanswered = take::<1>(r)?[0];
        if unanswered > MAX_DOUBLINGS {
            return None;
        }
        let mut partial = Vec::new();
        for _ in 0..take::<1>(r)?[0] {
            let msg_id = u64::from_be_bytes(*take(r)?);
            let count = u32::from_be_bytes(*take(r)?);
            let mut parts = BTreeMap::new();
            for _ in 0..u32::from_be_bytes(*take(r)?) {
                let index = u32::from_be_bytes(*take(r)?);
                let len = u16::from_be_bytes(*take(r)?);
                let (content, rest) = r.split_at_checked(len.into())?;
                *r = rest;
                parts.insert(index, Zeroizing::new(content.to_vec()));
            }
            partial.push(Partial {
                msg_id,
                count,
                parts,
            });
        }
        let mut outbox = Vec::new();
        for _ in 0..u32::from_be_bytes(*take(r)?) {
            outbox.push(*take::<BLOCK_LEN>(r)?);
        }
        Some(Session {
            ratchet: Ratchet::from_bytes(r)?,
            interval,
            safety,
            confirmed,
            wall,
            clock,
            last_rotation,
            silence,
            unanswered,
            partial,
            outbox,
        })
    }

    fn queue_ids(&self) -> Vec<QueueId> {
        self.ratchet.queue_ids()
    }

    fn parts(&self) -> usize {
        self.partial.iter().map(|p| p.parts.len()).sum()
    }

    /// Drops the oldest partial message and returns how many fragments it held.
    fn evict_partial(&mut self) -> usize {
        self.partial.remove(0).parts.len()
    }

    fn reassemble(&mut self, f: &Fragment) -> Option<Zeroizing<Vec<u8>>> {
        if f.count == 1 {
            return Some(Zeroizing::new(f.content.to_vec()));
        }
        if f.count as usize > MAX_FRAGMENTS {
            return None;
        }
        let at = match self.partial.iter().position(|p| p.msg_id == f.msg_id) {
            Some(at) => at,
            None => {
                if self.partial.len() >= MAX_PARTIALS {
                    self.partial.remove(0);
                }
                self.partial.push(Partial {
                    msg_id: f.msg_id,
                    count: f.count,
                    parts: BTreeMap::new(),
                });
                self.partial.len() - 1
            }
        };
        let p = &mut self.partial[at];
        if p.count != f.count {
            return None;
        }
        p.parts
            .entry(f.index)
            .or_insert_with(|| Zeroizing::new(f.content.to_vec()));
        if p.parts.len() < p.count as usize {
            return None;
        }
        let p = self.partial.remove(at);
        let mut out = Zeroizing::new(Vec::with_capacity(p.parts.values().map(|c| c.len()).sum()));
        for content in p.parts.values() {
            out.extend_from_slice(content);
        }
        Some(out)
    }

    /// Malformed frames are ignored.
    fn control(&mut self, frame: &[u8]) {
        let Some((&subtype, rest)) = frame.split_first() else {
            return;
        };
        // Ack and Cover carry no id and need no action.
        let Some((id, key)) = rest.split_first_chunk::<4>() else {
            return;
        };
        let id = u32::from_be_bytes(*id);
        match subtype {
            REKEY => {
                if let Some(ct) = self.ratchet.kem_accept(id, key) {
                    self.queue(&[&[REKEY_REPLY][..], &id.to_be_bytes(), &ct].concat());
                    self.last_rotation = self.clock;
                }
            }
            REKEY_REPLY if self.ratchet.kem_complete(id, key).is_some() => self.queue(&[ACK]),
            _ => {}
        }
    }

    fn seal_control(&mut self, frame: &[u8]) -> Block {
        self.ratchet.seal(&block::split(Kind::Control, 0, frame)[0])
    }

    fn queue(&mut self, frame: &[u8]) {
        let block = self.seal_control(frame);
        if self.outbox.len() >= MAX_OUTBOX {
            self.outbox.remove(0);
        }
        self.outbox.push(block);
    }
}

fn take<'a, const N: usize>(r: &mut &'a [u8]) -> Option<&'a [u8; N]> {
    let (head, rest) = r.split_first_chunk::<N>()?;
    *r = rest;
    Some(head)
}

/// Handle to a session inside one `Engine`. Not persisted: `import` returns a fresh one, so
/// clients keep their own contact-to-id mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

/// The pending handshake steps, each with the queue its answer arrives on.
enum Pending {
    /// Plus the wrong answers received so far.
    Invite(Box<Initiator>, QueueId, u8),
    /// A's handshake is done; its session waits for B's safety words until the deadline.
    Verify(Box<Established>, u64),
    /// One per invitation answered from the rendezvous queue, at most `MAX_REPLIES`.
    Replies(Vec<(Responder, QueueId)>),
}

/// All sessions of a device plus its pending handshake.
///
/// Handshake messages travel as blocks too: `queue id 16 | message | random padding`. A posts
/// msg1 on the public `rendezvous` queue of the words; each answer goes to a queue derived from
/// the message it answers, which `pending_queues` names.
///
/// Export a session after every `encrypt`, `receive`, `outgoing` or `cover` that touches it,
/// before sending its blocks or showing the message; otherwise a crash restores a state that
/// reuses message keys. Import each export at most once per `Engine`.
#[derive(Default)]
pub struct Engine {
    sessions: HashMap<SessionId, Session>,
    /// Every session's `queue_ids`, so `receive` tries at most one session per block.
    queues: HashMap<QueueId, SessionId>,
    /// Fragments held in partial messages across all sessions.
    parts: usize,
    pending: Option<Pending>,
    last_id: u64,
}

impl Engine {
    /// A: starts an invitation on `network`, replacing any pending handshake on success. Post
    /// the block on `rendezvous(words)` on that network, then listen on `pending_queues` there.
    pub fn invite(
        &mut self,
        words: &str,
        network: &NetworkId,
        interval: Interval,
        now: u64,
    ) -> Result<Block, Error> {
        let queue = handshake::rendezvous(words)?;
        let (initiator, msg1) = Initiator::start(words, network, interval, now)?;
        self.pending = Some(Pending::Invite(Box::new(initiator), reply_queue(&msg1), 0));
        Ok(frame(&queue, &msg1))
    }

    /// B: answers an invitation found on `rendezvous(words)`; answer every one that shows up
    /// there, since unrelated invitations can share the queue. Replaces a pending invitation on
    /// success. Send the result, then listen on `pending_queues`. `Rejected` once
    /// `MAX_REPLIES` answers are pending. An invitation made on another network than `network`
    /// is answered too, but never completes.
    pub fn respond(
        &mut self,
        words: &str,
        network: &NetworkId,
        msg1: &Block,
        now: u64,
    ) -> Result<Block, Error> {
        let msg1 = unframe(msg1, &handshake::rendezvous(words)?, MSG1_LEN)?;
        if let Some(Pending::Replies(replies)) = &mut self.pending {
            replies.retain(|(r, _)| !r.expired(now));
            if replies.len() >= MAX_REPLIES {
                return Err(Error::Rejected);
            }
        }
        let (responder, msg2) = Responder::respond(words, network, msg1, now)?;
        let reply = (responder, reply_queue(&msg2));
        match &mut self.pending {
            Some(Pending::Replies(replies)) => replies.push(reply),
            _ => self.pending = Some(Pending::Replies(vec![reply])),
        }
        Ok(frame(&reply_queue(msg1), &msg2))
    }

    /// The queues answers to the pending handshake arrive on; empty once it is gone.
    pub fn pending_queues(&self) -> Vec<QueueId> {
        match &self.pending {
            Some(Pending::Invite(_, queue, _)) => vec![*queue],
            Some(Pending::Replies(replies)) => replies.iter().map(|(_, q)| *q).collect(),
            Some(Pending::Verify(..)) | None => Vec::new(),
        }
    }

    /// A: completes the handshake with B's answer. Send the result to B, which then shows its
    /// safety words, and pass what the user types to `verify`. A wrong answer, such as a third
    /// party's guess, leaves the invitation pending until it expires or has taken `MAX_ANSWERS`.
    pub fn finish_invite(&mut self, msg2: &Block, now: u64) -> Result<Block, Error> {
        let Some(Pending::Invite(initiator, queue, wrong)) = &mut self.pending else {
            return Err(Error::Rejected);
        };
        let msg2 = unframe(msg2, queue, MSG2_LEN)?;
        match initiator.finish(msg2, now) {
            Ok((established, msg3)) => {
                let deadline = initiator.deadline();
                self.pending = Some(Pending::Verify(Box::new(established), deadline));
                Ok(frame(&reply_queue(msg2), &msg3))
            }
            Err(e) => {
                *wrong += 1;
                if e == Error::Expired || *wrong >= MAX_ANSWERS {
                    self.pending = None;
                }
                Err(e)
            }
        }
    }

    /// A: opens the session once the user types the safety words B shows. A mismatch, from a
    /// typo or from someone in the middle, leaves it pending until the invitation's deadline;
    /// tell the user to stop if the words really differ.
    pub fn verify(&mut self, typed: &str, now: u64) -> Result<SessionId, Error> {
        match self.pending.take() {
            Some(Pending::Verify(_, deadline)) if now > deadline => Err(Error::Expired),
            Some(Pending::Verify(established, deadline)) => {
                if handshake::spells(typed, &established.safety) {
                    Ok(self.add(Session::new(*established, now)))
                } else {
                    self.pending = Some(Pending::Verify(established, deadline));
                    Err(Error::Rejected)
                }
            }
            other => {
                self.pending = other;
                Err(Error::Rejected)
            }
        }
    }

    /// B: completes the handshake with A's confirmation, dropping the other pending replies.
    /// Show the user `safety_words` to read out to A, and `confirm` once A says they matched.
    /// A forged confirmation leaves the replies pending: it reveals nothing about the words.
    /// Each reply dies `INVITE_TTL` after its `respond`; `Expired` once none is left.
    pub fn finish_response(&mut self, msg3: &Block, now: u64) -> Result<SessionId, Error> {
        let Some(Pending::Replies(replies)) = &mut self.pending else {
            return Err(Error::Rejected);
        };
        replies.retain(|(r, _)| !r.expired(now));
        if replies.is_empty() {
            self.pending = None;
            return Err(Error::Expired);
        }
        let (responder, queue) = replies
            .iter()
            .find(|(_, q)| q == block::outer(msg3).0)
            .ok_or(Error::Rejected)?;
        let established = responder.finish(unframe(msg3, queue, MSG3_LEN)?, now)?;
        self.pending = None;
        Ok(self.add(Session::new(established, now)))
    }

    /// Three words derived from the handshake, equal on both sides unless someone who had the
    /// invitation words sits in the middle. Not secret, but read them to your peer over a
    /// channel where they recognize you, such as in person or on a call.
    pub fn safety_words(&self, id: SessionId) -> Option<String> {
        Some(handshake::to_words(&self.sessions.get(&id)?.safety).to_string())
    }

    /// B: unlocks sending once A says the safety words matched. Until then the session sends no
    /// messages or cover, and what it receives may come from someone in the middle. False for
    /// an unknown session.
    pub fn confirm(&mut self, id: SessionId) -> bool {
        self.sessions
            .get_mut(&id)
            .map(|s| s.confirmed = true)
            .is_some()
    }

    /// `None` for an unknown or unconfirmed session or data over ~16 MB.
    pub fn encrypt(&mut self, id: SessionId, data: &[u8]) -> Option<Vec<Block>> {
        self.sessions
            .get_mut(&id)
            .filter(|s| s.confirmed)?
            .encrypt(data)
    }

    /// The session the block belongs to and what it produced. `None`: no session opens it, so
    /// it is dropped silently and nothing changed. The session's `queue_ids` may change.
    pub fn receive(&mut self, block: &Block, now: u64) -> Option<(SessionId, Received)> {
        let id = *self.queues.get(block::outer(block).0)?;
        let mut session = self.detach(id)?;
        let received = session.decrypt(block, now);
        if received != Some(Received::Closed) {
            self.attach(id, session);
        }
        Some((id, received?))
    }

    /// Queues the peer's blocks arrive on, for the client to listen on. Only `receive` changes
    /// them.
    pub fn queue_ids(&self, id: SessionId) -> Option<Vec<QueueId>> {
        Some(self.sessions.get(&id)?.queue_ids())
    }

    /// Ends a session on both sides: forgets it and returns the block that tells the peer.
    /// Delete its export too.
    pub fn close(&mut self, id: SessionId) -> Option<Block> {
        Some(self.detach(id)?.seal_control(&[CLOSE]))
    }

    /// A decoy block, indistinguishable from a real one, that the peer drops after decrypting.
    /// When and how often to send it is up to the client.
    pub fn cover(&mut self, id: SessionId) -> Option<Block> {
        Some(
            self.sessions
                .get_mut(&id)
                .filter(|s| s.confirmed)?
                .seal_control(&[COVER]),
        )
    }

    /// Control blocks to send, including forced rotations that are due. Call it periodically.
    pub fn outgoing(&mut self, now: u64) -> Vec<(SessionId, Block)> {
        self.sessions
            .iter_mut()
            .flat_map(|(id, s)| s.outgoing(now).into_iter().map(|b| (*id, b)))
            .collect()
    }

    /// The sessions that heard nothing from their peer for `MAX_SILENCE`. They send and rotate
    /// nothing, but are kept: the first block from the peer wakes them. Show them to the user,
    /// who may `remove` them; never remove them on your own, since silence can be forged.
    pub fn dormant(&mut self, now: u64) -> Vec<SessionId> {
        self.sessions
            .iter_mut()
            .filter_map(|(id, s)| s.dormant(now).then_some(*id))
            .collect()
    }

    /// Drops skipped message keys past their TTL and returns the sessions that lost some;
    /// export them again. Call it with `outgoing`: otherwise the key of a block an adversary
    /// withheld stays in memory and in the export until the next block of that session.
    pub fn purge(&mut self, now: u64) -> Vec<SessionId> {
        let purged: Vec<SessionId> = self
            .sessions
            .iter_mut()
            .filter_map(|(id, s)| s.purge(now).then_some(*id))
            .collect();
        for id in &purged {
            self.queues.retain(|_, s| s != id);
            for queue in self.sessions[id].queue_ids() {
                self.queues.insert(queue, *id);
            }
        }
        purged
    }

    /// The session state encrypted under `storage_key`. Write it atomically: to a temp file,
    /// then rename it over the old one. `storage_key` must be 32 random bytes (say, kept in the
    /// OS keychain), not a password hash: nothing here slows down guessing it.
    pub fn export(&self, id: SessionId, storage_key: &Key) -> Option<Vec<u8>> {
        Some(self.sessions.get(&id)?.export(storage_key))
    }

    /// Restores an `export` under a new id. Wrong key, tampered or malformed input is `None`.
    pub fn import(&mut self, bytes: &[u8], storage_key: &Key) -> Option<SessionId> {
        Some(self.add(Session::import(bytes, storage_key)?))
    }

    /// Forgets a session without telling the peer; use `close` to end it on both sides.
    pub fn remove(&mut self, id: SessionId) {
        self.detach(id);
    }

    fn add(&mut self, session: Session) -> SessionId {
        self.last_id += 1;
        let id = SessionId(self.last_id);
        self.attach(id, session);
        id
    }

    fn attach(&mut self, id: SessionId, session: Session) {
        for queue in session.queue_ids() {
            self.queues.insert(queue, id);
        }
        self.parts += session.parts();
        self.sessions.insert(id, session);
        self.trim();
    }

    fn detach(&mut self, id: SessionId) -> Option<Session> {
        let session = self.sessions.remove(&id)?;
        for queue in session.queue_ids() {
            self.queues.remove(&queue);
        }
        self.parts -= session.parts();
        Some(session)
    }

    /// Evicts the oldest partial message of the session holding the most fragments until all
    /// sessions fit `MAX_PARTS`, so one contact cannot crowd out the others.
    fn trim(&mut self) {
        while self.parts > MAX_PARTS {
            let session = self
                .sessions
                .values_mut()
                .max_by_key(|s| s.parts())
                .expect("held fragments belong to a session");
            self.parts -= session.evict_partial();
        }
    }
}

fn frame(queue: &QueueId, msg: &[u8]) -> Block {
    let mut block: Block = crypto::random();
    block[..QUEUE_ID_LEN].copy_from_slice(queue);
    block[QUEUE_ID_LEN..QUEUE_ID_LEN + msg.len()].copy_from_slice(msg);
    block
}

/// The handshake message in `block`, if it came on `queue`.
fn unframe<'a>(block: &'a Block, queue: &QueueId, len: usize) -> Result<&'a [u8], Error> {
    let (got, msg) = block.split_first_chunk().expect("fixed layout");
    if got != queue {
        return Err(Error::Rejected);
    }
    Ok(&msg[..len])
}

/// Queue of the answer to `msg`: anyone who saw `msg` can compute it, and it reveals nothing
/// more than `msg` does.
fn reply_queue(msg: &[u8]) -> QueueId {
    *crypto::hkdf(&[], msg, b"janus reply")
}

/// Ways past the encryption layers, so fuzz targets reach the parsers behind them. Built only
/// by `cargo fuzz`.
#[cfg(fuzzing)]
pub mod fuzz {
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::block::BODY_LEN;

    pub const KEY: Key = [7; 32];

    /// An engine holding one confirmed session, plus the peer's side of it.
    pub struct Pair {
        pub engine: Engine,
        pub id: SessionId,
        peer: Session,
    }

    impl Pair {
        /// What a handshake hands both sides, without its cost (the `handshake` target has it).
        pub fn connect() -> Pair {
            let root = Zeroizing::new(crypto::random());
            let a_dh = StaticSecret::from(crypto::random::<32>());
            let b_dh = StaticSecret::from(crypto::random::<32>());
            let side = |initiator, our_dh: &StaticSecret, their_dh: &StaticSecret| Established {
                initiator,
                root: root.clone(),
                our_dh: our_dh.clone(),
                their_dh: PublicKey::from(their_dh),
                interval: Interval::H1,
                safety: [0; SAFETY_LEN],
            };
            let mut engine = Engine::default();
            let id = engine.add(Session::new(side(false, &b_dh, &a_dh), 0));
            engine.confirm(id);
            let peer = Session::new(side(true, &a_dh, &b_dh), 0);
            Pair { engine, id, peer }
        }

        /// A block from the peer carrying `body`, cut or zero-padded to a block body.
        pub fn seal(&mut self, body: &[u8]) -> Block {
            let mut padded = [0u8; BODY_LEN];
            let len = body.len().min(BODY_LEN);
            padded[..len].copy_from_slice(&body[..len]);
            self.peer.ratchet.seal(&padded)
        }
    }

    /// Seals a session state's plaintext under `KEY`, as `Engine::export` does.
    pub fn seal_state(plain: &[u8]) -> Vec<u8> {
        let nonce = crypto::random::<NONCE_LEN>();
        let mut sealed = plain.to_vec();
        let tag = crypto::seal(&KEY, &nonce, STATE_AAD, &mut sealed);
        [&nonce[..], &sealed, &tag].concat()
    }

    /// The plaintext of an `Engine::export` under `KEY`.
    pub fn open_state(bytes: &[u8]) -> Option<Vec<u8>> {
        let (nonce, rest) = bytes.split_first_chunk::<NONCE_LEN>()?;
        let (sealed, tag) = rest.split_last_chunk::<TAG_LEN>()?;
        let mut plain = sealed.to_vec();
        crypto::open(&KEY, nonce, STATE_AAD, &mut plain, tag)?;
        Some(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BODY_LEN;
    use crate::ratchet::SKIP_TTL;

    const WORDS: &str = "alpha cable echo forest orbit velvet";
    const NOW: u64 = 1_800_000_000;
    const H: u64 = 3600;
    const DAY: u64 = 24 * H;
    const KEY: Key = [7; 32];

    fn pair() -> [Session; 2] {
        let (a, msg1) = Initiator::start(WORDS, &[0; 32], Interval::H1, NOW).unwrap();
        let (b, msg2) = Responder::respond(WORDS, &[0; 32], &msg1, NOW).unwrap();
        let (a, msg3) = a.finish(&msg2, NOW).unwrap();
        [
            Session::new(a, NOW),
            Session::new(b.finish(&msg3, NOW).unwrap(), NOW),
        ]
    }

    fn message(received: Option<Received>) -> Zeroizing<Vec<u8>> {
        match received {
            Some(Received::Message(m)) => m,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    fn talk(from: &mut Session, to: &mut Session, text: &[u8]) {
        let blocks = from.encrypt(text).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(message(to.decrypt(&blocks[0], NOW)).as_slice(), text);
    }

    fn deliver_silent(to: &mut Session, blocks: Vec<Block>, now: u64) {
        for block in blocks {
            assert_eq!(to.decrypt(&block, now), Some(Received::Nothing));
        }
    }

    /// Polls both sides before delivering anything, as simultaneous timers do, until quiet.
    fn rotate(p: &mut [Session; 2], now: u64) {
        for _ in 0..10 {
            let out = [p[0].outgoing(now), p[1].outgoing(now)];
            if out.iter().all(Vec::is_empty) {
                return;
            }
            for (i, blocks) in out.into_iter().enumerate() {
                deliver_silent(&mut p[1 - i], blocks, now);
            }
        }
        panic!("control blocks never quiet down");
    }

    /// Queue id of the next block; it changes only when the peer's new DH key arrives.
    fn queue_id(s: &Session) -> [u8; 16] {
        s.ratchet.clone().seal(&[0; BODY_LEN])[..16]
            .try_into()
            .unwrap()
    }

    /// True while no completed PQ secret waits to be mixed.
    fn pq_mixed(s: &Session) -> bool {
        s.ratchet.clone().kem_offer().is_some()
    }

    #[test]
    fn reassembly_out_of_order_with_duplicate_and_inconsistent_fragments() {
        let [mut a, mut b] = pair();
        let data: Vec<u8> = (0..MAX_CONTENT_LEN * 2 + 1).map(|i| i as u8).collect();
        let bodies = block::split(Kind::Message, 7, &data);
        let wrong_count = block::split(Kind::Message, 7, &[0; MAX_CONTENT_LEN * 3 + 1]);
        let blocks: Vec<Block> = [&bodies[2], &bodies[2], &wrong_count[3], &bodies[0]]
            .iter()
            .map(|body| a.ratchet.seal(body))
            .collect();
        deliver_silent(&mut b, blocks, NOW);
        let last = a.ratchet.seal(&bodies[1]);
        assert_eq!(*message(b.decrypt(&last, NOW)), data);
        assert!(b.partial.is_empty());
    }

    /// Each block opens only its own session, including on the new queue after a DH step,
    /// and the index tracks exactly the live sessions' queues.
    #[test]
    fn engine_routes_by_queue_among_many_sessions() {
        let indexed = |e: &Engine| e.sessions.values().map(|s| s.queue_ids().len()).sum();
        let mut engine = Engine::default();
        let mut peers: Vec<(SessionId, Session)> = (0..20)
            .map(|_| {
                let [mine, peer] = pair();
                (engine.add(mine), peer)
            })
            .collect();
        for (id, peer) in peers.iter_mut().rev() {
            for _ in 0..2 {
                let block = peer.encrypt(b"hi").unwrap().remove(0);
                assert_eq!(
                    engine.receive(&block, NOW).unwrap(),
                    (*id, Received::Message(Zeroizing::new(b"hi".to_vec())))
                );
                let reply = engine.encrypt(*id, b"yo").unwrap().remove(0);
                assert_eq!(*message(peer.decrypt(&reply, NOW)), b"yo");
            }
        }
        assert_eq!(engine.queues.len(), indexed(&engine));
        engine.remove(peers[3].0);
        assert!(
            engine
                .receive(&peers[3].1.encrypt(b"gone").unwrap()[0], NOW)
                .is_none()
        );
        assert_eq!(engine.queues.len(), indexed(&engine));
    }

    #[test]
    fn partial_messages_share_one_budget_and_the_biggest_holder_yields() {
        let mut engine = Engine::default();
        let [mine, mut honest] = pair();
        engine.add(mine);
        let [mine, mut greedy] = pair();
        engine.add(mine);
        let data = vec![1; 2 * MAX_CONTENT_LEN + 1];
        let mut blocks = honest.encrypt(&data).unwrap();
        let last = blocks.pop().unwrap();
        for block in &blocks {
            engine.receive(block, NOW).unwrap();
        }
        for _ in 0..5 {
            let mut blocks = greedy
                .encrypt(&[2; MAX_FRAGMENTS * MAX_CONTENT_LEN])
                .unwrap();
            blocks.pop();
            for block in &blocks {
                engine.receive(block, NOW).unwrap();
            }
            assert!(engine.parts <= MAX_PARTS);
            assert_eq!(
                engine.parts,
                engine.sessions.values().map(Session::parts).sum()
            );
        }
        let (_, received) = engine.receive(&last, NOW).unwrap();
        assert_eq!(*message(Some(received)), data);
    }

    #[test]
    fn silence_puts_a_session_to_sleep_and_a_block_from_the_peer_wakes_it() {
        let mut p = pair();
        let mut t = NOW;
        while t < NOW + 500 * DAY {
            t += 100 * DAY;
            rotate(&mut p, t);
        }
        let [a, b] = &mut p;
        let block = a.encrypt(b"late").unwrap().remove(0);
        let jump = t + 10 * MAX_SILENCE;
        assert!(
            !b.dormant(jump),
            "a forged clock jump puts nothing to sleep"
        );
        let days = (1..).find(|d| b.dormant(jump + d * DAY)).unwrap();
        assert_eq!(
            days * DAY,
            MAX_SILENCE,
            "a running clock still reaches the limit"
        );
        let asleep = jump + days * DAY;
        assert!(b.outgoing(asleep).is_empty());
        let mut b = Session::import(&b.export(&KEY), &KEY).unwrap();
        assert!(b.dormant(asleep));

        assert_eq!(*message(b.decrypt(&block, asleep)), b"late");
        assert!(!b.dormant(asleep) && !b.outgoing(asleep).is_empty());
    }

    #[test]
    fn clock_moved_back_neither_stalls_rotation_nor_keeps_skipped_keys() {
        let [mut a, mut b] = pair();
        let lost = a.encrypt(b"withheld").unwrap().remove(0);
        let next = a.encrypt(b"next").unwrap().remove(0);
        assert!(b.decrypt(&next, NOW).is_some());
        assert!(!a.outgoing(NOW + H).is_empty());

        let back = NOW - 1000 * DAY;
        assert!(a.outgoing(back).is_empty() && !b.purge(back));
        assert!(!a.outgoing(back + 2 * H).is_empty(), "rotation stalled");
        assert!(b.purge(back + SKIP_TTL));
        assert!(b.decrypt(&lost, back + SKIP_TTL).is_none());
    }

    #[test]
    fn unanswered_rotations_back_off_and_any_block_restores_the_interval() {
        let [mut a, mut b] = pair();
        let hours: Vec<u64> = (1..=300 * 24)
            .filter(|&h| !a.outgoing(NOW + h * H).is_empty())
            .collect();
        assert_eq!(hours[..9], [1, 3, 7, 15, 31, 63, 127, 255, 511]);
        assert!(hours.windows(2).all(|w| w[1] - w[0] <= MAX_BACKOFF / H));
        assert_eq!(hours.len(), 18, "instead of 7200 without backoff");

        let back = NOW + 300 * 24 * H;
        assert!(a.decrypt(&b.encrypt(b"back").unwrap()[0], back).is_some());
        assert!(!a.outgoing(back).is_empty(), "rotation resumes at once");
    }

    #[test]
    fn size_limits() {
        let [mut a, mut b] = pair();
        let max = vec![3; MAX_FRAGMENTS * MAX_CONTENT_LEN];
        assert!(a.encrypt(&[&max[..], &[0]].concat()).is_none());
        let mut blocks = a.encrypt(&max).unwrap();
        let first = blocks.remove(0);
        deliver_silent(&mut b, blocks.into_iter().rev().collect(), NOW);
        assert_eq!(*message(b.decrypt(&first, NOW)), max);
    }

    #[test]
    fn simultaneous_forced_rotation_completes_and_conversation_continues() {
        let mut p = pair();
        let [a, b] = &mut p;
        talk(a, b, b"hi");
        talk(b, a, b"yo");
        assert!(a.outgoing(NOW + 10).is_empty() && b.outgoing(NOW + 10).is_empty());
        let before = [queue_id(&p[0]), queue_id(&p[1])];

        // Crossing Rekeys leave one side's secret unmixed; its next bare Ack must mix it.
        let mut late_mix = [false; 2];
        for round in 1..=4 {
            let start = [pq_mixed(&p[0]), pq_mixed(&p[1])];
            rotate(&mut p, NOW + round * H);
            for i in 0..2 {
                let end = pq_mixed(&p[i]);
                assert!(start[i] || end, "secret unmixed for a whole interval");
                late_mix[i] |= !start[i] && end;
            }
        }
        assert_eq!(late_mix, [true; 2]);
        assert!(queue_id(&p[0]) != before[0] && queue_id(&p[1]) != before[1]);
        let [a, b] = &mut p;
        talk(a, b, b"after");
        talk(b, a, b"rotation");
    }

    #[test]
    fn export_import_mid_conversation() {
        let [mut a, mut b] = pair();
        talk(&mut a, &mut b, b"hi");
        let blocks = a.encrypt(&[5; MAX_CONTENT_LEN * 2 + 1]).unwrap();
        assert_eq!(b.decrypt(&blocks[0], NOW), Some(Received::Nothing));
        let later = NOW + H;
        deliver_silent(&mut b, a.outgoing(later), later);

        let bytes = b.export(&KEY);
        assert!(Session::import(&bytes, &[8; 32]).is_none());
        let mut tampered = bytes.clone();
        tampered[NONCE_LEN + 3] ^= 1;
        assert!(Session::import(&tampered, &KEY).is_none());
        assert!(Session::import(&bytes[..TAG_LEN + NONCE_LEN - 1], &KEY).is_none());

        let mut b = Session::import(&bytes, &KEY).unwrap();
        assert_eq!(b.export(&KEY).len(), bytes.len());
        let reply = b.outgoing(later);
        assert_eq!(reply.len(), 1, "queued RekeyReply lost in export");
        deliver_silent(&mut a, reply, later);
        assert_eq!(b.decrypt(&blocks[2], later), Some(Received::Nothing));
        assert_eq!(
            *message(b.decrypt(&blocks[1], later)),
            [5; MAX_CONTENT_LEN * 2 + 1]
        );
        talk(&mut b, &mut a, b"restored");
        talk(&mut a, &mut b, b"ok");
    }

    /// Both sides send and poll timers (sometimes together), blocks are reordered, control
    /// blocks dropped, states persisted; then a quiet phase with only timers. No user message
    /// may be lost, and rotation must keep completing.
    #[test]
    fn randomized_simulation() {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut below = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        for _ in 0..40 {
            let mut p = pair();
            let mut t = NOW;
            let mut inbox: [Vec<(Block, bool)>; 2] = Default::default();
            let (mut sent, mut got) = (0, 0);
            let mut deliver = |s: &mut Session, block: &Block, t: u64| {
                let received = s.decrypt(block, t).expect("block lost");
                got += usize::from(matches!(received, Received::Message(_)));
            };
            for _ in 0..150 {
                let i = below(2) as usize;
                match below(14) {
                    0..=2 => {
                        let len = 1 + below(2) as usize * MAX_CONTENT_LEN;
                        let blocks = p[i].encrypt(&vec![1; len]).unwrap();
                        inbox[1 - i].extend(blocks.into_iter().map(|b| (b, false)));
                        sent += 1;
                    }
                    3..=5 => {
                        let both = below(2) == 0;
                        for j in [i, 1 - i].into_iter().take(1 + usize::from(both)) {
                            let blocks = p[j].outgoing(t);
                            inbox[1 - j].extend(blocks.into_iter().map(|b| (b, true)));
                        }
                    }
                    6 => t += below(H),
                    7 => p[i] = Session::import(&p[i].export(&KEY), &KEY).unwrap(),
                    _ if inbox[i].is_empty() => {}
                    8 => {
                        let k = below(inbox[i].len() as u64) as usize;
                        if inbox[i][k].1 {
                            inbox[i].swap_remove(k);
                        }
                    }
                    _ => {
                        let k = below(inbox[i].len() as u64) as usize;
                        let (block, _) = inbox[i].swap_remove(k);
                        deliver(&mut p[i], &block, t);
                    }
                }
            }
            for (i, blocks) in inbox.iter_mut().enumerate() {
                while !blocks.is_empty() {
                    let k = below(blocks.len() as u64) as usize;
                    deliver(&mut p[i], &blocks.swap_remove(k).0, t);
                }
            }
            assert_eq!(got, sent, "user message lost");

            // Each side offers only once its previous secret is mixed, and every quiet-phase
            // exchange completes, so two offers per side prove a mix on each side.
            let before = [queue_id(&p[0]), queue_id(&p[1])];
            let mut offers = [0; 2];
            for _ in 0..6 {
                t += H;
                for (offer, s) in offers.iter_mut().zip(&p) {
                    *offer += usize::from(pq_mixed(s));
                }
                rotate(&mut p, t);
            }
            assert!(
                offers.iter().all(|&n| n >= 2),
                "rotation stalled: {offers:?}"
            );
            assert!(queue_id(&p[0]) != before[0] && queue_id(&p[1]) != before[1]);
        }
    }
}
