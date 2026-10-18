//! Double ratchet with header encryption and a sparse ML-KEM ratchet.
//!
//! Signal's Double Ratchet with header encryption, with two twists: the sending half of a DH
//! step runs lazily on the next `seal`, and a post-quantum secret agreed through
//! `kem_offer`/`kem_accept`/`kem_complete` is mixed into the next send chain of the offerer.

use ml_kem::{
    B32, Decapsulate, DecapsulationKey768, EncapsulationKey768, KeyExport, KeyInit, Seed,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::block::{
    self, BODY_LEN, Block, Body, HEADER_LEN, HEADER_PLAIN_LEN, QUEUE_ID_LEN, QueueId,
};
use crate::crypto::{self, CT_LEN, EK_LEN, KEY_LEN, Key, NONCE_LEN};

/// Most skipped message keys kept per session (oldest evicted first).
pub const MAX_SKIP: usize = 1000;
/// Largest gap a single header may open. Past `MAX_SKIP` the chain fast-forwards: the oldest
/// keys of the gap are never stored, so those blocks are lost but the session survives losing
/// many blocks in a row. Headers are authenticated, so only the peer can open a gap; this bounds
/// the work it can cause per block. A starting value, to tune.
const MAX_GAP: u32 = 1 << 16;
/// Seconds a skipped message key is kept. Short: the key of a block an adversary withholds
/// opens that block from any export seized while the key is still in it.
pub const SKIP_TTL: u64 = 24 * 3600;

type Secret = Zeroizing<Key>;

#[derive(Clone)]
struct Skipped {
    hk: Secret,
    qid: QueueId,
    n: u32,
    mk: Secret,
    at: u64,
}

struct Header {
    dh: PublicKey,
    pn: u32,
    n: u32,
    pq: u32,
}

#[derive(Clone)]
pub struct Ratchet {
    rk: Secret,
    dhs: StaticSecret,
    dhr: PublicKey,
    /// `None` means the sending half of the last DH step is still pending.
    cks: Option<Secret>,
    hks: Secret,
    nhks: Secret,
    ckr: Option<Secret>,
    hkr: Option<Secret>,
    nhkr: Secret,
    ns: u32,
    nr: u32,
    pn: u32,
    /// PQ id carried by every header of the current send chain.
    pq_send: u32,
    /// Last offer id issued; ids are monotonic so the peer can reject stale offers.
    offer_id: u32,
    offer: Option<(u32, Zeroizing<[u8; 64]>)>,
    pq_next: Option<(u32, Secret)>,
    /// Highest offer id ever accepted from the peer.
    accepted_id: u32,
    accepted: Option<(u32, Secret)>,
    skipped: Vec<Skipped>,
}

impl Ratchet {
    /// Starts a ratchet from the handshake root key and DH keys. Both sides can seal at once.
    pub fn new(initiator: bool, root: &Key, our_dh: StaticSecret, their_dh: &PublicKey) -> Ratchet {
        let okm = crypto::hkdf::<96>(&[], root, b"janus init");
        let (rk, hk_a, nhk_b) = (key(&okm[..32]), key(&okm[32..64]), key(&okm[64..]));
        let mut r = Ratchet {
            rk,
            dhs: our_dh,
            dhr: *their_dh,
            cks: None,
            hks: hk_a.clone(),
            nhks: nhk_b.clone(),
            ckr: None,
            hkr: None,
            nhkr: if initiator { nhk_b } else { hk_a },
            ns: 0,
            nr: 0,
            pn: 0,
            pq_send: 0,
            offer_id: 0,
            offer: None,
            pq_next: None,
            accepted_id: 0,
            accepted: None,
            skipped: Vec::new(),
        };
        if initiator {
            // Eager, so the initiator's rk matches the responder's even if the responder speaks
            // first.
            r.cks = Some(r.send_step());
        } else {
            r.recv_step(*their_dh, None);
        }
        r
    }

    pub fn seal(&mut self, body: &[u8; BODY_LEN]) -> Block {
        let ck = match self.cks.take() {
            Some(ck) => ck,
            None => {
                // Drawn now, not on receipt, so a state stolen while waiting to send lacks it.
                self.dhs = StaticSecret::from(crypto::random::<KEY_LEN>());
                self.send_step()
            }
        };
        let (ck, mk) = kdf_ck(&ck);
        self.cks = Some(ck);
        let mut plain = [0u8; HEADER_PLAIN_LEN];
        plain[..32].copy_from_slice(PublicKey::from(&self.dhs).as_bytes());
        plain[32..36].copy_from_slice(&self.pn.to_be_bytes());
        plain[36..40].copy_from_slice(&self.ns.to_be_bytes());
        plain[40..].copy_from_slice(&self.pq_send.to_be_bytes());
        self.ns = self
            .ns
            .checked_add(1)
            .expect("2^32 blocks in one send chain");
        let qid = queue_id(&self.hks);
        block::seal(&qid, &seal_header(&self.hks, &qid, &plain), &mk, body)
    }

    /// Queues the peer's blocks can arrive on: the current and next receive chains and every
    /// chain with skipped keys left. Only `open` changes them.
    pub fn queue_ids(&self) -> Vec<QueueId> {
        let mut ids: Vec<QueueId> = self
            .hkr
            .iter()
            .chain([&self.nhkr])
            .map(|hk| queue_id(hk))
            .collect();
        for s in &self.skipped {
            if !ids.contains(&s.qid) {
                ids.push(s.qid);
            }
        }
        ids
    }

    /// Opens a block for this session. `None` means drop it silently; the state is then unchanged.
    ///
    /// Forged blocks and replays end before the state is cloned: a flood on a known queue
    /// costs one header decryption per block.
    pub fn open(&mut self, block: &Block, now: u64) -> Option<Body> {
        let (qid, sealed) = block::outer(block);
        let current = self.hkr.as_ref().filter(|hk| queue_id(hk) == *qid);
        let next = queue_id(&self.nhkr) == *qid;
        // Equal queue ids mean the same header key, so the first match opens the header.
        let hk = match (current, next) {
            (Some(hk), _) => hk,
            (None, true) => &self.nhkr,
            (None, false) => &self.skipped.iter().find(|s| s.qid == *qid)?.hk,
        };
        let header = open_header(hk, qid, sealed)?;
        let skipped = self
            .skipped
            .iter()
            .any(|s| s.qid == *qid && s.n == header.n && now.saturating_sub(s.at) < SKIP_TTL);
        if !(skipped || next || current.is_some() && header.n >= self.nr) {
            return None;
        }
        let mut ratchet = self.clone();
        let body = ratchet.try_open(block, &header, now)?;
        *self = ratchet;
        Some(body)
    }

    /// Drops skipped keys older than `SKIP_TTL`; true if any went.
    pub fn purge(&mut self, now: u64) -> bool {
        let before = self.skipped.len();
        self.skipped.retain(|s| now.saturating_sub(s.at) < SKIP_TTL);
        self.skipped.len() < before
    }

    /// Starts a PQ exchange: returns the offer id and the encapsulation key to send.
    /// Replaces any outstanding offer. Refuses while a completed secret is not yet mixed, so
    /// the peer's single slot is never overwritten before the chain that uses it arrives.
    pub fn kem_offer(&mut self) -> Option<(u32, [u8; EK_LEN])> {
        if self.pq_next.is_some() {
            return None;
        }
        let id = self.offer_id.checked_add(1)?;
        let seed = Zeroizing::new(crypto::random::<64>());
        let ek = decapsulation_key(&seed)
            .encapsulation_key()
            .to_bytes()
            .into();
        self.offer_id = id;
        self.offer = Some((id, seed));
        Some((id, ek))
    }

    /// Answers a peer's offer newer than any accepted before: stores the shared secret for
    /// the peer's next chain and returns the ciphertext to send back.
    pub fn kem_accept(&mut self, id: u32, ek: &[u8]) -> Option<[u8; CT_LEN]> {
        if id <= self.accepted_id {
            return None;
        }
        let ek = EncapsulationKey768::new(ek.try_into().ok()?).ok()?;
        let m = Zeroizing::new(B32::from(crypto::random::<32>()));
        let (ct, ss) = ek.encapsulate_deterministic(&m);
        let ss = Zeroizing::new(ss);
        self.accepted_id = id;
        self.accepted = Some((id, key(&ss)));
        Some(ct.into())
    }

    /// Finishes our outstanding offer `id`; the secret goes into our next send chain.
    pub fn kem_complete(&mut self, id: u32, ct: &[u8]) -> Option<()> {
        let (offer_id, seed) = self.offer.as_ref()?;
        if *offer_id != id {
            return None;
        }
        let ss = Zeroizing::new(decapsulation_key(seed).decapsulate_slice(ct).ok()?);
        self.pq_next = Some((id, key(&ss)));
        self.offer = None;
        Some(())
    }

    /// Plaintext secrets: the caller encrypts it before persisting.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Reserved up front: a reallocation would leave unzeroized copies of secrets behind.
        let mut out = Zeroizing::new(Vec::with_capacity(512 + 76 * self.skipped.len()));
        let w = &mut *out;
        for k in [&self.rk, &self.hks, &self.nhks, &self.nhkr] {
            w.extend_from_slice(&k[..]);
        }
        w.extend_from_slice(self.dhs.as_bytes());
        w.extend_from_slice(self.dhr.as_bytes());
        for k in [&self.cks, &self.ckr, &self.hkr] {
            w.push(u8::from(k.is_some()));
            w.extend_from_slice(k.as_deref().unwrap_or(&[0; KEY_LEN]));
        }
        for n in [
            self.ns,
            self.nr,
            self.pn,
            self.pq_send,
            self.offer_id,
            self.accepted_id,
        ] {
            w.extend_from_slice(&n.to_be_bytes());
        }
        put_slot(w, &self.offer);
        put_slot(w, &self.pq_next);
        put_slot(w, &self.accepted);
        w.extend_from_slice(&(self.skipped.len() as u16).to_be_bytes());
        for s in &self.skipped {
            w.extend_from_slice(&s.hk[..]);
            w.extend_from_slice(&s.n.to_be_bytes());
            w.extend_from_slice(&s.mk[..]);
            w.extend_from_slice(&s.at.to_be_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Ratchet> {
        let mut r = Reader(bytes);
        let (rk, hks, nhks, nhkr) = (r.secret()?, r.secret()?, r.secret()?, r.secret()?);
        let dhs = StaticSecret::from(*r.secret::<KEY_LEN>()?);
        let dhr = PublicKey::from(*r.take()?);
        let (cks, ckr, hkr) = (r.opt_key()?, r.opt_key()?, r.opt_key()?);
        let (ns, nr, pn, pq_send) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        let (offer_id, accepted_id) = (r.u32()?, r.u32()?);
        let (offer, pq_next, accepted) = (r.slot()?, r.slot()?, r.slot()?);
        let count = usize::from(u16::from_be_bytes(*r.take()?));
        if count > MAX_SKIP {
            return None;
        }
        let skipped = (0..count)
            .map(|_| {
                let hk = r.secret()?;
                Some(Skipped {
                    qid: queue_id(&hk),
                    hk,
                    n: r.u32()?,
                    mk: r.secret()?,
                    at: u64::from_be_bytes(*r.take()?),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        if !r.0.is_empty() {
            return None;
        }
        Some(Ratchet {
            rk,
            dhs,
            dhr,
            cks,
            hks,
            nhks,
            ckr,
            hkr,
            nhkr,
            ns,
            nr,
            pn,
            pq_send,
            offer_id,
            offer,
            pq_next,
            accepted_id,
            accepted,
            skipped,
        })
    }

    /// The rest of `open`, on a copy, with the header it already authenticated.
    fn try_open(&mut self, block: &Block, h: &Header, now: u64) -> Option<Body> {
        let qid = block::outer(block).0;
        self.purge(now);
        if let Some(i) = self
            .skipped
            .iter()
            .position(|s| s.qid == *qid && s.n == h.n)
        {
            return block::open(block, &self.skipped.remove(i).mk);
        }
        if self.hkr.as_ref().is_some_and(|hk| queue_id(hk) == *qid) {
            self.skip(h.n, now)?;
        } else if queue_id(&self.nhkr) == *qid {
            let ss = match h.pq {
                0 => None,
                id => Some(self.accepted.take().filter(|(i, _)| *i == id)?.1),
            };
            self.skip(h.pn, now)?;
            self.recv_step(h.dh, ss.as_deref());
            self.skip(h.n, now)?;
        } else {
            return None;
        }
        let (ck, mk) = kdf_ck(self.ckr.as_ref()?);
        self.ckr = Some(ck);
        self.nr = self.nr.checked_add(1)?;
        block::open(block, &mk)
    }

    /// Stores the receive chain's keys up to `until`, evicting the oldest beyond `MAX_SKIP`.
    /// Rejects going back or a gap larger than `MAX_GAP`.
    fn skip(&mut self, until: u32, now: u64) -> Option<()> {
        let (Some(hk), Some(ck)) = (&self.hkr, &mut self.ckr) else {
            return Some(());
        };
        if until.checked_sub(self.nr)? > MAX_GAP {
            return None;
        }
        let qid = queue_id(hk);
        while self.nr < until {
            let (next, mk) = kdf_ck(ck);
            *ck = next;
            if (until - self.nr) as usize <= MAX_SKIP {
                self.skipped.push(Skipped {
                    hk: hk.clone(),
                    qid,
                    n: self.nr,
                    mk,
                    at: now,
                });
            }
            self.nr = self.nr.checked_add(1)?;
        }
        let excess = self.skipped.len().saturating_sub(MAX_SKIP);
        self.skipped.drain(..excess);
        Some(())
    }

    /// Receiving half of a DH step. The sending half waits for the next `seal`.
    fn recv_step(&mut self, dh: PublicKey, ss: Option<&Key>) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.hks = self.nhks.clone();
        self.hkr = Some(self.nhkr.clone());
        self.dhr = dh;
        let (rk, ck, nhk) = self.kdf_rk(ss);
        (self.rk, self.ckr, self.nhkr) = (rk, Some(ck), nhk);
        self.cks = None;
    }

    /// Sending half of a DH step, mixing a pending PQ secret. Returns the new send chain key.
    fn send_step(&mut self) -> Secret {
        let pq = self.pq_next.take();
        self.pq_send = pq.as_ref().map_or(0, |(id, _)| *id);
        let (rk, ck, nhk) = self.kdf_rk(pq.as_ref().map(|(_, ss)| &**ss));
        (self.rk, self.nhks) = (rk, nhk);
        ck
    }

    /// KDF_RK(rk, DH(DHs, DHr) [|| pq secret]) -> (rk, ck, nhk).
    fn kdf_rk(&self, ss: Option<&Key>) -> (Secret, Secret, Secret) {
        let mut ikm = Zeroizing::new([0u8; 2 * KEY_LEN]);
        ikm[..KEY_LEN].copy_from_slice(self.dhs.diffie_hellman(&self.dhr).as_bytes());
        let len = match ss {
            Some(ss) => {
                ikm[KEY_LEN..].copy_from_slice(ss);
                2 * KEY_LEN
            }
            None => KEY_LEN,
        };
        let okm = crypto::hkdf::<96>(&self.rk[..], &ikm[..len], b"janus rk");
        (key(&okm[..32]), key(&okm[32..64]), key(&okm[64..]))
    }
}

/// KDF_CK(ck) -> (ck, mk).
fn kdf_ck(ck: &Key) -> (Secret, Secret) {
    let okm = crypto::hkdf::<64>(&[], ck, b"janus ck");
    (key(&okm[..32]), key(&okm[32..]))
}

fn key(bytes: &[u8]) -> Secret {
    Zeroizing::new(bytes.try_into().expect("32-byte slice"))
}

fn queue_id(hk: &Key) -> QueueId {
    *crypto::hkdf::<QUEUE_ID_LEN>(&[], hk, b"janus queue")
}

fn decapsulation_key(seed: &[u8; 64]) -> DecapsulationKey768 {
    <DecapsulationKey768 as KeyInit>::new(<&Seed>::try_from(&seed[..]).expect("64-byte seed"))
}

/// Writes an optional `(id, secret)` as `id | secret`, all zeros when absent.
fn put_slot<const N: usize>(w: &mut Vec<u8>, slot: &Option<(u32, Zeroizing<[u8; N]>)>) {
    match slot {
        Some((id, secret)) => {
            w.extend_from_slice(&id.to_be_bytes());
            w.extend_from_slice(&secret[..]);
        }
        None => w.resize(w.len() + 4 + N, 0),
    }
}

fn seal_header(hk: &Key, qid: &QueueId, plain: &[u8; HEADER_PLAIN_LEN]) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    let nonce = crypto::random::<NONCE_LEN>();
    let ct = NONCE_LEN..NONCE_LEN + HEADER_PLAIN_LEN;
    out[..NONCE_LEN].copy_from_slice(&nonce);
    out[ct.clone()].copy_from_slice(plain);
    let tag = crypto::seal(hk, &nonce, qid, &mut out[ct.clone()]);
    out[ct.end..].copy_from_slice(&tag);
    out
}

fn open_header(hk: &Key, qid: &QueueId, sealed: &[u8; HEADER_LEN]) -> Option<Header> {
    let (nonce, rest) = sealed.split_first_chunk::<NONCE_LEN>()?;
    let (ct, tag) = rest.split_first_chunk::<HEADER_PLAIN_LEN>()?;
    let mut plain = *ct;
    crypto::open(hk, nonce, qid, &mut plain, tag.try_into().ok()?)?;
    let be = |at: usize| u32::from_be_bytes(plain[at..at + 4].try_into().expect("fixed layout"));
    Some(Header {
        dh: PublicKey::from(<[u8; 32]>::try_from(&plain[..32]).ok()?),
        pn: be(32),
        n: be(36),
        pq: be(40),
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Option<&'a [u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(head)
    }

    fn secret<const N: usize>(&mut self) -> Option<Zeroizing<[u8; N]>> {
        self.take().map(|s| Zeroizing::new(*s))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take().map(|b| u32::from_be_bytes(*b))
    }

    /// Reads a `put_slot` value; id 0 means absent.
    fn slot<const N: usize>(&mut self) -> Option<Option<(u32, Zeroizing<[u8; N]>)>> {
        let (id, secret) = (self.u32()?, self.secret()?);
        Some((id != 0).then_some((id, secret)))
    }

    fn opt_key(&mut self) -> Option<Option<Secret>> {
        let flag = self.take::<1>()?[0];
        let key = self.secret()?;
        match flag {
            0 => Some(None),
            1 => Some(Some(key)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Kind;

    fn pair() -> (Ratchet, Ratchet) {
        let root = crypto::random();
        let (a, b) = (
            StaticSecret::from(crypto::random::<32>()),
            StaticSecret::from(crypto::random::<32>()),
        );
        let (a_pub, b_pub) = (PublicKey::from(&a), PublicKey::from(&b));
        (
            Ratchet::new(true, &root, a, &b_pub),
            Ratchet::new(false, &root, b, &a_pub),
        )
    }

    fn msg(text: &[u8]) -> Body {
        block::split(Kind::Message, 0, text).remove(0)
    }

    fn read(r: &mut Ratchet, block: &Block, now: u64) -> Option<Vec<u8>> {
        r.open(block, now)
            .map(|body| block::parse(&body).unwrap().content.to_vec())
    }

    fn talk(from: &mut Ratchet, to: &mut Ratchet, text: &[u8]) {
        let block = from.seal(&msg(text));
        assert_eq!(read(to, &block, 0).as_deref(), Some(text));
    }

    #[test]
    fn ping_pong_either_side_first() {
        for initiator_first in [true, false] {
            let (mut a, mut b) = pair();
            if !initiator_first {
                std::mem::swap(&mut a, &mut b);
            }
            for (turn, count) in [2, 1, 3, 1, 2].into_iter().enumerate() {
                for _ in 0..count {
                    if turn % 2 == 0 {
                        talk(&mut a, &mut b, b"hi");
                    } else {
                        talk(&mut b, &mut a, b"yo");
                    }
                }
            }
        }
    }

    #[test]
    fn out_of_order_within_chain_and_across_dh_step() {
        let (mut a, mut b) = pair();
        let m: Vec<Block> = (0..3u8).map(|i| a.seal(&msg(&[i]))).collect();
        for i in [2, 0, 1] {
            assert_eq!(read(&mut b, &m[i], 0), Some(vec![i as u8]));
        }

        let x0 = a.seal(&msg(b"x0"));
        let x1 = a.seal(&msg(b"x1"));
        assert_eq!(read(&mut b, &x0, 0).unwrap(), b"x0");
        talk(&mut b, &mut a, b"turn");
        let z = a.seal(&msg(b"z"));
        assert_eq!(read(&mut b, &z, 0).unwrap(), b"z");
        assert_eq!(read(&mut b, &x1, 0).unwrap(), b"x1");
        assert!(b.skipped.is_empty());
    }

    /// On the current chain, from a used skipped key and from a chain the receiver left.
    #[test]
    fn replay_is_rejected() {
        let (mut a, mut b) = pair();
        let m0 = a.seal(&msg(b"m0"));
        let m1 = a.seal(&msg(b"m1"));
        let m2 = a.seal(&msg(b"m2"));
        assert!(read(&mut b, &m1, 0).is_some());
        assert!(read(&mut b, &m0, 0).is_some());
        let before = b.to_bytes();
        assert!(read(&mut b, &m0, 0).is_none());
        assert!(read(&mut b, &m1, 0).is_none());
        assert_eq!(*b.to_bytes(), *before);
        talk(&mut b, &mut a, b"turn");
        talk(&mut a, &mut b, b"new chain");
        assert!(read(&mut b, &m2, 0).is_some());
        let before = b.to_bytes();
        for old in [&m0, &m1, &m2] {
            assert!(read(&mut b, old, 0).is_none());
        }
        assert_eq!(*b.to_bytes(), *before);
    }

    #[test]
    fn tampered_or_foreign_block_leaves_state_unchanged() {
        let (mut a, mut b) = pair();
        let (mut other, _) = pair();
        // Same chain first, then the first block of a new chain, where the DH step would run.
        for new_chain in [false, true] {
            if new_chain {
                talk(&mut b, &mut a, b"turn");
            }
            let block = a.seal(&msg(b"ok"));
            let before = b.to_bytes();
            for at in [0, QUEUE_ID_LEN + 30, QUEUE_ID_LEN + HEADER_LEN + 100] {
                let mut tampered = block;
                tampered[at] ^= 1;
                assert!(
                    read(&mut b, &tampered, 0).is_none(),
                    "flip at {at} accepted"
                );
            }
            assert!(read(&mut b, &other.seal(&msg(b"ok")), 0).is_none());
            assert_eq!(*b.to_bytes(), *before);
            assert_eq!(read(&mut b, &block, 0).unwrap(), b"ok");
        }
    }

    /// A passive attacker holding the state from before the send must not derive its chain.
    #[test]
    fn state_stolen_while_waiting_to_send_misses_the_next_chain() {
        let (mut a, mut b) = pair();
        talk(&mut a, &mut b, b"1");
        talk(&mut b, &mut a, b"2");
        let mut stolen = Ratchet::from_bytes(&a.to_bytes()).unwrap();
        let block = a.seal(&msg(b"after theft"));
        stolen.seal(&msg(b"guess"));
        assert_ne!(
            *stolen.rk, *a.rk,
            "send chain derivable from the stolen state"
        );
        assert_eq!(read(&mut b, &block, 0).unwrap(), b"after theft");
    }

    /// Advances the send chain as if `n` sealed blocks were lost, without sealing them.
    fn lose(r: &mut Ratchet, n: u32) {
        for _ in 0..n {
            r.cks = Some(kdf_ck(r.cks.as_ref().unwrap()).0);
            r.ns += 1;
        }
    }

    #[test]
    fn skip_cap_eviction_and_expiry() {
        let (mut a, mut b) = pair();
        let m: Vec<Block> = (0..MAX_SKIP + 3).map(|_| a.seal(&msg(b"m"))).collect();
        assert!(read(&mut b, &m[MAX_SKIP], 0).is_some());
        assert_eq!(b.skipped.len(), MAX_SKIP);
        assert!(read(&mut b, &m[MAX_SKIP + 2], 0).is_some());
        assert_eq!(b.skipped.len(), MAX_SKIP);
        assert!(read(&mut b, &m[0], 0).is_none(), "oldest key not evicted");

        let mut fresh = Ratchet::from_bytes(&b.to_bytes()).unwrap();
        assert!(read(&mut fresh, &m[1], SKIP_TTL - 1).is_some());
        assert!(read(&mut b, &m[1], SKIP_TTL).is_none());
    }

    /// Losing more than `MAX_SKIP` blocks, on the same chain or before the sender's next DH
    /// step, fast-forwards and keeps the latest keys instead of cutting the direction.
    #[test]
    fn long_loss_fast_forwards_within_and_across_dh_steps() {
        let (mut a, mut b) = pair();
        talk(&mut a, &mut b, b"1");
        let lost: Vec<Block> = (0..3 * MAX_SKIP).map(|_| a.seal(&msg(b"lost"))).collect();
        talk(&mut b, &mut a, b"turn");
        talk(&mut a, &mut b, b"new chain");
        assert_eq!(b.skipped.len(), MAX_SKIP);
        assert!(
            read(&mut b, &lost[0], 0).is_none(),
            "fast-forwarded key kept"
        );
        assert_eq!(read(&mut b, &lost[3 * MAX_SKIP - 1], 0).unwrap(), b"lost");

        let lost: Vec<Block> = (0..2 * MAX_SKIP).map(|_| a.seal(&msg(b"lost"))).collect();
        talk(&mut a, &mut b, b"same chain");
        assert!(read(&mut b, &lost[MAX_SKIP - 1], 0).is_none());
        assert_eq!(read(&mut b, &lost[MAX_SKIP], 0).unwrap(), b"lost");
        talk(&mut b, &mut a, b"still");
        talk(&mut a, &mut b, b"talking");
    }

    #[test]
    fn gap_limit_is_exact_and_rejection_leaves_state_unchanged() {
        for (gap, opens) in [(MAX_GAP, true), (MAX_GAP + 1, false)] {
            let (mut a, mut b) = pair();
            talk(&mut a, &mut b, b"1");
            lose(&mut a, gap);
            let block = a.seal(&msg(b"far"));
            let before = b.to_bytes();
            assert_eq!(read(&mut b, &block, 0).is_some(), opens, "gap {gap}");
            if !opens {
                assert_eq!(*b.to_bytes(), *before);
            }
        }
    }

    #[test]
    fn pq_secret_mixed_into_offerer_next_chain() {
        let (mut a, mut b) = pair();
        talk(&mut a, &mut b, b"1");
        talk(&mut b, &mut a, b"2");

        let (id, ek) = a.kem_offer().unwrap();
        let ct = b.kem_accept(id, &ek).unwrap();
        assert!(a.kem_complete(id + 1, &ct).is_none());
        a.kem_complete(id, &ct).unwrap();
        assert!(a.offer.is_none());

        talk(&mut a, &mut b, b"3");
        assert_eq!(a.pq_send, id);
        assert!(b.accepted.is_none());
        talk(&mut a, &mut b, b"4");
        talk(&mut b, &mut a, b"5");
        talk(&mut a, &mut b, b"6");
        assert_eq!(a.pq_send, 0);
    }

    #[test]
    fn pq_secret_is_really_mixed() {
        let (mut a, mut b) = pair();
        let (id, ek) = a.kem_offer().unwrap();
        let ct = b.kem_accept(id, &ek).unwrap();
        a.kem_complete(id, &ct).unwrap();
        b.accepted = Some((id, Zeroizing::new([9; KEY_LEN])));
        talk(&mut b, &mut a, b"1");
        assert!(read(&mut b, &a.seal(&msg(b"2")), 0).is_none());
    }

    #[test]
    fn kem_rejects_duplicate_stale_and_early_offers() {
        let (mut a, mut b) = pair();
        let (old, old_ek) = a.kem_offer().unwrap();
        let (id, ek) = a.kem_offer().unwrap();
        assert!(id > old);
        let ct = b.kem_accept(id, &ek).unwrap();
        assert!(b.kem_accept(id, &ek).is_none());
        assert!(b.kem_accept(old, &old_ek).is_none());
        assert!(a.kem_complete(old, &ct).is_none());
        a.kem_complete(id, &ct).unwrap();
        assert!(a.kem_offer().is_none());
        talk(&mut b, &mut a, b"1");
        talk(&mut a, &mut b, b"2");
        assert!(a.kem_offer().is_some());
    }

    #[test]
    fn unknown_pq_id_is_rejected() {
        let (mut a, mut b) = pair();
        talk(&mut b, &mut a, b"1");
        a.pq_next = Some((7, Zeroizing::new([1; KEY_LEN])));
        let block = a.seal(&msg(b"2"));
        let before = b.to_bytes();
        assert!(read(&mut b, &block, 0).is_none());
        assert_eq!(*b.to_bytes(), *before);
    }

    #[test]
    fn persistence_roundtrip_mid_conversation() {
        let (mut a, mut b) = pair();
        talk(&mut a, &mut b, b"1");
        let m0 = a.seal(&msg(b"m0"));
        let m1 = a.seal(&msg(b"m1"));
        assert!(read(&mut b, &m1, 0).is_some());
        let (id, ek) = a.kem_offer().unwrap();

        let (bytes_a, bytes_b) = (a.to_bytes(), b.to_bytes());
        let (mut a, mut b) = (
            Ratchet::from_bytes(&bytes_a).unwrap(),
            Ratchet::from_bytes(&bytes_b).unwrap(),
        );
        assert_eq!(*a.to_bytes(), *bytes_a);
        assert_eq!(*b.to_bytes(), *bytes_b);

        assert_eq!(read(&mut b, &m0, 0).unwrap(), b"m0");
        let ct = b.kem_accept(id, &ek).unwrap();
        a.kem_complete(id, &ct).unwrap();
        talk(&mut b, &mut a, b"2");
        talk(&mut a, &mut b, b"3");
        assert_eq!(a.pq_send, id);

        for len in 0..bytes_b.len() {
            assert!(Ratchet::from_bytes(&bytes_b[..len]).is_none());
        }
        let mut longer = bytes_b.to_vec();
        longer.push(0);
        assert!(Ratchet::from_bytes(&longer).is_none());
        assert!(Ratchet::from_bytes(&[0xff; 600]).is_none());
    }

    /// Both sides send, deliveries are reordered, states are persisted at random, and PQ
    /// offers/ciphertexts travel inside control blocks. Every block must open exactly once.
    #[test]
    fn random_delivery_simulation() {
        let mut rng = 0x9E37_79B9_7F4A_7C15u64;
        let mut below = |n: usize| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng % n as u64) as usize
        };
        let mut completed = 0;
        for _ in 0..10 {
            let (a, b) = pair();
            let mut p = [a, b];
            let mut inbox: [Vec<Block>; 2] = Default::default();
            let mut outbox: [Vec<Vec<u8>>; 2] = Default::default();
            for step in 0..400 {
                let i = below(2);
                match below(12) {
                    0 => p[i] = Ratchet::from_bytes(&p[i].to_bytes()).unwrap(),
                    1 => {
                        if let Some((id, ek)) = p[i].kem_offer() {
                            outbox[i].push([&[0][..], &id.to_be_bytes(), &ek].concat());
                        }
                    }
                    2..=6 => {
                        let body = match outbox[i].pop() {
                            Some(control) => block::split(Kind::Control, 0, &control).remove(0),
                            None => msg(&(step as u32).to_be_bytes()),
                        };
                        inbox[1 - i].push(p[i].seal(&body));
                    }
                    _ if inbox[i].is_empty() => {}
                    _ => {
                        let block = inbox[i].swap_remove(below(inbox[i].len()));
                        let body = p[i].open(&block, 0).expect("delivered block lost");
                        assert!(p[i].open(&block, 0).is_none(), "block opened twice");
                        let frame = block::parse(&body).unwrap();
                        if frame.kind == Kind::Control {
                            let (tag, rest) = frame.content.split_first().unwrap();
                            let (id, key) = rest.split_first_chunk::<4>().unwrap();
                            let id = u32::from_be_bytes(*id);
                            if *tag == 0 {
                                if let Some(ct) = p[i].kem_accept(id, key) {
                                    outbox[i].push([&[1][..], &id.to_be_bytes(), &ct].concat());
                                }
                            } else if p[i].kem_complete(id, key).is_some() {
                                completed += 1;
                            }
                        }
                    }
                }
            }
            for i in 0..2 {
                for block in inbox[i].drain(..) {
                    assert!(p[i].open(&block, 0).is_some(), "drained block lost");
                }
            }
        }
        assert!(completed > 0, "simulation never completed a PQ exchange");
    }
}
