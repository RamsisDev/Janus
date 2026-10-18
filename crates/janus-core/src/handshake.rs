//! Three-message handshake: CPace + X25519 + ML-KEM-768.
//!
//! ```text
//! msg1 A->B | cpace 48 | x25519 pub 32 | commitment 32 | ml-kem key 1184 |
//! msg2 B->A | cpace 32 | x25519 pub 32 | ml-kem ciphertext 1088 | confirm_b 32 |
//! msg3 A->B | masked first ratchet pub 32 | confirm_a 32 |
//! ```
//!
//! The 6 words are only the CPace password, drawn by [`words`] from the BIP-39 English list
//! (66 bits). The root key is `HKDF(k_cpace || ss_x25519 || ss_mlkem, transcript hash)`, so
//! breaking it needs all three. A failed `finish` leaves its state usable, so a third party's
//! bogus answer cannot kill a handshake; the caller caps how many wrong answers it accepts.
//!
//! Someone who has the words can still sit in the middle. The 3 safety words, derived from the
//! whole transcript, catch it: B shows them and A must type them. The msg1 commitment, to A's
//! first ratchet key and the interval, keeps such a man in the middle from grinding either in
//! msg3 until both sides' words match.
//!
//! The interval travels only inside that commitment. msg3 masks the ratchet key with a key from
//! the handshake, so only B can test the commitment and learn the interval; nothing on the wire
//! names it.
//!
//! The [`NetworkId`] both sides run on joins the words in CPace's associated data, so devices on
//! different networks derive different keys and never complete the handshake. It never travels
//! on the wire either.

use ml_kem::{Decapsulate, DecapsulationKey768, EncapsulationKey768, KeyExport};
use pake_cpace::{CPace, STEP1_PACKET_BYTES, STEP2_PACKET_BYTES, SharedKeys, Step1Out};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::block::QueueId;
use crate::crypto::{self, CT_LEN, EK_LEN, KEY_LEN, Key};

/// A pending handshake step dies this many seconds after it started, on its own device's
/// clock. No time travels on the wire, so the two devices' clocks never need to agree.
pub const INVITE_TTL: u64 = 600;
/// Bytes of the words' hash the rendezvous queue is derived from. Whoever watches that queue
/// learns at most these 24 bits of the words, and each answer is still a single online guess at
/// the other 42.
const RENDEZVOUS_LEN: usize = 3;
/// BIP-39 English list, SHA-256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda:
/// 2048 words, 11 bits each.
const WORDLIST: &str = include_str!("wordlist.txt");
const WORD_COUNT: usize = 6;
/// Two bytes per safety word, 11 bits used: 3 words, 33 bits.
pub const SAFETY_LEN: usize = 6;

const ID_A: &str = "janus-a";
const ID_B: &str = "janus-b";
const AD: &[u8] = b"janus-core v1 invite";
const DH_LEN: usize = 32;

const DH1_AT: usize = STEP1_PACKET_BYTES;
const COMMIT_AT: usize = DH1_AT + DH_LEN;
const EK_AT: usize = COMMIT_AT + KEY_LEN;
pub const MSG1_LEN: usize = EK_AT + EK_LEN;

const DH2_AT: usize = STEP2_PACKET_BYTES;
const CT_AT: usize = DH2_AT + DH_LEN;
const CONFIRM_AT: usize = CT_AT + CT_LEN;
pub const MSG2_LEN: usize = CONFIRM_AT + KEY_LEN;

pub const MSG3_LEN: usize = DH_LEN + KEY_LEN;

/// The network a handshake runs on: a hash of its profile, opaque to the core.
pub type NetworkId = [u8; 32];

/// Forced rotation interval, chosen by A. Its byte, the number of hours, is committed to in
/// msg1 and kept in session exports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Interval {
    H1 = 1,
    H5 = 5,
    H10 = 10,
    H120 = 120,
}

impl Interval {
    const ALL: [Interval; 4] = [Self::H1, Self::H5, Self::H10, Self::H120];

    pub fn secs(self) -> u64 {
        u64::from(self as u8) * 3600
    }

    pub(crate) fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::H1),
            5 => Some(Self::H5),
            10 => Some(Self::H10),
            120 => Some(Self::H120),
            _ => None,
        }
    }
}

/// `Rejected` covers malformed input and failed confirmation, with no further detail.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadWords,
    Expired,
    Rejected,
}

/// The secret of a new invitation: 6 words drawn uniformly from the list. Words people pick
/// themselves are far easier to guess, so `normalize` accepts only list words.
pub fn words() -> Zeroizing<String> {
    to_words(&*Zeroizing::new(crypto::random::<{ 2 * WORD_COUNT }>()))
}

/// One list word per 2 bytes, from their low 11 bits.
pub(crate) fn to_words(bytes: &[u8]) -> Zeroizing<String> {
    // Reserved up front (list words are at most 8 letters) so no unzeroized copy is left behind.
    let mut out = Zeroizing::new(String::with_capacity(9 * bytes.len() / 2));
    for pair in bytes.as_chunks::<2>().0 {
        let index = usize::from(u16::from_be_bytes(*pair) & 0x7ff);
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(
            WORDLIST
                .lines()
                .nth(index)
                .expect("the list has 2048 words"),
        );
    }
    out
}

/// Whether `typed` spells the words of `bytes`, ignoring case and spacing.
pub(crate) fn spells(typed: &str, bytes: &[u8]) -> bool {
    let typed = Zeroizing::new(typed.to_lowercase());
    typed.split_whitespace().eq(to_words(bytes).split(' '))
}

/// Lowercases and collapses whitespace. Exactly 6 list words or `None`.
fn normalize(words: &str) -> Option<Zeroizing<String>> {
    let lower = Zeroizing::new(words.to_lowercase());
    let parts: Vec<&str> = lower.split_whitespace().collect();
    let known = |p: &&str| WORDLIST.lines().any(|w| w == *p);
    (parts.len() == WORD_COUNT && parts.iter().all(known)).then(|| Zeroizing::new(parts.join(" ")))
}

/// Public queue where A leaves its invitation and B looks for it. Unrelated invitations may
/// share it. Its bytes look random, but there are only 2^24 such queues, so whoever lists them
/// all still recognizes one.
pub fn rendezvous(words: &str) -> Result<QueueId, Error> {
    let words = normalize(words).ok_or(Error::BadWords)?;
    let tag = crypto::hkdf::<RENDEZVOUS_LEN>(&[], words.as_bytes(), b"janus rendezvous");
    Ok(*crypto::hkdf(&[], &*tag, b"janus rendezvous queue"))
}

pub struct Established {
    pub initiator: bool,
    pub root: Zeroizing<Key>,
    /// A: its first ratchet key. B: its handshake ephemeral.
    pub our_dh: StaticSecret,
    /// A: B's handshake ephemeral. B: A's first ratchet key.
    pub their_dh: PublicKey,
    pub interval: Interval,
    /// Equal on both sides unless someone sits in the middle.
    pub safety: [u8; SAFETY_LEN],
}

pub struct Initiator {
    cpace: Step1Out,
    dh: StaticSecret,
    /// First ratchet key, committed to in msg1 and revealed in msg3.
    ratchet: StaticSecret,
    dk: DecapsulationKey768,
    transcript: Sha256,
    started: u64,
    interval: Interval,
}

impl Initiator {
    pub fn start(
        words: &str,
        network: &NetworkId,
        interval: Interval,
        now: u64,
    ) -> Result<(Initiator, [u8; MSG1_LEN]), Error> {
        let words = normalize(words).ok_or(Error::BadWords)?;
        let cpace = CPace::step1(&words, ID_A, ID_B, Some(ad(network)))
            .expect("fixed identifiers; only fails without an OS random generator");
        let dh = StaticSecret::from(crypto::random::<DH_LEN>());
        let ratchet = StaticSecret::from(crypto::random::<DH_LEN>());
        let seed = Zeroizing::new(crypto::random::<64>());
        let dk = DecapsulationKey768::from_seed((*seed).into());

        let mut msg1 = [0u8; MSG1_LEN];
        msg1[..DH1_AT].copy_from_slice(&cpace.packet());
        msg1[DH1_AT..COMMIT_AT].copy_from_slice(PublicKey::from(&dh).as_bytes());
        let ratchet_pub = PublicKey::from(&ratchet);
        msg1[COMMIT_AT..EK_AT].copy_from_slice(&*commitment(ratchet_pub.as_bytes(), interval));
        msg1[EK_AT..].copy_from_slice(&dk.encapsulation_key().to_bytes());

        let initiator = Initiator {
            cpace,
            dh,
            ratchet,
            dk,
            transcript: Sha256::new().chain_update(msg1),
            started: now,
            interval,
        };
        Ok((initiator, msg1))
    }

    /// The last second this invitation, safety words included, may complete.
    pub fn deadline(&self) -> u64 {
        self.started.saturating_add(INVITE_TTL)
    }

    pub fn finish(&self, msg2: &[u8], now: u64) -> Result<(Established, [u8; MSG3_LEN]), Error> {
        if now > self.deadline() {
            return Err(Error::Expired);
        }
        let msg2: &[u8; MSG2_LEN] = msg2.try_into().map_err(|_| Error::Rejected)?;
        let keys = self
            .cpace
            .step3(msg2[..DH2_AT].try_into().expect("fixed layout"))
            .map_err(|_| Error::Rejected)?;
        let their_dh = public(&msg2[DH2_AT..CT_AT]);
        let ss_x = contributory(self.dh.diffie_hellman(&their_dh))?;
        let ss_kem = Zeroizing::new(
            self.dk
                .decapsulate(msg2[CT_AT..CONFIRM_AT].try_into().expect("fixed layout")),
        );
        let ikm = ikm(keys, &ss_x, &ss_kem);

        let mut transcript = self.transcript.clone().chain_update(&msg2[..CONFIRM_AT]);
        let confirm_b = crypto::hkdf::<KEY_LEN>(
            &transcript.clone().finalize(),
            ikm.as_slice(),
            b"janus confirm b",
        );
        if !bool::from(confirm_b.as_slice().ct_eq(&msg2[CONFIRM_AT..])) {
            return Err(Error::Rejected);
        }
        transcript.update(&msg2[CONFIRM_AT..]);

        let our_pub = PublicKey::from(&self.ratchet);
        let mut msg3 = [0u8; MSG3_LEN];
        msg3[..DH_LEN].copy_from_slice(&masked(our_pub.as_bytes(), &transcript, &ikm));
        let th3 = transcript.chain_update(our_pub.as_bytes()).finalize();
        msg3[DH_LEN..].copy_from_slice(&*crypto::hkdf::<KEY_LEN>(
            &th3,
            ikm.as_slice(),
            b"janus confirm a",
        ));

        let established = Established {
            initiator: true,
            root: crypto::hkdf(&th3, ikm.as_slice(), b"janus root"),
            our_dh: self.ratchet.clone(),
            their_dh,
            interval: self.interval,
            safety: *crypto::hkdf(&th3, ikm.as_slice(), b"janus safety"),
        };
        Ok((established, msg3))
    }
}

pub struct Responder {
    ikm: Zeroizing<[u8; 3 * KEY_LEN]>,
    dh: StaticSecret,
    transcript: Sha256,
    /// A's commitment to the key msg3 must carry and to the interval.
    commitment: [u8; KEY_LEN],
    started: u64,
}

impl Responder {
    /// Answers `msg1`. It carries no time, so an old invitation is answered too; that is
    /// harmless, since only A, holding the words, can complete it and A drops it after the TTL.
    pub fn respond(
        words: &str,
        network: &NetworkId,
        msg1: &[u8],
        now: u64,
    ) -> Result<(Responder, [u8; MSG2_LEN]), Error> {
        let words = normalize(words).ok_or(Error::BadWords)?;
        let msg1: &[u8; MSG1_LEN] = msg1.try_into().map_err(|_| Error::Rejected)?;
        let ek = EncapsulationKey768::new(msg1[EK_AT..].try_into().expect("fixed layout"))
            .map_err(|_| Error::Rejected)?;
        let cpace = CPace::step2(
            msg1[..DH1_AT].try_into().expect("fixed layout"),
            &words,
            ID_A,
            ID_B,
            Some(ad(network)),
        )
        .map_err(|_| Error::Rejected)?;
        let dh = StaticSecret::from(crypto::random::<DH_LEN>());
        let ss_x = contributory(dh.diffie_hellman(&public(&msg1[DH1_AT..COMMIT_AT])))?;
        let m = Zeroizing::new(crypto::random::<32>());
        let (ct, ss_kem) = ek.encapsulate_deterministic(&(*m).into());
        let ss_kem = Zeroizing::new(ss_kem);
        let ikm = ikm(cpace.shared_keys(), &ss_x, &ss_kem);

        let mut msg2 = [0u8; MSG2_LEN];
        msg2[..DH2_AT].copy_from_slice(&cpace.packet());
        msg2[DH2_AT..CT_AT].copy_from_slice(PublicKey::from(&dh).as_bytes());
        msg2[CT_AT..CONFIRM_AT].copy_from_slice(&ct);
        let transcript = Sha256::new()
            .chain_update(msg1)
            .chain_update(&msg2[..CONFIRM_AT]);
        let confirm_b = crypto::hkdf::<KEY_LEN>(
            &transcript.clone().finalize(),
            ikm.as_slice(),
            b"janus confirm b",
        );
        msg2[CONFIRM_AT..].copy_from_slice(&*confirm_b);

        let responder = Responder {
            ikm,
            dh,
            transcript: transcript.chain_update(confirm_b.as_slice()),
            commitment: msg1[COMMIT_AT..EK_AT].try_into().expect("fixed layout"),
            started: now,
        };
        Ok((responder, msg2))
    }

    pub fn expired(&self, now: u64) -> bool {
        now > self.started.saturating_add(INVITE_TTL)
    }

    pub fn finish(&self, msg3: &[u8], now: u64) -> Result<Established, Error> {
        if self.expired(now) {
            return Err(Error::Expired);
        }
        let msg3: &[u8; MSG3_LEN] = msg3.try_into().map_err(|_| Error::Rejected)?;
        let (mask, confirm_a) = msg3.split_at(DH_LEN);
        let their_pub = masked(mask, &self.transcript, &self.ikm);
        let th3 = self.transcript.clone().chain_update(their_pub).finalize();
        let expected = crypto::hkdf::<KEY_LEN>(&th3, self.ikm.as_slice(), b"janus confirm a");
        // Every candidate is tried, so timing does not tell which interval matched.
        let interval = Interval::ALL.into_iter().fold(None, |found, i| {
            let hit = commitment(&their_pub, i).ct_eq(&self.commitment);
            if bool::from(hit) { Some(i) } else { found }
        });
        let interval = match interval {
            Some(i) if bool::from(expected.as_slice().ct_eq(confirm_a)) => i,
            _ => return Err(Error::Rejected),
        };
        Ok(Established {
            initiator: false,
            root: crypto::hkdf(&th3, self.ikm.as_slice(), b"janus root"),
            our_dh: self.dh.clone(),
            their_dh: PublicKey::from(their_pub),
            interval,
            safety: *crypto::hkdf(&th3, self.ikm.as_slice(), b"janus safety"),
        })
    }
}

fn ad(network: &NetworkId) -> Vec<u8> {
    [AD, network].concat()
}

fn commitment(ratchet_pub: &[u8; DH_LEN], interval: Interval) -> Zeroizing<[u8; KEY_LEN]> {
    crypto::hkdf(&[interval as u8], ratchet_pub, b"janus commitment")
}

/// Masks or unmasks A's first ratchet key in msg3, under a key bound to the transcript up to
/// msg2. Without it, anyone who saw msg1 and msg3 could test the commitment for the interval.
fn masked(key: &[u8], transcript: &Sha256, ikm: &[u8; 3 * KEY_LEN]) -> [u8; DH_LEN] {
    let th2 = transcript.clone().finalize();
    let mask = crypto::hkdf::<DH_LEN>(&th2, ikm, b"janus msg3 mask");
    std::array::from_fn(|i| key[i] ^ mask[i])
}

fn public(bytes: &[u8]) -> PublicKey {
    PublicKey::from(<[u8; DH_LEN]>::try_from(bytes).expect("fixed layout"))
}

fn contributory(ss: SharedSecret) -> Result<SharedSecret, Error> {
    ss.was_contributory().then_some(ss).ok_or(Error::Rejected)
}

fn ikm(mut cpace: SharedKeys, ss_x: &SharedSecret, ss_kem: &[u8]) -> Zeroizing<[u8; 3 * KEY_LEN]> {
    let mut ikm = Zeroizing::new([0u8; 3 * KEY_LEN]);
    ikm[..KEY_LEN].copy_from_slice(&cpace.k1);
    cpace.k1.zeroize();
    cpace.k2.zeroize();
    ikm[KEY_LEN..2 * KEY_LEN].copy_from_slice(ss_x.as_bytes());
    ikm[2 * KEY_LEN..].copy_from_slice(ss_kem);
    ikm
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: &str = "alpha cable echo forest orbit velvet";
    const WRONG: &str = "alpha cable echo forest orbit zoo";
    const NOW: u64 = 1_800_000_000;
    const NET: NetworkId = [1; 32];

    fn run(
        words_b: &str,
        tamper: impl Fn(usize, &mut [u8]),
    ) -> Result<(Established, Established), Error> {
        let (a, mut msg1) = Initiator::start(WORDS, &NET, Interval::H5, NOW)?;
        tamper(1, &mut msg1);
        let (b, mut msg2) = Responder::respond(words_b, &NET, &msg1, NOW + 1)?;
        tamper(2, &mut msg2);
        let (a, mut msg3) = a.finish(&msg2, NOW + 2)?;
        tamper(3, &mut msg3);
        Ok((a, b.finish(&msg3, NOW + 3)?))
    }

    #[test]
    fn happy_path() {
        let (a, b) = run("  ALPHA cable\techo forest orbit  Velvet ", |_, _| {}).unwrap();
        assert_eq!(*a.root, *b.root);
        assert_eq!((a.interval, b.interval), (Interval::H5, Interval::H5));
        assert_eq!(PublicKey::from(&a.our_dh), b.their_dh);
        assert_eq!(PublicKey::from(&b.our_dh), a.their_dh);
        assert!(a.initiator && !b.initiator);
        assert_eq!(a.safety, b.safety);
    }

    #[test]
    fn a_man_in_the_middle_with_the_words_shows_different_safety_words() {
        // M answers A as B and invites B as A, running two handshakes with the same words.
        let (a, msg1) = Initiator::start(WORDS, &NET, Interval::H1, NOW).unwrap();
        let (m_as_b, msg2) = Responder::respond(WORDS, &NET, &msg1, NOW).unwrap();
        let (a, msg3) = a.finish(&msg2, NOW).unwrap();
        let m_with_a = m_as_b.finish(&msg3, NOW).unwrap();

        let (m_as_a, msg1) = Initiator::start(WORDS, &NET, Interval::H1, NOW).unwrap();
        let (b, msg2) = Responder::respond(WORDS, &NET, &msg1, NOW).unwrap();
        let (m_with_b, msg3) = m_as_a.finish(&msg2, NOW).unwrap();
        let b = b.finish(&msg3, NOW).unwrap();

        assert_eq!((a.safety, b.safety), (m_with_a.safety, m_with_b.safety));
        assert_ne!(a.safety, b.safety);
        let shown = to_words(&b.safety);
        assert_eq!(shown.split(' ').count(), 3);
        assert!(spells(&format!("  {}\t", shown.to_uppercase()), &b.safety));
        assert!(!spells(&shown, &a.safety));
    }

    #[test]
    fn msg3_must_carry_the_committed_key() {
        let (mut a, msg1) = Initiator::start(WORDS, &NET, Interval::H1, NOW).unwrap();
        let (b, msg2) = Responder::respond(WORDS, &NET, &msg1, NOW).unwrap();
        // A grinding man in the middle swaps in another key after seeing msg2.
        a.ratchet = StaticSecret::from(crypto::random::<DH_LEN>());
        let (_, msg3) = a.finish(&msg2, NOW).unwrap();
        assert_eq!(b.finish(&msg3, NOW).err(), Some(Error::Rejected));
    }

    #[test]
    fn wrong_words_rejected() {
        assert_eq!(run(WRONG, |_, _| {}).err(), Some(Error::Rejected));
    }

    #[test]
    fn devices_on_different_networks_never_complete() {
        let (a, msg1) = Initiator::start(WORDS, &NET, Interval::H1, NOW).unwrap();
        let (_, msg2) = Responder::respond(WORDS, &[2; 32], &msg1, NOW).unwrap();
        assert_eq!(a.finish(&msg2, NOW).err(), Some(Error::Rejected));
    }

    #[test]
    fn bogus_answers_leave_both_sides_usable() {
        let (a, msg1) = Initiator::start(WORDS, &NET, Interval::H1, NOW).unwrap();
        let (_, guess) = Responder::respond(WRONG, &NET, &msg1, NOW).unwrap();
        assert_eq!(a.finish(&guess, NOW).err(), Some(Error::Rejected));
        assert_eq!(a.finish(&[0; MSG2_LEN], NOW).err(), Some(Error::Rejected));

        let (b, msg2) = Responder::respond(WORDS, &NET, &msg1, NOW).unwrap();
        let (a, msg3) = a.finish(&msg2, NOW).unwrap();
        let mut forged = msg3;
        forged[MSG3_LEN - 1] ^= 1;
        assert_eq!(b.finish(&forged, NOW).err(), Some(Error::Rejected));
        assert_eq!(*b.finish(&msg3, NOW).unwrap().root, *a.root);
    }

    #[test]
    fn generated_words_are_valid_and_random() {
        assert_eq!(WORDLIST.lines().count(), 2048);
        let (w1, w2) = (words(), words());
        assert_ne!(w1, w2);
        for w in [&w1, &w2] {
            assert_eq!(normalize(w), Some(w.clone()));
        }
        let (a, msg1) = Initiator::start(&w1, &NET, Interval::H1, NOW).unwrap();
        let (b, msg2) = Responder::respond(&w1, &NET, &msg1, NOW).unwrap();
        let (a, msg3) = a.finish(&msg2, NOW).unwrap();
        assert_eq!(*b.finish(&msg3, NOW).unwrap().root, *a.root);
    }

    #[test]
    fn flipped_byte_in_any_field_rejected() {
        let msg1 = [0, 16, DH1_AT, COMMIT_AT, EK_AT, MSG1_LEN - 1];
        let msg2 = [0, DH2_AT, CT_AT, CONFIRM_AT, MSG2_LEN - 1];
        let msg3 = [0, DH_LEN, MSG3_LEN - 1];
        for (msg, fields) in [(1, &msg1[..]), (2, &msg2), (3, &msg3)] {
            for &at in fields {
                let flip = |m: usize, buf: &mut [u8]| {
                    if m == msg {
                        buf[at] ^= 1;
                    }
                };
                let res = run(WORDS, flip).err();
                assert_eq!(res, Some(Error::Rejected), "flip in msg{msg} at {at}");
            }
        }
    }

    #[test]
    fn low_order_dh_rejected() {
        for (msg, range) in [(1, DH1_AT..COMMIT_AT), (2, DH2_AT..CT_AT)] {
            let zero = |m: usize, buf: &mut [u8]| {
                if m == msg {
                    buf[range.clone()].fill(0);
                }
            };
            assert_eq!(run(WORDS, zero).err(), Some(Error::Rejected), "msg{msg}");
        }
    }

    #[test]
    fn wrong_length_rejected() {
        let (a, msg1) = Initiator::start(WORDS, &NET, Interval::H1, NOW).unwrap();
        let short = Responder::respond(WORDS, &NET, &msg1[..MSG1_LEN - 1], NOW);
        assert_eq!(short.err(), Some(Error::Rejected));
        let (b, _) = Responder::respond(WORDS, &NET, &msg1, NOW).unwrap();
        assert_eq!(
            a.finish(&[0; MSG2_LEN + 1], NOW).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            b.finish(&[0; MSG3_LEN - 1], NOW).err(),
            Some(Error::Rejected)
        );
    }

    #[test]
    fn the_interval_reaches_b_only_through_the_commitment() {
        for interval in Interval::ALL {
            let (a, msg1) = Initiator::start(WORDS, &NET, interval, NOW).unwrap();
            let (b, msg2) = Responder::respond(WORDS, &NET, &msg1, NOW).unwrap();
            let (a, msg3) = a.finish(&msg2, NOW).unwrap();
            assert_eq!(b.finish(&msg3, NOW).unwrap().interval, interval);
            assert_eq!(a.interval, interval);
            let ratchet_pub = PublicKey::from(&a.our_dh);
            assert_ne!(
                &msg3[..DH_LEN],
                ratchet_pub.as_bytes(),
                "msg3 key not masked"
            );
        }
    }

    #[test]
    fn each_side_expires_its_own_step_on_its_own_clock() {
        const B_CLOCK: u64 = 42;
        let (a, msg1) = Initiator::start(WORDS, &NET, Interval::H10, NOW).unwrap();
        let (b, msg2) = Responder::respond(WORDS, &NET, &msg1, B_CLOCK).unwrap();
        assert_eq!(
            a.finish(&msg2, NOW + INVITE_TTL + 1).err(),
            Some(Error::Expired)
        );
        let (_, msg3) = a.finish(&msg2, NOW + INVITE_TTL).unwrap();
        assert_eq!(
            b.finish(&msg3, B_CLOCK + INVITE_TTL + 1).err(),
            Some(Error::Expired)
        );
        assert!(b.finish(&msg3, B_CLOCK + INVITE_TTL).is_ok());
    }

    #[test]
    fn normalize_words() {
        assert_eq!(
            normalize(" Alpha  cable\nECHO forest Orbit   velvet ")
                .as_deref()
                .map(String::as_str),
            Some(WORDS)
        );
        assert!(normalize("alpha cable echo forest orbit").is_none());
        assert!(normalize("alpha cable echo forest orbit velvet zoo").is_none());
        assert!(normalize("alpha cable echo forest orbit bravo").is_none());
        assert_eq!(
            Initiator::start("my dog is called max now", &NET, Interval::H1, NOW).err(),
            Some(Error::BadWords)
        );
    }

    #[test]
    fn rendezvous_keeps_only_a_short_tag_of_the_normalized_words() {
        let queue = rendezvous(WORDS).unwrap();
        assert_eq!(
            rendezvous(" ALPHA cable echo forest orbit Velvet"),
            Ok(queue)
        );
        assert_ne!(rendezvous(WRONG), Ok(queue));
        let tag = crypto::hkdf::<RENDEZVOUS_LEN>(&[], WORDS.as_bytes(), b"janus rendezvous");
        assert_eq!(*crypto::hkdf(&[], &*tag, b"janus rendezvous queue"), queue);
        assert!(
            !queue.windows(2).any(|w| w == [0, 0]),
            "zero run left in the queue"
        );
        assert_eq!(rendezvous("alpha bravo"), Err(Error::BadWords));
    }
}
