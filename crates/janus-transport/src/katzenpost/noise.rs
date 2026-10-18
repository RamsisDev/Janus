//! `Noise_pqXX_XWING_ChaChaPoly_BLAKE2b`: the handshake under Katzenpost's wire protocol, from
//! the Noise specification (revision 34) and the pqXX pattern of the Post Quantum Noise paper.
//!
//! `wire.md` spells the KEM `Xwing`; the servers name it `XWING`, as in their key files, and
//! only that name completes a handshake with them. X-Wing is draft 06, with its keys as 32-byte
//! seeds.
//!
//! ```text
//! pqXX:
//!   -> e
//!   <- ekem, s
//!   -> skem, s
//!   <- skem
//! ```
//!
//! `e` and `s` send a KEM public key, `ekem` and `skem` a ciphertext to the peer's ephemeral and
//! static key. A ciphertext or key sent before any key exists travels in the clear and is
//! hashed, as `EncryptAndHash` does without a key. The `ekem` secret goes through `MixKey`, the
//! `skem` secrets through `MixKeyAndHash`: neither spec says which, and this is the only
//! combination the servers accept.

use blake2::{Blake2b512, Digest};
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit as _};
use hmac::{Mac, SimpleHmac};
use x_wing::{Decapsulate, DecapsulationKey, Decapsulator, EncapsulationKey, KeyExport};
use zeroize::{Zeroize, Zeroizing};

pub const PROTOCOL: &[u8] = b"Noise_pqXX_XWING_ChaChaPoly_BLAKE2b";
pub const PUBLIC_KEY_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;
pub const SECRET_KEY_LEN: usize = x_wing::DECAPSULATION_KEY_SIZE;
pub const CIPHERTEXT_LEN: usize = x_wing::CIPHERTEXT_SIZE;
pub const TAG_LEN: usize = 16;
const HASH_LEN: usize = 64;

/// One direction of an established session, or the handshake's current key.
pub struct Cipher {
    key: Zeroizing<[u8; 32]>,
    nonce: u64,
}

impl Cipher {
    fn new(key: &[u8]) -> Cipher {
        Cipher {
            key: Zeroizing::new(key[..32].try_into().expect("a hash is longer than a key")),
            nonce: 0,
        }
    }

    fn nonce(n: u64) -> [u8; 12] {
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&n.to_le_bytes());
        nonce
    }

    pub fn seal(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut out = plaintext.to_vec();
        let tag = ChaCha20Poly1305::new(&(*self.key).into())
            .encrypt_inout_detached(&Cipher::nonce(self.nonce).into(), ad, (&mut out[..]).into())
            .expect("message length within ChaCha20-Poly1305 limits");
        out.extend_from_slice(&tag);
        self.nonce += 1;
        out
    }

    pub fn open(&mut self, ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let (body, tag) = ciphertext.split_at_checked(ciphertext.len().checked_sub(TAG_LEN)?)?;
        let tag: &[u8; TAG_LEN] = tag.try_into().expect("TAG_LEN");
        let mut out = body.to_vec();
        ChaCha20Poly1305::new(&(*self.key).into())
            .decrypt_inout_detached(
                &Cipher::nonce(self.nonce).into(),
                ad,
                (&mut out[..]).into(),
                tag.into(),
            )
            .ok()?;
        self.nonce += 1;
        Some(out)
    }

    /// Noise's default `REKEY`: the first 32 bytes of 32 zeros sealed under the maximum nonce.
    pub fn rekey(&mut self) {
        let mut zeros = [0u8; 32];
        ChaCha20Poly1305::new(&(*self.key).into())
            .encrypt_inout_detached(
                &Cipher::nonce(u64::MAX).into(),
                &[],
                (&mut zeros[..]).into(),
            )
            .expect("32 bytes");
        self.key.copy_from_slice(&zeros);
        zeros.zeroize();
    }
}

fn hash(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut h = Blake2b512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; HASH_LEN]> {
    let mut mac = SimpleHmac::<Blake2b512>::new_from_slice(key).expect("HMAC takes any key");
    for p in parts {
        mac.update(p);
    }
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// Noise's `HKDF` with two outputs.
fn hkdf(ck: &[u8], ikm: &[u8]) -> (Zeroizing<[u8; HASH_LEN]>, Zeroizing<[u8; HASH_LEN]>) {
    let temp = hmac(ck, &[ikm]);
    let one = hmac(&*temp, &[&[1]]);
    let two = hmac(&*temp, &[&*one, &[2]]);
    (one, two)
}

struct Symmetric {
    ck: Zeroizing<[u8; HASH_LEN]>,
    h: [u8; HASH_LEN],
    k: Option<Cipher>,
}

impl Symmetric {
    fn new(prologue: &[u8]) -> Symmetric {
        let mut h = [0; HASH_LEN];
        h[..PROTOCOL.len()].copy_from_slice(PROTOCOL);
        let mut s = Symmetric {
            ck: Zeroizing::new(h),
            h,
            k: None,
        };
        s.mix_hash(prologue);
        s
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash(&[&self.h, data]);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf(&*self.ck, ikm);
        self.ck = ck;
        self.k = Some(Cipher::new(&*k));
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let temp = hmac(&*self.ck, &[ikm]);
        let ck = hmac(&*temp, &[&[1]]);
        let h = hmac(&*temp, &[&*ck, &[2]]);
        let k = hmac(&*temp, &[&*h, &[3]]);
        self.ck = ck;
        self.mix_hash(&*h);
        self.k = Some(Cipher::new(&*k));
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let out = match &mut self.k {
            Some(k) => k.seal(&self.h, plaintext),
            None => plaintext.to_vec(),
        };
        self.mix_hash(&out);
        out
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let out = match &mut self.k {
            Some(k) => k.open(&self.h, ciphertext)?,
            None => ciphertext.to_vec(),
        };
        self.mix_hash(ciphertext);
        Some(out)
    }

    fn sealed_len(&self, len: usize) -> usize {
        len + if self.k.is_some() { TAG_LEN } else { 0 }
    }

    fn split(&self) -> (Cipher, Cipher) {
        let (one, two) = hkdf(&*self.ck, &[]);
        (Cipher::new(&*one), Cipher::new(&*two))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

/// The four pqXX messages, run from either side. Message `i` (from 0) is written by the
/// initiator when `i` is even.
pub struct Handshake {
    role: Role,
    sym: Symmetric,
    s: DecapsulationKey,
    e: Option<DecapsulationKey>,
    re: Option<EncapsulationKey>,
    rs: Option<EncapsulationKey>,
    step: usize,
}

/// What a finished handshake leaves: the two directions and the handshake hash.
pub struct Transport {
    pub send: Cipher,
    pub recv: Cipher,
    pub hash: [u8; HASH_LEN],
}

fn random<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0; N]);
    getrandom::fill(&mut *out).expect("OS random generator unavailable");
    out
}

/// `(ciphertext, shared secret)` to `key`.
fn encapsulate(key: &EncapsulationKey) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let (ct, ss) = key.encapsulate_deterministic(&(*random::<64>()).into());
    (ct.to_vec(), Zeroizing::new(ss.to_vec()))
}

fn decapsulate(key: &DecapsulationKey, ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    Some(Zeroizing::new(key.decapsulate_slice(ct).ok()?.to_vec()))
}

/// The public key of the X-Wing secret key `secret` (a 32-byte seed).
pub fn public_key(secret: &[u8; SECRET_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    DecapsulationKey::from(*secret)
        .encapsulation_key()
        .to_bytes()
        .into()
}

pub fn generate() -> Zeroizing<[u8; SECRET_KEY_LEN]> {
    random()
}

impl Handshake {
    pub fn initiator(secret: &[u8; SECRET_KEY_LEN], prologue: &[u8]) -> Handshake {
        Handshake::new(Role::Initiator, secret, prologue)
    }

    pub fn responder(secret: &[u8; SECRET_KEY_LEN], prologue: &[u8]) -> Handshake {
        Handshake::new(Role::Responder, secret, prologue)
    }

    fn new(role: Role, secret: &[u8; SECRET_KEY_LEN], prologue: &[u8]) -> Handshake {
        Handshake {
            role,
            sym: Symmetric::new(prologue),
            s: DecapsulationKey::from(*secret),
            e: None,
            re: None,
            rs: None,
            step: 0,
        }
    }

    /// Whether the next message is ours to write.
    pub fn writing(&self) -> bool {
        self.step.is_multiple_of(2) == (self.role == Role::Initiator)
    }

    pub fn finished(&self) -> bool {
        self.step == 4
    }

    /// The peer's static public key, once received.
    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.rs.as_ref().map(|k| k.to_bytes().to_vec())
    }

    /// The length of the next message when it carries `payload` bytes. Every pqXX message has
    /// a fixed layout, so this is all the framing the handshake needs.
    pub fn message_len(&self, payload: usize) -> usize {
        let keyed = |n: usize| n + TAG_LEN;
        match self.step {
            0 => PUBLIC_KEY_LEN + payload,
            1 => CIPHERTEXT_LEN + keyed(PUBLIC_KEY_LEN) + keyed(payload),
            2 => keyed(CIPHERTEXT_LEN) + keyed(PUBLIC_KEY_LEN) + keyed(payload),
            3 => keyed(CIPHERTEXT_LEN) + keyed(payload),
            _ => self.sym.sealed_len(payload),
        }
    }

    pub fn write(&mut self, payload: &[u8]) -> Vec<u8> {
        assert!(self.writing() && !self.finished(), "not our turn to write");
        let mut out = Vec::new();
        match self.step {
            0 => {
                let e = DecapsulationKey::from(*random::<SECRET_KEY_LEN>());
                let pk = e.encapsulation_key().to_bytes();
                self.sym.mix_hash(&pk);
                out.extend_from_slice(&pk);
                self.e = Some(e);
            }
            1 => {
                let (ct, ss) = encapsulate(self.re.as_ref().expect("read e"));
                self.sym.mix_hash(&ct);
                out.extend_from_slice(&ct);
                self.sym.mix_key(&ss);
                self.write_static(&mut out);
            }
            2 => {
                self.write_skem(&mut out);
                self.write_static(&mut out);
            }
            _ => self.write_skem(&mut out),
        }
        out.extend(self.sym.encrypt_and_hash(payload));
        self.step += 1;
        out
    }

    fn write_static(&mut self, out: &mut Vec<u8>) {
        let pk = self.s.encapsulation_key().to_bytes();
        out.extend(self.sym.encrypt_and_hash(&pk));
    }

    fn write_skem(&mut self, out: &mut Vec<u8>) {
        let (ct, ss) = encapsulate(self.rs.as_ref().expect("read s"));
        out.extend(self.sym.encrypt_and_hash(&ct));
        self.sym.mix_key_and_hash(&ss);
    }

    /// The payload of `message`, or `None` if it does not authenticate; the handshake must then
    /// be abandoned.
    pub fn read(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        assert!(!self.writing() && !self.finished(), "not our turn to read");
        let r = &mut &message[..];
        match self.step {
            0 => {
                let pk = take(r, PUBLIC_KEY_LEN)?;
                self.sym.mix_hash(pk);
                self.re = Some(EncapsulationKey::try_from(pk).ok()?);
            }
            1 => {
                let ct = take(r, CIPHERTEXT_LEN)?;
                self.sym.mix_hash(ct);
                let ss = decapsulate(self.e.as_ref().expect("wrote e"), ct)?;
                self.sym.mix_key(&ss);
                self.read_static(r)?;
            }
            2 => {
                self.read_skem(r)?;
                self.read_static(r)?;
            }
            _ => self.read_skem(r)?,
        }
        let payload = self.sym.decrypt_and_hash(r)?;
        self.step += 1;
        Some(payload)
    }

    fn read_static(&mut self, r: &mut &[u8]) -> Option<()> {
        let sealed = take(r, self.sym.sealed_len(PUBLIC_KEY_LEN))?;
        let pk = self.sym.decrypt_and_hash(sealed)?;
        self.rs = Some(EncapsulationKey::try_from(&pk[..]).ok()?);
        Some(())
    }

    fn read_skem(&mut self, r: &mut &[u8]) -> Option<()> {
        let sealed = take(r, self.sym.sealed_len(CIPHERTEXT_LEN))?;
        let ct = self.sym.decrypt_and_hash(sealed)?;
        let ss = decapsulate(&self.s, &ct)?;
        self.sym.mix_key_and_hash(&ss);
        Some(())
    }

    pub fn finish(self) -> Transport {
        assert!(self.finished(), "handshake not finished");
        let (i_to_r, r_to_i) = self.sym.split();
        let (send, recv) = match self.role {
            Role::Initiator => (i_to_r, r_to_i),
            Role::Responder => (r_to_i, i_to_r),
        };
        Transport {
            send,
            recv,
            hash: self.sym.h,
        }
    }
}

fn take<'a>(r: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, rest) = r.split_at_checked(n)?;
    *r = rest;
    Some(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(payloads: [&[u8]; 4]) -> (Handshake, Handshake, [Vec<u8>; 4]) {
        let (si, sr) = (generate(), generate());
        let mut i = Handshake::initiator(&si, &[3]);
        let mut r = Handshake::responder(&sr, &[3]);
        let mut got: [Vec<u8>; 4] = Default::default();
        for (n, payload) in payloads.iter().enumerate() {
            let (w, rd) = if n % 2 == 0 {
                (&mut i, &mut r)
            } else {
                (&mut r, &mut i)
            };
            let len = w.message_len(payload.len());
            let msg = w.write(payload);
            assert_eq!(msg.len(), len, "message {n}");
            got[n] = rd.read(&msg).expect("authenticates");
        }
        (i, r, got)
    }

    #[test]
    fn both_sides_agree_and_learn_each_others_static_key() {
        let payloads: [&[u8]; 4] = [b"", b"responder", b"initiator", b"done"];
        let (i, r, got) = run(payloads);
        assert_eq!(got.map(|p| p.to_vec()), payloads.map(<[u8]>::to_vec));
        assert_eq!(
            i.remote_static().unwrap(),
            public_key(r.s.as_bytes()).to_vec()
        );
        assert_eq!(
            r.remote_static().unwrap(),
            public_key(i.s.as_bytes()).to_vec()
        );
        let (mut a, mut b) = (i.finish(), r.finish());
        assert_eq!(a.hash, b.hash);
        let sealed = a.send.seal(&[], b"ping");
        assert_eq!(b.recv.open(&[], &sealed).unwrap(), b"ping");
        a.send.rekey();
        b.recv.rekey();
        let sealed = a.send.seal(&[], b"after rekey");
        assert_eq!(b.recv.open(&[], &sealed).unwrap(), b"after rekey");
        let sealed = b.send.seal(&[], b"pong");
        assert_eq!(a.recv.open(&[], &sealed).unwrap(), b"pong");
    }

    #[test]
    fn a_tampered_message_or_another_prologue_fails() {
        let (si, sr) = (generate(), generate());
        let mut i = Handshake::initiator(&si, &[3]);
        let mut r = Handshake::responder(&sr, &[3]);
        let m1 = i.write(&[]);
        r.read(&m1).unwrap();
        let mut m2 = r.write(&[]);
        let last = m2.len() - 1;
        m2[last] ^= 1;
        assert!(i.read(&m2).is_none());

        let mut i = Handshake::initiator(&si, &[3]);
        let mut r = Handshake::responder(&sr, &[2]);
        r.read(&i.write(&[])).unwrap();
        assert!(i.read(&r.write(&[])).is_none());
    }
}
