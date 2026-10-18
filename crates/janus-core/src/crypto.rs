//! Thin wrappers over audited primitives. No primitive is implemented here.

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// ML-KEM-768 encapsulation key and ciphertext sizes.
pub const EK_LEN: usize = 1184;
pub const CT_LEN: usize = 1088;

pub type Key = [u8; KEY_LEN];

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS random generator unavailable");
    out
}

pub fn hkdf<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out.as_mut())
        .expect("HKDF output length is a compile-time constant within limits");
    out
}

pub fn seal(key: &Key, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> [u8; TAG_LEN] {
    XChaCha20Poly1305::new(&(*key).into())
        .encrypt_inout_detached(&(*nonce).into(), aad, buf.into())
        .expect("buffer length within XChaCha20-Poly1305 limits")
        .into()
}

/// On failure `buf` is left untouched.
pub fn open(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Option<()> {
    XChaCha20Poly1305::new(&(*key).into())
        .decrypt_inout_detached(&(*nonce).into(), aad, buf.into(), &(*tag).into())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        let okm = hkdf::<42>(
            &hex("000102030405060708090a0b0c"),
            &[0x0b; 22],
            &hex("f0f1f2f3f4f5f6f7f8f9"),
        );
        assert_eq!(
            okm.as_slice(),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let (key, nonce) = (random::<KEY_LEN>(), random::<NONCE_LEN>());
        let mut buf = *b"hello";
        let tag = seal(&key, &nonce, b"aad", &mut buf);
        assert_ne!(&buf, b"hello");

        let mut tampered = buf;
        tampered[0] ^= 1;
        assert!(open(&key, &nonce, b"aad", &mut tampered, &tag).is_none());
        assert!(open(&key, &nonce, b"other", &mut buf.clone(), &tag).is_none());

        assert!(open(&key, &nonce, b"aad", &mut buf, &tag).is_some());
        assert_eq!(&buf, b"hello");
    }
}
