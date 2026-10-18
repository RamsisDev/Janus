//! Fixed-size wire block.
//!
//! ```text
//! | queue id 16 | sealed header 84 | nonce 24 | sealed body 16244 | tag 16 |  = 16384
//! ```
//!
//! The body plaintext is a frame: `kind 1 | msg id 8 | index 4 | count 4 | len 2 | content | padding`.
//! Padding happens before encryption, so from outside every block looks the same.

use zeroize::Zeroizing;

use crate::crypto::{self, Key, NONCE_LEN, TAG_LEN};

/// 16 KiB, so 1000 blocks carry a 4K image (~16 MB) in one message.
pub const BLOCK_LEN: usize = 16384;
pub const QUEUE_ID_LEN: usize = 16;
/// Ratchet header plaintext: `dh public key 32 | pn 4 | n 4 | pq id 4`.
pub const HEADER_PLAIN_LEN: usize = 44;
pub const HEADER_LEN: usize = NONCE_LEN + HEADER_PLAIN_LEN + TAG_LEN;
pub const BODY_LEN: usize = BLOCK_LEN - QUEUE_ID_LEN - HEADER_LEN - NONCE_LEN - TAG_LEN;
const FRAME_HEADER_LEN: usize = 1 + 8 + 4 + 4 + 2;
pub const MAX_CONTENT_LEN: usize = BODY_LEN - FRAME_HEADER_LEN;

const HEADER_AT: usize = QUEUE_ID_LEN;
const NONCE_AT: usize = HEADER_AT + HEADER_LEN;
const BODY_AT: usize = NONCE_AT + NONCE_LEN;
const TAG_AT: usize = BODY_AT + BODY_LEN;

pub type Block = [u8; BLOCK_LEN];
pub type Body = Zeroizing<[u8; BODY_LEN]>;
pub type QueueId = [u8; QUEUE_ID_LEN];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Message = 0,
    Control = 1,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub kind: Kind,
    pub msg_id: u64,
    pub index: u32,
    pub count: u32,
    pub content: &'a [u8],
}

/// Empty data still yields one frame.
pub fn split(kind: Kind, msg_id: u64, data: &[u8]) -> Vec<Body> {
    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![data]
    } else {
        data.chunks(MAX_CONTENT_LEN).collect()
    };
    let count = u32::try_from(chunks.len()).expect("message exceeds u32::MAX fragments");
    chunks
        .iter()
        .zip(0u32..)
        .map(|(chunk, index)| {
            let mut body = Zeroizing::new([0u8; BODY_LEN]);
            body[0] = kind as u8;
            body[1..9].copy_from_slice(&msg_id.to_be_bytes());
            body[9..13].copy_from_slice(&index.to_be_bytes());
            body[13..17].copy_from_slice(&count.to_be_bytes());
            body[17..19].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
            body[FRAME_HEADER_LEN..FRAME_HEADER_LEN + chunk.len()].copy_from_slice(chunk);
            body
        })
        .collect()
}

pub fn parse(body: &[u8; BODY_LEN]) -> Option<Fragment<'_>> {
    let kind = match body[0] {
        0 => Kind::Message,
        1 => Kind::Control,
        _ => return None,
    };
    let msg_id = u64::from_be_bytes(body[1..9].try_into().ok()?);
    let index = u32::from_be_bytes(body[9..13].try_into().ok()?);
    let count = u32::from_be_bytes(body[13..17].try_into().ok()?);
    let len = usize::from(u16::from_be_bytes(body[17..19].try_into().ok()?));
    if index >= count || len > MAX_CONTENT_LEN {
        return None;
    }
    let content = &body[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len];
    Some(Fragment {
        kind,
        msg_id,
        index,
        count,
        content,
    })
}

/// The queue id and sealed header are bound as associated data.
pub fn seal(
    queue_id: &[u8; QUEUE_ID_LEN],
    header: &[u8; HEADER_LEN],
    key: &Key,
    body: &[u8; BODY_LEN],
) -> Block {
    let mut block = [0u8; BLOCK_LEN];
    let nonce = crypto::random::<NONCE_LEN>();
    block[..HEADER_AT].copy_from_slice(queue_id);
    block[HEADER_AT..NONCE_AT].copy_from_slice(header);
    block[NONCE_AT..BODY_AT].copy_from_slice(&nonce);
    block[BODY_AT..TAG_AT].copy_from_slice(body);
    let (aad, rest) = block.split_at_mut(NONCE_AT);
    let tag = crypto::seal(key, &nonce, aad, &mut rest[NONCE_LEN..NONCE_LEN + BODY_LEN]);
    block[TAG_AT..].copy_from_slice(&tag);
    block
}

/// Visible routing fields: queue id and sealed header, for the ratchet to pick a session.
pub fn outer(block: &Block) -> (&[u8; QUEUE_ID_LEN], &[u8; HEADER_LEN]) {
    (
        block[..HEADER_AT].try_into().expect("fixed layout"),
        block[HEADER_AT..NONCE_AT].try_into().expect("fixed layout"),
    )
}

/// Opens a block with `key`. Any failure is `None`, with no detail, so the caller can drop it
/// silently.
pub fn open(block: &Block, key: &Key) -> Option<Body> {
    let nonce: &[u8; NONCE_LEN] = block[NONCE_AT..BODY_AT].try_into().ok()?;
    let tag: &[u8; TAG_LEN] = block[TAG_AT..].try_into().ok()?;
    let mut body = Zeroizing::new([0u8; BODY_LEN]);
    body.copy_from_slice(&block[BODY_AT..TAG_AT]);
    crypto::open(key, nonce, &block[..NONCE_AT], body.as_mut(), tag)?;
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const QID: [u8; QUEUE_ID_LEN] = [7; QUEUE_ID_LEN];
    const HDR: [u8; HEADER_LEN] = [9; HEADER_LEN];

    fn join(bodies: &[Body]) -> Vec<u8> {
        bodies
            .iter()
            .flat_map(|b| parse(b).unwrap().content.to_vec())
            .collect()
    }

    #[test]
    fn layout_adds_up() {
        assert_eq!(HEADER_LEN, 84);
        assert_eq!(BODY_LEN, 16244);
        assert_eq!(TAG_AT + TAG_LEN, BLOCK_LEN);
    }

    #[test]
    fn split_boundaries() {
        assert_eq!(split(Kind::Message, 1, b"").len(), 1);
        assert_eq!(split(Kind::Message, 1, &[1; MAX_CONTENT_LEN]).len(), 1);
        assert_eq!(split(Kind::Message, 1, &[1; MAX_CONTENT_LEN + 1]).len(), 2);
    }

    #[test]
    fn split_parse_roundtrip() {
        let data: Vec<u8> = (0..MAX_CONTENT_LEN * 2 + 5).map(|i| i as u8).collect();
        let bodies = split(Kind::Control, 42, &data);
        assert_eq!(bodies.len(), 3);
        let last = parse(&bodies[2]).unwrap();
        assert_eq!(
            (last.kind, last.msg_id, last.index, last.count),
            (Kind::Control, 42, 2, 3)
        );
        assert_eq!(last.content.len(), 5);
        assert_eq!(join(&bodies), data);
        assert_eq!(join(&split(Kind::Message, 0, b"")), b"");
    }

    #[test]
    fn parse_rejects_malformed() {
        let good = split(Kind::Message, 1, b"ok").remove(0);
        let mut bad_kind = good.clone();
        bad_kind[0] = 9;
        let mut bad_index = good.clone();
        bad_index[9..13].copy_from_slice(&1u32.to_be_bytes());
        let mut bad_len = good.clone();
        bad_len[17..19].copy_from_slice(&(MAX_CONTENT_LEN as u16 + 1).to_be_bytes());
        for body in [bad_kind, bad_index, bad_len] {
            assert!(parse(&body).is_none());
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = crypto::random();
        let body = split(Kind::Message, 1, b"ok").remove(0);
        let block = seal(&QID, &HDR, &key, &body);
        assert_eq!(outer(&block), (&QID, &HDR));
        assert_eq!(parse(&open(&block, &key).unwrap()).unwrap().content, b"ok");
    }

    #[test]
    fn same_input_gives_different_blocks() {
        let key = crypto::random();
        let body = split(Kind::Message, 1, b"ok").remove(0);
        assert_ne!(seal(&QID, &HDR, &key, &body), seal(&QID, &HDR, &key, &body));
    }

    #[test]
    fn any_flipped_byte_or_wrong_key_is_rejected() {
        let key = crypto::random();
        let block = seal(&QID, &HDR, &key, &split(Kind::Message, 1, b"ok")[0]);
        for at in [
            0,
            HEADER_AT,
            NONCE_AT,
            BODY_AT,
            BODY_AT + 100,
            TAG_AT,
            BLOCK_LEN - 1,
        ] {
            let mut tampered = block;
            tampered[at] ^= 1;
            assert!(open(&tampered, &key).is_none(), "flip at {at} accepted");
        }
        assert!(open(&block, &crypto::random()).is_none());
    }
}
