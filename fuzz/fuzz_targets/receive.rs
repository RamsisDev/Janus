//! `Engine::receive` on blocks from the peer and from an attacker.
//!
//! Each step is one of: a body the peer seals (frame parsing, reassembly, control frames),
//! raw bytes on one of the session's queues (routing and header checks), or a genuine block
//! with bytes flipped. Genuine blocks must always open, and anything else never.

#![no_main]

use janus_core::fuzz::{KEY, Pair};
use janus_core::{BLOCK_LEN, Block, Engine, Received};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|steps: Vec<(u8, Vec<u8>)>| {
    let mut pair = Pair::connect();
    for (kind, bytes) in steps {
        let (block, genuine) = match kind % 3 {
            0 => (pair.seal(&bytes), true),
            1 => (raw(&pair, &bytes), false),
            _ => {
                let mut block = pair.seal(b"");
                for (at, flip) in bytes.iter().enumerate() {
                    block[at % BLOCK_LEN] ^= flip;
                }
                (block, bytes.iter().all(|&b| b == 0))
            }
        };
        match pair.engine.receive(&block, 0) {
            Some((_, Received::Closed)) => return,
            received => assert_eq!(received.is_some(), genuine, "kind {kind}"),
        }
    }
    let export = pair.engine.export(pair.id, &KEY).unwrap();
    assert!(Engine::default().import(&export, &KEY).is_some());
});

/// `bytes` after one of the session's queue ids, picked by the first byte.
fn raw(pair: &Pair, bytes: &[u8]) -> Block {
    let queues = pair.engine.queue_ids(pair.id).unwrap();
    let (pick, rest) = bytes.split_first().unwrap_or((&0, &[]));
    let mut block = [0u8; BLOCK_LEN];
    block[..16].copy_from_slice(&queues[usize::from(*pick) % queues.len()]);
    let len = rest.len().min(BLOCK_LEN - 16);
    block[16..16 + len].copy_from_slice(&rest[..len]);
    block
}
