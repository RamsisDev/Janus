//! The handshake parsers: msg1 as B, msg2 as A, msg3 as B, and the invitation words. The
//! first byte picks which. msg2 and msg3 are never genuine here, so they must be rejected.

#![no_main]

use janus_core::{BLOCK_LEN, Engine, Interval, NetworkId, rendezvous};
use libfuzzer_sys::fuzz_target;

const WORDS: &str = "alpha cable echo forest orbit velvet";
const NET: NetworkId = [0; 32];

fuzz_target!(|data: &[u8]| {
    let Some((&step, msg)) = data.split_first() else {
        return;
    };
    let mut block = [0u8; BLOCK_LEN];
    let len = msg.len().min(BLOCK_LEN - 16);
    block[16..16 + len].copy_from_slice(&msg[..len]);
    let (mut a, mut b) = (Engine::default(), Engine::default());
    match step % 4 {
        0 => {
            block[..16].copy_from_slice(&rendezvous(WORDS).unwrap());
            let _ = b.respond(WORDS, &NET, &block, 0);
        }
        1 => {
            a.invite(WORDS, &NET, Interval::H1, 0).unwrap();
            block[..16].copy_from_slice(&a.pending_queues()[0]);
            assert!(a.finish_invite(&block, 0).is_err(), "forged msg2 accepted");
        }
        2 => {
            let msg1 = a.invite(WORDS, &NET, Interval::H1, 0).unwrap();
            b.respond(WORDS, &NET, &msg1, 0).unwrap();
            block[..16].copy_from_slice(&b.pending_queues()[0]);
            assert!(
                b.finish_response(&block, 0).is_err(),
                "forged msg3 accepted"
            );
        }
        _ => {
            let _ = rendezvous(&String::from_utf8_lossy(msg));
        }
    }
});
