//! `Engine::import` on session state plaintexts, sealed under the right key so they reach the
//! parser. The first byte picks raw bytes or a real export with bytes flipped. Whatever
//! imports must export again, and that export must be stable.

#![no_main]

use janus_core::Engine;
use janus_core::fuzz::{KEY, Pair, open_state, seal_state};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, data)) = data.split_first() else {
        return;
    };
    let plain = if mode % 2 == 0 {
        data.to_vec()
    } else {
        let pair = Pair::connect();
        let mut plain = open_state(&pair.engine.export(pair.id, &KEY).unwrap()).unwrap();
        let len = plain.len();
        for (at, flip) in data.iter().enumerate() {
            plain[at % len] ^= flip;
        }
        plain
    };
    let mut engine = Engine::default();
    let Some(id) = engine.import(&seal_state(&plain), &KEY) else {
        return;
    };
    let first = open_state(&engine.export(id, &KEY).unwrap()).unwrap();
    let mut again = Engine::default();
    let id = again
        .import(&seal_state(&first), &KEY)
        .expect("an export always imports");
    let second = open_state(&again.export(id, &KEY).unwrap()).unwrap();
    assert_eq!(first, second, "export not stable across import");
});
