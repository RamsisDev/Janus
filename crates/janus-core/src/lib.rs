//! Core of a peer-to-peer privacy engine.
//!
//! The core only turns plaintext into fixed-size encrypted blocks and back; there is no
//! unencrypted path out of it, and handshake messages are blocks too. [`Engine`] is the whole
//! surface: invitations (`invite`, `respond`, `finish_invite`, `finish_response`), `encrypt`
//! into blocks, `receive` blocks into messages, `outgoing` control blocks (forced key rotation),
//! `cover` decoys, `close` to end a session on both sides, and encrypted `export`/`import` of
//! each session. [`words`] draws the secret of a new invitation and `safety_words` lets both
//! sides check nobody sat in the middle. [`rendezvous`], `pending_queues` and `queue_ids` name
//! the queues a client listens on, `dormant` names sessions whose peer
//! went silent for [`MAX_SILENCE`], and `purge` drops expired skipped message keys.
//!
//! Time is passed in as seconds and only differences on the same device matter: no time
//! travels on the wire and no two clocks are compared. Pass a monotonic clock that keeps counting
//! while the device sleeps (`mach_continuous_time` on Apple, `CLOCK_BOOTTIME` on Linux and
//! Android), never the wall clock: the network can forge the wall clock (NTP, cell towers), not
//! this one. A reset at boot counts as no time passing.

mod block;
mod crypto;
mod handshake;
mod ratchet;
mod session;

pub use block::{BLOCK_LEN, Block, QueueId};
pub use crypto::Key;
pub use handshake::{
    Error, INVITE_TTL, Interval, MSG1_LEN, MSG2_LEN, MSG3_LEN, NetworkId, rendezvous, words,
};
#[cfg(fuzzing)]
pub use session::fuzz;
pub use session::{Engine, MAX_ANSWERS, MAX_REPLIES, MAX_SILENCE, Received, SessionId};
