//! Two engines talking through the public API only.

use janus_core::{
    BLOCK_LEN, Block, Engine, Error, Interval, Key, MAX_ANSWERS, MAX_REPLIES, MAX_SILENCE,
    NetworkId, Received, SessionId, rendezvous,
};

const WORDS: &str = "alpha cable echo forest orbit velvet";
const WRONG: &str = "alpha cable echo forest orbit zoo";
const NOW: u64 = 1_800_000_000;
const NET: NetworkId = [1; 32];
const DAY: u64 = 24 * 3600;
const KEY: Key = [7; 32];

fn connect(a: &mut Engine, b: &mut Engine) -> (SessionId, SessionId) {
    let msg1 = a.invite(WORDS, &NET, Interval::H1, NOW).unwrap();
    let msg2 = b.respond(WORDS, &NET, &msg1, NOW).unwrap();
    finish(a, b, &msg2)
}

/// A sends msg3, B shows its safety words, A types them and B confirms.
fn finish(a: &mut Engine, b: &mut Engine, msg2: &Block) -> (SessionId, SessionId) {
    let msg3 = a.finish_invite(msg2, NOW).unwrap();
    let id_b = b.finish_response(&msg3, NOW).unwrap();
    let id_a = a.verify(&b.safety_words(id_b).unwrap(), NOW).unwrap();
    assert!(b.confirm(id_b));
    (id_a, id_b)
}

fn send(from: &mut Engine, id: SessionId, to: &mut Engine, to_id: SessionId, data: &[u8]) {
    let mut blocks = from.encrypt(id, data).unwrap();
    let listening = to.queue_ids(to_id).unwrap();
    assert!(
        blocks
            .iter()
            .all(|b| listening.contains(&b[..16].try_into().unwrap()))
    );
    let last = blocks.pop().unwrap();
    for block in blocks.iter().rev() {
        assert_eq!(to.receive(block, NOW), Some((to_id, Received::Nothing)));
    }
    let (got_id, received) = to.receive(&last, NOW).unwrap();
    assert_eq!(got_id, to_id);
    assert_eq!(received, Received::Message(data.to_vec().into()));
}

#[test]
fn conversation_rotation_persistence_and_drops() {
    let (mut a, mut b) = (Engine::default(), Engine::default());
    let (id_a, mut id_b) = connect(&mut a, &mut b);

    send(&mut a, id_a, &mut b, id_b, b"hello");
    send(&mut b, id_b, &mut a, id_a, b"hi");
    let big: Vec<u8> = (0..BLOCK_LEN as u32 * 4).map(|i| i as u8).collect();
    assert!(a.encrypt(id_a, &big).unwrap().len() > 3);
    send(&mut a, id_a, &mut b, id_b, &big);
    send(&mut b, id_b, &mut a, id_a, &big);

    let later = NOW + Interval::H1.secs();
    let mut controls = 0;
    for _ in 0..5 {
        let out_a = a.outgoing(later);
        for (_, block) in &out_a {
            assert_eq!(b.receive(block, later), Some((id_b, Received::Nothing)));
        }
        let out_b = b.outgoing(later);
        for (_, block) in &out_b {
            assert_eq!(a.receive(block, later), Some((id_a, Received::Nothing)));
        }
        if out_a.is_empty() && out_b.is_empty() {
            break;
        }
        controls += out_a.len() + out_b.len();
    }
    assert_eq!(controls, 3, "expected Rekey, RekeyReply and Ack only");
    assert!(a.outgoing(later).is_empty() && b.outgoing(later).is_empty());
    send(&mut a, id_a, &mut b, id_b, b"rotated");
    send(&mut b, id_b, &mut a, id_a, b"too");

    let blocks = a.encrypt(id_a, &big).unwrap();
    assert_eq!(b.receive(&blocks[0], NOW), Some((id_b, Received::Nothing)));
    let saved = b.export(id_b, &KEY).unwrap();
    assert!(b.import(&saved, &[1; 32]).is_none());
    b = Engine::default();
    id_b = b.import(&saved, &KEY).unwrap();
    for block in &blocks[1..blocks.len() - 1] {
        assert_eq!(b.receive(block, NOW), Some((id_b, Received::Nothing)));
    }
    let (_, received) = b.receive(blocks.last().unwrap(), NOW).unwrap();
    assert_eq!(received, Received::Message(big.clone().into()));
    send(&mut b, id_b, &mut a, id_a, b"restored");
    send(&mut a, id_a, &mut b, id_b, b"welcome back");

    let mut noise: Block = [0; BLOCK_LEN];
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    for byte in &mut noise {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *byte = x as u8;
    }
    assert!(b.receive(&noise, NOW).is_none());
    let (mut c, mut d) = (Engine::default(), Engine::default());
    let (id_c, id_d) = connect(&mut c, &mut d);
    let foreign = c.encrypt(id_c, b"not for b").unwrap();
    assert!(b.receive(&foreign[0], NOW).is_none());
    assert_eq!(d.receive(&foreign[0], NOW).unwrap().0, id_d);
}

#[test]
fn cover_is_dropped_and_close_ends_both_sides() {
    let (mut a, mut b) = (Engine::default(), Engine::default());
    let (id_a, id_b) = connect(&mut a, &mut b);

    let cover = a.cover(id_a).unwrap();
    assert_eq!(b.receive(&cover, NOW), Some((id_b, Received::Nothing)));
    send(&mut a, id_a, &mut b, id_b, b"real");
    let late = b.encrypt(id_b, b"in flight").unwrap();

    let close = a.close(id_a).unwrap();
    assert!(a.encrypt(id_a, b"x").is_none() && a.close(id_a).is_none());
    assert!(a.receive(&late[0], NOW).is_none());
    assert_eq!(b.receive(&close, NOW), Some((id_b, Received::Closed)));
    assert!(b.receive(&close, NOW).is_none());
    assert!(b.encrypt(id_b, b"x").is_none() && b.cover(id_b).is_none());
}

#[test]
fn a_year_of_silence_puts_the_session_to_sleep_until_the_peer_writes() {
    let (mut a, mut b) = (Engine::default(), Engine::default());
    let (id_a, id_b) = connect(&mut a, &mut b);
    let block = b.encrypt(id_b, b"still here").unwrap().remove(0);
    assert!(
        a.dormant(NOW + 2 * MAX_SILENCE).is_empty(),
        "one clock jump puts nothing to sleep"
    );
    let mut t = NOW + 2 * MAX_SILENCE;
    while a.dormant(t + DAY).is_empty() {
        t += DAY;
        a.outgoing(t);
    }
    t += DAY;
    assert_eq!(a.dormant(t), [id_a]);
    assert!(a.outgoing(t).is_empty() && a.export(id_a, &KEY).is_some());

    let (_, woke) = a.receive(&block, t).unwrap();
    assert_eq!(woke, Received::Message(b"still here".to_vec().into()));
    assert!(a.dormant(t).is_empty() && !a.outgoing(t).is_empty());
    send(&mut a, id_a, &mut b, id_b, b"welcome back");
}

/// The network drops one block and lets the next through. The withheld block's key must be
/// gone from the export by the time the device can be seized, whatever clock the seizer uses.
#[test]
fn a_withheld_block_cannot_be_opened_from_a_later_export() {
    let (mut a, mut b) = (Engine::default(), Engine::default());
    let (id_a, id_b) = connect(&mut a, &mut b);
    let withheld = a
        .encrypt(id_a, b"meet at the safe house")
        .unwrap()
        .remove(0);
    send(&mut a, id_a, &mut b, id_b, b"ok?");

    let early = b.export(id_b, &KEY).unwrap();
    assert!(b.purge(NOW + DAY - 1).is_empty());
    assert_eq!(b.purge(NOW + DAY), [id_b]);
    let late = b.export(id_b, &KEY).unwrap();
    for (export, opens) in [(early, true), (late, false)] {
        let mut seizer = Engine::default();
        seizer.import(&export, &KEY).unwrap();
        assert_eq!(seizer.receive(&withheld, NOW).is_some(), opens);
    }
    send(&mut a, id_a, &mut b, id_b, b"still talking");
}

#[test]
fn handshake_travels_as_blocks_on_the_named_queues() {
    let (mut a, mut b) = (Engine::default(), Engine::default());
    let msg1 = a.invite(WORDS, &NET, Interval::H1, NOW).unwrap();
    assert_eq!(msg1[..16], rendezvous(WORDS).unwrap());
    let msg2 = b.respond(WORDS, &NET, &msg1, NOW).unwrap();
    assert_eq!(a.pending_queues().concat(), msg2[..16]);
    let msg3 = a.finish_invite(&msg2, NOW).unwrap();
    assert_eq!(b.pending_queues().concat(), msg3[..16]);
    let id_b = b.finish_response(&msg3, NOW).unwrap();
    assert!(a.pending_queues().is_empty() && b.pending_queues().is_empty());
    let id_a = a.verify(&b.safety_words(id_b).unwrap(), NOW).unwrap();
    assert!(b.confirm(id_b));
    for block in [&msg1, &msg2, &msg3] {
        assert!(a.receive(block, NOW).is_none() && b.receive(block, NOW).is_none());
    }
    send(&mut a, id_a, &mut b, id_b, b"first");
    send(&mut b, id_b, &mut a, id_a, b"reply");
}

/// An attacker sees the public rendezvous queue, so it can answer `msg1` with a guess.
fn guess(msg1: &Block) -> Block {
    let mut seen = *msg1;
    seen[..16].copy_from_slice(&rendezvous(WRONG).unwrap());
    Engine::default().respond(WRONG, &NET, &seen, NOW).unwrap()
}

#[test]
fn third_party_answers_cannot_break_the_handshake() {
    let (mut a, mut b) = (Engine::default(), Engine::default());
    let msg1 = a.invite(WORDS, &NET, Interval::H5, NOW).unwrap();
    assert_eq!(
        b.respond(WRONG, &NET, &msg1, NOW).err(),
        Some(Error::Rejected)
    );
    assert_eq!(
        a.finish_invite(&guess(&msg1), NOW).err(),
        Some(Error::Rejected)
    );

    let msg2 = b.respond(WORDS, &NET, &msg1, NOW).unwrap();
    let msg3 = a.finish_invite(&msg2, NOW).unwrap();
    let mut forged = msg3;
    forged[16] ^= 1;
    assert_eq!(b.finish_response(&forged, NOW).err(), Some(Error::Rejected));
    let id_b = b.finish_response(&msg3, NOW).unwrap();
    let id_a = a.verify(&b.safety_words(id_b).unwrap(), NOW).unwrap();
    assert!(b.confirm(id_b));
    send(&mut a, id_a, &mut b, id_b, b"still just us");
}

#[test]
fn an_invitation_completes_only_on_its_own_network() {
    let (mut a, mut b) = (Engine::default(), Engine::default());
    let msg1 = a.invite(WORDS, &NET, Interval::H1, NOW).unwrap();
    let elsewhere = b.respond(WORDS, &[2; 32], &msg1, NOW).unwrap();
    assert_eq!(
        a.finish_invite(&elsewhere, NOW).err(),
        Some(Error::Rejected)
    );
    let msg2 = Engine::default().respond(WORDS, &NET, &msg1, NOW).unwrap();
    assert!(
        a.finish_invite(&msg2, NOW).is_ok(),
        "the invitation survives"
    );
}

#[test]
fn only_the_safety_words_b_shows_open_a_and_b_sends_only_once_confirmed() {
    let (mut a, mut b) = (Engine::default(), Engine::default());
    let msg1 = a.invite(WORDS, &NET, Interval::H1, NOW).unwrap();
    let msg2 = b.respond(WORDS, &NET, &msg1, NOW).unwrap();
    let msg3 = a.finish_invite(&msg2, NOW).unwrap();
    let id_b = b.finish_response(&msg3, NOW).unwrap();
    let shown = b.safety_words(id_b).unwrap();
    assert_eq!(shown.split(' ').count(), 3);
    assert!(b.encrypt(id_b, b"too early").is_none() && b.cover(id_b).is_none());

    assert_eq!(
        a.verify("abandon ability able", NOW).err(),
        Some(Error::Rejected)
    );
    let id_a = a
        .verify(&format!(" {} ", shown.to_uppercase()), NOW)
        .unwrap();
    assert_eq!(a.safety_words(id_a), Some(shown.clone()));
    send(&mut a, id_a, &mut b, id_b, b"you can talk now");
    assert!(b.confirm(id_b));
    send(&mut b, id_b, &mut a, id_a, b"thanks");

    let mut restored = Engine::default();
    let id = restored
        .import(&b.export(id_b, &KEY).unwrap(), &KEY)
        .unwrap();
    assert_eq!(restored.safety_words(id), Some(shown));
    assert!(restored.encrypt(id, b"still confirmed").is_some());

    let msg1 = a.invite(WORDS, &NET, Interval::H1, NOW).unwrap();
    let msg2 = Engine::default().respond(WORDS, &NET, &msg1, NOW).unwrap();
    a.finish_invite(&msg2, NOW).unwrap();
    assert_eq!(a.verify("any words", NOW + 601).err(), Some(Error::Expired));
    assert_eq!(a.verify("any words", NOW).err(), Some(Error::Rejected));
}

#[test]
fn b_answers_every_invitation_on_its_queue() {
    let (mut a, mut b, mut stranger) = (Engine::default(), Engine::default(), Engine::default());
    // An unrelated invitation that landed on the same rendezvous queue.
    let mut foreign = stranger.invite(WRONG, &NET, Interval::H1, NOW).unwrap();
    foreign[..16].copy_from_slice(&rendezvous(WORDS).unwrap());
    let msg1 = a.invite(WORDS, &NET, Interval::H1, NOW).unwrap();
    let wasted = b.respond(WORDS, &NET, &foreign, NOW).unwrap();
    let msg2 = b.respond(WORDS, &NET, &msg1, NOW).unwrap();
    assert_eq!(b.pending_queues().len(), 2);
    assert_eq!(
        stranger.finish_invite(&wasted, NOW).err(),
        Some(Error::Rejected)
    );
    let (id_a, id_b) = finish(&mut a, &mut b, &msg2);
    assert!(b.pending_queues().is_empty());
    send(&mut b, id_b, &mut a, id_a, b"found you");

    let invites: Vec<Block> = (0..=MAX_REPLIES)
        .map(|_| {
            Engine::default()
                .invite(WORDS, &NET, Interval::H1, NOW)
                .unwrap()
        })
        .collect();
    for msg1 in &invites[..MAX_REPLIES] {
        assert!(b.respond(WORDS, &NET, msg1, NOW).is_ok());
    }
    let last = &invites[MAX_REPLIES];
    assert_eq!(
        b.respond(WORDS, &NET, last, NOW).err(),
        Some(Error::Rejected)
    );
    assert!(
        b.respond(WORDS, &NET, last, NOW + 601).is_ok(),
        "expired replies free their slots"
    );
}

#[test]
fn an_invitation_dies_after_max_answers_or_expiry() {
    let mut a = Engine::default();
    let msg1 = a.invite(WORDS, &NET, Interval::H5, NOW).unwrap();
    let bad = guess(&msg1);
    for _ in 0..MAX_ANSWERS {
        assert!(!a.pending_queues().is_empty());
        assert_eq!(a.finish_invite(&bad, NOW).err(), Some(Error::Rejected));
    }
    assert!(a.pending_queues().is_empty());
    let good = Engine::default().respond(WORDS, &NET, &msg1, NOW).unwrap();
    assert_eq!(a.finish_invite(&good, NOW).err(), Some(Error::Rejected));

    let msg1 = a.invite(WORDS, &NET, Interval::H5, NOW).unwrap();
    let good = Engine::default().respond(WORDS, &NET, &msg1, NOW).unwrap();
    assert_eq!(
        a.finish_invite(&good, NOW + 601).err(),
        Some(Error::Expired)
    );
    assert!(a.pending_queues().is_empty());

    let msg1 = a.invite(WORDS, &NET, Interval::H5, NOW).unwrap();
    let mut b = Engine::default();
    let msg2 = b.respond(WORDS, &NET, &msg1, 42).unwrap();
    let msg3 = a.finish_invite(&msg2, NOW).unwrap();
    assert_eq!(
        b.finish_response(&msg3, 42 + 601).err(),
        Some(Error::Expired)
    );
    assert!(
        b.pending_queues().is_empty(),
        "B's reply dies on B's own clock"
    );
}

#[test]
fn new_invite_invalidates_the_previous() {
    for use_old in [true, false] {
        let (mut a, mut b) = (Engine::default(), Engine::default());
        let old = a.invite(WORDS, &NET, Interval::H10, NOW).unwrap();
        let new = a.invite(WORDS, &NET, Interval::H10, NOW).unwrap();
        let typo = a.invite("alpha bravo", &NET, Interval::H10, NOW);
        assert_eq!(
            typo.err(),
            Some(Error::BadWords),
            "a failed attempt kills nothing"
        );
        let msg2 = b
            .respond(WORDS, &NET, if use_old { &old } else { &new }, NOW)
            .unwrap();
        assert_eq!(a.finish_invite(&msg2, NOW).is_ok(), !use_old);
    }
}
