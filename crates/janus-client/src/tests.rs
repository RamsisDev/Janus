//! Clients over an in-memory mailbox, and the crash test that closes Phase 2 of the roadmap.

use std::cell::Cell;
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::sync::Once;
use std::{env, fs};

use janus_core::rendezvous;
use janus_transport::sim::{Net, SimLink, test_directory};
use janus_transport::{Authority, Memory, Mixnet, Node, SLOT};

use super::*;

const NOW: u64 = 1_800_000_000;
const KEY: Key = [7; 32];
/// Restarts of the crash test, nearly all of them after a crash.
const ROUNDS: usize = 2000;

thread_local! {
    /// Crash points left before the next crash; 0 never crashes.
    static CRASH_IN: Cell<u32> = const { Cell::new(0) };
}

/// Panic payload of a simulated crash.
struct Crash;

pub fn crash_point() {
    CRASH_IN.with(|left| match left.get() {
        0 => {}
        1 => {
            left.set(0);
            panic::panic_any(Crash);
        }
        n => left.set(n - 1),
    });
}

#[derive(Clone)]
struct TestPlatform {
    dir: PathBuf,
    key: Key,
    clock: Rc<Cell<u64>>,
}

impl TestPlatform {
    fn new(name: &str, clock: &Rc<Cell<u64>>) -> TestPlatform {
        let dir = env::temp_dir().join(format!("janus-client-{name}-{}", store::new_id()));
        TestPlatform {
            dir,
            key: KEY,
            clock: Rc::clone(clock),
        }
    }
}

impl Platform for TestPlatform {
    fn storage_key(&self) -> Zeroizing<Key> {
        Zeroizing::new(self.key)
    }

    fn now(&self) -> u64 {
        self.clock.get()
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.clone()
    }
}

fn message(contact: &str, text: &[u8]) -> Event {
    Event::Message {
        contact: contact.to_owned(),
        data: Zeroizing::new(text.to_vec()),
    }
}

fn texts(history: &[(bool, Zeroizing<Vec<u8>>)], mine: bool) -> Vec<Vec<u8>> {
    history
        .iter()
        .filter(|(m, _)| *m == mine)
        .map(|(_, text)| text.to_vec())
        .collect()
}

fn in_order(needles: &[Vec<u8>], haystack: &[Vec<u8>]) -> bool {
    let mut rest = haystack.iter();
    needles.iter().all(|n| rest.any(|h| h == n))
}

#[test]
fn two_clients_meet_chat_restart_and_close() {
    let clock = Rc::new(Cell::new(NOW));
    let mailbox = Memory::default();
    let (pa, pb) = (
        TestPlatform::new("a", &clock),
        TestPlatform::new("b", &clock),
    );
    let net = mailbox.network();
    let mut a = Client::open(pa.clone(), vec![mailbox.clone()]).unwrap();
    let mut b = Client::open(pb.clone(), vec![mailbox.clone()]).unwrap();

    assert!(matches!(
        a.invite(&[0; 32], Interval::H1),
        Err(Error::UnknownNetwork)
    ));
    let words = a.invite(&net, Interval::H1).unwrap();
    assert!(a.tick().unwrap().is_empty());
    b.join(&net, &words).unwrap();
    assert!(b.tick().unwrap().is_empty(), "B answers on its first tick");
    assert_eq!(a.tick().unwrap(), [Event::Answered]);
    let [
        Event::Joined {
            contact: alice,
            safety_words,
        },
    ] = &b.tick().unwrap()[..]
    else {
        panic!("B joined")
    };
    assert!(matches!(
        a.verify("abandon ability able", "bob"),
        Err(Error::Handshake(janus_core::Error::Rejected))
    ));
    let bob = a.verify(safety_words, "bob").unwrap();
    a.send(&bob, b"before confirm").unwrap();
    assert!(b.tick().unwrap().is_empty(), "nothing shown before confirm");
    assert!(matches!(b.send(alice, b"x"), Err(Error::NotConfirmed)));
    b.confirm(alice, "alice").unwrap();
    b.send(alice, b"hi").unwrap();
    assert_eq!(a.tick().unwrap(), [message(&bob, b"hi")]);

    drop((a, b));
    let wrong = TestPlatform {
        key: [8; 32],
        ..pa.clone()
    };
    assert!(Client::open(wrong, vec![mailbox.clone()]).is_err());
    let mut a = Client::open(pa.clone(), vec![mailbox.clone()]).unwrap();
    let mut b = Client::open(pb.clone(), Vec::<Memory>::new()).unwrap();
    assert!(matches!(b.send(alice, b"x"), Err(Error::UnknownNetwork)));
    b.add_transport(mailbox.clone());
    b.add_transport(mailbox.clone());
    let contact = Contact {
        id: alice.clone(),
        network: net,
        name: "alice".into(),
        confirmed: true,
        dormant: false,
    };
    assert_eq!(b.contacts(), [contact]);
    let history = b.history(alice).unwrap();
    assert_eq!(texts(&history, false), [b"before confirm"]);
    assert_eq!(texts(&history, true), [b"hi"]);
    a.send(&bob, b"after restart").unwrap();
    assert_eq!(b.tick().unwrap(), [message(alice, b"after restart")]);

    a.close(&bob).unwrap();
    assert_eq!(
        b.tick().unwrap(),
        [Event::Closed {
            contact: alice.clone()
        }]
    );
    assert!(a.contacts().is_empty() && b.contacts().is_empty());
    for dir in [&pa.dir, &pb.dir] {
        assert_eq!(fs::read_dir(dir).unwrap().count(), 0, "files left behind");
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn a_history_record_torn_by_a_crash_is_cut_off() {
    let dir = env::temp_dir().join(format!("janus-client-torn-{}", store::new_id()));
    let store = Store::open(dir.clone(), &KEY).unwrap();
    let id = store::new_id();
    let at = store.append(&id, 0, 0, true, b"one").unwrap();
    CRASH_IN.set(1);
    let torn = panic::catch_unwind(AssertUnwindSafe(|| {
        store.append(&id, 1, at, false, b"two").unwrap();
    }));
    assert!(torn.is_err_and(|p| p.is::<Crash>()));
    assert_eq!(store.scan(&id).unwrap(), (1, at));
    store.append(&id, 1, at, false, b"three").unwrap();
    let history = store.history(&id).unwrap();
    assert_eq!(texts(&history, true), [b"one"]);
    assert_eq!(texts(&history, false), [b"three"]);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn installed_networks_persist_and_a_tampered_one_is_refused() {
    let clock = Rc::new(Cell::new(NOW));
    let platform = TestPlatform::new("networks", &clock);
    let authority = Authority {
        identity: vec![1; 32],
        link: vec![2; 32],
        addresses: vec!["auth.example:30000".into()],
    };
    let profile = Network::new("test", vec![authority]).unwrap();
    assert!(networks(&platform).unwrap().is_empty());
    assert!(matches!(
        install_network(&platform, b"junk"),
        Err(Error::BadProfile)
    ));
    assert_eq!(
        install_network(&platform, &profile.to_bytes()).unwrap(),
        profile
    );
    install_network(&platform, &profile.to_bytes()).unwrap();
    assert_eq!(networks(&platform).unwrap(), [profile]);
    assert!(Client::open(platform.clone(), vec![Memory::default()]).is_ok());

    let dir = platform.dir.join("networks");
    let file = fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
    fs::rename(&file, dir.join(format!("{}.network", "00".repeat(32)))).unwrap();
    assert!(networks(&platform).is_err(), "a profile under another id");
    fs::remove_dir_all(&platform.dir).unwrap();
}

/// B's side of the crash test: fetches, opens and answers. Every block on B's queues comes
/// from A, so one that does not open means A reused a message key.
fn step_b(b: &mut Engine, id: SessionId, tb: &mut Memory, now: u64, got: &mut Vec<Vec<u8>>) {
    tb.listen(&b.queue_ids(id).unwrap());
    for block in tb.poll() {
        match b.receive(&block, now) {
            Some((_, Received::Message(m))) => got.push(m.to_vec()),
            Some((_, Received::Nothing)) => {}
            other => panic!("a block from A did not open: a reused key? {other:?}"),
        }
    }
    for (_, block) in b.outgoing(now) {
        tb.post(&block);
    }
    b.purge(now);
}

/// A is killed at a random crash point (between writing and renaming a state, mid history
/// record, before a post...) and restarted from disk, `ROUNDS` times, while both sides send,
/// rotate keys and send cover. B is a bare engine that never crashes, so it notices any key A
/// reuses. After every restart, A's history holds every message A showed and every send that
/// returned; at the end, B opened exactly the sends that returned.
#[test]
fn crashes_at_random_points_never_reuse_keys_nor_lose_accepted_messages() {
    static QUIET: Once = Once::new();
    QUIET.call_once(|| {
        let default = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if !info.payload().is::<Crash>() {
                default(info);
            }
        }));
    });
    let clock = Rc::new(Cell::new(NOW));
    let mailbox = Memory::default();
    let platform = TestPlatform::new("crash", &clock);
    let open = || Client::open(platform.clone(), vec![mailbox.clone()]).unwrap();
    let mut a = open();

    let (mut b, mut tb) = (Engine::default(), mailbox.clone());
    let net = tb.network();
    let words = a.invite(&net, Interval::H1).unwrap();
    tb.listen(&[rendezvous(&words).unwrap()]);
    let [msg1] = &tb.poll()[..] else {
        panic!("one invitation")
    };
    tb.post(&b.respond(&words, &net, msg1, NOW).unwrap());
    tb.listen(&b.pending_queues());
    assert_eq!(a.tick().unwrap(), [Event::Answered]);
    let [msg3] = &tb.poll()[..] else {
        panic!("one confirmation")
    };
    let id_b = b.finish_response(msg3, NOW).unwrap();
    b.confirm(id_b);
    let bob = a.verify(&b.safety_words(id_b).unwrap(), "bob").unwrap();

    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut below = |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let (mut sent, mut shown, mut got) = (Vec::new(), Vec::new(), Vec::new());
    let (mut b_sent, mut crashes) = (0, 0);
    for _ in 0..ROUNDS {
        CRASH_IN.set(1 + below(40) as u32);
        let run = panic::catch_unwind(AssertUnwindSafe(|| {
            for _ in 0..30 {
                let now = clock.get();
                match below(6) {
                    0 => {
                        let text = format!("a{}", sent.len()).into_bytes();
                        a.send(&bob, &text).unwrap();
                        sent.push(text);
                    }
                    1 | 2 => {
                        for event in a.tick().unwrap() {
                            if let Event::Message { data, .. } = event {
                                shown.push(data.to_vec());
                            }
                        }
                    }
                    3 => step_b(&mut b, id_b, &mut tb, now, &mut got),
                    4 => {
                        for block in b.encrypt(id_b, format!("b{b_sent}").as_bytes()).unwrap() {
                            tb.post(&block);
                        }
                        b_sent += 1;
                    }
                    _ => clock.set(now + below(1800)),
                }
            }
        }));
        CRASH_IN.set(0);
        if let Err(payload) = run {
            if !payload.is::<Crash>() {
                panic::resume_unwind(payload);
            }
            crashes += 1;
        }
        a = open();
        let history = a.history(&bob).unwrap();
        assert!(
            in_order(&shown, &texts(&history, false)),
            "a shown message was lost"
        );
        assert!(
            in_order(&sent, &texts(&history, true)),
            "a returned send was lost"
        );
    }
    assert!(crashes > ROUNDS * 3 / 4, "only {crashes} crashes");
    assert!(!shown.is_empty() && sent.len() > ROUNDS);

    for _ in 0..3 {
        a.tick().unwrap();
        step_b(&mut b, id_b, &mut tb, clock.get(), &mut got);
    }
    got.sort();
    sent.sort();
    assert_eq!(got, sent, "B opened exactly the sends that returned");
    fs::remove_dir_all(&platform.dir).unwrap();
}

type OnMixnet = Client<TestPlatform, Mixnet<SimLink>>;

const MIXNET: NetworkId = [9; 32];

fn on_mixnet(name: &str, net: &Net, clock: &Rc<Cell<u64>>) -> (OnMixnet, PathBuf) {
    let platform = TestPlatform::new(name, clock);
    let dir = platform.dir.clone();
    let transport = Mixnet::new(MIXNET, net.link(), SLOT, net.clock());
    (Client::open(platform, vec![transport]).unwrap(), dir)
}

/// Ticks A then B once, then moves both clocks one slot ahead: the app's fixed timer.
fn step(net: &Net, clock: &Cell<u64>, a: &mut OnMixnet, b: &mut OnMixnet) -> [Vec<Event>; 2] {
    let events = [a.tick().unwrap(), b.tick().unwrap()];
    net.advance(SLOT);
    clock.set(clock.get() + SLOT / 1000);
    events
}

/// Runs the invitation through the mixnet; returns B at A and A at B.
fn meet(net: &Net, clock: &Cell<u64>, a: &mut OnMixnet, b: &mut OnMixnet) -> (String, String) {
    let words = a.invite(&MIXNET, Interval::H1).unwrap();
    b.join(&MIXNET, &words).unwrap();
    let (mut answered, mut joined) = (false, None);
    for _ in 0..200 {
        let [at_a, at_b] = step(net, clock, a, b);
        answered |= at_a.contains(&Event::Answered);
        for event in at_b {
            if let Event::Joined {
                contact,
                safety_words,
            } = event
            {
                joined = Some((contact, safety_words));
            }
        }
        if answered && joined.is_some() {
            break;
        }
    }
    let (alice, safety_words) = joined.expect("B joined");
    let bob = a.verify(&safety_words, "bob").unwrap();
    b.confirm(&alice, "alice").unwrap();
    (bob, alice)
}

/// Steps until B (or A) shows `text`; false after `slots`.
fn arrives(
    (net, clock): (&Net, &Cell<u64>),
    a: &mut OnMixnet,
    b: &mut OnMixnet,
    (to_b, text): (bool, &[u8]),
    slots: usize,
) -> bool {
    (0..slots).any(|_| {
        step(net, clock, a, b)[usize::from(to_b)]
            .iter()
            .any(|e| matches!(e, Event::Message { data, .. } if data.as_slice() == text))
    })
}

/// "A packet capture at the client shows the same traffic whether the user writes or not", from
/// Phase 3 of the roadmap, on the simulated mixnet.
#[test]
fn the_traffic_of_a_client_is_the_same_whether_its_user_writes_or_not() {
    let timeline = |talk: bool| {
        let net = Net::new(test_directory());
        let clock = Rc::new(Cell::new(NOW));
        let (mut a, dir_a) = on_mixnet("talk-a", &net, &clock);
        let (mut b, dir_b) = on_mixnet("talk-b", &net, &clock);
        let (bob, _) = meet(&net, &clock, &mut a, &mut b);
        let start = net.clock()();
        let skip = net.capture().lock().unwrap().len();
        let mut shown = 0;
        for i in 0..150 {
            if talk && i % 10 == 0 {
                a.send(&bob, b"are you there?").unwrap();
            }
            let [_, at_b] = step(&net, &clock, &mut a, &mut b);
            shown += at_b.len();
        }
        for dir in [dir_a, dir_b] {
            fs::remove_dir_all(dir).unwrap();
        }
        let capture = net.capture();
        let sent: Vec<(u64, usize)> = capture.lock().unwrap()[skip..]
            .iter()
            .map(|s| (s.at - start, s.link))
            .collect();
        (sent, shown)
    };
    let (talking, shown) = timeline(true);
    let (quiet, none) = timeline(false);
    assert!(shown >= 10, "only {shown} of 15 messages arrived");
    assert_eq!(none, 0);
    assert_eq!(talking.len(), 2 * 150, "one packet per slot and client");
    assert_eq!(talking, quiet);
}

/// "The chaos test (one node killed at a time) never stops a conversation", from Phase 3 of the
/// roadmap, on the simulated mixnet. Around a dead gateway, clients fail over before the
/// directory drops it. A dead mix loses the packets whose path crosses it, which no client can
/// tell apart, so what was sent meanwhile arrives once the directory drops it and lost puts are
/// sent again. A dead mailbox loses what it held, and its queues move to the others. A revived
/// node comes back in the next directory.
#[test]
fn killing_one_node_at_a_time_never_stops_a_conversation() {
    let dir = test_directory();
    let names = |nodes: &mut dyn Iterator<Item = &Node>| -> Vec<String> {
        nodes.map(|n| n.name.clone()).collect()
    };
    let gateways = names(&mut dir.gateways.iter());
    let mixes = names(&mut dir.layers.iter().flatten());
    let mailboxes = names(&mut dir.mailboxes.iter());
    let names = [&gateways[..], &mixes, &mailboxes].concat();
    const WAIT: usize = 300;
    let net = Net::new(dir);
    let clock = Rc::new(Cell::new(NOW));
    let (mut a, dir_a) = on_mixnet("chaos-a", &net, &clock);
    let (mut b, dir_b) = on_mixnet("chaos-b", &net, &clock);
    let (bob, alice) = meet(&net, &clock, &mut a, &mut b);
    for name in &names {
        net.kill(name);
        let down = format!("while {name} is down");
        a.send(&bob, down.as_bytes()).unwrap();
        let wait = if gateways.contains(name) { WAIT } else { 20 };
        let early = arrives(
            (&net, &clock),
            &mut a,
            &mut b,
            (true, down.as_bytes()),
            wait,
        );
        assert!(early || !gateways.contains(name), "{down}");
        net.publish();
        if mixes.contains(name) && !early {
            let late = arrives(
                (&net, &clock),
                &mut a,
                &mut b,
                (true, down.as_bytes()),
                WAIT,
            );
            assert!(late, "{down}");
        }
        let to_b = format!("to bob, {name} gone");
        a.send(&bob, to_b.as_bytes()).unwrap();
        let got = arrives(
            (&net, &clock),
            &mut a,
            &mut b,
            (true, to_b.as_bytes()),
            WAIT,
        );
        assert!(got, "{to_b}");
        let to_a = format!("to alice, {name} gone");
        b.send(&alice, to_a.as_bytes()).unwrap();
        let got = arrives(
            (&net, &clock),
            &mut a,
            &mut b,
            (false, to_a.as_bytes()),
            WAIT,
        );
        assert!(got, "{to_a}");
        net.revive(name);
        net.publish();
    }
    for dir in [dir_a, dir_b] {
        fs::remove_dir_all(dir).unwrap();
    }
}
