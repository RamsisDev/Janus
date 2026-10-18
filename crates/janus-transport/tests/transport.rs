//! Two engines talking through each transport, with a real TLS mailbox for `Direct`.

use std::net::TcpListener;
use std::thread;

use janus_core::{BLOCK_LEN, Engine, Interval, NetworkId, Received, SessionId, rendezvous};
use janus_transport::{Direct, Memory, Transport};

const WORDS: &str = "alpha cable echo forest orbit velvet";
const NOW: u64 = 1_800_000_000;
const NET: NetworkId = [0; 32];

/// A mailbox server on a free local port: its address and certificate.
fn mailbox() -> (String, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (cert, key) = janus_mailbox::self_signed();
    let der = cert.to_vec();
    thread::spawn(move || janus_mailbox::serve(listener, cert, key));
    (addr, der)
}

/// A invites before B even listens, so the mailbox must keep msg1 until B fetches it.
fn connect(
    a: &mut Engine,
    ta: &mut impl Transport,
    b: &mut Engine,
    tb: &mut impl Transport,
) -> (SessionId, SessionId) {
    ta.post(&a.invite(WORDS, &NET, Interval::H1, NOW).unwrap());
    ta.listen(&a.pending_queues());
    tb.listen(&[rendezvous(WORDS).unwrap()]);
    let [msg1] = &tb.poll()[..] else {
        panic!("one invitation")
    };
    tb.post(&b.respond(WORDS, &NET, msg1, NOW).unwrap());
    tb.listen(&b.pending_queues());
    let [msg2] = &ta.poll()[..] else {
        panic!("one answer")
    };
    ta.post(&a.finish_invite(msg2, NOW).unwrap());
    let [msg3] = &tb.poll()[..] else {
        panic!("one confirmation")
    };
    let id_b = b.finish_response(msg3, NOW).unwrap();
    let id_a = a.verify(&b.safety_words(id_b).unwrap(), NOW).unwrap();
    assert!(b.confirm(id_b));
    (id_a, id_b)
}

fn send(from: &mut Engine, id: SessionId, t: &mut impl Transport, data: &[u8]) {
    for block in from.encrypt(id, data).unwrap() {
        t.post(&block);
    }
}

fn receive(to: &mut Engine, id: SessionId, t: &mut impl Transport) -> Vec<Vec<u8>> {
    t.listen(&to.queue_ids(id).unwrap());
    t.poll()
        .iter()
        .filter_map(|block| match to.receive(block, NOW) {
            Some((got, Received::Message(m))) if got == id => Some(m.to_vec()),
            _ => None,
        })
        .collect()
}

fn chat(ta: &mut impl Transport, tb: &mut impl Transport) {
    let (mut a, mut b) = (Engine::default(), Engine::default());
    let (id_a, id_b) = connect(&mut a, ta, &mut b, tb);
    let big: Vec<u8> = (0..BLOCK_LEN as u32 * 3).map(|i| i as u8).collect();
    send(&mut a, id_a, ta, b"hello");
    send(&mut a, id_a, ta, &big);
    assert_eq!(receive(&mut b, id_b, tb), [b"hello".to_vec(), big]);
    send(&mut b, id_b, tb, b"hi");
    assert_eq!(receive(&mut a, id_a, ta), [b"hi".to_vec()]);
    assert!(
        receive(&mut a, id_a, ta).is_empty(),
        "fetched blocks are deleted"
    );
}

#[test]
fn chat_over_memory() {
    let mailbox = Memory::default();
    chat(&mut mailbox.clone(), &mut mailbox.clone());
}

#[test]
fn chat_over_direct() {
    let (addr, cert) = mailbox();
    chat(
        &mut Direct::new(&addr, &cert).unwrap(),
        &mut Direct::new(&addr, &cert).unwrap(),
    );
}

#[test]
fn offline_client_gets_its_messages_when_it_comes_back() {
    let (addr, cert) = mailbox();
    let (mut a, mut b) = (Engine::default(), Engine::default());
    let mut ta = Direct::new(&addr, &cert).unwrap();
    let mut tb = Direct::new(&addr, &cert).unwrap();
    let (id_a, id_b) = connect(&mut a, &mut ta, &mut b, &mut tb);
    drop(tb);

    send(&mut a, id_a, &mut ta, b"while you were away");
    send(&mut a, id_a, &mut ta, b"and this too");
    let mut tb = Direct::new(&addr, &cert).unwrap();
    assert_eq!(
        receive(&mut b, id_b, &mut tb),
        [b"while you were away".to_vec(), b"and this too".to_vec()]
    );
}

#[test]
fn direct_refuses_a_mailbox_with_another_certificate() {
    let (addr, cert) = mailbox();
    let (impostor, _) = janus_mailbox::self_signed();
    let mut wrong = Direct::new(&addr, &impostor).unwrap();
    wrong.post(&[7; BLOCK_LEN]);
    assert!(!wrong.connected());

    let mut right = Direct::new(&addr, &cert).unwrap();
    right.listen(&[[7; 16]]);
    assert!(right.poll().is_empty() && right.connected());
}
