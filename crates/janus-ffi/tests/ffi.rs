//! Two apps on the binding layer, with the platform implemented in Rust as Swift or Kotlin would.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, thread};

use janus_ffi::{Client, DevMailbox, Event, HistoryEntry, JanusError, Platform, read_network};
use janus_transport::{Authority, Network};

struct App {
    dir: String,
    key: Vec<u8>,
}

impl Platform for App {
    fn storage_key(&self) -> Vec<u8> {
        self.key.clone()
    }

    fn now_ms(&self) -> u64 {
        1_800_000_000_000
    }

    fn data_dir(&self) -> String {
        self.dir.clone()
    }
}

fn app(name: &str, key: Vec<u8>) -> Arc<App> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("janus-ffi-{name}-{nanos}"));
    Arc::new(App {
        dir: dir.to_string_lossy().into_owned(),
        key,
    })
}

#[test]
fn two_apps_meet_and_chat_through_a_mailbox() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (cert, key) = janus_mailbox::self_signed();
    let der = cert.to_vec();
    thread::spawn(move || janus_mailbox::serve(listener, cert, key));
    let mailbox = || {
        Some(DevMailbox {
            address: address.clone(),
            cert: der.clone(),
        })
    };

    let bad = Client::new(app("bad", vec![1; 31]), mailbox());
    assert!(matches!(bad, Err(JanusError::BadKey)));
    let (pa, pb) = (app("a", vec![1; 32]), app("b", vec![2; 32]));
    let a = Client::new(pa.clone(), mailbox()).unwrap();
    let b = Client::new(pb.clone(), mailbox()).unwrap();
    let [dev] = &a.networks()[..] else {
        panic!("only the development mailbox")
    };
    assert_eq!(b.networks(), std::slice::from_ref(dev));
    let net = dev.id.clone();

    assert!(matches!(
        a.invite("00".repeat(32), 1),
        Err(JanusError::UnknownNetwork)
    ));
    assert!(matches!(
        a.invite(net.clone(), 2),
        Err(JanusError::BadInterval)
    ));
    let words = a.invite(net.clone(), 1).unwrap();
    b.join(net.clone(), words).unwrap();
    b.tick().unwrap();
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
    let bob = a.verify(safety_words.clone(), "bob".into()).unwrap();
    b.confirm(alice.clone(), "alice".into()).unwrap();
    b.send(alice.clone(), b"hola".to_vec()).unwrap();
    assert_eq!(
        a.tick().unwrap(),
        [Event::Message {
            contact: bob.clone(),
            data: b"hola".to_vec()
        }]
    );
    assert_eq!(a.contacts()[0].name, "bob");
    assert_eq!(a.contacts()[0].network, net);
    assert_eq!(
        a.history(bob).unwrap(),
        [HistoryEntry {
            mine: false,
            data: b"hola".to_vec()
        }]
    );
    for p in [pa, pb] {
        fs::remove_dir_all(&p.dir).unwrap();
    }
}

#[test]
fn an_installed_network_is_read_first_and_kept_across_restarts() {
    let authority = Authority {
        identity: vec![1; 32],
        link: vec![2; 32],
        addresses: vec!["127.0.0.1:1".into()],
    };
    let profile = Network::new("community", vec![authority])
        .unwrap()
        .to_bytes();
    assert!(matches!(
        read_network(b"junk".to_vec()),
        Err(JanusError::BadProfile)
    ));
    let read = read_network(profile.clone()).unwrap();
    assert_eq!(read.name, "community");

    let p = app("install", vec![3; 32]);
    let client = Client::new(p.clone(), None).unwrap();
    assert!(client.networks().is_empty());
    assert!(matches!(
        client.install_network(b"junk".to_vec()),
        Err(JanusError::BadProfile)
    ));
    assert_eq!(client.install_network(profile.clone()).unwrap(), read);
    client.install_network(profile).unwrap();
    assert_eq!(client.networks(), std::slice::from_ref(&read));
    client.invite(read.id.clone(), 1).unwrap();
    client.tick().unwrap();
    drop(client);
    assert_eq!(Client::new(p.clone(), None).unwrap().networks(), [read]);
    fs::remove_dir_all(&p.dir).unwrap();
}
