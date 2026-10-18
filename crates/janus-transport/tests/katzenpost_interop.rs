//! Interop against a live Katzenpost network, proving our client speaks its protocol: the PQ
//! Noise wire handshake, the consensus request, and verification against the pinned authorities.
//!
//! Ignored by default; it needs a running network (Katzenpost's own Docker tooling). Point it at
//! the generated config and a reachable authority:
//!
//! ```sh
//! KP_NET=.../docker/mixnet-alpine KP_AUTH=192.168.107.5:1000 \
//!   cargo test -p janus-transport --test katzenpost_interop -- --ignored --nocapture
//! ```
//!
//! `KP_PERIOD` overrides the epoch length (default 1200s; the test network uses 120s).

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use janus_transport::Link;
use janus_transport::katzenpost::Client;
use janus_transport::katzenpost::client::EPOCH_PERIOD;
use janus_transport::{Authority, Network};

fn pem(text: &str) -> Vec<u8> {
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .expect("valid base64 PEM body")
}

fn read_key(dir: &str, node: &str, file: &str) -> Vec<u8> {
    pem(&std::fs::read_to_string(format!("{dir}/{node}/{file}")).expect("key file"))
}

fn test_network(dir: &str, auth_addr: &str) -> Network {
    let mut authorities = Vec::new();
    for (i, node) in ["auth1", "auth2", "auth3"].iter().enumerate() {
        authorities.push(Authority {
            identity: read_key(dir, node, "identity.public.pem"),
            link: read_key(dir, node, "link.public.pem"),
            addresses: vec![if i == 0 {
                auth_addr.to_owned()
            } else {
                format!("{node}:1000")
            }],
        });
    }
    Network::new("katzenpost-testnet", authorities).expect("a valid profile")
}

#[test]
#[ignore = "needs a running Katzenpost network; see the module docs"]
fn downloads_and_verifies_the_consensus() {
    let dir = std::env::var("KP_NET").expect("KP_NET: the generated mixnet config directory");
    let auth_addr = std::env::var("KP_AUTH").expect("KP_AUTH: a reachable authority host:port");
    let period: u64 = std::env::var("KP_PERIOD")
        .map(|p| p.parse().unwrap())
        .unwrap_or(EPOCH_PERIOD);

    // Only the first authority is reachable, at KP_AUTH; the others' in-container hostnames
    // are not reachable from here.
    let network = test_network(&dir, &auth_addr);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut client = Client::new(network, || 0, move || now).with_epoch_period(period);
    client
        .refresh_consensus()
        .expect("handshake, GetConsensus and signature verification all succeed");

    let directory = client.directory().expect("a verified directory");
    assert!(
        !directory.gateways.is_empty(),
        "no gateways in the consensus"
    );
    assert_eq!(directory.layers.len(), 3, "expected three mix layers");
    for layer in &directory.layers {
        assert!(!layer.is_empty(), "an empty mix layer");
    }
    eprintln!(
        "verified consensus {}: {} gateways, {} mix layers, {} mailbox services",
        directory.epoch,
        directory.gateways.len(),
        directory.layers.len(),
        directory.mailboxes.len(),
    );
}
