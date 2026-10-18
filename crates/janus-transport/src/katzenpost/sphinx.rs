//! Sphinx packets with X25519, as Katzenpost instantiates them (`sphinx.md`, `mixnet.md`): what
//! a client needs to build forward packets and single-use reply blocks (SURBs), and to open the
//! replies. Every hop is unwrapped by the servers; [`unwrap`] is here so tests can check our
//! packets against the specified processing.
//!
//! ```text
//! packet  | header | payload
//! header  | additional data 2 (0, 0) | group element 32 | routing info | MAC 32
//! routing | per hop: commands, zero padded
//! payload | SPRP layers over: zero tag | plaintext
//! SURB    | header | first hop id 32 | payload key
//! ```
//!
//! Primitives: X25519, HMAC-SHA256, HKDF-SHA256 (expand only, info `Katzenpost-kdf-v0-hkdf-
//! sha256`), AES-256-CTR, and AEZ v5 as the SPRP.

use aes::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

const AD: [u8; 2] = [0, 0];
const ELEMENT_LEN: usize = 32;
const MAC_LEN: usize = 32;
pub const NODE_ID_LEN: usize = 32;
pub const RECIPIENT_LEN: usize = 64;
pub const SURB_ID_LEN: usize = 16;
const KDF_INFO: &[u8] = b"Katzenpost-kdf-v0-hkdf-sha256";
const STREAM_KEY_LEN: usize = 32;
/// CTR-AES256 with a 96-bit IV and a 32-bit counter (`mixnet.md`).
const STREAM_IV_LEN: usize = 12;
const AEZ_KEY_LEN: usize = 48;

/// Commands, by number.
const NULL: u8 = 0;
const NEXT_HOP: u8 = 1;
const RECIPIENT: u8 = 2;
const SURB_REPLY: u8 = 3;
const DELAY: u8 = 0x80;

type Aes256Ctr = ctr::Ctr32BE<aes::Aes256>;

/// The sizes of a network's packets, published by its directory as `SphinxGeometry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Hops of the longest path; shorter paths are padded to it.
    pub hops: usize,
    pub per_hop: usize,
    /// Plaintext bytes in a payload, after the tag.
    pub payload: usize,
    pub tag: usize,
    /// SPRP key material per hop: an AEZ key then its nonce.
    pub sprp_key: usize,
}

impl Geometry {
    /// Katzenpost's default: 5 hops, X25519, 2000 bytes for the application.
    pub const DEFAULT: Geometry = Geometry {
        hops: 5,
        per_hop: 82,
        payload: 2574,
        tag: 32,
        sprp_key: 64,
    };

    fn routing_len(&self) -> usize {
        self.hops * self.per_hop
    }

    pub fn header_len(&self) -> usize {
        AD.len() + ELEMENT_LEN + self.routing_len() + MAC_LEN
    }

    pub fn packet_len(&self) -> usize {
        self.header_len() + self.tag + self.payload
    }

    pub fn surb_len(&self) -> usize {
        self.header_len() + NODE_ID_LEN + self.sprp_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Added by [`packet`] and [`surb`] to every hop but the last; [`unwrap`] returns it.
    NextHop([u8; NODE_ID_LEN]),
    /// Who the packet is for at its last hop: a service endpoint or a client's queue.
    Recipient([u8; RECIPIENT_LEN]),
    /// Marks a reply and names the SURB it came from.
    SurbReply([u8; SURB_ID_LEN]),
    /// Milliseconds the hop holds the packet.
    Delay(u32),
}

impl Command {
    fn encode(&self, mac: &[u8; MAC_LEN], out: &mut Vec<u8>) {
        match self {
            Command::NextHop(id) => {
                out.push(NEXT_HOP);
                out.extend_from_slice(id);
                out.extend_from_slice(mac);
            }
            Command::Recipient(r) => {
                out.push(RECIPIENT);
                out.extend_from_slice(r);
            }
            Command::SurbReply(id) => {
                out.push(SURB_REPLY);
                out.extend_from_slice(id);
            }
            Command::Delay(ms) => {
                out.push(DELAY);
                out.extend_from_slice(&ms.to_be_bytes());
            }
        }
    }
}

/// A recipient name, such as a service endpoint, zero padded.
pub fn recipient(name: &[u8]) -> Option<[u8; RECIPIENT_LEN]> {
    let mut r = [0; RECIPIENT_LEN];
    r.get_mut(..name.len())?.copy_from_slice(name);
    Some(r)
}

/// One hop of a path: the node's id, its Sphinx key for the epoch, and what it must do besides
/// forwarding.
#[derive(Clone, Debug)]
pub struct Hop {
    pub id: [u8; NODE_ID_LEN],
    pub key: [u8; ELEMENT_LEN],
    pub commands: Vec<Command>,
}

struct Keys {
    mac: Zeroizing<[u8; MAC_LEN]>,
    stream: Zeroizing<[u8; STREAM_KEY_LEN]>,
    iv: Vec<u8>,
    sprp: Zeroizing<Vec<u8>>,
    blinding: Zeroizing<[u8; ELEMENT_LEN]>,
}

fn kdf(geo: &Geometry, shared: &[u8; ELEMENT_LEN]) -> Keys {
    let mut out = Zeroizing::new(vec![
        0u8;
        MAC_LEN
            + STREAM_KEY_LEN
            + STREAM_IV_LEN
            + geo.sprp_key
            + ELEMENT_LEN
    ]);
    // Katzenpost's Sphinx KDF: HKDF-SHA256, expand only, the shared secret as the key and
    // KDF_INFO as the info parameter.
    Hkdf::<Sha256>::from_prk(shared)
        .expect("a 32-byte key")
        .expand(KDF_INFO, &mut out)
        .expect("within HKDF limits");
    let r = &mut &out[..];
    let mut take = |n: usize| {
        let (head, rest) = r.split_at(n);
        *r = rest;
        head.to_vec()
    };
    Keys {
        mac: Zeroizing::new(take(MAC_LEN).try_into().expect("MAC_LEN")),
        stream: Zeroizing::new(take(STREAM_KEY_LEN).try_into().expect("key")),
        iv: take(STREAM_IV_LEN),
        sprp: Zeroizing::new(take(geo.sprp_key)),
        blinding: Zeroizing::new(take(ELEMENT_LEN).try_into().expect("element")),
    }
}

fn keystream(keys: &Keys, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    let mut counter = [0u8; 16];
    counter[..STREAM_IV_LEN].copy_from_slice(&keys.iv);
    Aes256Ctr::new(&(*keys.stream).into(), &counter.into()).apply_keystream(&mut out);
    out
}

fn header_mac(keys: &Keys, element: &[u8], routing: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(&keys.mac[..]).expect("any key length");
    mac.update(&AD);
    mac.update(element);
    mac.update(routing);
    mac.finalize().into_bytes().into()
}

fn aez(material: &[u8]) -> (zears::Aez, &[u8]) {
    let (key, nonce) = material.split_at(AEZ_KEY_LEN);
    (zears::Aez::new(key), nonce)
}

pub fn sprp_encrypt(material: &[u8], data: &mut [u8]) {
    let (aez, nonce) = aez(material);
    aez.encrypt_inplace(nonce, &[], 0, data);
}

pub fn sprp_decrypt(material: &[u8], data: &mut [u8]) {
    let (aez, nonce) = aez(material);
    aez.decrypt_inplace(nonce, &[], 0, data)
        .expect("without a tag AEZ always deciphers");
}

fn xor(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

fn random<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0; N]);
    getrandom::fill(&mut *out).expect("OS random generator unavailable");
    out
}

/// A header for `path` and the SPRP key material of each hop.
fn header(geo: &Geometry, path: &[Hop]) -> (Vec<u8>, Vec<Zeroizing<Vec<u8>>>) {
    let n = path.len();
    assert!((1..=geo.hops).contains(&n), "path longer than the geometry");
    let (p, r) = (geo.per_hop, geo.routing_len());

    let secret = random::<ELEMENT_LEN>();
    let mut element = x25519(*secret, X25519_BASEPOINT_BYTES);
    let mut elements = Vec::with_capacity(n);
    let mut keys: Vec<Keys> = Vec::with_capacity(n);
    for hop in path {
        let mut shared = Zeroizing::new(x25519(*secret, hop.key));
        for k in &keys {
            *shared = x25519(*k.blinding, *shared);
        }
        if let Some(prev) = keys.last() {
            element = x25519(*prev.blinding, element);
        }
        elements.push(element);
        keys.push(kdf(geo, &shared));
    }

    // The filler: what hop i appends when it shifts the routing info, as seen by the last hop.
    let mut filler: Vec<u8> = Vec::new();
    for k in &keys[..n - 1] {
        filler.resize(filler.len() + p, 0);
        let stream = keystream(k, r + p);
        let len = filler.len();
        xor(&mut filler, &stream[r + p - len..]);
    }

    let commands = |i: usize, mac: &[u8; MAC_LEN]| {
        let mut out = Vec::with_capacity(p);
        if let Some(next) = path.get(i + 1) {
            Command::NextHop(next.id).encode(mac, &mut out);
        }
        for c in &path[i].commands {
            c.encode(mac, &mut out);
        }
        assert!(out.len() <= p, "commands longer than a hop's routing info");
        out.resize(p, NULL);
        out
    };

    let last = n - 1;
    let mut routing = commands(last, &[0; MAC_LEN]);
    let mut pad = vec![0; r - n * p];
    getrandom::fill(&mut pad).expect("OS random generator unavailable");
    routing.extend(pad);
    xor(&mut routing, &keystream(&keys[last], r - last * p));
    routing.extend(&filler);
    let mut mac = header_mac(&keys[last], &elements[last], &routing);
    for i in (0..last).rev() {
        let mut next = commands(i, &mac);
        next.extend_from_slice(&routing[..r - p]);
        xor(&mut next, &keystream(&keys[i], r));
        routing = next;
        mac = header_mac(&keys[i], &elements[i], &routing);
    }

    let mut out = Vec::with_capacity(geo.header_len());
    out.extend_from_slice(&AD);
    out.extend_from_slice(&elements[0]);
    out.extend_from_slice(&routing);
    out.extend_from_slice(&mac);
    (out, keys.into_iter().map(|k| k.sprp).collect())
}

/// A forward packet along `path` carrying `payload`, which is zero padded to the geometry.
pub fn packet(geo: &Geometry, path: &[Hop], payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= geo.payload, "payload too long");
    let (mut out, keys) = header(geo, path);
    let mut body = vec![0; geo.tag + geo.payload];
    body[geo.tag..geo.tag + payload.len()].copy_from_slice(payload);
    for k in keys.iter().rev() {
        sprp_encrypt(k, &mut body);
    }
    out.extend(body);
    out
}

/// What opens the reply to a SURB: its final key, then each hop's key.
pub struct ReplyKeys(Vec<Zeroizing<Vec<u8>>>);

/// A SURB for a reply along `path` (first hop first), and the keys that open the reply.
pub fn surb(geo: &Geometry, path: &[Hop]) -> (Vec<u8>, ReplyKeys) {
    let (mut out, hop_keys) = header(geo, path);
    let mut last = Zeroizing::new(vec![0; geo.sprp_key]);
    getrandom::fill(&mut last).expect("OS random generator unavailable");
    out.extend_from_slice(&path[0].id);
    out.extend_from_slice(&last);
    let mut keys = vec![last];
    keys.extend(hop_keys);
    (out, ReplyKeys(keys))
}

/// The plaintext of a reply payload, or `None` if it does not authenticate.
pub fn open_reply(geo: &Geometry, keys: &ReplyKeys, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() != geo.tag + geo.payload {
        return None;
    }
    let mut body = payload.to_vec();
    for k in keys.0[1..].iter().rev() {
        sprp_encrypt(k, &mut body);
    }
    sprp_decrypt(&keys.0[0], &mut body);
    body[..geo.tag]
        .iter()
        .all(|b| *b == 0)
        .then(|| body.split_off(geo.tag))
}

/// A hop's processing of `packet` with its Sphinx secret key, as `sphinx.md` specifies it:
/// the commands for this hop, with the packet turned into what the next hop gets. At the last
/// hop the payload is left decrypted, tag first.
pub fn unwrap(
    geo: &Geometry,
    secret: &[u8; ELEMENT_LEN],
    packet: &mut [u8],
) -> Option<Vec<Command>> {
    let (p, r) = (geo.per_hop, geo.routing_len());
    let (header, payload) = packet.split_at_mut(geo.header_len());
    let element: [u8; ELEMENT_LEN] = header[2..2 + ELEMENT_LEN].try_into().expect("32");
    let shared = Zeroizing::new(x25519(*secret, element));
    let keys = kdf(geo, &shared);
    let routing = &header[2 + ELEMENT_LEN..2 + ELEMENT_LEN + r];
    let mac = header_mac(&keys, &element, routing);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        &mac[..],
        &header[2 + ELEMENT_LEN + r..],
    )) {
        return None;
    }
    let mut b = routing.to_vec();
    b.resize(r + p, 0);
    xor(&mut b, &keystream(&keys, r + p));
    let mut commands = Vec::new();
    let mut next_mac = None;
    let mut i = 0;
    while i < p {
        let rest = &b[i + 1..p];
        let take = |n: usize| rest.get(..n);
        match b[i] {
            NULL => break,
            NEXT_HOP => {
                let body = take(NODE_ID_LEN + MAC_LEN)?;
                commands.push(Command::NextHop(body[..NODE_ID_LEN].try_into().ok()?));
                next_mac = Some(body[NODE_ID_LEN..].to_vec());
                i += 1 + NODE_ID_LEN + MAC_LEN;
            }
            RECIPIENT => {
                commands.push(Command::Recipient(take(RECIPIENT_LEN)?.try_into().ok()?));
                i += 1 + RECIPIENT_LEN;
            }
            SURB_REPLY => {
                commands.push(Command::SurbReply(take(SURB_ID_LEN)?.try_into().ok()?));
                i += 1 + SURB_ID_LEN;
            }
            DELAY => {
                commands.push(Command::Delay(u32::from_be_bytes(
                    take(4)?.try_into().ok()?,
                )));
                i += 5;
            }
            _ => return None,
        }
    }
    sprp_decrypt(&keys.sprp, payload);
    if let Some(mac) = next_mac {
        let next = x25519(*keys.blinding, element);
        header[2..2 + ELEMENT_LEN].copy_from_slice(&next);
        header[2 + ELEMENT_LEN..2 + ELEMENT_LEN + r].copy_from_slice(&b[p..]);
        header[2 + ELEMENT_LEN + r..].copy_from_slice(&mac);
    }
    Some(commands)
}

/// The packet a service sends with `surb` to carry `payload`.
pub fn reply_packet(geo: &Geometry, surb: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    if surb.len() != geo.surb_len() || payload.len() > geo.payload {
        return None;
    }
    let (header, rest) = surb.split_at(geo.header_len());
    let key = &rest[NODE_ID_LEN..];
    let mut body = vec![0; geo.tag + geo.payload];
    body[geo.tag..geo.tag + payload.len()].copy_from_slice(payload);
    sprp_encrypt(key, &mut body);
    let mut out = header.to_vec();
    out.extend(body);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(n: u8) -> ([u8; 32], Hop) {
        let secret = [n; 32];
        let hop = Hop {
            id: [n ^ 0xff; 32],
            key: x25519(secret, X25519_BASEPOINT_BYTES),
            commands: vec![Command::Delay(u32::from(n) * 10)],
        };
        (secret, hop)
    }

    fn path(len: u8) -> (Vec<[u8; 32]>, Vec<Hop>) {
        let (secrets, mut hops): (Vec<_>, Vec<_>) = (1..=len).map(node).unzip();
        let last = hops.last_mut().unwrap();
        last.commands = vec![Command::Recipient(recipient(b"+echo").unwrap())];
        (secrets, hops)
    }

    #[test]
    fn the_default_geometry_matches_katzenpost() {
        let g = Geometry::DEFAULT;
        assert_eq!(
            (g.header_len(), g.packet_len(), g.surb_len()),
            (476, 3082, 572)
        );
    }

    #[test]
    fn every_hop_unwraps_its_commands_and_the_last_gets_the_payload() {
        let g = Geometry::DEFAULT;
        for len in 1..=5 {
            let (secrets, hops) = path(len);
            let mut pkt = packet(&g, &hops, b"hello mixnet");
            assert_eq!(pkt.len(), g.packet_len());
            for (i, secret) in secrets.iter().enumerate() {
                let cmds = unwrap(&g, secret, &mut pkt).expect("authenticates");
                if let Some(next) = hops.get(i + 1) {
                    assert_eq!(cmds[0], Command::NextHop(next.id));
                    assert_eq!(cmds[1..], hops[i].commands[..]);
                } else {
                    assert_eq!(cmds, hops[i].commands);
                }
            }
            let body = &pkt[g.header_len()..];
            assert!(body[..g.tag].iter().all(|b| *b == 0), "tag of path {len}");
            assert_eq!(&body[g.tag..g.tag + 12], b"hello mixnet");
        }
    }

    #[test]
    fn a_flipped_header_bit_or_the_wrong_key_fails() {
        let g = Geometry::DEFAULT;
        let (secrets, hops) = path(3);
        let pkt = packet(&g, &hops, b"x");
        let mut flipped = pkt.clone();
        flipped[40] ^= 1;
        assert!(unwrap(&g, &secrets[0], &mut flipped).is_none());
        assert!(unwrap(&g, &secrets[1], &mut pkt.clone()).is_none());
    }

    #[test]
    fn a_reply_through_a_surb_opens_with_its_keys_only() {
        let g = Geometry::DEFAULT;
        let (secrets, mut hops) = path(4);
        hops[3].commands = vec![
            Command::Recipient(recipient(b"client").unwrap()),
            Command::SurbReply([7; SURB_ID_LEN]),
        ];
        let (surb, keys) = surb(&g, &hops);
        assert_eq!(surb.len(), g.surb_len());
        assert_eq!(&surb[g.header_len()..g.header_len() + 32], &hops[0].id);
        let mut pkt = reply_packet(&g, &surb, b"reply").unwrap();
        let mut last = Vec::new();
        for secret in &secrets {
            last = unwrap(&g, secret, &mut pkt).unwrap();
        }
        assert_eq!(last[1], Command::SurbReply([7; SURB_ID_LEN]));
        let body = &pkt[g.header_len()..];
        assert_eq!(&open_reply(&g, &keys, body).unwrap()[..5], b"reply");
        let (_, other) = super::surb(&g, &hops);
        assert!(open_reply(&g, &other, body).is_none());
    }
}
