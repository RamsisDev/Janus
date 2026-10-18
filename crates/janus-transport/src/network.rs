//! Network profiles: which Katzenpost network a client uses, pinned by its directory
//! authorities.
//!
//! ```text
//! profile    | version 1 | name length 1 | name | authorities 1 | authority...
//! authority  | identity key length 2 | identity key | link key length 2 | link key
//!            | addresses 1 | (length 1 | address)...
//! ```
//!
//! A profile is installed from a file or a QR code holding exactly these bytes, and only one
//! encoding parses, so its [`Network::id`] is the same on every device. The core binds that id
//! into the handshake, so two contacts need the very same profile. The client accepts a
//! directory only when more than half of the profile's authorities signed it.

use janus_core::NetworkId;
use sha2::{Digest, Sha256};

const VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    /// Verifies the authority's signature on the directory.
    pub identity: Vec<u8>,
    /// Authenticates the authority's end of the wire protocol.
    pub link: Vec<u8>,
    /// `host:port`, at least one.
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    name: String,
    authorities: Vec<Authority>,
}

impl Network {
    /// `None` unless the profile fits its encoding: a name and every address of at most 255
    /// bytes, 1 to 255 authorities with distinct identity keys, keys of at most 65535 bytes,
    /// and 1 to 255 addresses per authority.
    pub fn new(name: &str, authorities: Vec<Authority>) -> Option<Network> {
        let fits = |len: usize, max: usize| (1..=max).contains(&len);
        let valid = name.len() <= 255
            && fits(authorities.len(), 255)
            && authorities.iter().enumerate().all(|(i, a)| {
                fits(a.identity.len(), 0xffff)
                    && fits(a.link.len(), 0xffff)
                    && fits(a.addresses.len(), 255)
                    && a.addresses.iter().all(|s| fits(s.len(), 255))
                    && authorities[..i].iter().all(|b| b.identity != a.identity)
            });
        valid.then(|| Network {
            name: name.to_owned(),
            authorities,
        })
    }

    /// Shown to users; never trusted, since anyone can pick any name.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn authorities(&self) -> &[Authority] {
        &self.authorities
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = vec![VERSION];
        short(&mut w, self.name.as_bytes());
        w.push(self.authorities.len() as u8);
        for a in &self.authorities {
            for key in [&a.identity, &a.link] {
                w.extend_from_slice(&(key.len() as u16).to_be_bytes());
                w.extend_from_slice(key);
            }
            w.push(a.addresses.len() as u8);
            for address in &a.addresses {
                short(&mut w, address.as_bytes());
            }
        }
        w
    }

    /// The profile in `bytes`, which must be exactly what `to_bytes` writes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Network> {
        let r = &mut &bytes[..];
        if take(r, 1)? != [VERSION] {
            return None;
        }
        let name = text(r)?;
        let mut authorities = Vec::new();
        for _ in 0..take(r, 1)?[0] {
            let mut key = || {
                let len = u16::from_be_bytes(take(r, 2)?.try_into().expect("2 bytes"));
                take(r, len.into()).map(<[u8]>::to_vec)
            };
            let (identity, link) = (key()?, key()?);
            let addresses = (0..take(r, 1)?[0])
                .map(|_| text(r))
                .collect::<Option<_>>()?;
            authorities.push(Authority {
                identity,
                link,
                addresses,
            });
        }
        if !r.is_empty() {
            return None;
        }
        Network::new(&name, authorities)
    }

    /// What the core binds into handshakes run on this network.
    pub fn id(&self) -> NetworkId {
        Sha256::new()
            .chain_update(b"janus network")
            .chain_update(self.to_bytes())
            .finalize()
            .into()
    }

    /// Whether directory signatures that verified under these identity keys come from more
    /// than half of the authorities. Keys of strangers and repeats count for nothing.
    pub fn accepts<'a>(&self, signers: impl IntoIterator<Item = &'a [u8]>) -> bool {
        let mut seen = vec![false; self.authorities.len()];
        for key in signers {
            if let Some(i) = self.authorities.iter().position(|a| a.identity == key) {
                seen[i] = true;
            }
        }
        seen.iter().filter(|s| **s).count() > self.authorities.len() / 2
    }
}

fn short(w: &mut Vec<u8>, bytes: &[u8]) {
    w.push(bytes.len() as u8);
    w.extend_from_slice(bytes);
}

fn take<'a>(r: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, rest) = r.split_at_checked(n)?;
    *r = rest;
    Some(head)
}

fn text(r: &mut &[u8]) -> Option<String> {
    let len = take(r, 1)?[0];
    String::from_utf8(take(r, len.into())?.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(n: u8) -> Authority {
        Authority {
            identity: vec![n; 32],
            link: vec![n; 1216],
            addresses: vec![
                format!("auth{n}.example:30000"),
                format!("10.0.0.{n}:30000"),
            ],
        }
    }

    fn network() -> Network {
        Network::new("janus test", (1..=3).map(authority).collect()).unwrap()
    }

    #[test]
    fn a_profile_round_trips_and_only_its_exact_bytes_parse() {
        let net = network();
        let bytes = net.to_bytes();
        assert_eq!(Network::from_bytes(&bytes), Some(net.clone()));
        assert_eq!(Network::from_bytes(&bytes).unwrap().id(), net.id());
        for cut in [0, 1, bytes.len() - 1] {
            assert!(Network::from_bytes(&bytes[..cut]).is_none(), "cut at {cut}");
        }
        assert!(Network::from_bytes(&[&bytes[..], &[0]].concat()).is_none());
        let mut version = bytes.clone();
        version[0] = 2;
        assert!(Network::from_bytes(&version).is_none());
    }

    #[test]
    fn every_field_changes_the_id() {
        let id = network().id();
        let mut moved = network().authorities;
        moved[2].addresses[1] = "10.0.0.4:30000".into();
        let mut rekeyed = network().authorities;
        rekeyed[0].link[0] ^= 1;
        let fewer = network().authorities[..2].to_vec();
        for other in [moved, rekeyed, fewer] {
            assert_ne!(Network::new("janus test", other).unwrap().id(), id);
        }
        let renamed = Network::new("janus tset", network().authorities).unwrap();
        assert_ne!(renamed.id(), id);
    }

    #[test]
    fn profiles_that_do_not_fit_are_refused() {
        assert!(Network::new("x", Vec::new()).is_none());
        assert!(Network::new("x", vec![authority(1), authority(1)]).is_none());
        let no_address = Authority {
            addresses: Vec::new(),
            ..authority(1)
        };
        assert!(Network::new("x", vec![no_address]).is_none());
        assert!(Network::new(&"x".repeat(256), vec![authority(1)]).is_none());
    }

    #[test]
    fn a_directory_needs_more_than_half_of_the_authorities() {
        let net = network();
        let key = |n: u8| vec![n; 32];
        let (one, two, stranger) = (key(1), key(2), key(9));
        assert!(net.accepts([&one[..], &two[..]]));
        assert!(!net.accepts([&one[..], &one[..], &stranger[..]]));
        assert!(!net.accepts([]));
    }
}
