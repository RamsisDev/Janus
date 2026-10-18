//! Katzenpost's directory: the consensus document its authorities sign each epoch, how a client
//! verifies it against a pinned [`Network`], and the [`Directory`] it yields.
//!
//! The published PKI specification still describes JSON with JWS; the servers send CBOR, in
//! the certificate format of `certificate.md`. What follows is what the servers send, checked
//! against their signatures:
//!
//! ```text
//! Consensus2 | error 1 | chunk u32 BE | chunks u32 BE | part of gzip(certificate)
//! certificate  { Version, Expiration: epoch, KeyType, Certified: document, Signatures }
//! Signatures   { BLAKE2b-256(identity key): { PublicKeySum256, Payload: signature } }
//! signed bytes   Version u32 | Expiration i64 LE | KeyType | Certified
//! document     { Epoch, Topology: [[descriptor]], GatewayNodes, ServiceNodes,
//!                SphinxGeometryHash, Mu, ... }
//! descriptor   { Name, IdentityKey, LinkKey, MixKeys: { epoch: key }, Addresses: { transport:
//!                [url] }, Kaetzchen: { capability: { endpoint } }, ... }
//! ```
//!
//! Descriptors name no operator (`pki.md` describes a `Family` field; the servers do not send
//! it), so each node counts as its own operator until the format carries one.

use std::collections::HashMap;
use std::io::Read;

use blake2::Digest;
use ciborium::Value;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::{Directory, Network, Node};

pub type Blake2b256 = blake2::Blake2b<blake2::digest::consts::U32>;

/// The largest consensus we inflate, against a gateway sending a compression bomb.
const MAX_DOCUMENT: u64 = 16 << 20;

/// A node as the consensus describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub name: String,
    pub identity: Vec<u8>,
    pub link: Vec<u8>,
    /// Sphinx public keys by epoch.
    pub mix_keys: HashMap<u64, [u8; 32]>,
    /// `host:port`, from the `tcp` addresses.
    pub addresses: Vec<String>,
    /// Service endpoints by capability.
    pub services: HashMap<String, String>,
}

impl Descriptor {
    /// The node's id in Sphinx routing commands.
    pub fn id(&self) -> [u8; 32] {
        Blake2b256::digest(&self.identity).into()
    }

    fn node(&self) -> Node {
        Node {
            name: self.name.clone(),
            operator: hex(&self.identity),
            key: self.identity.clone(),
            addresses: self.addresses.clone(),
        }
    }
}

/// A verified consensus.
#[derive(Clone, Debug)]
pub struct Consensus {
    pub epoch: u64,
    pub gateways: Vec<Descriptor>,
    pub layers: Vec<Vec<Descriptor>>,
    pub services: Vec<Descriptor>,
    pub geometry_hash: Vec<u8>,
    /// Mean per-hop delay is `1 / mu` milliseconds.
    pub mu: f64,
}

impl Consensus {
    pub fn descriptor(&self, name: &str) -> Option<&Descriptor> {
        self.gateways
            .iter()
            .chain(self.layers.iter().flatten())
            .chain(&self.services)
            .find(|d| d.name == name)
    }

    /// The directory for `Mixnet`, whose mailboxes are the service nodes offering `capability`.
    pub fn directory(&self, capability: &str) -> Directory {
        Directory {
            epoch: self.epoch,
            gateways: self.gateways.iter().map(Descriptor::node).collect(),
            layers: self
                .layers
                .iter()
                .map(|l| l.iter().map(Descriptor::node).collect())
                .collect(),
            mailboxes: self
                .services
                .iter()
                .filter(|d| d.services.contains_key(capability))
                .map(Descriptor::node)
                .collect(),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Joins `Consensus2` chunks, each `error | chunk | chunks | data`, into the certificate they
/// carry. `None` while chunks are missing or if any reports an error.
pub fn join_chunks(chunks: &[Vec<u8>]) -> Option<Vec<u8>> {
    let mut parts: Vec<Option<&[u8]>> = Vec::new();
    for c in chunks {
        if c.len() < 9 || c[0] != 0 {
            return None;
        }
        let n = u32::from_be_bytes(c[1..5].try_into().expect("4")) as usize;
        let total = u32::from_be_bytes(c[5..9].try_into().expect("4")) as usize;
        if total == 0 || total > 4096 || n >= total {
            return None;
        }
        if parts.is_empty() {
            parts = vec![None; total];
        }
        *parts.get_mut(n)? = Some(&c[9..]);
    }
    if parts.is_empty() || parts.iter().any(Option::is_none) {
        return None;
    }
    let gz: Vec<u8> = parts.into_iter().flatten().flatten().copied().collect();
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .take(MAX_DOCUMENT)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

fn field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

fn int(v: &Value) -> Option<i128> {
    v.as_integer().map(i128::from)
}

fn bytes(v: &Value) -> Option<Vec<u8>> {
    v.as_bytes().cloned()
}

/// Verifies `certificate` (CBOR) against `network` for `epoch` and parses the document in it.
pub fn verify(network: &Network, certificate: &[u8], epoch: u64) -> Option<Consensus> {
    let cert: Value = ciborium::from_reader(certificate).ok()?;
    let cert = cert.as_map()?;
    let version = u32::try_from(int(field(cert, "Version")?)?).ok()?;
    let expiration = i64::try_from(int(field(cert, "Expiration")?)?).ok()?;
    let key_type = field(cert, "KeyType")?.as_text()?;
    let certified = field(cert, "Certified")?.as_bytes()?;
    if key_type != "Ed25519" || expiration < i64::try_from(epoch).ok()? {
        return None;
    }
    let mut signed = Vec::with_capacity(12 + key_type.len() + certified.len());
    signed.extend_from_slice(&version.to_le_bytes());
    signed.extend_from_slice(&expiration.to_le_bytes());
    signed.extend_from_slice(key_type.as_bytes());
    signed.extend_from_slice(certified);

    let signatures = field(cert, "Signatures")?.as_map()?;
    let mut signers: Vec<&[u8]> = Vec::new();
    for authority in network.authorities() {
        let sum = Blake2b256::digest(&authority.identity);
        let Some((_, sig)) = signatures
            .iter()
            .find(|(k, _)| k.as_bytes().is_some_and(|k| k[..] == sum[..]))
        else {
            continue;
        };
        let Some(payload) = sig.as_map().and_then(|m| field(m, "Payload")?.as_bytes()) else {
            continue;
        };
        let (Ok(key), Ok(sig)) = (
            <[u8; 32]>::try_from(&authority.identity[..]),
            <[u8; 64]>::try_from(&payload[..]),
        ) else {
            continue;
        };
        let Ok(key) = VerifyingKey::from_bytes(&key) else {
            continue;
        };
        if key.verify(&signed, &Signature::from_bytes(&sig)).is_ok() {
            signers.push(&authority.identity);
        }
    }
    if !network.accepts(signers) {
        return None;
    }
    let consensus = document(certified)?;
    (consensus.epoch == epoch).then_some(consensus)
}

fn document(certified: &[u8]) -> Option<Consensus> {
    let doc: Value = ciborium::from_reader(certified).ok()?;
    let doc = doc.as_map()?;
    let list = |key: &str| -> Option<Vec<Descriptor>> {
        match field(doc, key)? {
            Value::Null => Some(Vec::new()),
            v => v.as_array()?.iter().map(descriptor).collect(),
        }
    };
    let layers = field(doc, "Topology")?
        .as_array()?
        .iter()
        .map(|l| l.as_array()?.iter().map(descriptor).collect())
        .collect::<Option<Vec<Vec<Descriptor>>>>()?;
    Some(Consensus {
        epoch: u64::try_from(int(field(doc, "Epoch")?)?).ok()?,
        gateways: list("GatewayNodes")?,
        layers,
        services: list("ServiceNodes")?,
        geometry_hash: field(doc, "SphinxGeometryHash").and_then(bytes)?,
        mu: field(doc, "Mu")?.as_float()?,
    })
}

/// A descriptor, which the document carries as CBOR inside a byte string.
fn descriptor(v: &Value) -> Option<Descriptor> {
    let raw: &[u8] = v.as_bytes()?;
    let d: Value = ciborium::from_reader(raw).ok()?;
    let d = d.as_map()?;
    let mut mix_keys = HashMap::new();
    if let Some(Value::Map(keys)) = field(d, "MixKeys") {
        for (e, k) in keys {
            let e = u64::try_from(int(e)?).ok()?;
            mix_keys.insert(e, k.as_bytes()?[..].try_into().ok()?);
        }
    }
    let mut addresses = Vec::new();
    if let Some(Value::Map(by_transport)) = field(d, "Addresses") {
        for (transport, urls) in by_transport {
            if !transport.as_text()?.starts_with("tcp") {
                continue;
            }
            for url in urls.as_array()? {
                let url = url.as_text()?;
                addresses.push(url.strip_prefix("tcp://").unwrap_or(url).to_owned());
            }
        }
    }
    let mut services = HashMap::new();
    if let Some(Value::Map(kaetzchen)) = field(d, "Kaetzchen") {
        for (capability, params) in kaetzchen {
            let endpoint = field(params.as_map()?, "endpoint")?.as_text()?;
            services.insert(capability.as_text()?.to_owned(), endpoint.to_owned());
        }
    }
    Some(Descriptor {
        name: field(d, "Name")?.as_text()?.to_owned(),
        identity: field(d, "IdentityKey").and_then(bytes)?,
        link: field(d, "LinkKey").and_then(bytes)?,
        mix_keys,
        addresses,
        services,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn chunks_join_in_any_order_and_a_missing_one_waits() {
        let doc = b"a consensus document".repeat(50);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&doc).unwrap();
        let gz = gz.finish().unwrap();
        let parts: Vec<Vec<u8>> = gz
            .chunks(gz.len() / 3 + 1)
            .enumerate()
            .map(|(i, part)| {
                let mut c = vec![0];
                c.extend_from_slice(&(i as u32).to_be_bytes());
                c.extend_from_slice(&3u32.to_be_bytes());
                c.extend_from_slice(part);
                c
            })
            .collect();
        let shuffled = [parts[2].clone(), parts[0].clone(), parts[1].clone()];
        assert_eq!(join_chunks(&shuffled).unwrap(), doc);
        assert!(join_chunks(&parts[..2]).is_none());
        let mut failed = parts.clone();
        failed[1][0] = 1;
        assert!(join_chunks(&failed).is_none());
    }
}
