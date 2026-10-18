//! Files in the data directory: one pair per contact, named after its random id, and one per
//! installed network, named after its id.
//!
//! ```text
//! <id>.state               nonce 24 | sealed(network id 32 | confirmed 1 | name length 2 | name
//!                          | session export) | tag 16
//! <id>.history             records: length 4 | nonce 24 | sealed(mine 1 | message) | tag 16
//! networks/<id>.network    nonce 24 | sealed(profile) | tag 16
//! ```
//!
//! States are replaced atomically (temp file, flush, rename). History records are appended; a
//! record torn by a crash is cut off by `scan`. The associated data binds each state to its id
//! and each record to its id and position, so files cannot be swapped nor records reordered.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use janus_core::{Key, NetworkId};
use janus_transport::Network;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{History, crash_point};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const STATE: &str = "state";
const HISTORY: &str = "history";
const TMP: &str = "tmp";
const NETWORKS: &str = "networks";
const NETWORK: &str = "network";

pub struct State {
    pub network: NetworkId,
    pub confirmed: bool,
    pub name: String,
    pub session: Zeroizing<Vec<u8>>,
}

pub struct Store {
    dir: PathBuf,
    storage_key: Zeroizing<Key>,
    state_key: Zeroizing<Key>,
}

impl Store {
    /// Creates `dir` if needed and drops what a crash left behind: temp files and the history
    /// of a contact whose state was already deleted.
    pub fn open(dir: PathBuf, storage_key: &Key) -> io::Result<Store> {
        fs::create_dir_all(&dir)?;
        let store = Store {
            state_key: derive(storage_key, b"", b"janus client state"),
            storage_key: Zeroizing::new(*storage_key),
            dir,
        };
        for entry in fs::read_dir(&store.dir)? {
            let path = entry?.path();
            let orphan = match path.extension().and_then(|e| e.to_str()) {
                Some(TMP) => true,
                Some(HISTORY) => !path.with_extension(STATE).exists(),
                _ => false,
            };
            if orphan {
                shred(&path)?;
            }
        }
        Ok(store)
    }

    pub fn ids(&self) -> io::Result<Vec<String>> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == STATE)
                && let Some(id) = path.file_stem().and_then(|s| s.to_str())
                && is_id(id)
            {
                ids.push(id.to_owned());
            }
        }
        ids.sort();
        Ok(ids)
    }

    pub fn save(&self, id: &str, state: &State) -> io::Result<()> {
        let name = state.name.as_bytes();
        let len = u16::try_from(name.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut plain = Zeroizing::new(Vec::with_capacity(35 + name.len() + state.session.len()));
        plain.extend_from_slice(&state.network);
        plain.push(u8::from(state.confirmed));
        plain.extend_from_slice(&len.to_be_bytes());
        plain.extend_from_slice(name);
        plain.extend_from_slice(&state.session);
        let sealed = seal(&self.state_key, id.as_bytes(), &plain);
        replace(&self.path(id, STATE), &sealed)
    }

    pub fn load(&self, id: &str) -> io::Result<State> {
        let sealed = fs::read(self.path(id, STATE))?;
        let plain = open(&self.state_key, id.as_bytes(), &sealed).ok_or_else(invalid)?;
        let (network, rest) = plain.split_first_chunk().ok_or_else(invalid)?;
        let (&confirmed, rest) = rest.split_first().ok_or_else(invalid)?;
        let (len, rest) = rest.split_first_chunk::<2>().ok_or_else(invalid)?;
        let (name, session) = rest
            .split_at_checked(u16::from_be_bytes(*len).into())
            .ok_or_else(invalid)?;
        Ok(State {
            network: *network,
            confirmed: confirmed == 1,
            name: String::from_utf8(name.to_vec()).map_err(|_| invalid())?,
            session: Zeroizing::new(session.to_vec()),
        })
    }

    /// Cuts a record torn by a crash off the history and returns `(records, bytes)` kept.
    pub fn scan(&self, id: &str) -> io::Result<(u64, u64)> {
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.path(id, HISTORY))
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(e),
        };
        let total = file.metadata()?.len();
        let (mut records, mut at) = (0, 0);
        let mut len = [0; 4];
        while at + 4 <= total {
            file.seek(SeekFrom::Start(at))?;
            file.read_exact(&mut len)?;
            let end = at + 4 + u64::from(u32::from_be_bytes(len));
            if end > total {
                break;
            }
            records += 1;
            at = end;
        }
        if at < total {
            file.set_len(at)?;
            sync(&file)?;
        }
        Ok((records, at))
    }

    /// Writes record number `index` at byte `at`, the end of the valid history, and returns the
    /// new end.
    pub fn append(&self, id: &str, index: u64, at: u64, mine: bool, msg: &[u8]) -> io::Result<u64> {
        let mut plain = Zeroizing::new(Vec::with_capacity(1 + msg.len()));
        plain.push(u8::from(mine));
        plain.extend_from_slice(msg);
        let sealed = seal(&self.history_key(id), &record_aad(id, index), &plain);
        let len = u32::try_from(sealed.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let record = [&len.to_be_bytes()[..], &sealed].concat();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.path(id, HISTORY))?;
        // A failed earlier append may have left a partial record past `at`.
        file.set_len(at)?;
        file.seek(SeekFrom::Start(at))?;
        let (head, tail) = record.split_at(record.len() / 2);
        file.write_all(head)?;
        crash_point();
        file.write_all(tail)?;
        sync(&file)?;
        if at == 0 {
            sync_dir(&self.dir)?;
        }
        Ok(at + record.len() as u64)
    }

    pub fn history(&self, id: &str) -> io::Result<History> {
        let bytes = match fs::read(self.path(id, HISTORY)) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let key = self.history_key(id);
        let mut rest = &bytes[..];
        let mut out = Vec::new();
        while let Some((len, tail)) = rest.split_first_chunk::<4>() {
            let (sealed, tail) = tail
                .split_at_checked(u32::from_be_bytes(*len) as usize)
                .ok_or_else(invalid)?;
            let aad = record_aad(id, out.len() as u64);
            let plain = open(&key, &aad, sealed).ok_or_else(invalid)?;
            let (&mine, msg) = plain.split_first().ok_or_else(invalid)?;
            out.push((mine == 1, Zeroizing::new(msg.to_vec())));
            rest = tail;
        }
        Ok(out)
    }

    /// Deletes the contact's state, then its history.
    pub fn delete(&self, id: &str) -> io::Result<()> {
        shred(&self.path(id, STATE))?;
        crash_point();
        shred(&self.path(id, HISTORY))?;
        sync_dir(&self.dir)
    }

    fn history_key(&self, id: &str) -> Zeroizing<Key> {
        derive(&self.storage_key, id.as_bytes(), b"janus client history")
    }

    fn path(&self, id: &str, extension: &str) -> PathBuf {
        self.dir.join(format!("{id}.{extension}"))
    }
}

pub fn save_network(dir: &Path, storage_key: &Key, network: &Network) -> io::Result<()> {
    let dir = dir.join(NETWORKS);
    fs::create_dir_all(&dir)?;
    let name = hex(&network.id());
    let sealed = seal(
        &network_key(storage_key),
        name.as_bytes(),
        &network.to_bytes(),
    );
    replace(&dir.join(format!("{name}.{NETWORK}")), &sealed)
}

/// Installed profiles. One that does not open, or whose bytes do not hash to its file name, is
/// an error: it was tampered with.
pub fn networks(dir: &Path, storage_key: &Key) -> io::Result<Vec<Network>> {
    let entries = match fs::read_dir(dir.join(NETWORKS)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let key = network_key(storage_key);
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if path.extension().is_none_or(|e| e != NETWORK) {
            continue;
        }
        let network = open(&key, name.as_bytes(), &fs::read(&path)?)
            .and_then(|plain| Network::from_bytes(&plain))
            .filter(|n| hex(&n.id()) == name)
            .ok_or_else(invalid)?;
        out.push(network);
    }
    out.sort_by_key(Network::id);
    Ok(out)
}

fn network_key(storage_key: &Key) -> Zeroizing<Key> {
    derive(storage_key, b"", b"janus client network")
}

/// Writes `bytes` over `path` atomically: a temp file, flushed, then renamed.
fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(TMP);
    let mut file = File::create(&tmp)?;
    file.write_all(bytes)?;
    sync(&file)?;
    crash_point();
    fs::rename(&tmp, path)?;
    crash_point();
    sync_dir(path.parent().expect("files live in a directory"))
}

pub fn derive(storage_key: &Key, salt: &[u8], info: &[u8]) -> Zeroizing<Key> {
    let mut out = Zeroizing::new(Key::default());
    Hkdf::<Sha256>::new(Some(salt), storage_key)
        .expand(info, out.as_mut())
        .expect("a 32-byte output is within HKDF limits");
    out
}

/// 16 random bytes in hex.
pub fn new_id() -> String {
    hex(&random::<16>())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0; N];
    getrandom::fill(&mut out).expect("OS random generator unavailable");
    out
}

fn record_aad(id: &str, index: u64) -> Vec<u8> {
    [id.as_bytes(), &index.to_be_bytes()].concat()
}

fn seal(key: &Key, aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce = random::<NONCE_LEN>();
    let mut buf = plain.to_vec();
    let tag: [u8; TAG_LEN] = XChaCha20Poly1305::new(&(*key).into())
        .encrypt_inout_detached(&nonce.into(), aad, buf.as_mut_slice().into())
        .expect("buffer length within XChaCha20-Poly1305 limits")
        .into();
    [&nonce[..], &buf, &tag].concat()
}

fn open(key: &Key, aad: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce, rest) = sealed.split_first_chunk::<NONCE_LEN>()?;
    let (body, tag) = rest.split_last_chunk::<TAG_LEN>()?;
    let mut buf = Zeroizing::new(body.to_vec());
    XChaCha20Poly1305::new(&(*key).into())
        .decrypt_inout_detached(
            &(*nonce).into(),
            aad,
            buf.as_mut_slice().into(),
            &(*tag).into(),
        )
        .ok()?;
    Some(buf)
}

/// Overwrites the file with zeros before unlinking it.
// shortcut: flash wear levelling and copy-on-write filesystems (APFS, btrfs) may keep old copies
// of deleted or replaced files, and they open with the storage key; real erasure needs
// per-contact keys in effaceable platform storage (Keychain, Keystore), from Phase 4.
fn shred(path: &Path) -> io::Result<()> {
    let mut file = match OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let zeros = [0; 64 * 1024];
    let mut left = file.metadata()?.len();
    while left > 0 {
        let n = left.min(zeros.len() as u64);
        file.write_all(&zeros[..n as usize])?;
        left -= n;
    }
    sync(&file)?;
    fs::remove_file(path)
}

fn sync(file: &File) -> io::Result<()> {
    // Crash tests stop the client, not the power, and a flush per write would take minutes.
    if cfg!(test) { Ok(()) } else { file.sync_all() }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    if cfg!(unix) && !cfg!(test) {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "stored state does not open: wrong storage key or tampered",
    )
}
