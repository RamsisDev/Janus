//! The client role shared by every app: it owns the [`Engine`], the contacts and their files, and
//! drives a [`Transport`]. Apps implement [`Platform`], call [`Client::tick`] about once a
//! second and on every wake-up, and show the [`Event`]s it returns.
//!
//! The rules of `janus-core` that a client must keep live here, written once:
//!
//! - A session is on disk before any block it produced is posted, so a crash never restores a
//!   state that reuses message keys.
//! - A received message is in the history before its session is written and before the app
//!   hears of it, so a crash never loses a message the app showed.
//! - Each network's transport listens on exactly the rendezvous queue (while joining there),
//!   the pending handshake's queues (if it runs there) and the queues of its contacts.
//! - A contact lives on the network its invitation chose: its handshake, and every block after
//!   it, go through that network's transport only.
//! - Every tick runs `outgoing`, `purge` and `dormant`, and each session sends a cover block at
//!   random intervals averaging [`COVER_MEAN`].
//!
//! Contacts are named by a random id, which is also their file name. The pending handshake lives
//! in memory only: a crash during one means starting it again. Installed network profiles live
//! in the data directory too ([`install_network`], [`networks`]), so the app can build each
//! network's transport before opening the client.

mod store;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::PathBuf;

use janus_core::{
    Block, Engine, INVITE_TTL, Interval, Key, NetworkId, QueueId, Received, SessionId,
};
use janus_transport::{Network, Transport};
use zeroize::Zeroizing;

use store::{State, Store};

/// Mean seconds between session cover blocks while the app runs: the Normal level of
/// `protocol.md`. A starting value, to tune with battery and data tests.
pub const COVER_MEAN: u64 = 600;

/// What each app provides from its operating system.
pub trait Platform {
    /// 32 random bytes, the same on every call, kept by the OS: wrapped by the Secure Enclave or
    /// Android Keystore where available. Everything on disk is encrypted under keys derived from
    /// it.
    fn storage_key(&self) -> Zeroizing<Key>;
    /// Seconds of a monotonic clock that keeps counting while the device sleeps
    /// (`mach_continuous_time`, `elapsedRealtime`), never the wall clock.
    fn now(&self) -> u64;
    /// A directory only this app reads, excluded from backups: restoring one is a rollback that
    /// breaks sessions and revives deleted keys.
    fn data_dir(&self) -> PathBuf;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// A: B answered the invitation. Ask the user for the 3 safety words B reads out and pass
    /// them to `verify`.
    Answered,
    /// B: the handshake is done. Show the safety words for the user to read to A, and call
    /// `confirm` once A says they match.
    Joined {
        contact: String,
        safety_words: String,
    },
    /// Only from confirmed contacts; what arrives before `confirm` waits in the history.
    Message {
        contact: String,
        data: Zeroizing<Vec<u8>>,
    },
    /// The peer ended the session; the contact and its history are gone.
    Closed { contact: String },
    /// Nothing heard from the peer for `MAX_SILENCE`. Offer to `close` it; never do it on your
    /// own, since silence can be forged.
    Dormant { contact: String },
    /// A dormant contact heard from its peer again.
    Awake { contact: String },
}

/// `(mine, message)` pairs, oldest first.
pub type History = Vec<(bool, Zeroizing<Vec<u8>>)>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub id: String,
    pub network: NetworkId,
    pub name: String,
    pub confirmed: bool,
    pub dormant: bool,
}

#[derive(Debug)]
pub enum Error {
    /// Storage failed; nothing that depended on it was sent.
    Io(io::Error),
    Handshake(janus_core::Error),
    UnknownContact,
    /// B sends nothing until its user confirms the safety words.
    NotConfirmed,
    /// Over the ~16 MB a message can carry.
    TooLarge,
    /// No transport for that network was given to `open`.
    UnknownNetwork,
    /// Not a network profile.
    BadProfile,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<janus_core::Error> for Error {
    fn from(e: janus_core::Error) -> Error {
        Error::Handshake(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "storage: {e}"),
            Error::Handshake(janus_core::Error::BadWords) => {
                write!(f, "exactly 6 words from the list are needed")
            }
            Error::Handshake(janus_core::Error::Expired) => write!(f, "the invitation expired"),
            Error::Handshake(janus_core::Error::Rejected) => write!(f, "rejected"),
            Error::UnknownContact => write!(f, "no such contact"),
            Error::NotConfirmed => write!(f, "the safety words are not confirmed yet"),
            Error::TooLarge => write!(f, "message over ~16 MB"),
            Error::UnknownNetwork => write!(f, "that network is not installed"),
            Error::BadProfile => write!(f, "not a network profile"),
        }
    }
}

impl std::error::Error for Error {}

struct Entry {
    session: SessionId,
    network: NetworkId,
    name: String,
    confirmed: bool,
    dormant: bool,
    next_cover: u64,
    /// History records and bytes on disk.
    records: u64,
    history_len: u64,
}

/// B while it looks for the invitation.
struct Joining {
    network: NetworkId,
    words: Zeroizing<String>,
    rendezvous: QueueId,
    until: u64,
}

pub struct Client<P: Platform, T: Transport> {
    platform: P,
    /// One per network.
    transports: Vec<T>,
    store: Store,
    engine: Engine,
    session_key: Zeroizing<Key>,
    contacts: BTreeMap<String, Entry>,
    joining: Option<Joining>,
    /// The network of the engine's pending handshake.
    pending: Option<NetworkId>,
}

impl<P: Platform, T: Transport> Client<P, T> {
    /// Loads every stored contact, to talk over one transport per network. Contacts of a
    /// network without one stay idle. Fails if a state does not open under the storage key.
    pub fn open(platform: P, transports: Vec<T>) -> Result<Self, Error> {
        let key = platform.storage_key();
        let store = Store::open(platform.data_dir(), &key)?;
        let now = platform.now();
        let mut client = Client {
            session_key: store::derive(&key, b"", b"janus client session"),
            platform,
            transports,
            store,
            engine: Engine::default(),
            contacts: BTreeMap::new(),
            joining: None,
            pending: None,
        };
        for id in client.store.ids()? {
            let state = client.store.load(&id)?;
            let session = client
                .engine
                .import(&state.session, &client.session_key)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad session"))?;
            let (records, history_len) = client.store.scan(&id)?;
            let entry = Entry {
                session,
                network: state.network,
                name: state.name,
                confirmed: state.confirmed,
                dormant: false,
                next_cover: now.saturating_add(cover_wait()),
                records,
                history_len,
            };
            client.contacts.insert(id, entry);
        }
        client.listen();
        Ok(client)
    }

    /// Adds the transport of a network installed after `open`; one already there is kept.
    pub fn add_transport(&mut self, transport: T) {
        if self.transport(&transport.network()).is_err() {
            self.transports.push(transport);
            self.listen();
        }
    }

    /// A: starts an invitation on `network` and returns the 6 words to read out to B, who must
    /// join on the same network. Replaces any pending handshake. Then tick until
    /// `Event::Answered`.
    pub fn invite(
        &mut self,
        network: &NetworkId,
        interval: Interval,
    ) -> Result<Zeroizing<String>, Error> {
        self.transport(network)?;
        let words = janus_core::words();
        let msg1 = self
            .engine
            .invite(&words, network, interval, self.platform.now())?;
        self.joining = None;
        self.pending = Some(*network);
        self.post(network, &msg1);
        self.listen();
        Ok(words)
    }

    /// B: looks for the invitation of `words` on `network` for `INVITE_TTL`, answering every
    /// one found. Then tick until `Event::Joined`.
    pub fn join(&mut self, network: &NetworkId, words: &str) -> Result<(), Error> {
        self.transport(network)?;
        self.joining = Some(Joining {
            network: *network,
            rendezvous: janus_core::rendezvous(words)?,
            words: Zeroizing::new(words.to_owned()),
            until: self.platform.now().saturating_add(INVITE_TTL),
        });
        self.listen();
        Ok(())
    }

    /// A: opens the contact once the user types the safety words B shows. `Rejected` on a
    /// mismatch: let the user retype, and warn that words that really differ mean someone is
    /// in the middle.
    pub fn verify(&mut self, typed: &str, name: &str) -> Result<String, Error> {
        let network = self.pending.ok_or(janus_core::Error::Rejected)?;
        let session = self.engine.verify(typed, self.platform.now())?;
        self.add(session, network, name, true)
    }

    /// B: unlocks sending once A says the safety words matched, and names the contact.
    pub fn confirm(&mut self, contact: &str, name: &str) -> Result<(), Error> {
        let entry = self
            .contacts
            .get_mut(contact)
            .ok_or(Error::UnknownContact)?;
        self.engine.confirm(entry.session);
        entry.confirmed = true;
        name.clone_into(&mut entry.name);
        Ok(self.save(contact)?)
    }

    pub fn send(&mut self, contact: &str, data: &[u8]) -> Result<(), Error> {
        let entry = self.contacts.get(contact).ok_or(Error::UnknownContact)?;
        if !entry.confirmed {
            return Err(Error::NotConfirmed);
        }
        let network = entry.network;
        self.transport(&network)?;
        let blocks = self
            .engine
            .encrypt(entry.session, data)
            .ok_or(Error::TooLarge)?;
        self.save(contact)?;
        self.append(contact, true, data)?;
        for block in &blocks {
            self.post(&network, block);
        }
        Ok(())
    }

    /// Ends the session on both sides and deletes the contact with its history.
    pub fn close(&mut self, contact: &str) -> Result<(), Error> {
        let entry = self.contacts.remove(contact).ok_or(Error::UnknownContact)?;
        let block = self.engine.close(entry.session);
        self.store.delete(contact)?;
        if let Some(block) = block {
            self.post(&entry.network, &block);
        }
        self.listen();
        Ok(())
    }

    pub fn contacts(&self) -> Vec<Contact> {
        self.contacts
            .iter()
            .map(|(id, e)| Contact {
                id: id.clone(),
                network: e.network,
                name: e.name.clone(),
                confirmed: e.confirmed,
                dormant: e.dormant,
            })
            .collect()
    }

    pub fn history(&self, contact: &str) -> Result<History, Error> {
        if !self.contacts.contains_key(contact) {
            return Err(Error::UnknownContact);
        }
        Ok(self.store.history(contact)?)
    }

    pub fn safety_words(&self, contact: &str) -> Option<String> {
        self.engine
            .safety_words(self.contacts.get(contact)?.session)
    }

    /// Fetches and handles what arrived, then runs the timers. On an error, blocks fetched and
    /// not yet handled are lost, as on a crash.
    pub fn tick(&mut self) -> Result<Vec<Event>, Error> {
        let now = self.platform.now();
        let mut events = Vec::new();
        if self.joining.as_ref().is_some_and(|j| now > j.until) {
            self.joining = None;
        }
        self.listen();
        for i in 0..self.transports.len() {
            let network = self.transports[i].network();
            for block in self.transports[i].poll() {
                self.handle(&network, &block, now, &mut events)?;
            }
        }

        let outgoing = self.engine.outgoing(now);
        let mut touched: Vec<SessionId> = Vec::new();
        for session in outgoing
            .iter()
            .map(|(s, _)| *s)
            .chain(self.engine.purge(now))
        {
            if !touched.contains(&session) {
                touched.push(session);
            }
        }
        for &session in &touched {
            if let Some(id) = self.contact_of(session) {
                self.save(&id)?;
            }
        }
        for (session, block) in &outgoing {
            if let Some(id) = self.contact_of(*session) {
                let network = self.contacts[&id].network;
                self.post(&network, block);
            }
        }

        let dormant = self.engine.dormant(now);
        for (id, entry) in &mut self.contacts {
            let asleep = dormant.contains(&entry.session);
            if asleep != entry.dormant {
                entry.dormant = asleep;
                let contact = id.clone();
                events.push(if asleep {
                    Event::Dormant { contact }
                } else {
                    Event::Awake { contact }
                });
            }
        }

        let due: Vec<String> = self
            .contacts
            .iter()
            .filter(|(_, e)| e.confirmed && !e.dormant && now >= e.next_cover)
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            let entry = self.contacts.get_mut(&id).expect("just listed");
            entry.next_cover = now.saturating_add(cover_wait());
            let (session, network) = (entry.session, entry.network);
            if let Some(block) = self.engine.cover(session) {
                self.save(&id)?;
                self.post(&network, &block);
            }
        }
        self.listen();
        Ok(events)
    }

    fn handle(
        &mut self,
        network: &NetworkId,
        block: &Block,
        now: u64,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if let Some((session, received)) = self.engine.receive(block, now) {
            let id = self
                .contact_of(session)
                .expect("every session belongs to a contact");
            match received {
                Received::Message(data) => {
                    self.append(&id, false, &data)?;
                    self.save(&id)?;
                    if self.contacts[&id].confirmed {
                        events.push(Event::Message { contact: id, data });
                    }
                }
                Received::Nothing => self.save(&id)?,
                Received::Closed => {
                    self.contacts.remove(&id);
                    self.store.delete(&id)?;
                    events.push(Event::Closed { contact: id });
                }
            }
            return Ok(());
        }
        if let Some(joining) = &self.joining
            && joining.network == *network
            && block.starts_with(&joining.rendezvous)
        {
            // Unrelated invitations can share the queue: answer them all.
            if let Ok(msg2) = self.engine.respond(&joining.words, network, block, now) {
                self.pending = Some(*network);
                self.post(network, &msg2);
            }
            return Ok(());
        }
        if self.pending != Some(*network) {
            return Ok(());
        }
        if let Ok(msg3) = self.engine.finish_invite(block, now) {
            self.post(network, &msg3);
            events.push(Event::Answered);
        } else if let Ok(session) = self.engine.finish_response(block, now) {
            self.joining = None;
            let safety_words = self.engine.safety_words(session).expect("just established");
            let contact = self.add(session, *network, "", false)?;
            events.push(Event::Joined {
                contact,
                safety_words,
            });
        }
        Ok(())
    }

    fn add(
        &mut self,
        session: SessionId,
        network: NetworkId,
        name: &str,
        confirmed: bool,
    ) -> Result<String, Error> {
        let id = store::new_id();
        let entry = Entry {
            session,
            network,
            name: name.to_owned(),
            confirmed,
            dormant: false,
            next_cover: self.platform.now().saturating_add(cover_wait()),
            records: 0,
            history_len: 0,
        };
        self.contacts.insert(id.clone(), entry);
        if let Err(e) = self.save(&id) {
            self.contacts.remove(&id);
            self.engine.remove(session);
            return Err(e.into());
        }
        self.listen();
        Ok(id)
    }

    fn save(&self, id: &str) -> io::Result<()> {
        let entry = &self.contacts[id];
        let session = self
            .engine
            .export(entry.session, &self.session_key)
            .expect("contacts hold live sessions");
        self.store.save(
            id,
            &State {
                network: entry.network,
                confirmed: entry.confirmed,
                name: entry.name.clone(),
                session: Zeroizing::new(session),
            },
        )
    }

    fn append(&mut self, id: &str, mine: bool, data: &[u8]) -> io::Result<()> {
        let entry = self.contacts.get_mut(id).expect("a known contact");
        entry.history_len = self
            .store
            .append(id, entry.records, entry.history_len, mine, data)?;
        entry.records += 1;
        Ok(())
    }

    fn transport(&self, network: &NetworkId) -> Result<usize, Error> {
        self.transports
            .iter()
            .position(|t| t.network() == *network)
            .ok_or(Error::UnknownNetwork)
    }

    /// Blocks for a network without a transport are dropped, as on a network that loses them.
    fn post(&mut self, network: &NetworkId, block: &Block) {
        crash_point();
        if let Ok(i) = self.transport(network) {
            self.transports[i].post(block);
        }
    }

    fn listen(&mut self) {
        for transport in &mut self.transports {
            let network = transport.network();
            let mut queues = Vec::new();
            if self.pending == Some(network) {
                queues.extend(self.engine.pending_queues());
            }
            for joining in self.joining.iter().filter(|j| j.network == network) {
                queues.push(joining.rendezvous);
            }
            for entry in self.contacts.values().filter(|e| e.network == network) {
                queues.extend(self.engine.queue_ids(entry.session).unwrap_or_default());
            }
            transport.listen(&queues);
        }
    }

    fn contact_of(&self, session: SessionId) -> Option<String> {
        self.contacts
            .iter()
            .find(|(_, e)| e.session == session)
            .map(|(id, _)| id.clone())
    }
}

/// Installs a network profile read from a file or a QR code, and returns it. Make it a
/// deliberate step of the user's, from a source they verified: a substituted profile would route
/// them through an attacker's servers. Installing a profile again changes nothing.
pub fn install_network(platform: &impl Platform, profile: &[u8]) -> Result<Network, Error> {
    let network = Network::from_bytes(profile).ok_or(Error::BadProfile)?;
    store::save_network(&platform.data_dir(), &platform.storage_key(), &network)?;
    Ok(network)
}

/// The installed network profiles, to build each one's transport before `Client::open`.
pub fn networks(platform: &impl Platform) -> Result<Vec<Network>, Error> {
    Ok(store::networks(
        &platform.data_dir(),
        &platform.storage_key(),
    )?)
}

/// Exponentially distributed, so cover blocks form no pattern.
fn cover_wait() -> u64 {
    let r = u64::from_be_bytes(store::random());
    let uniform = (r >> 11) as f64 / (1u64 << 53) as f64;
    (-(1.0 - uniform).ln() * COVER_MEAN as f64) as u64
}

#[cfg(not(test))]
fn crash_point() {}

#[cfg(test)]
use tests::crash_point;
