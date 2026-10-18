//! UniFFI bindings over `janus-client`, the one interface the Swift and Kotlin apps see.
//!
//! The app implements [`Platform`] and creates a [`Client`]; then it calls `tick` about once a
//! second and on every wake-up, and shows the events. Every call can wait on the network, so
//! the app makes them off its UI thread, one at a time. Contacts and networks are ids
//! (strings), messages are bytes. Generate the bindings with `make bindings`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use janus_core::{Interval, Key, NetworkId};
use janus_transport::{Direct, Mixnet, SLOT, Transport, katzenpost};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

/// What the app provides from its operating system; see `janus_client::Platform`.
#[uniffi::export(with_foreign)]
pub trait Platform: Send + Sync {
    /// 32 random bytes, the same on every call, wrapped by the Secure Enclave or Keystore.
    fn storage_key(&self) -> Vec<u8>;
    /// Milliseconds of a monotonic clock that keeps counting during sleep
    /// (`mach_continuous_time`, `elapsedRealtime`), never the wall clock.
    fn now_ms(&self) -> u64;
    /// A directory only this app reads, excluded from backups.
    fn data_dir(&self) -> String;
}

#[derive(Clone)]
struct Foreign {
    platform: Arc<dyn Platform>,
    key: Zeroizing<Key>,
}

impl Foreign {
    fn new(platform: Arc<dyn Platform>) -> Result<Foreign, JanusError> {
        let key = Zeroizing::new(platform.storage_key());
        let key = Zeroizing::new(Key::try_from(&key[..]).map_err(|_| JanusError::BadKey)?);
        Ok(Foreign { platform, key })
    }

    /// The transport of an installed network: our Katzenpost client under the mixnet's
    /// constant-rate requests.
    fn mixnet(&self, network: janus_transport::Network) -> Box<dyn Transport + Send> {
        let platform = Arc::clone(&self.platform);
        let clock = move || platform.now_ms();
        let id = network.id();
        let link = katzenpost::Client::new(network, clock.clone(), wall_clock);
        Box::new(Mixnet::new(id, link, SLOT, clock))
    }
}

impl janus_client::Platform for Foreign {
    fn storage_key(&self) -> Zeroizing<Key> {
        self.key.clone()
    }

    fn now(&self) -> u64 {
        self.platform.now_ms() / 1000
    }

    fn data_dir(&self) -> PathBuf {
        self.platform.data_dir().into()
    }
}

/// Seconds since 1970, only for Katzenpost's epochs; the core never sees it.
fn wall_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Debug, uniffi::Error)]
pub enum JanusError {
    Storage {
        reason: String,
    },
    /// The storage key is not 32 bytes.
    BadKey,
    /// The interval is not 1, 5, 10 or 120 hours.
    BadInterval,
    BadWords,
    Expired,
    Rejected,
    UnknownContact,
    NotConfirmed,
    TooLarge,
    UnknownNetwork,
    BadProfile,
}

impl std::fmt::Display for JanusError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for JanusError {}

impl From<janus_client::Error> for JanusError {
    fn from(e: janus_client::Error) -> JanusError {
        use janus_client::Error as E;
        match e {
            E::Io(e) => JanusError::Storage {
                reason: e.to_string(),
            },
            E::Handshake(janus_core::Error::BadWords) => JanusError::BadWords,
            E::Handshake(janus_core::Error::Expired) => JanusError::Expired,
            E::Handshake(janus_core::Error::Rejected) => JanusError::Rejected,
            E::UnknownContact => JanusError::UnknownContact,
            E::NotConfirmed => JanusError::NotConfirmed,
            E::TooLarge => JanusError::TooLarge,
            E::UnknownNetwork => JanusError::UnknownNetwork,
            E::BadProfile => JanusError::BadProfile,
        }
    }
}

/// See `janus_client::Event`.
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Event {
    Answered,
    Joined {
        contact: String,
        safety_words: String,
    },
    Message {
        contact: String,
        data: Vec<u8>,
    },
    Closed {
        contact: String,
    },
    Dormant {
        contact: String,
    },
    Awake {
        contact: String,
    },
}

impl From<janus_client::Event> for Event {
    fn from(e: janus_client::Event) -> Event {
        use janus_client::Event as E;
        match e {
            E::Answered => Event::Answered,
            E::Joined {
                contact,
                safety_words,
            } => Event::Joined {
                contact,
                safety_words,
            },
            E::Message { contact, data } => Event::Message {
                contact,
                data: data.to_vec(),
            },
            E::Closed { contact } => Event::Closed { contact },
            E::Dormant { contact } => Event::Dormant { contact },
            E::Awake { contact } => Event::Awake { contact },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Contact {
    pub id: String,
    /// The id of its network, from `Client::networks`.
    pub network: String,
    pub name: String,
    pub confirmed: bool,
    pub dormant: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct HistoryEntry {
    pub mine: bool,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NetworkInfo {
    /// Hex of the network id, the same on every device with this network.
    pub id: String,
    /// Shown to users; never trusted, since anyone can pick any name.
    pub name: String,
}

impl NetworkInfo {
    fn new(id: &NetworkId, name: &str) -> NetworkInfo {
        NetworkInfo {
            id: hex(id),
            name: name.to_owned(),
        }
    }
}

/// A `janus-mailbox` server reached over TLS, for development only: it sees client addresses.
#[derive(Debug, uniffi::Record)]
pub struct DevMailbox {
    /// `host:port`.
    pub address: String,
    /// The certificate it wrote at startup (DER), the only one trusted.
    pub cert: Vec<u8>,
}

const DEV_MAILBOX_NAME: &str = "Development mailbox";

/// Reads a network profile from a file or QR code without installing it, to show the user
/// what they are about to install.
#[uniffi::export]
pub fn read_network(profile: Vec<u8>) -> Result<NetworkInfo, JanusError> {
    let network = janus_transport::Network::from_bytes(&profile).ok_or(JanusError::BadProfile)?;
    Ok(NetworkInfo::new(&network.id(), network.name()))
}

type Inner = janus_client::Client<Foreign, Box<dyn Transport + Send>>;

struct State {
    client: Inner,
    /// One per transport, in the order they were added.
    networks: Vec<(NetworkId, NetworkInfo)>,
}

#[derive(uniffi::Object)]
pub struct Client {
    state: Mutex<State>,
    foreign: Foreign,
}

#[uniffi::export]
impl Client {
    /// Opens the stored contacts on every installed network and, if given, the development
    /// mailbox.
    #[uniffi::constructor]
    pub fn new(
        platform: Arc<dyn Platform>,
        dev_mailbox: Option<DevMailbox>,
    ) -> Result<Arc<Client>, JanusError> {
        let foreign = Foreign::new(platform)?;
        let mut transports = Vec::new();
        let mut networks = Vec::new();
        if let Some(dev) = dev_mailbox {
            let direct = Direct::new(&dev.address, &dev.cert).map_err(|e| JanusError::Storage {
                reason: e.to_string(),
            })?;
            networks.push((
                direct.network(),
                NetworkInfo::new(&direct.network(), DEV_MAILBOX_NAME),
            ));
            transports.push(Box::new(direct) as Box<dyn Transport + Send>);
        }
        for network in janus_client::networks(&foreign)? {
            networks.push((
                network.id(),
                NetworkInfo::new(&network.id(), network.name()),
            ));
            transports.push(foreign.mixnet(network));
        }
        let client = janus_client::Client::open(foreign.clone(), transports)?;
        Ok(Arc::new(Client {
            state: Mutex::new(State { client, networks }),
            foreign,
        }))
    }

    /// The networks this client reaches, the development mailbox first if it was given.
    pub fn networks(&self) -> Vec<NetworkInfo> {
        self.lock()
            .networks
            .iter()
            .map(|(_, n)| n.clone())
            .collect()
    }

    /// Installs a network profile read from a file or QR code and starts using it. Make it a
    /// deliberate step of the user's, from a source they verified (see `read_network`).
    pub fn install_network(&self, profile: Vec<u8>) -> Result<NetworkInfo, JanusError> {
        let network = janus_client::install_network(&self.foreign, &profile)?;
        let id = network.id();
        let info = NetworkInfo::new(&id, network.name());
        let mut state = self.lock();
        if !state.networks.iter().any(|(n, _)| *n == id) {
            state.client.add_transport(self.foreign.mixnet(network));
            state.networks.push((id, info.clone()));
        }
        Ok(info)
    }

    /// A: returns the 6 words to read out to B, who must answer on the same network.
    pub fn invite(&self, network: String, interval_hours: u8) -> Result<String, JanusError> {
        let interval = match interval_hours {
            1 => Interval::H1,
            5 => Interval::H5,
            10 => Interval::H10,
            120 => Interval::H120,
            _ => return Err(JanusError::BadInterval),
        };
        let mut state = self.lock();
        let network = state.network(&network)?;
        Ok(state.client.invite(&network, interval)?.to_string())
    }

    pub fn join(&self, network: String, words: String) -> Result<(), JanusError> {
        let mut state = self.lock();
        let network = state.network(&network)?;
        Ok(state.client.join(&network, &words)?)
    }

    /// A: returns the new contact's id.
    pub fn verify(&self, typed: String, name: String) -> Result<String, JanusError> {
        Ok(self.lock().client.verify(&typed, &name)?)
    }

    pub fn confirm(&self, contact: String, name: String) -> Result<(), JanusError> {
        Ok(self.lock().client.confirm(&contact, &name)?)
    }

    pub fn send(&self, contact: String, data: Vec<u8>) -> Result<(), JanusError> {
        Ok(self.lock().client.send(&contact, &data)?)
    }

    pub fn close(&self, contact: String) -> Result<(), JanusError> {
        Ok(self.lock().client.close(&contact)?)
    }

    pub fn tick(&self) -> Result<Vec<Event>, JanusError> {
        Ok(self
            .lock()
            .client
            .tick()?
            .into_iter()
            .map(Event::from)
            .collect())
    }

    pub fn contacts(&self) -> Vec<Contact> {
        self.lock()
            .client
            .contacts()
            .into_iter()
            .map(|c| Contact {
                id: c.id,
                network: hex(&c.network),
                name: c.name,
                confirmed: c.confirmed,
                dormant: c.dormant,
            })
            .collect()
    }

    pub fn history(&self, contact: String) -> Result<Vec<HistoryEntry>, JanusError> {
        Ok(self
            .lock()
            .client
            .history(&contact)?
            .into_iter()
            .map(|(mine, data)| HistoryEntry {
                mine,
                data: data.to_vec(),
            })
            .collect())
    }

    pub fn safety_words(&self, contact: String) -> Option<String> {
        self.lock().client.safety_words(&contact)
    }
}

impl Client {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Safe to go on after a panic: memory is never behind disk, and every post follows a save.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl State {
    fn network(&self, id: &str) -> Result<NetworkId, JanusError> {
        self.networks
            .iter()
            .find(|(_, n)| n.id == id)
            .map(|(n, _)| *n)
            .ok_or(JanusError::UnknownNetwork)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
