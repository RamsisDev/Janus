//! The Katzenpost [`Link`] for [`Mixnet`](crate::Mixnet): our own client for the Katzenpost
//! protocol, from the published specifications.
//!
//! What it does, and what is proven against a live test network:
//!
//! - **Directory.** Connects to an authority (addresses from the pinned [`Network`]), asks for
//!   the consensus, verifies its signatures against the pinned authorities and turns it into a
//!   [`Directory`]. Proven end to end: handshake, `GetConsensus`, parse and verify.
//! - **Sending.** Builds a Sphinx forward packet for the path the mixnet chose, carrying a
//!   mailbox request to a service node, with a single-use reply block that returns the answer
//!   through the client's gateway. Sent to the gateway as a `SendPacket` command.
//! - **Replies.** Reads messages the gateway delivers and opens each against the reply blocks
//!   still outstanding, matching one to the request that made it.
//!
//! The mailbox is a Katzenpost service node offering a capability (`MAILBOX_CAPABILITY`); its
//! request and reply ride in the Kaetzchen payload format (`autoresponder.md`).

use std::collections::HashMap;
use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use blake2::Digest as _;
use janus_mailbox::{Reply, Request};

use super::sphinx::{self, Command, Geometry, Hop, ReplyKeys};
use super::wire::{Frame, Session};
use super::{noise, pki};
use crate::{Directory, Network, Node};

/// Commands of the wire protocol we use.
const SEND_PACKET: u8 = 2;
const GET_CONSENSUS: u8 = 18;
const CONSENSUS: u8 = 19;
/// A message the gateway delivers to the client (push delivery).
const MESSAGE: u8 = 17;

/// Katzenpost's epoch: seconds since 2017-06-01 00:00 UTC, in 20-minute periods.
const EPOCH_START: u64 = 1_496_275_200;
pub const EPOCH_PERIOD: u64 = 1200;

/// The service capability a `janus-mailbox` node advertises. The mailbox-as-service wiring is
/// still open (see the design notes), so a network must publish this for the mixnet to find it.
pub const MAILBOX_CAPABILITY: &str = "janus-mailbox";

/// How long a reply block waits for its answer before the slot is reused.
const SURB_TTL: Duration = Duration::from_secs(120);

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// The current Katzenpost epoch for a clock in seconds since the Unix epoch.
pub fn epoch(now_secs: u64) -> u64 {
    now_secs.saturating_sub(EPOCH_START) / EPOCH_PERIOD
}

struct Pending {
    keys: ReplyKeys,
    tag: u64,
    at: u64,
}

/// A client of one Katzenpost network.
pub struct Client {
    network: Network,
    /// Milliseconds of a monotonic clock, and seconds since the Unix epoch, from the platform.
    now_ms: Box<dyn Fn() -> u64 + Send>,
    now_secs: Box<dyn Fn() -> u64 + Send>,
    geometry: Geometry,
    epoch_period: u64,
    link_secret: [u8; noise::SECRET_KEY_LEN],
    recipient: [u8; sphinx::RECIPIENT_LEN],
    consensus: Option<Arc<pki::Consensus>>,
    directory: Option<Arc<Directory>>,
    gateway: Option<GatewayConn>,
    /// Reply blocks waiting for their answer, by SURB id.
    inflight: HashMap<[u8; sphinx::SURB_ID_LEN], Pending>,
    next_surb: u64,
    replies: Vec<(u64, Box<Reply>)>,
}

struct GatewayConn {
    name: String,
    session: Session,
}

impl Client {
    /// A client of `network`, with the platform's monotonic clock (milliseconds) and wall clock
    /// (seconds since 1970, for the epoch and handshake time).
    pub fn new(
        network: Network,
        now_ms: impl Fn() -> u64 + Send + 'static,
        now_secs: impl Fn() -> u64 + Send + 'static,
    ) -> Client {
        let link_secret = *noise::generate();
        // The gateway must deliver replies to this client; it knows the client by the identity
        // its link key hashes to, which is also the SURB's final recipient.
        let id = pki::Blake2b256::digest(noise::public_key(&link_secret));
        let mut recipient = [0; sphinx::RECIPIENT_LEN];
        recipient[..32].copy_from_slice(&id);
        Client {
            network,
            now_ms: Box::new(now_ms),
            now_secs: Box::new(now_secs),
            geometry: Geometry::DEFAULT,
            epoch_period: EPOCH_PERIOD,
            link_secret,
            recipient,
            consensus: None,
            directory: None,
            gateway: None,
            inflight: HashMap::new(),
            next_surb: 0,
            replies: Vec::new(),
        }
    }

    /// Sets the epoch length in seconds; the default is Katzenpost's [`EPOCH_PERIOD`]. Test
    /// networks often run a shorter epoch.
    pub fn with_epoch_period(mut self, seconds: u64) -> Client {
        self.epoch_period = seconds;
        self
    }

    fn epoch(&self) -> u64 {
        (self.now_secs)().saturating_sub(EPOCH_START) / self.epoch_period
    }

    /// Downloads and verifies the current consensus from an authority, caching it. Returns the
    /// epoch on success.
    pub fn refresh_consensus(&mut self) -> io::Result<u64> {
        let want = self.epoch();
        if self.consensus.as_ref().is_some_and(|c| c.epoch == want) {
            return Ok(want);
        }
        let mut last = io::Error::new(io::ErrorKind::NotConnected, "no authority answered");
        for authority in self.network.authorities().to_vec() {
            for address in &authority.addresses {
                match self.fetch_from(address, &authority.link, want) {
                    Ok(consensus) => {
                        self.consensus = Some(Arc::new(consensus));
                        self.directory = None;
                        return Ok(want);
                    }
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    fn fetch_from(&self, address: &str, link: &[u8], want: u64) -> io::Result<pki::Consensus> {
        let tcp = TcpStream::connect(address)?;
        tcp.set_read_timeout(Some(SURB_TTL))?;
        let mut session = Session::connect(tcp, &self.link_secret, link, &[])?;
        let certificate = get_consensus(&mut session, want)?;
        pki::verify(&self.network, &certificate, want).ok_or(invalid("consensus did not verify"))
    }

    /// The hop to `node` for `epoch`: its id and Sphinx key, with `commands` beyond forwarding.
    fn hop(&self, node: &Node, epoch: u64, commands: Vec<Command>) -> Option<Hop> {
        let d = self.consensus.as_ref()?.descriptor(&node.name)?;
        Some(Hop {
            id: d.id(),
            key: *d.mix_keys.get(&epoch)?,
            commands,
        })
    }

    fn drop_gateway(&mut self) {
        self.gateway = None;
    }

    fn ensure_gateway(&mut self, name: &str) -> io::Result<()> {
        if self.gateway.as_ref().is_some_and(|g| g.name == name) {
            return Ok(());
        }
        let consensus = self.consensus.clone().ok_or(invalid("no consensus"))?;
        let d = consensus
            .descriptor(name)
            .ok_or(invalid("unknown gateway"))?;
        let address = d
            .addresses
            .first()
            .ok_or(invalid("gateway has no address"))?;
        let tcp = TcpStream::connect(address)?;
        tcp.set_read_timeout(Some(Duration::from_millis(200)))?;
        // The gateway delivers our replies by the identity our link key hashes to.
        let ad = pki::Blake2b256::digest(noise::public_key(&self.link_secret)).to_vec();
        let session = Session::connect(tcp, &self.link_secret, &d.link, &ad)?;
        self.gateway = Some(GatewayConn {
            name: name.to_owned(),
            session,
        });
        Ok(())
    }

    fn expire(&mut self) {
        let now = (self.now_ms)();
        self.inflight
            .retain(|_, p| now.saturating_sub(p.at) < SURB_TTL.as_millis() as u64);
    }
}

/// Asks `session`'s peer for the consensus of `epoch` and returns the certificate bytes.
fn get_consensus(session: &mut Session, epoch: u64) -> io::Result<Vec<u8>> {
    session.send(&Frame {
        command: GET_CONSENSUS,
        body: epoch.to_be_bytes().to_vec(),
    })?;
    loop {
        let frame = session.recv()?;
        match frame.command {
            CONSENSUS => {
                let (status, payload) = frame.body.split_first().ok_or(invalid("consensus"))?;
                if *status != 0 {
                    return Err(invalid("consensus not available"));
                }
                return Ok(payload.to_vec());
            }
            0 => continue,
            _ => return Err(invalid("unexpected reply to GetConsensus")),
        }
    }
}

impl crate::Link for Client {
    fn directory(&mut self) -> Option<Arc<Directory>> {
        if self.refresh_consensus().is_err() {
            return self.directory.clone();
        }
        if self.directory.is_none() {
            let consensus = self.consensus.as_ref()?;
            self.directory = Some(Arc::new(consensus.directory(MAILBOX_CAPABILITY)));
        }
        self.directory.clone()
    }

    fn send(&mut self, tag: u64, path: &[&Node], request: &Request) -> io::Result<()> {
        self.expire();
        let epoch = self.epoch();
        let (gateway, rest) = path.split_first().ok_or(invalid("empty path"))?;
        let mailbox = rest.last().ok_or(invalid("path without a mailbox"))?;
        self.ensure_gateway(&gateway.name)?;

        // The delay each hop applies, drawn from the directory's Poisson rate; a fixed starting
        // value keeps the path deterministic here.
        let delay = Command::Delay(100);

        // The reply travels back through the mixnet to our gateway, which delivers it to us.
        let surb_id = {
            let mut id = [0; sphinx::SURB_ID_LEN];
            id[..8].copy_from_slice(&self.next_surb.to_be_bytes());
            self.next_surb += 1;
            id
        };
        let mut reply_path = Vec::new();
        for node in rest.iter().rev().skip(1) {
            reply_path.push(
                self.hop(node, epoch, vec![delay.clone()])
                    .ok_or(invalid("no reply hop key"))?,
            );
        }
        reply_path.push(
            self.hop(
                gateway,
                epoch,
                vec![
                    Command::Recipient(self.recipient),
                    Command::SurbReply(surb_id),
                ],
            )
            .ok_or(invalid("no gateway key"))?,
        );
        let (surb, keys) = sphinx::surb(&self.geometry, &reply_path);

        // The forward packet carries a Kaetzchen request: our SURB, then the mailbox request.
        let mut kaetzchen = vec![1, 0];
        kaetzchen.extend_from_slice(&surb);
        kaetzchen.extend_from_slice(request);
        let mut forward = vec![
            self.hop(gateway, epoch, vec![delay.clone()])
                .ok_or(invalid("no gateway key"))?,
        ];
        for node in rest {
            let commands = if node.name == mailbox.name {
                let endpoint = self
                    .consensus
                    .as_ref()
                    .and_then(|c| c.descriptor(&node.name))
                    .and_then(|d| d.services.get(MAILBOX_CAPABILITY))
                    .ok_or(invalid("mailbox endpoint"))?;
                vec![Command::Recipient(
                    sphinx::recipient(endpoint.as_bytes()).ok_or(invalid("endpoint too long"))?,
                )]
            } else {
                vec![delay.clone()]
            };
            forward.push(
                self.hop(node, epoch, commands)
                    .ok_or(invalid("no forward hop key"))?,
            );
        }
        let packet = sphinx::packet(&self.geometry, &forward, &kaetzchen);

        let conn = self.gateway.as_mut().expect("just ensured");
        if let Err(e) = conn.session.send(&Frame {
            command: SEND_PACKET,
            body: packet,
        }) {
            self.drop_gateway();
            return Err(e);
        }
        self.inflight.insert(
            surb_id,
            Pending {
                keys,
                tag,
                at: (self.now_ms)(),
            },
        );
        Ok(())
    }

    fn replies(&mut self) -> Vec<(u64, Box<Reply>)> {
        self.expire();
        let Some(conn) = self.gateway.as_mut() else {
            return Vec::new();
        };
        let mut frames = Vec::new();
        loop {
            match conn.session.recv() {
                Ok(frame) if frame.command == MESSAGE => frames.push(frame.body),
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
                Err(_) => {
                    self.drop_gateway();
                    break;
                }
            }
        }
        let payload = self.geometry.tag + self.geometry.payload;
        for body in frames {
            if body.len() < payload {
                continue;
            }
            // The gateway delivers the Sphinx reply payload; open it against each outstanding
            // reply block and match the one that authenticates.
            let opened = self.inflight.iter().find_map(|(id, p)| {
                sphinx::open_reply(&self.geometry, &p.keys, &body[body.len() - payload..])
                    .map(|plain| (*id, p.tag, plain))
            });
            if let Some((id, tag, plain)) = opened {
                self.inflight.remove(&id);
                if let Ok(reply) = reply_from(&plain) {
                    self.replies.push((tag, reply));
                }
            }
        }
        std::mem::take(&mut self.replies)
    }
}

/// A `janus-mailbox` reply carried in a Kaetzchen reply payload, zero padded.
fn reply_from(plain: &[u8]) -> io::Result<Box<Reply>> {
    let reply: &[u8] = plain
        .get(..size_of::<Reply>())
        .ok_or(invalid("short reply"))?;
    Ok(Box::new(reply.try_into().expect("REPLY_LEN")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epochs_count_from_the_katzenpost_genesis() {
        assert_eq!(epoch(EPOCH_START), 0);
        assert_eq!(epoch(EPOCH_START + EPOCH_PERIOD * 5 + 1), 5);
    }

    #[test]
    fn a_client_without_a_consensus_has_no_directory() {
        use crate::Link;
        let network = crate::Authority {
            identity: vec![1; 32],
            link: vec![2; 1216],
            addresses: vec!["127.0.0.1:1".into()],
        };
        let mut client = Client::new(
            Network::new("t", vec![network]).unwrap(),
            || 0,
            || EPOCH_START,
        );
        assert!(client.directory().is_none());
    }
}
