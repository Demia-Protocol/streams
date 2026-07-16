// Rust
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};

// 3rd-party
use async_trait::async_trait;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// IOTA

// Streams

// Local
use crate::id::{Ed25519Pub, Ed25519Sig};
use crate::{
    address::Address,
    error::{Error, Result},
    message::TransportMessage,
    transport::{MessageStore, Transport},
};

/// A sealed, ready-to-broadcast message captured in the write (outbox) mapping.
///
/// Unlike the read mapping, the outbox must retain the public key and signature
/// produced at seal time, because the network send handler needs the full wire
/// tuple to broadcast without any access to the originating identity.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Sealed<Msg> {
    /// The sealed (encrypted + signed) transport message.
    pub msg: Msg,
    /// The signing public key, stored as raw bytes (32).
    pub public_key: Vec<u8>,
    /// The detached signature, stored as raw bytes (64).
    pub signature: Vec<u8>,
}

/// Split read/outbox transport client backing the queue-based network send pipeline.
///
/// Unlike [`bucket::Client`](crate::transport::bucket::Client) (a single-map in-memory loopback
/// for tests), this client holds two independent mappings:
/// - `read`: confirmed messages. All normal `recv`/`sync` traffic reads from here.
/// - `write`: an outbox of locally-sealed messages awaiting broadcast. `send_message`
///   captures into here; the network send handler drains it; [`push_to_reading`] purges
///   an entry once it has round-tripped back as a confirmed message.
///
/// The write mapping is invisible to `recv` by default. It is only consulted when
/// `include_write_in_recv` is set, which is done exclusively around a "sync_all" pass so
/// that, immediately before sealing new sends, the user's frontier accounts for the
/// undrained tail and cannot fork the branch.
///
/// [`push_to_reading`]: Client::push_to_reading
// Use BTreeMap instead of HashMap to stay nostd without pulling hashbrown.
#[derive(Clone, Debug)]
pub struct Client<Msg = TransportMessage> {
    /// Confirmed messages, read by all normal `recv`/`sync` traffic.
    read: Arc<spin::RwLock<BTreeMap<Address, Vec<Msg>>>>,
    /// Outbox of locally-sealed messages awaiting broadcast.
    write: Arc<spin::RwLock<BTreeMap<Address, Vec<Sealed<Msg>>>>>,
    /// When set, `recv` falls through to the write mapping on a read miss.
    /// Per-instance (copied on clone); the maps remain shared via `Arc`.
    include_write_in_recv: bool,
    /// When set, `send_message` captures into the write (outbox) mapping. When unset
    /// (the default), the client behaves as a legacy in-memory loopback: `send_message`
    /// writes into the read mapping so `recv` sees it immediately. Existing protocol
    /// tests and examples rely on the loopback default; the SDK/USM enable outbox mode.
    outbox_mode: bool,
}

impl<Msg> Client<Msg> {
    /// Creates a new [Bucket Client](`Client`) in legacy loopback mode.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new [Bucket Client](`Client`) with outbox mode enabled, so
    /// `send_message` captures sealed messages into the write (outbox) mapping rather
    /// than the read mapping.
    pub fn new_outbox() -> Self {
        let mut client = Self::default();
        client.outbox_mode = true;
        client
    }

    /// Toggle whether `send_message` captures into the outbox (write) mapping.
    pub fn set_outbox_mode(&mut self, on: bool) {
        self.outbox_mode = on;
    }

    /// Whether `send_message` currently captures into the outbox mapping.
    pub fn outbox_mode(&self) -> bool {
        self.outbox_mode
    }

    /// Toggle whether `recv`/`sync` falls through to the write (outbox) mapping.
    ///
    /// Default is `false`. Set to `true` only for the duration of a "sync_all" pass
    /// run immediately before sealing new sends, then reset to `false`.
    pub fn set_recv_include_write(&mut self, include: bool) {
        self.include_write_in_recv = include;
    }

    /// Whether `recv` currently falls through to the write mapping.
    pub fn recv_includes_write(&self) -> bool {
        self.include_write_in_recv
    }
}

impl<Msg: Clone> Client<Msg> {
    /// Deposit a confirmed message into the read mapping, bypassing the outbox.
    ///
    /// This is the path the SQL handler uses to populate the read bucket from the
    /// network mirror. It is deliberately *not* `send_message` (which targets the
    /// outbox). Dedup is checked against the read mapping directly (never via `recv`,
    /// which may be falling through to the outbox during a concurrent sync_all).
    ///
    /// If the same address is sitting in the outbox as a pending send, it is removed:
    /// the message having round-tripped back as confirmed *is* its delivery ack.
    ///
    /// Returns `true` if the message was newly inserted into the read mapping.
    pub fn push_to_reading(&mut self, address: Address, msg: Msg) -> bool {
        // Always purge any pending outbox entry for this address: confirmation.
        self.write.write().remove(&address);

        let mut read = self.read.write();
        if read.contains_key(&address) {
            return false;
        }
        read.entry(address).or_default().push(msg);
        true
    }

    /// Snapshot the outbox for the send handler to broadcast.
    ///
    /// Returns the full wire tuple for every pending message. This is a *copy* — entries
    /// are not removed here; removal happens via [`push_to_reading`](Client::push_to_reading)
    /// once the message round-trips back as confirmed.
    pub fn outbox_snapshot(&self) -> Vec<(Address, Msg, Ed25519Pub, Ed25519Sig)> {
        let write = self.write.read();
        let mut out = Vec::new();
        for (address, sealed_msgs) in write.iter() {
            for sealed in sealed_msgs {
                let pk = to_pub(&sealed.public_key);
                let sig = to_sig(&sealed.signature);
                out.push((*address, sealed.msg.clone(), pk, sig));
            }
        }
        out
    }

    /// Number of messages currently pending in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.write.read().values().map(|v| v.len()).sum()
    }

    /// Deep-copy both mappings into a fully independent client (new `Arc`s), preserving
    /// mode flags. Use this to materialise an isolated session snapshot — e.g. to model
    /// rebuilding a user from persisted bucket state without sharing the live maps.
    pub fn deep_clone(&self) -> Self {
        Self {
            read: Arc::new(spin::RwLock::new(self.read.read().clone())),
            write: Arc::new(spin::RwLock::new(self.write.read().clone())),
            include_write_in_recv: self.include_write_in_recv,
            outbox_mode: self.outbox_mode,
        }
    }
}

impl<Msg> MessageStore for Client<Msg>
where
    Msg: Clone,
{
    type Msg = Msg;

    fn store_message(&mut self, address: Address, msg: Msg) -> bool {
        self.push_to_reading(address, msg)
    }
}

impl<Msg> Default for Client<Msg> {
    // Implement default manually because derive puts Default bounds in type parameters
    fn default() -> Self {
        Self {
            read: Arc::new(spin::RwLock::new(BTreeMap::default())),
            write: Arc::new(spin::RwLock::new(BTreeMap::default())),
            include_write_in_recv: false,
            outbox_mode: false,
        }
    }
}

/// Reconstruct a public key from stored bytes, falling back to a zero key on a malformed
/// entry (outbox bytes always come from `to_bytes`, so this is purely defensive).
fn to_pub(bytes: &[u8]) -> Ed25519Pub {
    <[u8; 32]>::try_from(bytes)
        .ok()
        .and_then(|b| Ed25519Pub::try_from_bytes(b).ok())
        .unwrap_or_else(|| Ed25519Pub::try_from_bytes([0u8; 32]).unwrap())
}

/// Reconstruct a signature from stored bytes, falling back to a zero signature on a
/// malformed entry.
fn to_sig(bytes: &[u8]) -> Ed25519Sig {
    <[u8; 64]>::try_from(bytes)
        .map(Ed25519Sig::from_bytes)
        .unwrap_or_else(|_| Ed25519Sig::from_bytes([0u8; 64]))
}

#[async_trait]
impl<Msg> Transport<'_> for Client<Msg>
where
    Msg: Clone + Send + Sync + PartialEq,
{
    type Msg = Msg;
    type SendResponse = Msg;

    /// Capture a sealed message into the write (outbox) mapping and return it.
    ///
    /// The public key and signature are retained (as bytes) so the send handler can
    /// broadcast the full wire tuple later without the originating identity.
    async fn send_message(
        &mut self,
        addr: Address,
        msg: Msg,
        public_key: Ed25519Pub,
        signature: Ed25519Sig,
    ) -> Result<Msg>
    where
        Self::Msg: 'async_trait,
    {
        if self.outbox_mode {
            self.write.write().entry(addr).or_default().push(Sealed {
                msg: msg.clone(),
                public_key: public_key.to_bytes().to_vec(),
                signature: signature.to_bytes().to_vec(),
            });
        } else {
            // Legacy loopback: send is immediately visible to recv.
            self.read.write().entry(addr).or_default().push(msg.clone());
        }
        Ok(msg)
    }

    /// Returns the messages stored at `address`.
    ///
    /// Reads from the read mapping. Only if `include_write_in_recv` is set (during a
    /// sync_all pass) does it fall through to the outbox on a read miss.
    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Msg>> {
        if let Some(msgs) = self.read.read().get(&address).cloned() {
            return Ok(msgs);
        }
        if self.include_write_in_recv {
            if let Some(sealed) = self.write.read().get(&address) {
                return Ok(sealed.iter().map(|s| s.msg.clone()).collect());
            }
        }
        Err(Error::AddressError("No message found", address))
    }

    /// Acquires the read lock once and resolves all addresses in a single pass,
    /// avoiding repeated lock acquisitions from sequential `recv_message` calls.
    ///
    /// Falls through to the outbox per-address only when `include_write_in_recv` is set.
    async fn recv_messages_batch(
        &mut self,
        addresses: Vec<Address>,
    ) -> Vec<(Address, Result<Self::Msg>)> {
        let read = self.read.read();
        let write = if self.include_write_in_recv {
            Some(self.write.read())
        } else {
            None
        };
        addresses
            .into_iter()
            .map(|address| {
                let result = read
                    .get(&address)
                    .and_then(|v| v.last().cloned())
                    .or_else(|| {
                        write
                            .as_ref()
                            .and_then(|w| w.get(&address))
                            .and_then(|v| v.last())
                            .map(|s| s.msg.clone())
                    })
                    .ok_or(Error::AddressError("No message found", address));
                (address, result)
            })
            .collect()
    }

    async fn latest_timestamp(&self) -> Result<u128> {
        let start = std::time::SystemTime::now();
        Ok(start
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis())
    }
}

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
struct ClientSerde<Msg> {
    read: BTreeMap<Address, Vec<Msg>>,
    write: BTreeMap<Address, Vec<Sealed<Msg>>>,
}

#[cfg(feature = "serde")]
impl<Msg: Serialize + Clone> Serialize for Client<Msg> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let snapshot = ClientSerde {
            read: self.read.read().clone(),
            write: self.write.read().clone(),
        };
        snapshot.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, Msg: Deserialize<'de>> Deserialize<'de> for Client<Msg> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let snapshot = ClientSerde::<Msg>::deserialize(deserializer)?;
        Ok(Client {
            read: Arc::new(spin::RwLock::new(snapshot.read)),
            write: Arc::new(spin::RwLock::new(snapshot.write)),
            include_write_in_recv: false,
            outbox_mode: false,
        })
    }
}
