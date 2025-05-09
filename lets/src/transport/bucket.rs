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
    transport::Transport,
};

/// [`BTreeMap`] wrapper client for testing purposes
#[derive(Clone, Debug)]
pub struct Client<Msg = TransportMessage> {
    /// Mapping of stored [Addresses](`Address`) and `Messages`
    // Use BTreeMap instead of HashMap to make BucketTransport nostd without pulling hashbrown
    // (this transport is for hacking purposes only, performance is no concern)
    bucket: Arc<spin::RwLock<BTreeMap<Address, Vec<Msg>>>>,
}

impl<Msg> Client<Msg> {
    /// Creates a new [Bucket Client](`Client`)
    pub fn new() -> Self {
        Self::default()
    }
}

impl<Msg> Default for Client<Msg> {
    // Implement default manually because derive puts Default bounds in type parameters
    fn default() -> Self {
        Self {
            bucket: Arc::new(spin::RwLock::new(BTreeMap::default())),
        }
    }
}

#[async_trait]
impl<Msg> Transport<'_> for Client<Msg>
where
    Msg: Clone + Send + Sync + PartialEq,
{
    type Msg = Msg;
    type SendResponse = Msg;

    /// If the address is not in the bucket, add it and return the message.
    ///
    /// # Arguments
    /// * `addr`: Address - The address of the message to store.
    /// * `msg`: The message to store.
    ///
    /// Returns:
    /// The message that was sent.
    /*#[cfg(not(feature = "did"))]
    async fn send_message(&mut self, addr: Address, msg: Msg) -> Result<Msg>
    where
        Self::Msg: 'async_trait,
    {
        self.bucket.lock().entry(addr).or_default().push(msg.clone());
        Ok(msg)
    }

    #[cfg(feature = "did")]*/
    async fn send_message(
        &mut self,
        addr: Address,
        msg: Msg,
        _public_key: Ed25519Pub,
        _signature: Ed25519Sig,
    ) -> Result<Msg>
    where
        Self::Msg: 'async_trait,
    {
        self.bucket
            .write()
            .entry(addr)
            .or_default()
            .push(msg.clone());
        Ok(msg)
    }

    /// Returns a vector of messages from the bucket, or an error if the bucket doesn't contain the
    /// address
    ///
    /// # Arguments
    /// * `address`: The address to retrieve messages from.
    ///
    /// Returns:
    /// A vector of messages.
    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Msg>> {
        self.bucket
            .read()
            .get(&address)
            .cloned()
            .ok_or(Error::AddressError("No message found", address))
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
impl<Msg: Serialize> Serialize for Client<Msg> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let bucket = self.bucket.read();
        bucket.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, Msg: Deserialize<'de>> Deserialize<'de> for Client<Msg> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bucket: BTreeMap<Address, Vec<Msg>> = Deserialize::deserialize(deserializer)?;
        Ok(Client {
            bucket: Arc::new(spin::RwLock::new(bucket)),
        })
    }
}
