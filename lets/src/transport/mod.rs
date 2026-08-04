// Rust
use alloc::{boxed::Box, vec::Vec};

// 3rd-party
use async_trait::async_trait;

// IOTA

// Streams

// Local
//#[cfg(feature = "did")]
use crate::id::{Ed25519Pub, Ed25519Sig};
use crate::{
    address::Address,
    error::{Error, Result},
    message::TransportMessage,
};

/// A sealed streams message that can be sent without reconstructing the originating user.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreparedMessage<Msg = TransportMessage> {
    pub address: Address,
    pub msg: Msg,
}

impl<Msg> PreparedMessage<Msg> {
    pub fn new(address: Address, msg: Msg) -> Self {
        Self { address, msg }
    }
}

impl PreparedMessage {
    pub fn public_key(&self) -> Result<Ed25519Pub> {
        self.msg.public_key().ok_or(Error::AddressError(
            "prepared message public key is missing",
            self.address,
        ))
    }

    pub fn signature(&self) -> Result<Ed25519Sig> {
        self.msg.signature().ok_or(Error::AddressError(
            "prepared message signature is missing",
            self.address,
        ))
    }

    pub async fn send_with<T, R>(self, transport: &mut T) -> Result<R>
    where
        T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = R> + Send,
    {
        let public_key = self.public_key()?;
        let signature = self.signature()?;
        transport
            .send_message(self.address, self.msg, public_key, signature)
            .await
    }
}

/// Network transport abstraction.
/// Parametrized by the type of message addresss.
/// Message address is used to identify/locate a message (eg. like URL for HTTP).
#[async_trait]
pub trait Transport<'a> {
    type Msg;
    type SendResponse;
    /// Send a message
    /*#[cfg(not(feature = "did"))]
    async fn send_message(&mut self, address: Address, msg: Self::Msg) -> Result<Self::SendResponse>
    where
        'a: 'async_trait;
    #[cfg(feature = "did")]*/
    async fn send_message(
        &mut self,
        address: Address,
        msg: Self::Msg,
        public_key: Ed25519Pub,
        signature: Ed25519Sig,
    ) -> Result<Self::SendResponse>
    where
        'a: 'async_trait;

    /// Receive messages
    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Self::Msg>>
    where
        'a: 'async_trait;

    /// Receive a single message
    async fn recv_message(&mut self, address: Address) -> Result<Self::Msg> {
        let mut msgs = self.recv_messages(address).await?;
        if let Some(msg) = msgs.pop() {
            //Todo: Sorting/filtering, popping and erroring out on doubles breaks functionality
            //match msgs.is_empty() {
            //    true => Ok(msg),
            //    false => Err(Error::AddressError("More than one found", address)),
            //}
            Ok(msg)
        } else {
            Err(Error::AddressError("not found in transport", address))
        }
    }

    /// Receive multiple messages by address, potentially concurrently.
    ///
    /// Returns a vec of `(Address, Result<Msg>)` covering every input address,
    /// with an `Err` entry for any address where no message was found.
    /// Implementations should issue fetches concurrently where the transport allows it.
    async fn recv_messages_batch(
        &mut self,
        addresses: Vec<Address>,
    ) -> Vec<(Address, Result<Self::Msg>)>
    where
        'a: 'async_trait;

    async fn latest_timestamp(&self) -> Result<u128>;
}

/// Store a confirmed message into a local readable transport cache.
///
/// This is intentionally separate from [`Transport::send_message`]. Some local transports use
/// `send_message` to capture outbound messages before they are published, while SQL replay and
/// network mirrors need to insert messages that are already confirmed/readable.
pub trait MessageStore {
    type Msg;

    fn store_message(&mut self, address: Address, msg: Self::Msg) -> bool;
}

/// Localised mapping for tests and simulations
#[cfg(feature = "bucket")]
pub mod bucket;
/// `sqlx` based mysql client
#[cfg(feature = "mysql-client")]
pub mod mysql;
/// Localised micro tangle client
#[cfg(feature = "utangle-client")]
pub mod utangle;
