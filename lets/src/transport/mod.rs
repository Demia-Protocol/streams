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
};

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
        // Sort messages by timestamp and pop the most recent one
        // TODO: We need to explore the ramifications of this approach
        msgs.sort_by(|a, b| a.timestamp().cmp(&b.timestamp()));
        msgs.pop().ok_or(Error::AddressError("not found in transport", address))
    }

    async fn latest_timestamp(&self) -> Result<u128>;
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
