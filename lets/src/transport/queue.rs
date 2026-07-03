use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use async_trait::async_trait;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    address::Address,
    error::Result,
    id::{Ed25519Pub, Ed25519Sig},
    message::TransportMessage,
    transport::{bucket, Transport},
};

/// A sealed streams message that can be sent without reconstructing the originating user.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PreparedMessage<Msg = TransportMessage> {
    pub address: Address,
    pub msg: Msg,
}

impl<Msg> PreparedMessage<Msg> {
    pub fn new(address: Address, msg: Msg) -> Self {
        Self { address, msg }
    }
}

/// Shared streams client: reads come from `input`, sends enqueue prepared messages into `outbox`.
///
/// TODO(task-persistence): back this outbox by SQL on shutdown/startup so prepared messages survive
/// reboots without reconstructing users.
#[derive(Clone, Debug)]
pub struct Client<Msg = TransportMessage> {
    bucket: bucket::Client<Msg>,
    outbox: Arc<spin::Mutex<VecDeque<PreparedMessage<Msg>>>>,
}

impl<Msg> Client<Msg> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_input(input: bucket::Client<Msg>) -> Self {
        Self {
            bucket: input,
            outbox: Arc::new(spin::Mutex::new(VecDeque::new())),
        }
    }

    pub fn input(&self) -> &bucket::Client<Msg> {
        &self.bucket
    }
}

impl<Msg: Clone> Client<Msg> {
    pub fn pop_prepared(&self) -> Option<PreparedMessage<Msg>> {
        self.outbox.lock().pop_front()
    }

    pub fn requeue_prepared(&self, message: PreparedMessage<Msg>) {
        self.outbox.lock().push_back(message);
    }

    pub fn prepared_len(&self) -> usize {
        self.outbox.lock().len()
    }
}

impl Client<TransportMessage> {
    pub async fn insert_message(
        &mut self,
        address: Address,
        msg: TransportMessage,
    ) -> Result<TransportMessage> {
        let public_key =
            Ed25519Pub::try_from_bytes([0u8; 32]).expect("zeroed public key should be valid");
        let signature = Ed25519Sig::from_bytes([0u8; 64]);
        self.bucket
            .send_message(address, msg, public_key, signature)
            .await
    }
}

impl<Msg> Default for Client<Msg> {
    fn default() -> Self {
        Self {
            bucket: bucket::Client::new(),
            outbox: Arc::new(spin::Mutex::new(VecDeque::new())),
        }
    }
}

#[async_trait]
impl Transport<'_> for Client<TransportMessage> {
    type Msg = TransportMessage;
    type SendResponse = TransportMessage;

    async fn send_message(
        &mut self,
        address: Address,
        msg: TransportMessage,
        public_key: Ed25519Pub,
        signature: Ed25519Sig,
    ) -> Result<TransportMessage>
    where
        Self::Msg: 'async_trait,
    {
        let prepared_msg = msg
            .clone()
            .with_pk(public_key.to_bytes().to_vec())
            .with_sig(signature.to_bytes().to_vec());
        self.outbox
            .lock()
            .push_back(PreparedMessage::new(address, prepared_msg));
        Ok(msg)
    }

    async fn recv_messages(&mut self, address: Address) -> Result<Vec<TransportMessage>> {
        self.bucket.recv_messages(address).await
    }

    async fn recv_messages_batch(
        &mut self,
        addresses: Vec<Address>,
    ) -> Vec<(Address, Result<Self::Msg>)> {
        self.bucket.recv_messages_batch(addresses).await
    }

    async fn latest_timestamp(&self) -> Result<u128> {
        self.bucket.latest_timestamp().await
    }
}
