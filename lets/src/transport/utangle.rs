// Rust
#[cfg(not(std))]
use alloc::string::ToString;
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
};

// 3rd-party
use async_trait::async_trait;
use rayon::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

// IOTA
use crypto::{
    encoding::ternary::{b1t6, Btrit, T1B1Buf, TritBuf},
    hashes::{
        blake2b::Blake2b256,
        ternary::{self, curl_p},
        Digest,
    },
};

// Streams

// Local
use crate::id::{Ed25519Pub, Ed25519Sig};
use crate::{
    address::Address,
    error::{Error, Result},
    message::TransportMessage,
    transport::Transport,
};

const NONCE_SIZE: usize = core::mem::size_of::<u64>();
// Precomputed natural logarithm of 3 for performance reasons.
// See https://oeis.org/A002391.
const LN_3: f64 = 1.098_612_288_668_109;

/// A [`Transport`] Client for sending and retrieving binary messages from an `IOTA Tangle` node.
/// This Client uses a lightweight [reqwest](`reqwest::Client`) Client implementation.
#[derive(Debug, Clone)]
pub struct Client<Message = TransportMessage, SendResponse = SentMessageResponse> {
    /// Node endpoint URL
    node_url: String,
    /// HTTP Client
    client: reqwest::Client,
    _phantom: PhantomData<(Message, SendResponse)>,
}

impl<M, S> Default for Client<M, S> {
    fn default() -> Self {
        Self {
            node_url: String::from("https://chrysalis-nodes.iota.org"),
            client: reqwest::Client::new(),
            _phantom: PhantomData,
        }
    }
}

impl<Message, SendResponse> Client<Message, SendResponse> {
    /// Creates a new `uTangle` [`Client`] implementation from the provided URL
    ///
    /// # Arguments:
    /// * `node_url`: Tangle node endpoint
    pub fn new<U>(node_url: U) -> Self
    where
        U: Into<String>,
    {
        Self {
            node_url: node_url.into(),
            client: reqwest::Client::new(),
            _phantom: PhantomData,
        }
    }

    /// Returns basic network details from node request
    async fn get_network_info(&self) -> Result<NetworkInfo> {
        let network_info_path = "api/core/v2/info";
        let network_info: NetworkInfo = self
            .client
            .get(format!("{}/{}", self.node_url, network_info_path))
            .send()
            .await?
            .json()
            .await?;
        Ok(network_info)
    }

    /// Returns [`Tips`] from node request
    async fn get_tips(&self) -> Result<Tips> {
        let tips_path = "api/core/v2/tips";
        let tips: Tips = self
            .client
            .get(format!("{}/{}", self.node_url, tips_path))
            .send()
            .await?
            .json()
            .await?;
        Ok(tips)
    }
}

#[async_trait]
impl<Message, SendResponse> Transport<'_> for Client<Message, SendResponse>
where
    Message: AsRef<[u8]> + TryFrom<Block, Error = crate::error::Error> + Send + Sync,
    SendResponse: DeserializeOwned + Send + Sync,
{
    type Msg = Message;
    type SendResponse = SendResponse;

    /// Sends a message indexed at the provided [`Address`] to the tangle.
    ///
    /// # Arguments
    /// * `address`: The address of the message.
    /// * `msg`: Message - The message to send.
    async fn send_message(
        &mut self,
        address: Address,
        msg: Message,
        public_key: Ed25519Pub,
        signature: Ed25519Sig,
    ) -> Result<SendResponse>
    where
        Message: 'async_trait + Send,
    {
        let network_info = self.get_network_info().await?;
        let tips = self.get_tips().await?;

        let mut block = Block::new(
            tips,
            address.to_msg_index().to_vec(),
            msg.as_ref().to_vec(),
            public_key.as_slice().to_vec(),
            signature.to_bytes().to_vec(),
        );
        let message_bytes = serde_json::to_vec(&block)?;
        block.set_nonce(nonce(&message_bytes, network_info.protocol.min_pow_score as f64)?);

        let path = "api/core/v2/blocks";

        let response: SendResponse = self
            .client
            .post(format!("{}/{}", self.node_url, path))
            .header("Content-Type", "application/json")
            .body(message_bytes)
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    /// Retrieves a message indexed at the provided [`Address`] from the tangle. Errors if no
    /// messages are found.
    ///
    /// # Arguments
    /// * `address`: The address of the message to retrieve.
    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Message>> {
        let path = format!("api/core/v2/tagged/{}", prefix_hex::encode(address.to_msg_index()));
        let index_data: BlockResponse = self
            .client
            .get(format!("{}/{}", self.node_url, path))
            .send()
            .await?
            .json()
            .await?;

        let msg = index_data
            .0
            .into_iter()
            .next()
            .ok_or(Error::AddressError("No message found", address))?;
        Ok(vec![msg.try_into()?])
    }
}

fn nonce(data: &[u8], target_score: f64) -> Result<u64> {
    let target_zeros = (((data.len() + NONCE_SIZE) as f64 * target_score).ln() / LN_3).ceil() as usize;
    let hash = Blake2b256::digest(data);
    let mut pow_digest = TritBuf::<T1B1Buf>::new();
    b1t6::encode::<T1B1Buf>(&hash).iter().for_each(|t| pow_digest.push(t));
    (0..u32::MAX)
        .into_par_iter()
        .step_by(curl_p::BATCH_SIZE)
        .find_map_any(|n| {
            let mut hasher = curl_p::CurlPBatchHasher::new(ternary::HASH_LENGTH);
            for i in 0..curl_p::BATCH_SIZE {
                let mut buffer = TritBuf::<T1B1Buf>::zeros(ternary::HASH_LENGTH);
                buffer[..pow_digest.len()].copy_from(&pow_digest);
                let nonce_trits = b1t6::encode::<T1B1Buf>(&(n as u64 + i as u64).to_le_bytes());
                buffer[pow_digest.len()..pow_digest.len() + nonce_trits.len()].copy_from(&nonce_trits);
                hasher.add(buffer);
            }
            for (i, hash) in hasher.hash().enumerate() {
                let trailing_zeros = hash.iter().rev().take_while(|t| *t == Btrit::Zero).count();

                if trailing_zeros >= target_zeros {
                    return Some(n as u64 + i as u64);
                }
            }
            None
        })
        .ok_or(Error::Nonce(target_score))
}

#[derive(Deserialize)]
struct NetworkInfo {
    /// Protocol Info, contains the pow score
    #[serde(rename = "protocol")]
    protocol: Protocol,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Protocol {
    /// The minimum pow score of the network.
    min_pow_score: u32,
}

#[derive(Serialize, Deserialize, PartialEq)]
struct Tips {
    /// Tips to be used as parents in block
    tips: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Block {
    /// Protocol version of the block.
    #[serde(rename = "protocolVersion")]
    protocol_version: u8,
    /// The [`BlockId`]s that this block directly approves.
    parents: Vec<String>,
    /// The [Payload] of the block.
    payload: TaggedPayload,
    /// The result of the Proof of Work in order for the block to be accepted into the tangle.
    pub nonce: String,
}

impl Block {
    fn new(tips: Tips, tag: Vec<u8>, data: Vec<u8>, public_key: Vec<u8>, signature: Vec<u8>) -> Block {
        Block {
            protocol_version: 2_u8,
            parents: tips.tips,
            payload: TaggedPayload::new(tag, data, public_key, signature),
            nonce: String::new(),
        }
    }

    fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce.to_string()
    }
}

#[derive(Serialize, Deserialize)]
struct TaggedPayload {
    // TODO: add limit checks
    #[serde(rename = "type")]
    kind: u8,
    tag: String,
    data: String,
    #[serde(rename = "publicKey")]
    pub_key: String,
    signature: String,
}

impl TaggedPayload {
    fn new(tag: Vec<u8>, data: Vec<u8>, pk: Vec<u8>, sig: Vec<u8>) -> TaggedPayload {
        TaggedPayload {
            kind: 5_u8,
            tag: prefix_hex::encode(tag),
            data: prefix_hex::encode(data),
            pub_key: prefix_hex::encode(pk),
            signature: prefix_hex::encode(sig),
        }
    }
}

#[derive(Deserialize)]
struct BlockResponse(Vec<Block>);

#[derive(Clone, Deserialize)]
pub struct SentMessageResponse {
    #[serde(rename = "blockId")]
    pub block_id: String,
}

impl TryFrom<Block> for TransportMessage {
    type Error = crate::error::Error;
    fn try_from(message: Block) -> Result<Self> {
        Ok(
            Self::new(prefix_hex::decode(message.payload.data.clone())?)
                .with_pk(prefix_hex::decode(message.payload.pub_key)?)
                .with_sig(prefix_hex::decode(message.payload.signature)?)
        )
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::{
        address::{Address, AppAddr, MsgId},
        id::Identifier,
        message::{Topic, TransportMessage},
    };

    use super::*;

    #[tokio::test]
    async fn send_and_recv_message() -> Result<()> {
        let mut client = Client::new("http://nodes.02.demia-testing-domain.com:14102");
        let address = Address::new(
            AppAddr::default(),
            MsgId::gen(
                AppAddr::default(),
                &Identifier::default(),
                &Topic::default(),
                Utc::now().timestamp_millis() as usize,
            ),
        );
        let body = vec![12; 50];
        let key = crypto::signatures::ed25519::SecretKey::generate().unwrap();
        let pk = key.public_key();
        let sig = key.sign(&body);
        let msg = TransportMessage::new(body)
            .with_pk(pk.to_bytes().to_vec())
            .with_sig(sig.to_bytes().to_vec());
        let _: serde_json::Value = client.send_message(address, msg.clone(), pk, sig).await?;

        let response = client.recv_message(address).await?;
        assert_eq!(msg, response);
        Ok(())
    }
}
