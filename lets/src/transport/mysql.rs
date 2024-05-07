use crate::id::{Ed25519Pub, Ed25519Sig};
use crate::{
    address::Address,
    error::{Error, Result},
    message::TransportMessage,
    transport::Transport,
};
use alloc::vec::Vec;
use async_trait::async_trait;
//use base64::Engine;
//use base64::prelude::BASE64_STANDARD;
use serde::__private::PhantomData;
use serde::{Deserialize, Serialize};
use sqlx::mysql::MySqlPool;
use sqlx::{Execute, QueryBuilder};

/// -- Create the 'app' table
/// CREATE TABLE IF NOT EXISTS app (
///     app_id VARBINARY(255) NOT NULL PRIMARY KEY
/// );

/// -- Create the 'messages' table
/// CREATE TABLE IF NOT EXISTS sql_messages (
///     msg_id VARBINARY(255) NOT NULL,
///     raw_content LONGBLOB NOT NULL,
///     timestamp DATETIME NOT NULL,
///     public_key VARBINARY(255) NOT NULL,
///     signature VARBINARY(255) NOT NULL,
///     app_id VARBINARY(255) NOT NULL,
///     PRIMARY KEY (msg_id, app_id),
///     FOREIGN KEY (app_id) REFERENCES app(app_id)
/// );
pub struct Client<StreamsMessage = TransportMessage, DbMessage = SqlMessage>(
    MySqlPool,
    PhantomData<(StreamsMessage, DbMessage)>,
);

impl<SM, DM> Client<SM, DM> {
    pub async fn new(url: &str) -> Result<Client> {
        Ok(Client(
            MySqlPool::connect(url)
                .await
                .map_err(|e| Error::MySqlClient("building client", e))?,
            PhantomData,
        ))
    }
}

impl<SM, DM> Client<SM, DM> {
    async fn insert_message(&mut self, sql_msg: SqlMessage) -> Result<()> {
        // TODO: check sql error code to confirm it's just a 23000 (already stored) error
        let _ = sqlx::query!(r#"INSERT INTO app (app_id) VALUES (?)"#, sql_msg.app_id,)
            .execute(&self.0)
            .await;

        Ok(sqlx::query!(
            r#"INSERT INTO sql_messages (msg_id, raw_content, timestamp, public_key, signature, app_id) VALUES (?, ?, ?, ?, ?, ?)"#,
            sql_msg.msg_id,
            sql_msg.raw_content,
            sql_msg.timestamp,
            sql_msg.public_key,
            sql_msg.signature,
            sql_msg.app_id,
        )
        .execute(&self.0)
        .await
        .map_err(|e| Error::MySqlClient("inserting message", e))
        .and_then(|r| {
            if r.rows_affected() == 0 {
                Err(Error::MySqlNotInserted)
            } else {
                Ok(())
            }
        })?)
    }

    // Sending multiple messages simultaneously. Messages are processed in chunks of 25
    pub async fn insert_messages(&mut self, sql_msgs: &[SqlMessage]) -> Result<()> {
        // TODO: check sql error code to confirm it's just a 23000 (already stored) error
        let mut query = QueryBuilder::new(r#"INSERT INTO app (app_id) "#);
        query.push_values(sql_msgs.iter(), |mut q, sql_msg| {
            q.push_bind(&sql_msg.app_id);
        });
        let _ = query.build()
            .execute(&self.0)
            .await;

        // Loop through the messages in chunks of 25
        for chunk in sql_msgs.chunks(25) {
            //TODO: investigate building query with binds to use ON DUPLICATE KEY UPDATE
            let mut query = QueryBuilder::new(r#"INSERT IGNORE INTO sql_messages (msg_id, raw_content, timestamp, public_key, signature, app_id) "#);
            query.push_values(chunk.into_iter(), |mut b, msg| {
                b.push_bind(&msg.msg_id)
                    .push_bind(&msg.raw_content)
                    .push_bind(&msg.timestamp)
                    .push_bind(&msg.public_key)
                    .push_bind(&msg.signature)
                    .push_bind(&msg.app_id);
            });

            query.build()
                .execute(&self.0)
                .await
                .map_err(|e| Error::MySqlClient("inserting bulk messages", e))
                .and_then(|r| {
                    if r.rows_affected() == 0 {
                        Err(Error::MySqlNotInserted)
                    } else {
                        Ok(())
                    }
                })?
        }
        Ok(())
    }

    async fn retrieve_message(&mut self, address: Address) -> Result<SqlMessage> {
        let app_id_bytes = address.base().as_bytes().to_vec();
        let msg_id_bytes = address.relative().as_bytes().to_vec();
        let sql_message: SqlMessage = sqlx::query_as!(
            SqlMessage,
            r#"SELECT * FROM sql_messages WHERE msg_id = ? AND app_id = ?"#,
            msg_id_bytes,
            app_id_bytes
        )
        .fetch_one(&self.0)
        .await
        .map_err(|e| Error::MySqlClient("fetching message", e))?;

        self.verify_sql_msg(&sql_message)?;

        Ok(sql_message)
    }

    fn verify_sql_msg(&self, sql_message: &SqlMessage) -> Result<()> {
        if sql_message.signature.len() != 64 {
            return Err(Error::InvalidSize(
                "signature",
                64,
                sql_message.signature.len() as u64,
            ));
        }

        if sql_message.public_key.len() != 32 {
            return Err(Error::InvalidSize(
                "signature",
                32,
                sql_message.public_key.len() as u64,
            ));
        }

        let mut bytes = [0u8; 32];
        bytes.clone_from_slice(&sql_message.public_key);
        let pk =
            Ed25519Pub::try_from_bytes(bytes).map_err(|e| Error::Crypto("making public key", e))?;
        let mut bytes = [0u8; 64];
        bytes.clone_from_slice(&sql_message.signature);
        let sig = Ed25519Sig::from_bytes(bytes);
        if !pk.verify(&sig, &sql_message.raw_content) {
            return Err(Error::Signature("verifying", "retrieve message"));
        }
        Ok(())
    }

    // Bulk retrieval tool for sql db's
    // TODO: Build out unit test for retrieving multiple messages
    pub async fn retrieve_messages(&mut self, addresses: Vec<Address>) -> Result<Vec<SqlMessage>> {
        let app_id_bytes = addresses[0].base().as_bytes().to_vec();

        let placeholders: String = addresses.iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");

        let query_string = format!("SELECT * FROM sql_messages WHERE msg_id IN ({}) AND app_id = ?", placeholders);

        let mut query = sqlx::query_as::<sqlx::mysql::MySql, SqlMessage>(&query_string);
        for addr in addresses {
            query = query.bind(addr.relative().as_bytes().to_vec());
        }
        let sql_messages: Vec<SqlMessage> = query.bind(app_id_bytes)
            .fetch_all(&self.0)
            .await
            .map_err(|e| Error::MySqlClient("fetching batch messages", e))?
            .iter()
            .cloned()
            .collect();

        for msg in &sql_messages {
            self.verify_sql_msg(msg)?;
        }

        Ok(sql_messages)
    }
}

#[async_trait]
impl<StreamsMessage, DbMessage> Transport<'_> for Client<StreamsMessage, DbMessage>
where
    StreamsMessage: From<SqlMessage> + Into<SqlMessage> + Send + Sync,
    DbMessage: From<SqlMessage> + Clone + Send + Sync,
{
    type Msg = StreamsMessage;
    type SendResponse = DbMessage;

    /// This function stands as a DON alternative for sending that includes the public key and
    /// verifiable signature of the message for inclusion as a Data message within the network
    /// Signatures are conducted using ED25519 keys so the method uses that as a baseline assumption
    /// for sending and retrieval.
    /// TODO: Make this function more ubiquitous for use in other protocols, or with other signature
    /// formats
    async fn send_message(
        &mut self,
        address: Address,
        msg: StreamsMessage,
        public_key: Ed25519Pub,
        signature: Ed25519Sig,
    ) -> Result<Self::SendResponse>
    where
        StreamsMessage: 'async_trait,
    {
        let db_msg = msg
            .into()
            .with_address(address)
            .with_public_key(public_key)
            .with_signature(signature);
        self.insert_message(db_msg.clone()).await?;
        Ok(db_msg.into())
    }

    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Self::Msg>>
    where
        StreamsMessage: 'async_trait,
    {
        let msg = self.retrieve_message(address).await?;
        Ok(vec![msg.into()])
    }

    async fn latest_timestamp(&self) -> Result<u128> {
        let start = std::time::SystemTime::now();
        Ok(start
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis())
    }
}

#[derive(sqlx::FromRow, Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct SqlMessage {
    pub msg_id: Vec<u8>,
    pub raw_content: Vec<u8>,
    pub timestamp: chrono::NaiveDateTime,
    //#[cfg(feature = "did")]
    pub public_key: Vec<u8>,
    //#[cfg(feature = "did")]
    pub signature: Vec<u8>,
    pub app_id: Vec<u8>,
}

impl SqlMessage {
    fn new() -> SqlMessage {
        SqlMessage::default()
    }

    fn with_timestamp(mut self, timestamp: chrono::NaiveDateTime) -> SqlMessage {
        self.timestamp = timestamp;
        self
    }

    fn with_content(mut self, raw_content: Vec<u8>) -> Self {
        self.raw_content = raw_content;
        self
    }

    fn with_address(mut self, address: Address) -> Self {
        self.msg_id = address.relative().as_bytes().to_vec();
        self.app_id = address.base().as_bytes().to_vec();
        self
    }

    fn with_public_key(mut self, public_key: Ed25519Pub) -> Self {
        self.public_key = public_key.to_bytes().to_vec();
        self
    }

    fn with_signature(mut self, signature: Ed25519Sig) -> Self {
        self.signature = signature.to_bytes().to_vec();
        self
    }
}

impl AsRef<[u8]> for SqlMessage {
    fn as_ref(&self) -> &[u8] {
        self.raw_content.as_slice()
    }
}

impl From<TransportMessage> for SqlMessage {
    fn from(msg: TransportMessage) -> SqlMessage {
        Self::new()
            .with_content(msg.into_body())
            .with_timestamp(chrono::Utc::now().naive_utc())
    }
}

impl From<SqlMessage> for TransportMessage {
    fn from(msg: SqlMessage) -> TransportMessage {
        Self::new(msg.raw_content)
            .with_pk(msg.public_key)
            .with_sig(msg.signature)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;
    use chrono::{Timelike, Utc};

    use crate::{
        address::{Address, AppAddr, MsgId},
        id::Identifier,
        message::{Topic, TransportMessage},
    };

    use super::*;

    #[tokio::test]
    async fn send_and_recv_message() -> Result<()> {
        let url = std::env::var("DATABASE_URL").unwrap();
        // This test requires that there be an existing db running on mysql. Credentials can be updated here
        let mut client = Client::<SqlMessage>::new(&url).await?;
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
        client
            .send_message(address, msg.clone().into(), pk, sig)
            .await?;
        let response = client.recv_message(address).await?;
        assert_eq!(msg, response);
        Ok(())
    }

    #[tokio::test]
    async fn bulk_send_and_recv_messages() -> Result<()> {
        let url = std::env::var("DATABASE_URL").unwrap();
        // This test requires that there be an existing db running on mysql. Credentials can be updated here
        let mut client = Client::<SqlMessage>::new(&url).await?;
        let mut addresses: Vec<Address> = Vec::new();
        let mut messages: Vec<SqlMessage> = Vec::new();

        for _ in 0..10 {
            addresses.push(Address::new(
                AppAddr::default(),
                MsgId::gen(
                    AppAddr::default(),
                    &Identifier::default(),
                    &Topic::default(),
                    Utc::now().timestamp_millis() as usize,
                ),
            ));

            let body = vec![12; 50];
            let key = crypto::signatures::ed25519::SecretKey::generate().unwrap();
            let pk = key.public_key();
            let sig = key.sign(&body);
            let msg = TransportMessage::new(body)
                .with_pk(pk.to_bytes().to_vec())
                .with_sig(sig.to_bytes().to_vec());

            let sql_msg = SqlMessage::new()
                .with_content(msg.into_body())
                .with_timestamp(chrono::Utc::now().naive_utc())
                .with_address(addresses.last().unwrap().clone())
                .with_public_key(pk)
                .with_signature(sig);

            messages.push(sql_msg);

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        client
            .insert_messages(&messages)
            .await?;
        let mut response = client.retrieve_messages(addresses).await?;

        response.sort_by(|a, b| a.msg_id.partial_cmp(&b.msg_id).unwrap());
        messages.sort_by(|a, b| a.msg_id.partial_cmp(&b.msg_id).unwrap());

        for (i, sql_message) in messages.iter().enumerate() {
            println!("Checking msg {}", i);
            assert_eq!(sql_message.msg_id, response[i].msg_id);
            assert_eq!(sql_message.raw_content, response[i].raw_content);

            println!("{}   -   {}", sql_message.timestamp.time(), response[i].timestamp.time());
            // Timestamp is stored in sql without fractional percentage, so round here
            // TODO: Adjust timestamp on store
            let timestamp = if sql_message.timestamp.time().nanosecond() > 500_000_000 {
                sql_message.timestamp.time().add(std::time::Duration::from_secs(1)).with_nanosecond(0).unwrap()
            } else {
                sql_message.timestamp.time().with_nanosecond(0).unwrap()
            };
            assert_eq!(timestamp, response[i].timestamp.time());
            assert_eq!(sql_message.public_key, response[i].public_key);
            assert_eq!(sql_message.signature, response[i].signature);
            assert_eq!(sql_message.app_id, response[i].app_id)
        }

        Ok(())
    }
}
