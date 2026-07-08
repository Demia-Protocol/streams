// Streams
use lets::id::Permissioned;

// Local
use crate::api::cursor_store::CursorStore;
use crate::api::user::INIT_MESSAGE_NUM;
use crate::{Error, Result, User};

impl<T> User<T> {
    /// Reset message processing state so the next sync reads messages from the beginning again.
    ///
    /// This preserves identity, PSKs, subscribers, and the stream announcement anchor. Branches,
    /// permissions, cursors, latest links, and message Spongos states are rebuilt by the next sync.
    /// Use this after adding newly available keys when messages may previously have been skipped.
    pub fn reset_message_state(&mut self) -> Result<()> {
        let stream_address = self
            .stream_address()
            .ok_or(Error::NoStream("reset message state"))?;
        let author_identifier = self
            .state
            .author_identifier
            .clone()
            .ok_or(Error::NoStream("reset message state"))?;
        let base_branch = self.state.base_branch.clone();
        let announcement_spongos = self
            .state
            .spongos_store
            .get(&stream_address.relative())
            .copied()
            .ok_or(Error::MessageMissing(
                stream_address.relative(),
                "spongos store",
            ))?;

        self.state.cursor_store = CursorStore::new();
        self.state.cursor_store.new_branch(base_branch.clone());
        self.state.cursor_store.insert_cursor(
            &base_branch,
            Permissioned::Admin(author_identifier),
            INIT_MESSAGE_NUM,
        );
        self.state
            .cursor_store
            .set_latest_link(base_branch.clone(), stream_address.relative());

        self.state.topics.clear();
        self.state.topics.insert(base_branch);

        self.state.spongos_store.clear();
        self.state
            .spongos_store
            .insert(stream_address.relative(), announcement_spongos);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;
    use lets::{
        id::{Ed25519, Psk},
        transport::bucket,
    };

    use crate::{MessageContent, Result, User};

    #[tokio::test]
    async fn reset_replays_messages_after_adding_a_psk() -> Result<()> {
        let transport = bucket::Client::new();
        let psk = Psk::from_seed("retroactive psk");
        let mut author = User::builder()
            .with_identity(Ed25519::from_seed("author"))
            .with_psk(psk.to_pskid(), psk)
            .with_transport(transport.clone())
            .build();
        let announcement = author.create_stream("BASE_BRANCH").await?;
        let mut reader = User::builder().lean().with_transport(transport).build();
        reader.receive_message(announcement.address()).await?;

        author.new_branch("BASE_BRANCH", "READINGS").await?;
        author.send_keyload_for_all("READINGS").await?;
        author
            .send_signed_packet("READINGS", b"", b"reading")
            .await?;

        let initially_readable = reader.messages().try_collect::<Vec<_>>().await?;
        assert!(!initially_readable
            .iter()
            .any(|message| matches!(message.content(), MessageContent::SignedPacket(_))));

        assert!(reader.add_psk(psk));
        reader.reset_message_state()?;

        let replayed = reader.messages().try_collect::<Vec<_>>().await?;
        assert!(replayed.iter().any(|message| {
            message
                .as_signed_packet()
                .is_some_and(|packet| packet.masked_payload == b"reading")
        }));

        Ok(())
    }
}
