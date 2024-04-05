// Rust


// 3rd-party

// IOTA

// Streams
use lets::{
    address::{Address, MsgId},
    id::{Permissioned},
    message::{Message as LetsMessage, PreparsedMessage, TransportMessage, HDF, PCF},
    transport::Transport,
};

#[cfg(feature = "did")]
use lets::id::{
    did::{StrongholdSecretManager, DID},
    IdentityKind,
};

// Local
use crate::{
    api::{message::Message, send_response::SendResponse},
    message::{message_types, unsubscription},
    Error, Result, User,
};

impl<T, TSR> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = TSR> + Send,
{
    /// Create and send a new Unsubscription message, informing the stream author that this [`User`]
    /// instance can be removed from the stream.
    pub async fn unsubscribe(&mut self) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self.stream_address().ok_or(Error::Setup(
            "before unsubscribing, the stream must be created",
        ))?;
        // Confirm user has identity
        let identifier = self
            .identifier()
            .ok_or(Error::NoIdentity("unsubscribe"))?
            .clone();
        // Get base branch topic
        let base_branch = self.state.base_branch.clone();
        // Link message to channel announcement
        let link_to = self
            .get_latest_link(&base_branch)
            .ok_or_else(|| Error::TopicNotFound(base_branch.clone()))?;

        // Update own's cursor
        let new_cursor = self.next_cursor(&base_branch)?;
        let rel_address = MsgId::gen(stream_address.base(), &identifier, &base_branch, new_cursor);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or(Error::MessageMissing(link_to, "spongos store"))?;
        let user_id = self
            .identity_mut()
            .ok_or(Error::NoIdentity("unsubscribe"))?;
        let content = PCF::new_final_frame()
            .with_content(unsubscription::Wrap::new(&mut linked_msg_spongos, user_id));
        let header = HDF::new(
            message_types::UNSUBSCRIPTION,
            new_cursor,
            identifier.clone(),
            &base_branch,
        )
        .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("unsubscribe", e))?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        if self.transport.recv_message(message_address).await.is_err() {
            return Err(Error::AddressUsed("unsubscribe", message_address));
        }

        let send_response = self.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        let permission = Permissioned::Read(identifier);
        self.state
            .cursor_store
            .insert_cursor(&base_branch, permission, new_cursor);
        self.store_spongos(rel_address, spongos, link_to);
        Ok(SendResponse::new(message_address, send_response))
    }
}

impl<T> User<T> {
    /// Processes a [`User`] unsubscription message, removing the subscriber [`Identifier`] from
    /// store.
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    pub(crate) async fn handle_unsubscription(
        &mut self,
        address: Address,
        preparsed: PreparsedMessage,
    ) -> Result<Message> {
        // Cursor is not stored, as user is unsubscribing

        // Unwrap message
        let linked_msg_address = preparsed
            .header()
            .linked_msg_address()
            .ok_or(Error::NotLinked("unsubscribe", address))?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                *spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let unsubscription = unsubscription::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed
            .unwrap(unsubscription)
            .await
            .map_err(|e| Error::Unwrapping("unsubscribe", address, e))?;

        // Store spongos
        self.store_spongos(address.relative(), spongos, linked_msg_address);

        // Store message content into stores
        self.remove_subscriber(message.payload().content().subscriber_identifier());

        Ok(Message::from_lets_message(address, message))
    }
}
