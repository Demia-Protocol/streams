// Rust


// 3rd-party
use rand::{rngs::StdRng, Rng, SeedableRng};

// IOTA

// Streams
use lets::{
    address::{Address, MsgId},
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
    api::{message::Message, send_response::SendResponse, user::SUB_MESSAGE_NUM},
    message::{message_types, subscription},
    Error, Result, User,
};

impl<T, TSR> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = TSR> + Send,
{
    /// Create and send a new Subscription message, awaiting the stream author's acceptance into the
    /// stream.
    pub async fn subscribe(&mut self) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self.stream_address().ok_or(Error::Setup(
            "before starting a new branch, the stream must be created",
        ))?;
        // Confirm user has identity
        let identifier = self
            .identifier()
            .ok_or(Error::NoIdentity("subscribe"))?
            .clone();
        // Get base branch topic
        let base_branch = self.state.base_branch.clone();
        // Link message to channel announcement
        let link_to = stream_address.relative();
        let rel_address = MsgId::gen(
            stream_address.base(),
            &identifier,
            &base_branch,
            SUB_MESSAGE_NUM,
        );

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or(Error::MessageMissing(link_to, "spongos store"))?;
        let unsubscribe_key = StdRng::from_entropy().gen();
        let mut author_identifier = self
            .state
            .author_identifier
            .as_ref()
            .ok_or(Error::Setup("failed to retrieve author identifier"))?
            .clone();

        let user_id = self.identity_mut().ok_or(Error::NoIdentity("subscribe"))?;
        let content = PCF::new_final_frame().with_content(subscription::Wrap::new(
            &mut linked_msg_spongos,
            unsubscribe_key,
            user_id,
            &mut author_identifier,
        ));
        let header = HDF::new(
            message_types::SUBSCRIPTION,
            SUB_MESSAGE_NUM,
            identifier.clone(),
            &base_branch,
        )
        .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, _spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("subscribe", e))?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);

        // Attempt to send message
        let has_msg = self.transport.recv_message(message_address).await;
        if !has_msg.is_err() {
            return Err(Error::AddressUsed("subscribe", message_address));
        }

        let send_response = self.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        // - Subscription messages are not stored in the cursor store
        // - Subscription messages are never stored in spongos to maintain consistency about the view of the
        // set of messages of the stream between all the subscribers and across stateless recovers
        Ok(SendResponse::new(message_address, send_response))
    }
}

impl<T> User<T> {
    /// Processes a [`User`] subscription message, storing the subscriber [`Identifier`].
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    pub(crate) async fn handle_subscription(
        &mut self,
        address: Address,
        preparsed: PreparsedMessage,
    ) -> Result<Message> {
        // Cursor is not stored, as cursor is only tracked for subscribers with write permissions

        // Unwrap message
        let linked_msg_address = preparsed
            .header()
            .linked_msg_address()
            .ok_or(Error::NotLinked("subscription", address))?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let user_id = self
            .identity_mut()
            .ok_or(Error::NoIdentity("Derive a secret key"))?;

        let subscription = subscription::Unwrap::new(&mut linked_msg_spongos, user_id);
        let (message, _spongos) = preparsed
            .unwrap(subscription)
            .await
            .map_err(|e| Error::Unwrapping("subscription", address, e))?;

        // Store spongos
        // Subscription messages are never stored in spongos to maintain consistency about the view of the
        // set of messages of the stream between all the subscribers and across stateless recovers

        // Store message content into stores
        let subscriber_identifier = message.payload().content().subscriber_identifier().clone();
        let final_message = Message::from_lets_message(address, message);
        self.add_subscriber(subscriber_identifier);

        Ok(final_message)
    }
}
