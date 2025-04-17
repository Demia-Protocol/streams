// Rust

// 3rd-party

// IOTA

// Streams
use lets::{
    address::{Address, MsgId},
    message::{Message as LetsMessage, PreparsedMessage, Topic, TransportMessage, HDF, PCF},
    transport::Transport,
};

// Local
use crate::{
    api::{message::Message, send_response::SendResponse},
    message::{message_types, message_types::MessageType, tagged_packet},
    Error, Result, User,
};

impl<T, TSR> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = TSR> + Send,
{
    /// Create and send a new Tagged Packet message to the specified branch. The message will
    /// contain a masked and an unmasked payload.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to send the message to.
    /// * `public_payload`: The unmasked payload of the message.
    /// * `masked_payload`: The masked payload of the message.
    pub async fn send_tagged_packet<P, M, Top>(
        &mut self,
        topic: Top,
        public_payload: P,
        masked_payload: M,
    ) -> Result<SendResponse<TSR>>
    where
        M: AsRef<[u8]>,
        P: AsRef<[u8]>,
        Top: Into<Topic>,
    {
        // Check conditions
        let stream_address = self.stream_address().ok_or(Error::Setup(
            "before sending a tagged packet, the stream must be created",
        ))?;
        let user_id = self
            .identity()
            .ok_or(Error::NoIdentity("send tagged packet"))?;
        let identifier = user_id.identifier().clone();
        // Check Topic
        let topic = topic.into();
        // Check Permission
        let mut permission = self
            .state
            .cursor_store
            .get_permission(&topic, &identifier)
            .ok_or(Error::NoCursor(topic.clone()))?
            .clone();

        // Check pre for time-related permissions
        permission = self
            .check_and_update_permission(
                MessageType::TaggedPacket.into(),
                &topic,
                permission.clone(),
                None,
            )
            .await?
            .1;

        if permission.is_readonly() {
            return Err(Error::WrongRole(
                "ReadWrite",
                Box::new(permission.identifier().clone()),
                "send a tagged packet",
            ));
        }
        // Link message to latest message in branch
        let link_to = self
            .get_latest_link(&topic)
            .ok_or_else(|| Error::TopicNotFound(topic.clone()))?;

        // Update own's cursor
        let new_cursor = self.next_cursor(&topic)?;
        let rel_address = MsgId::gen(stream_address.base(), &identifier, &topic, new_cursor);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or(Error::MessageMissing(link_to, "spongos store"))?;
        let content = PCF::new_final_frame().with_content(tagged_packet::Wrap::new(
            &mut linked_msg_spongos,
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header = HDF::new(
            message_types::TAGGED_PACKET,
            new_cursor,
            identifier.clone(),
            &topic,
        )
        .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("send tagged packet", e))?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        if self.transport.recv_message(message_address).await.is_ok() {
            return Err(Error::AddressUsed("tagged packet", message_address));
        }
        let send_response = self.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state
            .cursor_store
            .insert_cursor(&topic, permission.clone(), new_cursor);
        self.store_spongos(rel_address, spongos, link_to);
        // Post permission check to remove permisisons if this was the last msg allowed
        self.check_and_update_permission(
            MessageType::TaggedPacket.into(),
            &topic,
            permission,
            None,
        )
        .await?;
        // Update Branch Links
        self.set_latest_link(topic, rel_address);

        Ok(SendResponse::new(message_address, send_response))
    }
}

impl<'a, T> User<T>
where
    T: Transport<'a> + Send,
{
    /// Processes a tagged packet message, retrieving the public and masked payloads.
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    pub(crate) async fn handle_tagged_packet(
        &mut self,
        address: Address,
        preparsed: PreparsedMessage,
    ) -> Result<Message> {
        let raw = preparsed.transport_msg().body().clone();

        let topic = self
            .topic_by_hash(preparsed.header().topic_hash())
            .ok_or(Error::UnknownTopic(*preparsed.header().topic_hash()))?;
        let publisher = preparsed.header().publisher();

        // Retrieve public key and signature for Message return
        let pk = preparsed.transport_msg().pk().clone();
        let sig = preparsed.transport_msg().sig().clone();

        let permission = self
            .state
            .cursor_store
            .get_permission(&topic, publisher)
            .ok_or(Error::NoCursor(topic.clone()))?
            .clone();
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state.cursor_store.insert_cursor(
            &topic,
            permission.clone(),
            preparsed.header().sequence(),
        );

        // Check pre for time-related permissions
        let (changed, permission) = self
            .check_and_update_permission(
                MessageType::TaggedPacket.into(),
                &topic,
                permission.clone(),
                Some(preparsed.header().timestamp as u128),
            )
            .await?;
        if changed {
            // lost permission
        }

        // Unwrap message
        let linked_msg_address = preparsed
            .header()
            .linked_msg_address()
            .ok_or(Error::NotLinked("tagged", address))?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, pk, sig, preparsed));
            }
        };
        let tagged_packet = tagged_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed
            .unwrap(tagged_packet)
            .await
            .map_err(|e| Error::Unwrapping("tagged packet", address, e))?;

        // Store spongos
        self.store_spongos(address.relative(), spongos, linked_msg_address);

        // Post permission check to remove permisisons if this was the last msg allowed
        self.check_and_update_permission(
            MessageType::TaggedPacket.into(),
            &topic,
            permission,
            Some(u128::MAX),
        )
        .await?;

        // Store message content into stores
        self.set_latest_link(topic.clone(), address.relative());

        Ok(Message::from_lets_message(address, pk, sig, raw, message))
    }
}
