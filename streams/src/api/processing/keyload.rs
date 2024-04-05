// Rust
use alloc::vec::Vec;

// 3rd-party
use rand::{rngs::StdRng, Rng, SeedableRng};

// IOTA

// Streams
use lets::{
    address::{Address, MsgId},
    id::{Identifier, PermissionDuration, Permissioned, Psk, PskId},
    message::{Message as LetsMessage, PreparsedMessage, Topic, TransportMessage, HDF, PCF},
    transport::Transport,
};

#[cfg(feature = "did")]
use lets::id::{
    did::{StrongholdSecretManager, DID},
    IdentityKind,
};

// Local
use crate::{
    api::{message::Message, send_response::SendResponse, user::INIT_MESSAGE_NUM},
    message::{
        keyload::{Unwrap, Wrap},
        message_types,
    },
    Error, Result, User,
};

impl<T, TSR> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = TSR> + Send,
{
    /// Create and send a new Keyload message for all participants, updating the specified branch to
    /// grant all known subscribers read permissions.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch the permissions will be updated for.
    pub async fn send_keyload_for_all<Top>(&mut self, topic: Top) -> Result<SendResponse<TSR>>
    where
        Top: Into<Topic> + Clone,
    {
        let topic = topic.into();
        let permission = self
            .permission(&topic)
            .ok_or(Error::NoCursor(topic.clone()))?;
        if !permission.is_admin() {
            return Err(Error::WrongRole(
                "Admin",
                permission.identifier().clone(),
                "send a keyload",
            ));
        }
        let psks: Vec<PskId> = self.state.psk_store.keys().copied().collect();
        let subscribers: Vec<Permissioned<Identifier>> = self
            .subscribers()
            .map(|s| {
                if s == permission.identifier() {
                    Permissioned::Admin(s.clone())
                } else {
                    Permissioned::Read(s.clone())
                }
            })
            .collect();
        self.send_keyload(
            topic,
            // Alas, must collect to release the &self immutable borrow
            subscribers,
            psks,
        )
        .await
    }

    /// Create and send a new Keyload message for all participants, updating the specified branch to
    /// grant all known subscribers read and write permissions.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch the permissions will be updated for.
    pub async fn send_keyload_for_all_rw<Top>(&mut self, topic: Top) -> Result<SendResponse<TSR>>
    where
        Top: Into<Topic> + Clone,
    {
        let topic = topic.into();
        let permission = self
            .permission(&topic)
            .ok_or(Error::NoCursor(topic.clone()))?;
        if !permission.is_admin() {
            return Err(Error::WrongRole(
                "Admin",
                permission.identifier().clone(),
                "send a keyload",
            ));
        }
        let psks: Vec<PskId> = self.state.psk_store.keys().copied().collect();
        let subscribers: Vec<Permissioned<Identifier>> = self
            .subscribers()
            .map(|s| {
                if s == permission.identifier() {
                    Permissioned::Admin(s.clone())
                } else {
                    Permissioned::ReadWrite(s.clone(), PermissionDuration::Perpetual)
                }
            })
            .collect();
        self.send_keyload(
            topic,
            // Alas, must collect to release the &self immutable borrow
            subscribers,
            psks,
        )
        .await
    }

    /// Create and send a new Keyload message, updating the read/write permissions for a specified
    /// branch. All keyload messages are linked to the announcement message to ensure they
    /// can always be read by a [`User`] that can sequence up to it.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch the permissions will be updated for.
    /// * `subscribers`: The updated [`Permissioned`] list for the branch.
    /// * `psk_ids`: A list of [Psk Id's](`PskId`) with read access for the branch.
    pub async fn send_keyload<'a, Subscribers, Psks, Top>(
        &mut self,
        topic: Top,
        subscribers: Subscribers,
        psk_ids: Psks,
    ) -> Result<SendResponse<TSR>>
    where
        Subscribers: IntoIterator<Item = Permissioned<Identifier>> + Clone,
        Subscribers::IntoIter: ExactSizeIterator + Clone + Send + Sync,
        Top: Into<Topic>,
        Psks: IntoIterator<Item = PskId>,
    {
        // Check conditions
        let stream_address = self.stream_address().ok_or(Error::Setup(
            "before sending a keyload, the stream must be created",
        ))?;
        // Confirm user has identity
        let user_id = self
            .identity_mut()
            .ok_or(Error::NoIdentity("send keyload"))?;
        let identifier = user_id.to_identifier();
        // Check Topic
        let topic = topic.into();
        // Check Permission
        let permission = self
            .permission(&topic)
            .ok_or(Error::NoCursor(topic.clone()))?;
        if !permission.is_admin() {
            return Err(Error::WrongRole("Admin", identifier, "send a keyload"));
        }

        // Link message to edge of branch
        let link_to = self
            .get_latest_link(&topic)
            .ok_or_else(|| Error::TopicNotFound(topic.clone()))?;
        // Update own's cursor
        let new_cursor = self.next_cursor(&topic)?;
        let rel_address = MsgId::gen(stream_address.base(), &identifier, &topic, new_cursor);

        // Prepare HDF and PCF
        // All Keyload messages will attach to stream Announcement message spongos
        let mut announcement_msg_spongos = self
            .state
            .spongos_store
            .get(&stream_address.relative())
            .copied()
            .ok_or(Error::Setup(
                "a user must keep a stream announcement spongos in store",
            ))?;

        let mut rng = StdRng::from_entropy();
        let encryption_key = rng.gen();
        let nonce = rng.gen();
        let psk_ids_with_psks = psk_ids
            .into_iter()
            .map(|pskid| {
                let psk = self
                    .state
                    .psk_store
                    .get(&pskid)
                    .ok_or(Error::UnknownPsk(pskid))?
                    .clone();
                Ok((pskid, psk))
            })
            .collect::<Result<Vec<(PskId, Psk)>>>()?; // collect to handle possible error
        let user_id = self
            .identity_mut()
            .ok_or(Error::NoIdentity("send keyload"))?;
        let content = PCF::new_final_frame().with_content(Wrap::new(
            &mut announcement_msg_spongos,
            subscribers.clone().into_iter(),
            &psk_ids_with_psks,
            encryption_key,
            nonce,
            user_id,
        ));
        let header = HDF::new(
            message_types::KEYLOAD,
            new_cursor,
            identifier.clone(),
            &topic,
        )
        .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("send keyload", e))?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        if !self.transport.recv_message(message_address).await.is_err() {
            return Err(Error::AddressUsed("keyload", message_address));
        }

        let send_response = self.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        for subscriber in subscribers {
            if self.should_store_cursor(&topic, subscriber.as_ref()) {
                self.update_permissions(&topic, subscriber, Some(INIT_MESSAGE_NUM));
            }
        }

        self.update_permissions(&topic, Permissioned::Admin(identifier), Some(new_cursor));
        self.store_spongos(rel_address, spongos, link_to);
        // Update Branch Links
        self.set_latest_link(topic, message_address.relative());
        Ok(SendResponse::new(message_address, send_response))
    }
}

impl<T> User<T> {
    /// Processes a keyload message, updating store to include the contained list of
    /// [permissions](`Permissioned`). All keyload messages are linked to the announcement
    /// message to ensure they can always be read by a [`User`] that can sequence up to it.
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    pub(crate) async fn handle_keyload(
        &mut self,
        address: Address,
        preparsed: PreparsedMessage,
    ) -> Result<Message> {
        let stream_address = self
            .stream_address()
            .ok_or(Error::NoStream("handling a keyload"))?;

        let topic = self
            .topic_by_hash(preparsed.header().topic_hash())
            .ok_or(Error::UnknownTopic(*preparsed.header().topic_hash()))?;
        let publisher = preparsed.header().publisher().clone();
        // Confirm keyload came from administrator
        if !self
            .state
            .cursor_store
            .get_permission(&topic, &publisher)
            .ok_or(Error::NoCursor(topic.clone()))?
            .is_admin()
        {
            return Err(Error::WrongRole("admin", publisher, "receive keyload"));
        }
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state.cursor_store.insert_cursor(
            &topic,
            Permissioned::Admin(publisher),
            preparsed.header().sequence(),
        );

        // Unwrap message
        // Ok to unwrap since an author identifier is set at the same time as the stream address
        let author_identifier = self.state.author_identifier.as_ref().unwrap();
        let mut announcement_spongos = self
            .state
            .spongos_store
            .get(&stream_address.relative())
            .copied()
            .expect("a subscriber that has received an stream announcement must keep its spongos in store");

        // Fetch stored subscribers first as we'll be passing mutable references into the message
        // If a branch admin does not include a user in the keyload, any further messages sent by
        // the user will not be received by the others, so remove them from the publisher pool
        let stored_subscribers: Vec<(Permissioned<Identifier>, usize)> = self
            .cursors_by_topic(&topic)?
            .map(|(perm, cursor)| (perm.clone(), *cursor))
            .collect();

        let user_id = self.state.user_id.as_mut();
        // TODO: Remove Psk from Identity and Identifier, and manage it as a complementary permission
        let keyload = Unwrap::new(
            &mut announcement_spongos,
            user_id,
            author_identifier,
            &self.state.psk_store,
        );
        let (message, spongos) = preparsed
            .unwrap(keyload)
            .await
            .map_err(|e| Error::Unwrapping("keyload", address, e))?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        let subscribers = message.payload().content().subscribers().to_vec();

        for (perm, cursor) in stored_subscribers {
            if !(perm.identifier() == author_identifier
                || subscribers
                    .iter()
                    .any(|p| p.identifier() == perm.identifier()))
            {
                self.state.cursor_store.insert_cursor(
                    &topic,
                    Permissioned::Read(perm.identifier().clone()),
                    cursor,
                );
            }
        }

        // Have to make message before setting branch links due to immutable borrow in keyload::unwrap
        let final_message = Message::from_lets_message(address, message);

        // Store message content into stores
        for subscriber in subscribers {
            if self.should_store_cursor(&topic, subscriber.as_ref()) {
                self.state
                    .cursor_store
                    .insert_cursor(&topic, subscriber.clone(), INIT_MESSAGE_NUM);
            }
        }

        // Update branch links
        self.set_latest_link(topic, address.relative());
        Ok(final_message)
    }
}
