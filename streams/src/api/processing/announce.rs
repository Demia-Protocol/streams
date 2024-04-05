// Rust
use alloc::vec::Vec;

// 3rd-party

// IOTA

// Streams
use lets::{
    address::{Address, MsgId},
    id::{Identifier, Permissioned},
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
    message::{announcement, branch_announcement, message_types},
    Error, Result, User,
};

impl<T, TSR> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = TSR> + Send,
{
    //TODO create_stream

    /// Create and send a new Branch Announcement message, creating a new branch in `CursorStore`
    /// with the previous branches permissions carried forward.
    ///
    /// # Arguments
    /// * `from_topic`: The [`Topic`] of the branch to generate the new branch from.
    /// * `to_topic`: The [`Topic`] of the new branch being created.
    pub async fn new_branch(
        &mut self,
        from_topic: impl Into<Topic>,
        to_topic: impl Into<Topic>,
    ) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self.stream_address().ok_or(Error::Setup(
            "before starting a new branch, the stream must be created",
        ))?;
        // Confirm user has identity
        let identifier = self
            .identifier()
            .ok_or(Error::NoIdentity("create a branch"))?
            .clone();
        // Check Topic
        let topic: Topic = to_topic.into();
        let prev_topic: Topic = from_topic.into();
        // Don't allow duplicate topics
        if topic.eq(&prev_topic) {
            return Err(Error::DuplicateTopic(topic));
        }
        // Check Permission
        let permission = self
            .state
            .cursor_store
            .get_permission(&prev_topic, &identifier)
            .ok_or(Error::NoCursor(topic.clone()))?;
        if permission.is_readonly() {
            return Err(Error::WrongRole(
                "ReadWrite",
                identifier,
                "make a new branch",
            ));
        }
        let link_to = self
            .get_latest_link(&prev_topic)
            .ok_or_else(|| Error::TopicNotFound(prev_topic.clone()))?;

        // Update own's cursor
        let user_cursor = self
            .next_cursor(&prev_topic)
            .map_err(|_| Error::NoCursor(prev_topic.clone()))?;
        let msgid = MsgId::gen(stream_address.base(), &identifier, &prev_topic, user_cursor);
        let address = Address::new(stream_address.base(), msgid);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or(Error::MessageMissing(link_to, "spongos store"))?;
        let header = HDF::new(
            message_types::BRANCH_ANNOUNCEMENT,
            user_cursor,
            identifier.clone(),
            &prev_topic,
        )
        .with_linked_msg_address(link_to);
        let content = PCF::new_final_frame().with_content(branch_announcement::Wrap::new(
            &mut linked_msg_spongos,
            self.identity_mut().unwrap(),
            &topic,
        ));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("wrap new branch", e))?;

        if !self.transport.recv_message(address).await.is_err() {
            return Err(Error::AddressUsed("new branch", address));
        }

        let send_response = self.send_message(address, transport_msg).await?;

        // If message has been sent successfully, create the new branch in store
        self.state.cursor_store.new_branch(topic.clone());
        self.state.topics.insert(topic.clone());
        // Commit message to stores and update cursors
        self.state.cursor_store.insert_cursor(
            &prev_topic,
            Permissioned::Admin(identifier.clone()),
            self.next_cursor(&prev_topic)?,
        );
        self.state.spongos_store.insert(address.relative(), spongos);
        // Collect permissions from previous branch and clone them into new branch
        let prev_permissions = self
            .cursors_by_topic(&prev_topic)?
            .map(|(id, _)| id.clone())
            .collect::<Vec<Permissioned<Identifier>>>();
        for id in prev_permissions {
            self.state
                .cursor_store
                .insert_cursor(&topic, id, INIT_MESSAGE_NUM);
        }

        // Update branch links
        self.state
            .cursor_store
            .set_latest_link(topic, address.relative());
        Ok(SendResponse::new(address, send_response))
    }
}

impl<T> User<T> {
    /// Processes an announcement message, binding a [`User`] to the stream announced in the
    /// message.
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    pub(crate) async fn handle_announcement(
        &mut self,
        address: Address,
        preparsed: PreparsedMessage,
    ) -> Result<Message> {
        // Check Topic
        let publisher = preparsed.header().publisher().clone();

        // Unwrap message
        let announcement = announcement::Unwrap::default();
        let (message, spongos) = preparsed
            .unwrap(announcement)
            .await
            .map_err(|e| Error::Unwrapping("announcement", address, e))?;

        let topic = message.payload().content().topic();
        // Insert new branch into store
        self.state.cursor_store.new_branch(topic.clone());
        self.state.topics.insert(topic.clone());

        // When handling an announcement it means that no cursors have been stored, as no topics are
        // known yet. The message must be unwrapped to retrieve the initial topic before storing cursors
        self.state.cursor_store.insert_cursor(
            topic,
            Permissioned::Admin(publisher),
            INIT_MESSAGE_NUM,
        );

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores
        let author_id = message.payload().content().author_id().clone();

        // Update branch links
        self.set_latest_link(topic.clone(), address.relative());
        self.state.author_identifier = Some(author_id);
        self.state.base_branch = topic.clone();
        self.state.stream_address = Some(address);

        Ok(Message::from_lets_message(address, message))
    }

    /// Processes a branch announcement message, creating a new branch in [`CursorStore`], carrying
    /// over mapped permissions and cursors from the previous branch.
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    pub(crate) async fn handle_branch_announcement(
        &mut self,
        address: Address,
        preparsed: PreparsedMessage,
    ) -> Result<Message> {
        // Retrieve header values
        let prev_topic = self
            .topic_by_hash(preparsed.header().topic_hash())
            .ok_or(Error::UnknownTopic(*preparsed.header().topic_hash()))?;

        let publisher = preparsed.header().publisher().clone();
        let cursor = preparsed.header().sequence();

        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        let permission = self
            .state
            .cursor_store
            .get_permission(&prev_topic, &publisher)
            .ok_or(Error::NoCursor(prev_topic.clone()))?
            .clone();
        self.state
            .cursor_store
            .insert_cursor(&prev_topic, permission, cursor);

        // Unwrap message
        let linked_msg_address = preparsed
            .header()
            .linked_msg_address()
            .ok_or(Error::NotLinked("branch announcement", address))?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let branch_announcement = branch_announcement::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed
            .unwrap(branch_announcement)
            .await
            .map_err(|e| Error::Unwrapping("branch announcement", address, e))?;

        let new_topic = message.payload().content().new_topic();
        // Store spongos
        self.store_spongos(address.relative(), spongos, linked_msg_address);
        // Insert new branch into store
        self.state.cursor_store.new_branch(new_topic.clone());
        self.state.topics.insert(new_topic.clone());
        // Collect permissions from previous branch and clone them into new branch
        let prev_permissions = self
            .cursors_by_topic(&prev_topic)?
            .map(|(id, _)| id.clone())
            .collect::<Vec<Permissioned<Identifier>>>();
        for id in prev_permissions {
            self.state
                .cursor_store
                .insert_cursor(new_topic, id, INIT_MESSAGE_NUM);
        }

        // Update branch links
        self.set_latest_link(new_topic.clone(), address.relative());

        Ok(Message::from_lets_message(address, message))
    }
}
