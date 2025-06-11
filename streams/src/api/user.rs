// Rust
use alloc::{borrow::ToOwned, boxed::Box, string::ToString, vec::Vec};
use core::fmt::{Debug, Formatter, Result as FormatResult};

#[cfg(feature = "did")]
use alloc::sync::Arc;

// 3rd-party
use async_trait::async_trait;
use futures::{future, TryStreamExt};
use hashbrown::{HashMap, HashSet};
use rand::Rng;

#[cfg(feature = "did")]
use tokio::sync::RwLock;

// IOTA

// Streams
use lets::{
    address::{Address, AppAddr, MsgId},
    id::{Identifier, Identity, PermissionDuration, PermissionType, Permissioned, Psk, PskId},
    message::{
        ContentSizeof, ContentUnwrap, ContentWrap, Message as LetsMessage, Topic, TopicHash,
        TransportMessage, HDF, PCF,
    },
    transport::Transport,
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Mask, Squeeze},
        modifiers::External,
        types::{Mac, Maybe, NBytes, Size, Uint8},
    },
    error::{Error as SpongosError, Result as SpongosResult},
    KeccakF1600, Spongos, SpongosRng,
};

#[cfg(feature = "did")]
use lets::id::{
    did::{StrongholdSecretManager, DID},
    IdentityKind,
};

// Local
use crate::{
    api::{
        cursor_store::CursorStore, message::Message, message_builder::MessageBuilder,
        messages::Messages, send_response::SendResponse, user::message_types::MessageType,
        user_builder::UserBuilder,
    },
    message::{announcement, message_types},
    Error, Result, Selector,
};

pub(crate) const ANN_MESSAGE_NUM: usize = 0; // Announcement is always the first message of authors
pub(crate) const SUB_MESSAGE_NUM: usize = 0; // Subscription is always the first message of subscribers
pub(crate) const INIT_MESSAGE_NUM: usize = 1; // First non-reserved message number

/// The state of a user, mapping publisher cursors and link states for message processing.
#[derive(PartialEq, Eq, Default, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct State {
    /// Users' [`Identity`] information, contains keys and logic for signing and verification.
    ///
    /// None if the user is not created with an identity
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub(crate) user_id: Option<Identity>,

    /// [`Address`] of the stream announcement message.
    ///
    /// None if channel is not created or user is not subscribed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub(crate) stream_address: Option<Address>,

    /// [`Identifier`] of the channel author.
    ///
    /// None if channel is not created or user is not subscribed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub(crate) author_identifier: Option<Identifier>,

    /// Users' trusted public keys together with additional sequencing info: (msgid, seq_no) mapped
    /// by branch topic Vec.
    pub(crate) cursor_store: CursorStore,

    /// Mapping of trusted pre shared keys and identifiers.
    pub(crate) psk_store: HashMap<PskId, Psk>,

    /// List of Subscribed [Identifiers](`Identifier`).
    pub(crate) subscribers: HashSet<Identifier>,

    /// Mapping of message links ([`MsgId`]) and [`Spongos`] states. Messages are built from the
    /// [`Spongos`] state of a previous message. If the state for a link is not stored, then a
    /// message cannot be formed or processed.
    pub(crate) spongos_store: HashMap<MsgId, Spongos>,

    pub(crate) base_branch: Topic,

    /// Users' [`Spongos`] Storage configuration. If lean, only the announcement message and latest
    /// branch message spongos state is stored. This reduces the overall size of the user
    /// implementation over time. If not lean, all spongos states processed by the user will be
    /// stored.
    lean: bool,

    /// List of known branch topics.
    pub(crate) topics: HashSet<Topic>,
}

/// Public `API` Client for participation in a `Streams` channel.
pub struct User<T> {
    /// A transport client for sending and receiving messages.
    pub(crate) transport: T,
    /// The internal [state](`State`) of the user, containing message state mappings and publisher
    /// cursors for message processing.
    pub(crate) state: State,
}

impl User<()> {
    /// Creates a new [`UserBuilder`] instance.
    pub fn builder() -> UserBuilder<()> {
        UserBuilder::new()
    }
}

impl<T> User<T> {
    /// Creates a new [`User`] with the provided configurations.
    ///
    /// # Arguments
    /// * `user_id`: The user's [`Identity`]. This is used to sign messages.
    /// * `psks`: A list of trusted pre shared keys.
    /// * `transport`: The transport to use for sending and receiving messages.
    /// * `lean`: If true, the client will store only required message states.
    pub(crate) fn new<Psks>(user_id: Option<Identity>, psks: Psks, transport: T, lean: bool) -> Self
    where
        Psks: IntoIterator<Item = (PskId, Psk)>,
    {
        let mut psk_store = HashMap::new();
        let subscribers = HashSet::new();

        // Store any pre shared keys
        psks.into_iter().for_each(|(pskid, psk)| {
            psk_store.insert(pskid, psk);
        });

        Self {
            transport,
            state: State {
                user_id,
                cursor_store: CursorStore::new(),
                psk_store,
                subscribers,
                spongos_store: Default::default(),
                stream_address: None,
                author_identifier: None,
                base_branch: Default::default(),
                lean,
                topics: Default::default(),
            },
        }
    }

    /// Returns a reference to the [User's](`User`) [`Identifier`] if any.
    pub fn identifier(&self) -> Option<&Identifier> {
        self.identity().map(|id| id.identifier())
    }

    /// Returns a reference to the [User's](`User`) [`Identity`] if any.
    pub(crate) fn identity(&self) -> Option<&Identity> {
        self.state.user_id.as_ref()
    }

    /// Returns a mutable reference to the [User's](`User`) [`Identity`] if any.
    pub(crate) fn identity_mut(&mut self) -> Option<&mut Identity> {
        self.state.user_id.as_mut()
    }

    #[cfg(feature = "did")]
    pub fn with_stronghold(&mut self, stronghold: Arc<RwLock<StrongholdSecretManager>>) {
        if let Some(identity) = self.identity_mut() {
            if let IdentityKind::DID(DID::PrivateKey(info)) = identity.identity_kind() {
                let did_info = info.url_info_mut();
                *did_info = did_info.clone().with_stronghold(stronghold);
            }
        }
    }

    /// Returns a reference to the [User's](`User`) [permission](`Permissioned`) for a given branch
    /// if any
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to check
    pub fn permission(&self, topic: &Topic) -> Option<&Permissioned<Identifier>> {
        self.identifier()
            .and_then(|id| self.state.cursor_store.get_permission(topic, id))
    }

    /// Returns the [User's](`User`) cursor for a given branch if any
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to check
    pub fn cursor(&self, topic: &Topic) -> Option<usize> {
        self.identifier()
            .and_then(|id| self.state.cursor_store.get_cursor(topic, id))
    }

    /// Returns the [User's](`User`) next cursor for a given branch. Errors if there is
    /// no cursor present for the [`User`] in [`CursorStore`].
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to check
    pub fn next_cursor(&self, topic: &Topic) -> Result<usize> {
        self.cursor(topic)
            .map(|c| c + 1)
            .ok_or(Error::NoCursor(topic.clone()))
    }

    /// Returns a reference to the base branch [`Topic`] for the stream.
    pub fn base_branch(&self) -> &Topic {
        &self.state.base_branch
    }

    /// Returns a reference to the announcement message [`Address`] for the stream if any.
    pub fn stream_address(&self) -> Option<Address> {
        self.state.stream_address
    }

    /// Returns a reference to the [`User`] transport client.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns a mutable reference to the [`User`] transport client.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Returns an iterator over all known branch [topics](`Topic`)
    pub fn topics(&self) -> impl ExactSizeIterator<Item = &Topic> {
        self.state.topics.iter()
    }

    /// Iterates through known topics, returning the [`Topic`] that matches the [`TopicHash`]
    /// provided if any
    ///
    /// # Arguments
    /// * `hash`: The [`TopicHash`] from a message header
    pub fn topic_by_hash(&self, hash: &TopicHash) -> Option<Topic> {
        self.topics()
            .find(|t| &TopicHash::from(*t) == hash)
            .cloned()
    }

    /// Returns true if [`User`] lean state configuration is true
    pub fn lean(&self) -> bool {
        self.state.lean
    }

    /// Returns the identifier of the stream author.
    /// None if channel is not created or user is not subscribed.
    pub fn author(&self) -> Option<&Identifier> {
        self.state.author_identifier.as_ref()
    }

    /// Returns an iterator over [`CursorStore`], producing tuples of [`Topic`], [`Permissioned`]
    /// [`Identifier`], and the cursor. Used by [`Messages`] streams to find next messages.
    pub fn cursors(&self) -> impl Iterator<Item = (&Topic, &Permissioned<Identifier>, usize)> + '_ {
        self.state.cursor_store.cursors()
    }

    /// Returns an iterator over a [`Topic`] mapped branch in [`CursorStore`], producing tuples of
    /// [`Permissioned`][`Identifier`] and a cursor. Used to carry permissions forward through
    /// branch declarations. Returns an error if the [`Topic`] is not found in store.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to fetch cursors for
    pub fn cursors_by_topic(
        &self,
        topic: &Topic,
    ) -> Result<impl Iterator<Item = (&Permissioned<Identifier>, &usize)>> {
        self.state
            .cursor_store
            .cursors_by_topic(topic)
            .ok_or(Error::TopicNotFound(topic.clone()))
    }

    /// Returns an iterator over known subscriber [identifiers](`Identifier`)
    pub fn subscribers(&self) -> impl Iterator<Item = &Identifier> + Clone + '_ {
        self.state.subscribers.iter()
    }

    /// If the subscriber is not readonly and the [`Permissioned`] is not tracked or the
    /// [`Permissioned`] is tracked and not equal to the provided subscriber [`Permissioned`],
    /// then the cursor should be stored.
    ///
    /// # Arguments:
    /// * `topic`: The topic of the branch to be stored in.
    /// * `permission`: The [`Permissioned`] to check.
    pub(crate) fn should_store_cursor(
        &self,
        topic: &Topic,
        permission: Permissioned<&Identifier>,
    ) -> bool {
        let self_permission = self
            .state
            .cursor_store
            .get_permission(topic, permission.identifier());
        let tracked_and_equal =
            self_permission.is_some() && (self_permission.unwrap().as_ref() == permission);
        !permission.is_readonly() && !tracked_and_equal
    }

    /// Store a new [`Spongos`] state. If the [`User`] lean state configuration is set to true, and
    /// if the linked message is not the stream announcement message, remove the previous message
    /// from store.
    ///
    /// # Arguments:
    /// * `msg_address`: The [`Address`] of the message that we're storing the [`Spongos`] for.
    /// * `spongos`: The [`Spongos`] state to be stored.
    /// * `linked_msg_address`: The address of the message that the spongos is linked to.
    pub(crate) fn store_spongos(
        &mut self,
        msg_address: MsgId,
        spongos: Spongos,
        linked_msg_address: MsgId,
    ) {
        let is_stream_address = self
            .stream_address()
            .is_some_and(|stream_address| stream_address.relative() == linked_msg_address);
        // Do not remove announcement message from store
        if self.lean() && !is_stream_address {
            self.state.spongos_store.remove(&linked_msg_address);
        }

        self.state.spongos_store.insert(msg_address, spongos);
    }

    /// Store a new subscriber [`Identifier`] in state. Returns true if subscriber was not present.
    pub fn add_subscriber(&mut self, subscriber: Identifier) -> bool {
        self.state.subscribers.insert(subscriber)
    }

    /// Remove a subscriber [`Identifier`] from state. Returns true if the subscriber was present.
    pub fn remove_subscriber(&mut self, id: &Identifier) -> bool {
        self.state.subscribers.remove(id)
    }

    /// Get a [`Psk`] from state if it exists.
    pub fn get_psk(&mut self, psk: &PskId) -> Option<&Psk> {
        self.state.psk_store.get(psk)
    }

    /// Get all [`Psk`] from state.
    pub fn psks(&mut self) -> hashbrown::hash_map::Iter<'_, PskId, Psk> {
        self.state.psk_store.iter()
    }

    /// Store a new [Pre-Shared Key](`Psk`) in state. Returns true if [`Psk`] was not present.
    pub fn add_psk(&mut self, psk: Psk) -> bool {
        self.state.psk_store.insert(psk.to_pskid(), psk).is_none()
    }

    /// Remove a [`Psk`] from state by its [identifier](`PskId`). Returns true if the [`Psk`] was
    /// present.
    pub fn remove_psk(&mut self, pskid: PskId) -> bool {
        self.state.psk_store.remove(&pskid).is_some()
    }

    /// Sets the latest message link for a specified branch. If the branch does not exist, it is
    /// created.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch
    /// * `latest_link`: The [`MsgId`] link that will be set
    pub(crate) fn set_latest_link(&mut self, topic: Topic, latest_link: MsgId) {
        self.state.cursor_store.set_latest_link(topic, latest_link)
    }

    /// Returns the latest [`MsgId`] link for a specified branch, if any
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch
    pub(crate) fn get_latest_link(&self, topic: &Topic) -> Option<MsgId> {
        self.state.cursor_store.get_latest_link(topic)
    }

    /// Creates an encrypted, serialised representation of a [`User`] `State` for backup and
    /// recovery.
    ///
    /// # Arguments
    /// * `pwd`: The password to encrypt the `State` with
    pub async fn backup<P>(&mut self, pwd: P) -> Result<Vec<u8>>
    where
        P: AsRef<[u8]>,
    {
        let mut ctx = sizeof::Context::new();
        ctx.sizeof(&self.state).await.map_err(Error::Spongos)?;
        let buf_size = ctx.finalize() + 32; // State + Mac Size

        let mut buf = vec![0; buf_size];

        let mut ctx = wrap::Context::new(&mut buf[..]);
        let key: [u8; 32] = SpongosRng::<KeccakF1600>::new(pwd).gen();
        ctx.absorb(External::new(&NBytes::new(key)))
            .map_err(Error::Spongos)?
            .commit()
            .map_err(Error::Spongos)?
            .squeeze(&Mac::new(32))
            .map_err(Error::Spongos)?;
        ctx.wrap(&mut self.state).await.map_err(Error::Spongos)?;
        assert!(
            ctx.stream().is_empty(),
            "Missmatch between buffer size expected by SizeOf ({buf_size}) and actual size of Wrap ({})",
            ctx.stream().len()
        );

        Ok(buf)
    }

    /// Restore a [`User`] from an encrypted binary stream using the provided password and transport
    /// client.
    ///
    /// # Arguments
    /// * `backup`: Encrypted binary stream of backed up `State`.
    /// * `pwd`: The decryption password.
    /// * `transport`: The transport client for sending and receiving messages.
    pub async fn restore<B, P>(backup: B, pwd: P, transport: T) -> Result<Self>
    where
        P: AsRef<[u8]>,
        B: AsRef<[u8]>,
    {
        let mut ctx = unwrap::Context::new(backup.as_ref());
        let key: [u8; 32] = SpongosRng::<KeccakF1600>::new(pwd).gen();
        ctx.absorb(External::new(&NBytes::new(key)))
            .map_err(Error::Spongos)?
            .commit()
            .map_err(Error::Spongos)?
            .squeeze(&Mac::new(32))
            .map_err(Error::Spongos)?;
        let mut state = State::default();
        ctx.unwrap(&mut state).await.map_err(Error::Spongos)?;
        Ok(User { transport, state })
    }
}

impl<'a, T> User<T>
where
    T: Transport<'a>,
{
    /// Parse and process a [`TransportMessage`] dependent on its type.
    ///
    /// # Arguments
    /// * `address`: The [`Address`] of the message to process
    /// * `msg`: The raw [`TransportMessage`]
    pub(crate) async fn handle_message(
        &mut self,
        address: Address,
        msg: TransportMessage,
    ) -> Result<Message>
    where
        T: Send,
    {
        let preparsed = msg
            .parse_header()
            .await
            .map_err(|e| Error::Unwrapping("header", address, e))?;

        match preparsed.header().message_type().try_into()? {
            MessageType::Announcement => self.handle_announcement(address, preparsed).await,
            MessageType::BranchAnnouncement => {
                self.handle_branch_announcement(address, preparsed).await
            }
            MessageType::Subscription => self.handle_subscription(address, preparsed).await,
            MessageType::Unsubscription => self.handle_unsubscription(address, preparsed).await,
            MessageType::Keyload => self.handle_keyload(address, preparsed).await,
            MessageType::SignedPacket => self.handle_signed_packet(address, preparsed).await,
            MessageType::TaggedPacket => self.handle_tagged_packet(address, preparsed).await,
        }
    }

    /// The function `has_permission` checks if the user has the required permission for a
    /// specific action on a given topic.
    ///
    /// Arguments:
    ///
    /// * `topic`: The topic for whichv you want to check the permission.
    /// * `action`: the type of permission being checked for a specific topic.
    ///
    /// Returns:
    ///
    pub fn has_permission(&self, topic: &Topic, action: PermissionType) -> bool {
        let id = self.identifier();
        if id.is_none() {
            // TODO check psks access
            return false;
        }

        let perms = self
            .state
            .cursor_store
            .get_permission(topic, self.identifier().unwrap());
        match (perms, action) {
            (None, _) | (Some(_), PermissionType::Read) => true, // TODO: make it so we check if we can decrypt
            (Some(p), PermissionType::ReadWrite) => !(PermissionType::Read == p.into()),
            (Some(p), PermissionType::Admin) => PermissionType::Admin == p.into(),
        }
    }

    /**
     * Sets the cursor of the identified user on the branch to the value or INIT_MESSAGE_NUM.
     * If the identifier has a cursor stored with a different permission,
     * removes that permission (preserving the cursor).
     */
    pub(crate) fn update_permissions(
        &mut self,
        topic: &Topic,
        permission: Permissioned<Identifier>,
        cursor: Option<usize>,
    ) {
        // TODO: set old cursor and update when permisisons get updated to write again
        let cursor = cursor.unwrap_or(INIT_MESSAGE_NUM);
        self.state
            .cursor_store
            .insert_cursor(topic, permission, cursor);
    }

    // TODO: Re-evaluate the way we process permissions twice per message
    pub(crate) async fn check_and_update_permission(
        &mut self,
        action: PermissionType,
        topic: &Topic,
        mut permission: Permissioned<Identifier>,
        time: Option<u128>, // Intended to use with the header timestamp
    ) -> Result<(bool, Permissioned<Identifier>)>
    where
        T: Send,
    {
        if action == PermissionType::Read {
            return Ok((false, permission));
        }

        let mut change = false;
        if let Permissioned::ReadWrite(_, duration) = permission {
            change = match duration {
                PermissionDuration::Perpetual => false,
                PermissionDuration::Unix(t) => match time {
                    Some(time) => time > (t as u128),
                    None => self.latest_timestamp().await? > (t as u128),
                },
                PermissionDuration::NumBranchMsgs(n) => {
                    let num: u32 = self
                        .state
                        .cursor_store
                        .get_cursor(topic, &permission)
                        .unwrap_or(0)
                        .try_into()
                        .unwrap();
                    (num - INIT_MESSAGE_NUM as u32) > n
                }
                PermissionDuration::NumPublishedmsgs(n) => {
                    let num: u32 = self
                        .state
                        .cursor_store
                        .total_msg_for_id(&permission)
                        .try_into()
                        .unwrap();
                    num > n
                }
            };
        };

        if change {
            permission = Permissioned::Read(permission.identifier().clone());
            self.update_permissions(topic, permission.clone(), None);
        }
        Ok((change, permission))
    }

    pub(crate) async fn latest_timestamp(&self) -> Result<u128> {
        self.transport()
            .latest_timestamp()
            .await
            .map_err(|e| Error::PreCheck("time", e.to_string()))
    }
}

impl<T> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage> + Send + Sync,
{
    /// Receive a raw message packet using the internal [`Transport`] client
    ///
    /// # Arguments
    /// * `address`: The [`Address`] of the message to be retrieved.
    pub async fn receive_message(&mut self, address: Address) -> Result<Message>
    where
        T: for<'a> Transport<'a, Msg = TransportMessage>,
    {
        let msg = self
            .transport
            .recv_message(address)
            .await
            .map_err(|e| Error::Transport(address, "receive message", e))?;
        self.handle_message(address, msg).await
    }

    /// Start a [`Messages`] stream to traverse the channel messages
    ///
    /// See the documentation in [`Messages`] for more details and examples.
    pub fn messages(&mut self) -> Messages<T> {
        Messages::new(self)
    }

    /// Start a [`Messages`] stream to traverse the channel messages with a filter
    ///
    /// See the documentation in [`Messages`] for more details and examples.
    pub fn filtered_messages<'a>(&'a mut self, filter: &'a str) -> Messages<'a, T> {
        Messages::new_with_filter(self, filter)
    }

    /// Iteratively fetches all the next messages until internal state has caught up
    ///
    /// If succeeded, returns the number of messages advanced.
    pub async fn sync(&mut self) -> Result<usize> {
        // ignoring the result is sound as Drain::Error is Infallible
        self.messages()
            .try_fold(0, |n, _| future::ok(n + 1))
            .await
            .map_err(Error::Messages)
    }

    /// Synchronize the base branch of the Stream
    ///
    /// If succeeded, returns the number of messages advanced.
    pub async fn sync_base_branch(&mut self) -> Result<usize> {
        let base_branch = self.base_branch().to_string();
        self.filtered_messages(base_branch.as_str())
            .try_fold(0, |n, _| future::ok(n + 1))
            .await
            .map_err(Error::Messages)
    }

    pub async fn sync_from(
        &mut self,
        selector: &Selector,
        topic: impl Into<Topic>,
    ) -> Result<Messages<T>> {
        let topic = topic.into();
        let addr = AppAddr::gen(
            self.state.author_identifier.as_ref().unwrap(),
            &self.state.base_branch,
        );
        let mut latest = Address::new(
            addr,
            self.get_latest_link(&topic)
                .ok_or_else(|| Error::TopicNotFound(topic.clone()))?,
        );

        let mut msg = self
            .transport
            .recv_message(latest)
            .await
            .map_err(|e| Error::Transport(latest, "receive message", e))?;
        let mut preparsed: lets::message::PreparsedMessage = msg
            .parse_header()
            .await
            .map_err(|e| Error::Unwrapping("header", latest, e))?;
        let mut header = preparsed.header();

        let mut msgs = HashMap::new();

        // Check if the selector precedes the latest message already,
        // meaning we need to go forward before retuning any messages.
        let mut forward = selector.is_from_header(header, Some(latest));

        // sync up only if we really need to, to prevent double fetching
        if forward {
            // Only fetch until we meet our reqs
            while let (false, Some(Ok(m))) = (forward, self.messages().next().await) {
                // Add to the cache for later in order not to fetch twice
                msgs.insert(m.address().relative(), m.clone());
                latest = m.address();
                header = preparsed.header();
                forward = !selector.is_from_header(header, Some(latest));
            }
        }

        while selector.is_from_header(header, Some(latest)) && header.linked_msg_address.is_some() {
            latest = Address::new(addr, header.linked_msg_address.unwrap());

            msg = self
                .transport
                .recv_message(latest)
                .await
                .map_err(|e| Error::Transport(latest, "receive message", e))?;
            preparsed = msg
                .parse_header()
                .await
                .map_err(|e| Error::Unwrapping("header", latest, e))?;
            header = preparsed.header();
        }

        let start = (topic, header.publisher().clone(), header.sequence);
        let messages_stream = Messages::new_with_cache(self, msgs, Some(start));

        Ok(messages_stream)
    }

    /// Iteratively fetches all the pending messages from the transport
    ///
    /// Return a vector with all the messages collected. This is a convenience
    /// method around the [`Messages`] stream. Check out its docs for more
    /// advanced usages.
    pub async fn fetch_next_messages(&mut self) -> Result<Vec<Message>> {
        self.messages().try_collect().await.map_err(Error::Messages)
    }
}

impl<T, TSR> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = TSR> + Send,
{
    /// Create and send a stream Announcement message, anchoring the stream for others to attach to.
    /// Errors if the [`User`] is already attached to a stream, or if the message already exists in
    /// the transport layer.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] that will be used for the base branch
    pub async fn create_stream<Top: Into<Topic>>(
        &mut self,
        topic: Top,
    ) -> Result<SendResponse<TSR>> {
        // Check conditions
        if self.stream_address().is_some() {
            return Err(Error::Setup(
                "Cannot create a channel, user is already registered to channel",
            ));
        }
        // Confirm user has identity
        let identifier = self
            .identifier()
            .ok_or(Error::NoIdentity("create a stream"))?
            .clone();
        // Convert topic
        let topic = topic.into();
        // Generate stream address
        let stream_base_address = AppAddr::gen(&identifier, &topic);
        let stream_rel_address =
            MsgId::gen(stream_base_address, &identifier, &topic, INIT_MESSAGE_NUM);
        let stream_address = Address::new(stream_base_address, stream_rel_address);

        // Prepare HDF and PCF
        let header = HDF::new(
            message_types::ANNOUNCEMENT,
            ANN_MESSAGE_NUM,
            identifier.clone(),
            &topic,
        );
        let content = PCF::new_final_frame().with_content(announcement::Wrap::new(
            self.identity_mut().unwrap(),
            &topic,
        ));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("wrap announce", e))?;

        // Attempt to send message
        if self.transport.recv_message(stream_address).await.is_ok() {
            return Err(Error::Setup(
                "Cannot create a channel, announce address already in use",
            ));
        }

        let send_response = self.send_message(stream_address, transport_msg).await?;

        // If a message has been sent successfully, insert the base branch into store
        self.state.cursor_store.new_branch(topic.clone());
        self.state.topics.insert(topic.clone());
        // Commit message to stores
        self.state.cursor_store.insert_cursor(
            &topic,
            Permissioned::Admin(identifier.clone()),
            INIT_MESSAGE_NUM,
        );
        self.state
            .spongos_store
            .insert(stream_address.relative(), spongos);

        // Update branch links
        self.set_latest_link(topic.clone(), stream_address.relative());

        // Commit Author Identifier and Stream Address to store
        self.state.stream_address = Some(stream_address);
        self.state.author_identifier = Some(identifier);
        self.state.base_branch = topic;

        Ok(SendResponse::new(stream_address, send_response))
    }

    /// Create a new [`MessageBuilder`] instance.
    pub fn message<P: Default>(&mut self) -> MessageBuilder<P, T> {
        MessageBuilder::new(self)
    }

    pub(crate) async fn send_message(
        &mut self,
        address: Address,
        msg: TransportMessage,
    ) -> Result<TSR> {
        let identity = self
            .identity_mut()
            .ok_or(Error::NoIdentity("send messages"))?;
        // TODO: store pubkey in user instance for easy retrieval
        let sig = identity
            .sign_data(msg.as_ref())
            .await
            .map_err(|e| Error::Transport(address, "send message", e))?;
        let pub_key = identity
            .identifier()
            .sig_pk()
            .await
            .map_err(|e| Error::Transport(address, "send message", e))?;
        self.transport
            .send_message(address, msg, pub_key, sig)
            .await
            .map_err(|e| Error::Transport(address, "send announce message", e))
        // }
    }
}

#[async_trait]
impl ContentSizeof<State> for sizeof::Context {
    async fn sizeof(&mut self, user_state: &State) -> SpongosResult<&mut Self> {
        self.mask(Maybe::new(user_state.user_id.as_ref()))?
            .mask(Maybe::new(user_state.stream_address.as_ref()))?
            .mask(Maybe::new(user_state.author_identifier.as_ref()))?
            .mask(&user_state.base_branch)?;

        let amount_spongos = user_state.spongos_store.len();
        self.mask(Size::new(amount_spongos))?;
        for (address, spongos) in &user_state.spongos_store {
            self.mask(address)?.mask(spongos)?;
        }

        // Only keep topics that exist in cursor store, any others serve no purpose
        let topics = user_state
            .topics
            .iter()
            .filter(|t| user_state.cursor_store.get_latest_link(t).is_some());
        let amount_topics = topics.clone().count();
        self.mask(Size::new(amount_topics))?;

        for topic in topics {
            self.mask(topic)?;
            let latest_link = user_state.cursor_store.get_latest_link(topic).ok_or(
                SpongosError::InvalidAction(
                    "calculate sizeof for topic latest link",
                    topic.to_string(),
                    "No Cursor".to_owned(),
                ),
            )?;
            self.mask(&latest_link)?;

            let cursors: Vec<(&Permissioned<Identifier>, &usize)> = user_state
                .cursor_store
                .cursors_by_topic(topic)
                .ok_or(SpongosError::InvalidAction(
                    "get cursor for topic",
                    topic.to_string(),
                    "No Cursor".to_owned(),
                ))?
                .collect();
            let amount_cursors = cursors.len();
            self.mask(Size::new(amount_cursors))?;
            for (subscriber, cursor) in cursors {
                self.mask(subscriber)?.mask(Size::new(*cursor))?;
            }
        }

        let subs = &user_state.subscribers;
        let amount_subs = subs.len();
        self.mask(Size::new(amount_subs))?;
        for subscriber in subs {
            self.mask(subscriber)?;
        }

        let psks = user_state.psk_store.iter();
        let amount_psks = psks.len();
        self.mask(Size::new(amount_psks))?;
        for (pskid, psk) in psks {
            self.mask(pskid)?.mask(psk)?;
        }

        let lean = if user_state.lean { 1 } else { 0 };
        self.mask(Uint8::new(lean))?;

        self.commit()?.squeeze(Mac::new(32))
    }
}

#[async_trait]
impl ContentWrap<State> for wrap::Context<&mut [u8]> {
    async fn wrap(&mut self, user_state: &mut State) -> SpongosResult<&mut Self> {
        self.mask(Maybe::new(user_state.user_id.as_ref()))?
            .mask(Maybe::new(user_state.stream_address.as_ref()))?
            .mask(Maybe::new(user_state.author_identifier.as_ref()))?
            .mask(&user_state.base_branch)?;

        let amount_spongos = user_state.spongos_store.len();
        self.mask(Size::new(amount_spongos))?;
        for (address, spongos) in &user_state.spongos_store {
            self.mask(address)?.mask(spongos)?;
        }

        // Only keep topics that exist in cursor store, any others serve no purpose
        let topics = user_state
            .topics
            .iter()
            .filter(|t| user_state.cursor_store.get_latest_link(t).is_some());
        let amount_topics = topics.clone().count();
        self.mask(Size::new(amount_topics))?;

        for topic in topics {
            self.mask(topic)?;
            let latest_link = user_state.cursor_store.get_latest_link(topic).ok_or(
                SpongosError::InvalidAction(
                    "get latest link topic for wrap",
                    topic.to_string(),
                    "No latest link".to_owned(),
                ),
            )?;
            self.mask(&latest_link)?;

            let cursors: Vec<(&Permissioned<Identifier>, &usize)> = user_state
                .cursor_store
                .cursors_by_topic(topic)
                .ok_or(SpongosError::InvalidAction(
                    "get cursor for topic",
                    topic.to_string(),
                    "No cursor found".to_owned(),
                ))?
                .collect();
            let amount_cursors = cursors.len();
            self.mask(Size::new(amount_cursors))?;
            for (subscriber, cursor) in cursors {
                self.mask(subscriber)?.mask(Size::new(*cursor))?;
            }
        }

        let subs = &user_state.subscribers;
        let amount_subs = subs.len();
        self.mask(Size::new(amount_subs))?;
        for subscriber in subs {
            self.mask(subscriber)?;
        }

        let psks = user_state.psk_store.iter();
        let amount_psks = psks.len();
        self.mask(Size::new(amount_psks))?;
        for (pskid, psk) in psks {
            self.mask(pskid)?.mask(psk)?;
        }

        let lean = if user_state.lean { 1 } else { 0 };
        self.mask(Uint8::new(lean))?;

        self.commit()?.squeeze(Mac::new(32))
    }
}

#[async_trait]
impl ContentUnwrap<State> for unwrap::Context<&[u8]> {
    async fn unwrap(&mut self, user_state: &mut State) -> SpongosResult<&mut Self> {
        self.mask(Maybe::new(&mut user_state.user_id))?
            .mask(Maybe::new(&mut user_state.stream_address))?
            .mask(Maybe::new(&mut user_state.author_identifier))?
            .mask(&mut user_state.base_branch)?;

        let mut amount_spongos = Size::default();
        self.mask(&mut amount_spongos)?;
        for _ in 0..amount_spongos.inner() {
            let mut address = MsgId::default();
            let mut spongos = Spongos::default();
            self.mask(&mut address)?.mask(&mut spongos)?;
            user_state.spongos_store.insert(address, spongos);
        }

        let mut amount_topics = Size::default();
        self.mask(&mut amount_topics)?;

        for _ in 0..amount_topics.inner() {
            let mut topic = Topic::default();
            self.mask(&mut topic)?;
            let mut latest_link = MsgId::default();
            self.mask(&mut latest_link)?;

            user_state.topics.insert(topic.clone());
            user_state
                .cursor_store
                .set_latest_link(topic.clone(), latest_link);

            let mut amount_cursors = Size::default();
            self.mask(&mut amount_cursors)?;
            for _ in 0..amount_cursors.inner() {
                let mut subscriber = Permissioned::default();
                let mut cursor = Size::default();
                self.mask(&mut subscriber)?.mask(&mut cursor)?;
                user_state
                    .cursor_store
                    .insert_cursor(&topic, subscriber, cursor.inner());
            }
        }

        let mut amount_subs = Size::default();
        self.mask(&mut amount_subs)?;
        for _ in 0..amount_subs.inner() {
            let mut subscriber = Identifier::default();
            self.mask(&mut subscriber)?;
            user_state.subscribers.insert(subscriber);
        }

        let mut amount_psks = Size::default();
        self.mask(&mut amount_psks)?;
        for _ in 0..amount_psks.inner() {
            let mut pskid = PskId::default();
            let mut psk = Psk::default();
            self.mask(&mut pskid)?.mask(&mut psk)?;
            user_state.psk_store.insert(pskid, psk);
        }

        let mut lean = Uint8::new(0);
        self.mask(&mut lean)?;
        user_state.lean = lean.inner() == 1;

        self.commit()?.squeeze(Mac::new(32))
    }
}

impl<T> Debug for User<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FormatResult {
        write!(
            f,
            "\n* identifier: <{:?}>\n* topic: {}\n{:?}\n",
            self.identifier(),
            self.base_branch(),
            self.state.cursor_store,
        )?;

        writeln!(f, "* PSKs:")?;
        for pskid in self.state.psk_store.keys() {
            writeln!(f, "\t<{:?}>", pskid)?;
        }

        write!(f, "* lean: {}", self.state.lean)
    }
}

/// An streams user equality is determined by the equality of its state. The major consequence of
/// this fact is that two users with the same identity but different transport configurations are
/// considered equal
impl<T> PartialEq for User<T> {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

/// An streams user equality is determined by the equality of its state. The major consequence of
/// this fact is that two users with the same identity but different transport configurations are
/// considered equal
impl<T> Eq for User<T> {}

#[cfg(feature = "serde")]
impl<T: serde::Serialize> serde::Serialize for User<T> {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.state.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use lets::transport::bucket;

    use crate::{api::user::User, Result};

    type Transport = bucket::Client;

    #[tokio::test]
    async fn serialize() -> Result<()> {
        let psk = lets::id::Psk::from_seed(b"Psk1");
        let user = User::builder()
            .with_transport(Transport::new())
            .with_psk(psk.to_pskid(), psk)
            .build();

        let serialized: serde_json::Value = r#"{
            "cursor_store":{},
            "psk_store":{
                "8cea20dcc19c4bd897f09170bf748f38":[177,226,96,81,147,120,157,43,52,194,47,236,77,98,111,21,108,228,72,21,68,191,115,34,62,204,28,60,195,250,214,157]
            },
            "subscribers":[],
            "spongos_store":{},
            "base_branch":"",
            "lean":false,
            "topics":[]
        }"#.parse().unwrap();

        let parsed_user = serde_json::to_string(&user)
            .unwrap()
            .parse::<serde_json::Value>()
            .unwrap();

        // serialize then deserialize so the order doesnt matter
        assert_eq!(serialized, parsed_user);
        assert_eq!(user.state, serde_json::from_value(parsed_user).unwrap());
        Ok(())
    }
}
