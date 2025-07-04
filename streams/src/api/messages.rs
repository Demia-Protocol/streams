// Rust
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::{future::Future, pin::Pin};

// 3rd-party
use anyhow::Result;
use futures::{
    future,
    task::{Context, Poll},
    Stream, StreamExt, TryStream, TryStreamExt,
};
use hashbrown::HashMap;

// IOTA

// Streams
use lets::{
    address::{Address, MsgId},
    id::Identifier,
    message::{Topic, TransportMessage, HDF},
    transport::Transport,
};

// Local
use crate::api::{
    message::{Message, MessageContent, Orphan},
    selector::Selector,
    user::User,
};

/// a [`Stream`] over the messages of the channel pending to be fetch from the transport
///
/// Use this stream to preorderly traverse the messages of the channel. This stream is usually
/// created from any type implementing [`IntoMessages`], calling its [`IntoMessages::messages()`]
/// method. The main method is [`Messages::next()`], which returns the next message in the channel
/// that is readable by the user.
///
/// This type implements [`futures::Stream`] and [`futures::TryStream`], therefore it can be used
/// with all the adapters provided by [`futures::StreamExt`] and [`futures::TryStreamExt`]:
///
/// ```
/// use futures::TryStreamExt;
///
/// use streams::{id::Ed25519, transport::utangle, Address, Result, User};
///
/// # use streams::transport::bucket;
/// #
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let test_transport = bucket::Client::new();
/// #
/// let author_seed = "cryptographically-secure-random-author-seed";
/// let author_transport: utangle::Client =
///     utangle::Client::new("https://chrysalis-nodes.iota.org");
/// #
/// # let test_author_transport = test_transport.clone();
/// #
/// let mut author = User::builder()
///     .with_identity(Ed25519::from_seed(author_seed))
/// #     .with_transport(test_author_transport)
///     .build();
///
/// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// let subscriber_transport: utangle::Client =
///     utangle::Client::new("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// let mut subscriber = User::builder()
///     .with_identity(Ed25519::from_seed(subscriber_seed))
/// #    .with_transport(subscriber_transport)
///     .build();
///
/// let announcement = author.create_stream("BASE_BRANCH").await?;
/// subscriber.receive_message(announcement.address()).await?;
/// let first_packet = author
///     .send_signed_packet("BASE_BRANCH", b"public payload", b"masked payload")
///     .await?;
/// let second_packet = author
///     .send_signed_packet(
///         "BASE_BRANCH",
///         b"another public payload",
///         b"another masked payload",
///     )
///     .await?;
///
/// #
/// # let mut n = 0;
/// #
/// let mut messages = subscriber.messages();
/// while let Some(msg) = messages.try_next().await? {
///     println!(
///         "New message!\n\tPublic: {:?}\n\tMasked: {:?}\n",
///         msg.public_payload().unwrap_or(b"None"),
///         msg.masked_payload().unwrap_or(b"None")
///     );
/// #
/// #   n += 1;
/// #
/// }
/// #
/// # assert_eq!(n, 2);
/// # Ok(())
/// # }
/// ```
///
/// # Technical Details
/// This [`Stream`] makes sure the messages are traversed in topological order (preorder). This
/// means any parent message is yielded before its childs. As a consequence, there might be multiple
/// transport calls before a message is yielded, and several messages can be accumulated in memory
/// until their turn. Therefore, some jitter might be expected, with a worst case of fetching all
/// the messages before any is yielded.
///
/// After the last currently available message has been returned, [`Messages::next()`] returns
/// `None`, at which point the [`StreamExt`] and [`TryStreamExt`] methods will consider the
/// [`Stream`] finished and stop iterating. It is safe to continue calling [`Messages::next()`] or
/// any method from [`StreamExt`] and [`TryStreamExt`] polling for new messages.
///
/// Being a [`futures::Stream`] that fetches data from an external source, it's naturally defined as
/// a [`futures::TryStream`], which means it returns a [`Result`] wrapping the `UnwrappedMessage`.
/// In the event of a network failure, [`Messages::next()`] will return `Err`. It is strongly
/// suggested that, when suitable, use the methods in [`futures::TryStreamExt`] to make the
/// error-handling much more ergonomic (with the use of `?`) and shortcircuit the
/// [`futures::Stream`] on the first error.
pub struct Messages<'a, T: Send + Sync>(
    PinBoxFut<'a, (MessagesState<'a, T>, Option<Result<Message>>)>,
);

type PinBoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a + Send>>;

struct MessagesState<'a, T> {
    user: &'a mut User<T>,
    pub(crate) filter: Option<&'a str>,
    ids_stack: Vec<(Topic, Identifier, usize)>,
    msg_queue: HashMap<MsgId, VecDeque<(MsgId, TransportMessage)>>,
    stage: VecDeque<(MsgId, TransportMessage)>,
    successful_round: bool,
    cache: HashMap<MsgId, Message>,
}

impl<'a, T: Send + Sync> MessagesState<'a, T> {
    fn new(
        user: &'a mut User<T>,
        ids_stack: Vec<(Topic, Identifier, usize)>,
        cache: HashMap<MsgId, Message>,
        filter: Option<&'a str>,
    ) -> Self {
        Self {
            user,
            ids_stack,
            msg_queue: Default::default(),
            stage: Default::default(),
            successful_round: Default::default(),
            cache,
            filter,
        }
    }

    /// Fetch the next message of the channel
    ///
    /// See [`Messages`] documentation and examples for more details.
    async fn next(&mut self) -> Option<Result<Message>>
    where
        T: for<'b> Transport<'b, Msg = TransportMessage>,
    {
        loop {
            if let Some((relative_address, binary_msg)) = self.stage.pop_front() {
                // Drain stage if not empty...
                let address = Address::new(self.user.stream_address()?.base(), relative_address);
                let handled = self
                    .process_message(address, relative_address, binary_msg)
                    .await;

                match handled {
                    Some(Message {
                        header:
                            HDF {
                                linked_msg_address: Some(linked_msg_address),
                                ..
                            },
                        content:
                            MessageContent::Orphan(Orphan {
                                // Currently ignoring cursor, as `GenericUser::handle_message()` parses the whole binary
                                // message again this redundancy is acceptable in favour of
                                // avoiding carrying over the Spongos state within `Message`
                                message: orphaned_msg,
                                ..
                            }),
                        ..
                    }) => {
                        // The message might be unreadable because it's predecessor might still be pending
                        // to be retrieved from the Tangle. We could defensively check if the predecessor
                        // is already present in the state, but we don't want to couple this iterator to
                        // a memory-intensive storage. Instead, we take the optimistic approach and store
                        // the msg for later if the handling has failed.
                        self.msg_queue
                            .entry(linked_msg_address)
                            .or_default()
                            .push_back((relative_address, orphaned_msg));

                        continue;
                    }
                    Some(message) => {
                        // Check if message has descendants pending to process and stage them for processing
                        if let Some(msgs) = self.msg_queue.remove(&message.address().relative()) {
                            self.stage.extend(msgs);
                        }

                        return Some(Ok(message));
                    }
                    // message-Handling errors are a normal execution path, just skip them
                    None => continue,
                }
            } else if self.populate_stage().await.is_none() {
                return None;
            }
        }
    }

    async fn process_message(
        &mut self,
        address: Address,
        relative_address: MsgId,
        binary_msg: TransportMessage,
    ) -> Option<Message>
    where
        T: for<'b> Transport<'b, Msg = TransportMessage>,
    {
        let cached_message = self.cache.remove(&relative_address);
        if let Some(msg) = cached_message {
            return Some(msg);
        }

        match self.user.handle_message(address, binary_msg).await {
            Ok(message) => {
                self.cache.insert(relative_address, message.clone());
                Some(message)
            }
            Err(_) => None,
        }
    }

    async fn populate_stage(&mut self) -> Option<()>
    where
        T: for<'b> Transport<'b, Msg = TransportMessage>,
    {
        let (topic, publisher, cursor) = match self.ids_stack.pop() {
            Some(id_cursor) => id_cursor,
            None => {
                self.reset_stack();
                self.ids_stack.pop()?
            }
        };

        let base_address = self.user.stream_address()?.base();
        let rel_address = MsgId::gen(base_address, &publisher, &topic, cursor + 1);
        let address = Address::new(base_address, rel_address);

        match self.user.transport_mut().recv_message(address).await {
            Ok(msg) => {
                self.stage.push_back((address.relative(), msg));
                self.successful_round = true;
                Some(())
            }
            Err(_) => {
                if self.ids_stack.is_empty() && !self.successful_round {
                    // Officially end of stream
                    None
                } else {
                    // At least one id is producing existing links. continue...
                    Some(())
                }
            }
        }
    }

    fn reset_stack(&mut self) {
        self.successful_round = false;
        let filter = self.filter;
        self.ids_stack = self
            .user
            .cursors()
            .filter(|(_, p, _)| !p.is_readonly())
            .filter(|(t, _, _)| match filter {
                Some(filter) => filter.eq(t.str()),
                None => true,
            })
            .map(|(t, p, c)| (t.clone(), p.identifier().clone(), c))
            .collect();
    }
}

impl<'a, T: Send> From<&'a mut User<T>> for MessagesState<'a, T> {
    fn from(user: &'a mut User<T>) -> Self {
        Self {
            user,
            ids_stack: Vec::new(),
            msg_queue: HashMap::new(),
            stage: VecDeque::new(),
            successful_round: false,
            cache: HashMap::new(),
            filter: None,
        }
    }
}

impl<'a, T> Messages<'a, T>
where
    T: for<'b> Transport<'b, Msg = TransportMessage> + Send + Sync,
{
    pub(crate) fn new(user: &'a mut User<T>) -> Self {
        let mut state = MessagesState::from(user);
        Self(Box::pin(async move {
            let r = state.next().await;
            (state, r)
        }))
    }

    pub(crate) fn new_with_cache(
        user: &'a mut User<T>,
        cache: HashMap<MsgId, Message>,
        start: Option<(Topic, Identifier, usize)>,
    ) -> Self {
        let start = start.into_iter().collect();
        let mut state = MessagesState::new(user, start, cache, None);
        Self(Box::pin(async move {
            let r = state.next().await;
            (state, r)
        }))
    }

    pub(crate) fn new_with_filter(user: &'a mut User<T>, filter: &'a str) -> Self {
        let mut state = MessagesState::from(user);
        state.filter = Some(filter);
        Self(Box::pin(async move {
            let r = state.next().await;
            (state, r)
        }))
    }

    /// "Filter the stream of messages to only those that match the selectors, and return the result
    /// as a vector."
    /// A message is matched when at least one of the selectors is a match.
    ///
    /// Important to note is that the stream DISCARDS the messages that dont fit the criteria from
    /// the selectors.
    ///
    /// # Arguments
    ///
    /// * `selectors`: A list of selectors to filter the messages by.
    ///
    /// Returns:
    ///
    /// A vector of Messages.
    pub async fn from(&mut self, selectors: &[Selector]) -> Vec<Message> {
        StreamExt::filter(self, |x| match &x {
            Ok(m) => {
                for selector in selectors {
                    if selector.is(m) {
                        return future::ready(true);
                    }
                }
                future::ready(false)
            }
            Err(_) => future::ready(false),
        })
        .map(|x| x.unwrap())
        .collect::<Vec<_>>()
        .await
    }

    /// `next` is an async function that returns an Option of a Result of a Message
    ///
    /// Returns:
    ///
    /// A message
    pub async fn next(&mut self) -> Option<Result<Message>> {
        StreamExt::next(self).await
    }

    /// Start streaming from a particular message
    ///
    /// Once that message is fetched and yielded, the returned [`Stream`] will yield only
    /// descendants of that message.
    ///
    ///  See [example in `Messages`
    /// docs](struct.Messages.html#filter-the-messages-of-a-particular-branch) for more details.
    pub fn filter_branch<Fut>(
        self,
        predicate: impl FnMut(&Message) -> Fut + 'a,
    ) -> impl Stream<Item = Result<Message>> + 'a
    where
        Fut: Future<Output = Result<bool>> + 'a,
        Self: TryStream<Ok = Message, Error = anyhow::Error>,
    {
        self.try_skip_while(predicate)
            .scan(None, |branch_last_address, msg| {
                future::ready(Some(msg.map(|msg| {
                    let msg_linked_address = msg.header().linked_msg_address()?;
                    let branch_last_address = branch_last_address.get_or_insert(msg_linked_address);
                    if msg_linked_address == *branch_last_address {
                        *branch_last_address = msg.address().relative();
                        Some(msg)
                    } else {
                        None
                    }
                })))
            })
            .try_filter_map(future::ok)
    }
}

impl<'a, T> From<&'a mut User<T>> for Messages<'a, T>
where
    T: for<'b> Transport<'b, Msg = TransportMessage> + Send + Sync,
{
    fn from(user: &'a mut User<T>) -> Self {
        Self::new(user)
    }
}

impl<T> Stream for Messages<'_, T>
where
    T: for<'b> Transport<'b, Msg = TransportMessage> + Send + Sync,
{
    type Item = Result<Message>;

    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.as_mut().poll(ctx) {
            Poll::Ready((mut state, result)) => {
                self.set(Messages(Box::pin(async move {
                    let r = state.next().await;
                    (state, r)
                })));
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use lets::{address::Address, id::Ed25519, transport::bucket};

    use crate::{
        api::{
            message::{
                Message,
                MessageContent::{BranchAnnouncement, Keyload, SignedPacket},
            },
            user::User,
        },
        Result, Selector,
    };

    type Transport = bucket::Client;

    #[tokio::test]
    async fn messages_fetch_backwards() -> Result<()> {
        let (mut author, mut subscriber1, _, _) = author_subscriber_fixture().await?;

        let branch_1 = "BRANCH_1";
        author.new_branch("BASE_BRANCH", branch_1).await?;
        author.send_keyload_for_all_rw(branch_1).await?;

        // last timestamp subscriber1 is interested for all msgs
        let timestamp_6 = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("Failed to get system time")
            .as_secs();

        for i in 0..3 {
            std::thread::sleep(core::time::Duration::from_secs(1));
            let p = format!("payload{i}");
            author
                .send_signed_packet(branch_1, &p.as_bytes(), &p.as_bytes())
                .await?;
        }

        // last timestamp subscriber1 is interested in
        let timestamp_3 = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("Failed to get system time")
            .as_secs();

        subscriber1.sync().await?;
        let backup = subscriber1.backup("messages_fetch_backwards").await?;

        for i in 3..6 {
            std::thread::sleep(core::time::Duration::from_secs(1));
            let p = format!("payload{i}");
            let _packet = author
                .send_signed_packet(branch_1, &p.as_bytes(), &p.as_bytes())
                .await?;
        }

        subscriber1.sync().await?;
        let backup_all = subscriber1.backup("messages_fetch_backwards").await?;

        // last 3
        {
            println!("== last 3 - backup at 3");
            subscriber1 = User::restore(
                backup.clone(),
                "messages_fetch_backwards",
                author.transport().clone(),
            )
            .await?;
            // Read back until we find the time we care about
            let mut messages = subscriber1
                .sync_from(&Selector::Time(timestamp_3.into()), branch_1)
                .await?;
            let mut amount = 0;
            while let Some(Ok(msg)) = messages.next().await {
                let p = format!("payload{}", amount + 3);
                assert!(msg.header().timestamp as u64 > timestamp_3);
                assert_eq!(p.as_bytes(), msg.as_signed_packet().unwrap().masked_payload);
                amount += 1;
            }
            assert_eq!(3, amount);
        }

        // all messages
        {
            println!("== last 6 - backup at 3");
            subscriber1 = User::restore(
                backup,
                "messages_fetch_backwards",
                author.transport().clone(),
            )
            .await?;
            // Read back until we find the time we care about
            let mut messages = subscriber1
                .sync_from(&Selector::Time(timestamp_6.into()), branch_1)
                .await?;
            let mut amount = 0;
            while let Some(Ok(msg)) = messages.next().await {
                let p = format!("payload{amount}");
                assert!(msg.header().timestamp as u64 > timestamp_6);
                assert_eq!(p.as_bytes(), msg.as_signed_packet().unwrap().masked_payload);
                amount += 1;
            }
            assert_eq!(6, amount);
        }

        // last 3
        {
            println!("== last 3 - backup at 6");
            subscriber1 = User::restore(
                backup_all.clone(),
                "messages_fetch_backwards",
                author.transport().clone(),
            )
            .await?;
            // Read back until we find the time we care about
            let mut messages = subscriber1
                .sync_from(&Selector::Time(timestamp_3.into()), branch_1)
                .await?;

            let mut amount = 0;
            while let Some(Ok(msg)) = messages.next().await {
                let p = format!("payload{}", amount + 3);
                assert!(msg.header().timestamp as u64 > timestamp_3);
                assert_eq!(p.as_bytes(), msg.as_signed_packet().unwrap().masked_payload);
                amount += 1;
            }
            assert_eq!(3, amount);
        }

        // all messages
        {
            println!("== last 6 - backup at 6");
            subscriber1 = User::restore(
                backup_all,
                "messages_fetch_backwards",
                author.transport().clone(),
            )
            .await?;
            // Read back until we find the time we care about
            let mut messages = subscriber1
                .sync_from(&Selector::Time(timestamp_6.into()), branch_1)
                .await?;
            let mut amount = 0;
            while let Some(Ok(msg)) = messages.next().await {
                let p = format!("payload{amount}");
                assert!(msg.header().timestamp as u64 > timestamp_6);
                assert_eq!(p.as_bytes(), msg.as_signed_packet().unwrap().masked_payload);
                amount += 1;
            }
            assert_eq!(6, amount);
        }

        Ok(())
    }

    #[tokio::test]
    async fn messages_awake_pending_messages_link_to_them_even_if_their_content_is_unreadable(
    ) -> Result<()> {
        let p = b"payload";
        let (mut author, mut subscriber1, announcement_link, transport) =
            author_subscriber_fixture().await?;

        let branch_1 = "BRANCH_1";
        let branch_announcement = author.new_branch("BASE_BRANCH", branch_1).await?;
        let keyload_1 = author.send_keyload_for_all_rw(branch_1).await?;
        subscriber1.sync().await?;
        let _packet_1 = subscriber1.send_signed_packet(branch_1, &p, &p).await?;
        // This packet will never be readable by subscriber2. However, she will still be able to progress
        // through the next messages
        let _packet_2 = subscriber1.send_signed_packet(branch_1, &p, &p).await?;

        let mut subscriber2 =
            subscriber_fixture("subscriber2", &mut author, announcement_link, transport).await?;

        author.sync().await?;

        // This packet has to wait in the `Messages::msg_queue` until `packet` is processed
        let keyload_2 = author.send_keyload_for_all_rw(branch_1).await?;

        subscriber1.sync().await?;
        let last_signed_packet = subscriber1.send_signed_packet(branch_1, &p, &p).await?;

        let msgs = subscriber2.fetch_next_messages().await?;
        assert_eq!(4, msgs.len()); // branch_announcement, keyload_1, keyload_2 and last signed packet
        assert!(matches!(
            msgs.as_slice(),
            &[
                Message {
                    address: address_0,
                    content: BranchAnnouncement(..),
                    ..
                },
                Message {
                    address: address_1,
                    content: Keyload(..),
                    ..
                },
                Message {
                    address: address_2,
                    content: Keyload(..),
                    ..
                },
                Message {
                    address: address_3,
                    content: SignedPacket(..),
                    ..
                }
            ]
            if address_0 == branch_announcement.address()
            && address_1 == keyload_1.address()
            && address_2 == keyload_2.address()
            && address_3 == last_signed_packet.address()
        ));

        Ok(())
    }

    #[tokio::test]
    async fn fetch_messages_with_a_filter() {
        let result =
            tokio::time::timeout(tokio::time::Duration::from_secs(60), async { run().await }).await;

        if result.is_err() {
            panic!("timed out waiting for a filter");
        }
    }

    async fn run() -> Result<()> {
        let p = b"payload";
        let (mut author, mut subscriber1, announcement_link, transport) =
            author_subscriber_fixture().await?;

        let branch_1 = "BRANCH_1";
        let _branch_announcement = author.new_branch("BASE_BRANCH", branch_1).await?;
        let _keyload_1 = author.send_keyload_for_all_rw(branch_1).await?;

        let branch_2 = "BRANCH_2";
        let _branch_announcement_2 = author.new_branch("BASE_BRANCH", branch_2).await?;
        let _keyload_2 = author.send_keyload_for_all_rw(branch_2).await?;

        subscriber1.sync().await?;

        // Send messages into branch 1
        let mut sent_msgs = vec![];
        for _ in 0..5 {
            let packet = subscriber1.send_signed_packet(branch_1, &p, &p).await?;
            sent_msgs.push(packet.address());
        }

        // Send messages into branch 2
        for _ in 0..3 {
            let packet = subscriber1.send_signed_packet(branch_2, &p, &p).await?;
            sent_msgs.push(packet.address());
        }

        // Fetch the messages in order of branch 1 and then branch 2
        let mut msgs = vec![];
        let mut branch_1_message_filter = author.filtered_messages(branch_1);
        for _ in 0..5 {
            match branch_1_message_filter.next().await {
                Some(Ok(msg)) => match msg.as_signed_packet() {
                    Some(_) => msgs.push(msg.address),
                    None => panic!("Message should be a signed packet"),
                },
                _ => panic!("Should be able to find filtered messages for branch 1"),
            }
        }
        drop(branch_1_message_filter);

        let mut branch_2_message_filter = author.filtered_messages(branch_2);
        for _ in 0..3 {
            match branch_2_message_filter.next().await {
                Some(Ok(msg)) => match msg.as_signed_packet() {
                    Some(_) => msgs.push(msg.address),
                    None => panic!("Message should be a signed packet"),
                },
                _ => panic!("Should be able to find filtered messages for branch 1"),
            }
        }
        drop(branch_2_message_filter);

        // Compare sent and received messages, the orders should be the same if fetched via filter
        assert_eq!(msgs, sent_msgs);

        // Load up a second subscriber and sync the base branch
        let mut subscriber2 =
            subscriber_fixture("subscriber2", &mut author, announcement_link, transport).await?;
        let synced = subscriber2.sync_base_branch().await?;
        assert_eq!(synced, 2);

        Ok(())
    }

    /// Prepare a simple scenario with an author, a subscriber, a channel announcement and a bucket
    /// transport
    async fn author_subscriber_fixture(
    ) -> Result<(User<Transport>, User<Transport>, Address, Transport)> {
        let transport = bucket::Client::new();
        let mut author = User::builder()
            .with_identity(Ed25519::from_seed("author"))
            .with_transport(transport.clone())
            .build();
        let announcement = author.create_stream("BASE_BRANCH").await?;
        let subscriber = subscriber_fixture(
            "subscriber",
            &mut author,
            announcement.address(),
            transport.clone(),
        )
        .await?;
        Ok((author, subscriber, announcement.address(), transport))
    }

    async fn subscriber_fixture(
        seed: &str,
        author: &mut User<Transport>,
        announcement_link: Address,
        transport: Transport,
    ) -> Result<User<Transport>> {
        let mut subscriber = User::builder()
            .with_identity(Ed25519::from_seed(seed))
            .with_transport(transport)
            .build();
        subscriber.receive_message(announcement_link).await?;
        let subscription = subscriber.subscribe().await?;
        author.receive_message(subscription.address()).await?;
        Ok(subscriber)
    }
}
