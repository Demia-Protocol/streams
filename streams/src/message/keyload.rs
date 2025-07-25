//! `Keyload` message _wrapping_ and _unwrapping_.
//!
//! The `Keyload` message is the means to securely exchange the encryption key of a branch with a
//! set of subscribers and pre shared keys.
//!
//! ```ddml
//! message Keyload {
//!     join(spongos);
//!     absorb                      u8  nonce[32];
//!     absorb                      u8  size(n_subscribers);
//!     repeated(n_subscribers):
//!       fork;
//!       mask                      u8  permissioned;
//!       x25519(pub/priv_key)      u8  x25519_pubkey[32];
//!     absorb                      u8  size(n_psks);
//!     repeated(n_psks):
//!       fork;
//!       mask                      u8  pskid[16];
//!       absorb external           u8  psk[32];
//!       commit;
//!       mask                      u8  key[32];
//!     absorb external             u8  key[32];
//!     commit;
//!     squeeze external            u8  hash[64];
//!     ed25519(hash)               u8  signature[64];
//!     commit;
//! }
//! ```
// Rust
use alloc::{boxed::Box, vec::Vec};
use core::{iter::IntoIterator, marker::PhantomData};

// 3rd-party
use async_trait::async_trait;

// IOTA
use crypto::keys::x25519;
use hashbrown::HashMap;

// Streams
#[cfg(feature = "did")]
use lets::id::did::{DID_ENCRYPTED_DATA_SIZE, IdentityDocCache};
use lets::{
    id::{Identifier, Identity, Permissioned, Psk, PskId},
    message::{
        self, ContentDecrypt, ContentEncrypt, ContentEncryptSizeOf, ContentSign, ContentSignSizeof,
        ContentVerify,
    },
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Fork, Join, Mask},
        io,
        modifiers::External,
        types::{NBytes, Size},
    },
    error::Result,
    Spongos,
};

// Local

const NONCE_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

/// A struct that holds references needed for keyload message encoding
pub(crate) struct Wrap<'a, 'b, Subscribers, Psks> {
    /// The base [`Spongos`] state that the message will be joined to
    initial_state: &'a mut Spongos,
    /// A unique nonce
    nonce: [u8; NONCE_SIZE],
    /// A key that will be shared with intended subscribers
    key: [u8; KEY_SIZE],
    /// An iterator of [`Permissioned`] subscribers to be included in the key exchange
    subscribers: Subscribers,
    /// An iterator of [`Psks`] to mask the key with
    psks: Psks,
    /// The [`Identity`] of the stream author
    author_id: &'a mut Identity,
    // panthom subscriber's lifetime needed because we cannot add lifetime parameters to `ContentWrap` trait method.
    // subscribers need a different lifetime because they are provided directly from downstream. They are not stored by
    // the user instance thus they don't share its lifetime
    subscribers_lifetime: PhantomData<&'b Identifier>,
    #[cfg(feature = "did")]
    /// A cache for DID documents
    cache: IdentityDocCache,
}

impl<'a, Subscribers, Psks> Wrap<'a, '_, Subscribers, Psks> {
    /// Creates a new [`Wrap`] struct for a keyload message
    ///
    /// # Arguments:
    /// * `initial_state`: The initial [`Spongos`] state the message will be joined to
    /// * `subscribers`: A list of permissioned subscribers for the branch.
    /// * `psks`: A collection of pre-shared keys to be granted read access to the branch.
    /// * `key`: The key used to encrypt the message.
    /// * `nonce`: A random number that is used to ensure that the same message is not encrypted
    ///   twice.
    /// * `author_id`: The [`Identity`] of the author of the message.
    pub(crate) fn new(
        initial_state: &'a mut Spongos,
        subscribers: Subscribers,
        psks: Psks,
        key: [u8; KEY_SIZE],
        nonce: [u8; NONCE_SIZE],
        author_id: &'a mut Identity,
        #[cfg(feature = "did")] cache: IdentityDocCache,
    ) -> Self
    where
        Subscribers: IntoIterator<Item = Permissioned<Identifier>>,
        Subscribers::IntoIter: ExactSizeIterator,
        Psks: IntoIterator<Item = &'a (PskId, Psk)> + Clone,
        Psks::IntoIter: ExactSizeIterator,
    {
        Self {
            initial_state,
            subscribers,
            psks,
            key,
            nonce,
            author_id,
            subscribers_lifetime: PhantomData,
            #[cfg(feature = "did")] 
            cache,
        }
    }
}

#[async_trait]
impl<'a, 'b, Subscribers, Psks> message::ContentSizeof<Wrap<'a, 'b, Subscribers, Psks>>
    for sizeof::Context
where
    Subscribers: IntoIterator<Item = Permissioned<Identifier>> + Clone + Send + Sync,
    Subscribers::IntoIter: ExactSizeIterator + Send,
    Psks: IntoIterator<Item = &'a (PskId, Psk)> + Clone + Send + Sync,
    Psks::IntoIter: ExactSizeIterator + Send,
{
    async fn sizeof(
        &mut self,
        keyload: &Wrap<'a, 'b, Subscribers, Psks>,
    ) -> Result<&mut sizeof::Context> {
        let psks = keyload.psks.clone().into_iter();
        let n_psks = Size::new(psks.len());
        self.absorb(NBytes::new(keyload.nonce))?;

        // Loop through provided identifiers, masking the shared key for each one
        #[cfg(not(feature = "did"))]
        {
            let subscribers = keyload.subscribers.clone().into_iter();
            let n_subscribers = Size::new(subscribers.len());
            self.absorb(n_subscribers)?;
            for subscriber in subscribers {
                self.fork()
                    .mask(&subscriber)?
                    .encrypt_sizeof(subscriber.identifier(), &keyload.key)
                    .await?;
            }
        }

        // Loop through with did and ed subscribers separately
        #[cfg(feature = "did")]
        {
            let did_subscribers = keyload
                .subscribers
                .clone()
                .into_iter()
                .filter(|s| matches!(s.identifier(), Identifier::DID(_)))
                .collect::<Vec<_>>();
            let ed_subscribers = keyload
                .subscribers
                .clone()
                .into_iter()
                .filter(|s| matches!(s.identifier(), Identifier::Ed25519(_)))
                .collect::<Vec<_>>();

            let n_did_subscribers = Size::new(did_subscribers.len());
            self.absorb(n_did_subscribers)?;
            for subscriber in did_subscribers {
                self.fork()
                    .mask(&subscriber)?
                    .encrypt_sizeof(subscriber.identifier(), &keyload.key)
                    .await?;
            }

            let n_ed_subscribers = Size::new(ed_subscribers.len());
            self.absorb(n_ed_subscribers)?;
            for subscriber in ed_subscribers {
                self.fork()
                    .mask(&subscriber)?
                    .encrypt_sizeof(subscriber.identifier(), &keyload.key)
                    .await?;
            }
        }
        self.absorb(n_psks)?;
        // Loop through provided pskids, masking the shared key for each one
        for (pskid, psk) in psks {
            self.fork()
                .mask(pskid)?
                .absorb(External::new(&NBytes::new(psk)))?
                .commit()?
                .mask(NBytes::new(&keyload.key))?;
        }
        self.absorb(External::new(&NBytes::new(&keyload.key)))?
            .sign_sizeof(keyload.author_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

#[async_trait]
impl<'a, 'b, OS, Subscribers, Psks> message::ContentWrap<Wrap<'a, 'b, Subscribers, Psks>>
    for wrap::Context<OS>
where
    Subscribers: IntoIterator<Item = Permissioned<Identifier>> + Clone + Send,
    Subscribers::IntoIter: ExactSizeIterator + Send,
    Psks: IntoIterator<Item = &'a (PskId, Psk)> + Clone + Send,
    Psks::IntoIter: ExactSizeIterator + Send,
    OS: io::OStream,
{
    async fn wrap(&mut self, keyload: &mut Wrap<'a, 'b, Subscribers, Psks>) -> Result<&mut Self> {
        let psks = keyload.psks.clone().into_iter();
        let n_psks = Size::new(psks.len());

        self.join(keyload.initial_state)?
            .absorb(NBytes::new(keyload.nonce))?;

        // Loop through provided identifiers, masking the shared key for each one
        #[cfg(not(feature = "did"))]
        {
            let subscribers = keyload.subscribers.clone().into_iter();
            let n_subscribers = Size::new(subscribers.len());
            self.absorb(n_subscribers)?;
            for subscriber in subscribers {
                self.fork()
                    .mask(&subscriber)?
                    .encrypt(subscriber.identifier(), &keyload.key)
                    .await?;
            }
        }

        // Loop through with did and ed subscribers separately
        #[cfg(feature = "did")]
        {
            let did_subscribers = keyload
                .subscribers
                .clone()
                .into_iter()
                .filter(|s| matches!(s.identifier(), Identifier::DID(_)))
                .collect::<Vec<_>>();
            let ed_subscribers = keyload
                .subscribers
                .clone()
                .into_iter()
                .filter(|s| matches!(s.identifier(), Identifier::Ed25519(_)))
                .collect::<Vec<_>>();

            let n_did_subscribers = Size::new(did_subscribers.len());
            self.absorb(n_did_subscribers)?;
            for mut subscriber in did_subscribers {
                self.fork()
                    .mask(&subscriber)?
                    .encrypt(
                        keyload.author_id.identity_kind(),
                        subscriber.identifier_mut(),
                        &keyload.key,
                        &mut keyload.cache,
                    )
                    .await?;
            }

            let n_ed_subscribers = Size::new(ed_subscribers.len());
            self.absorb(n_ed_subscribers)?;
            for mut subscriber in ed_subscribers {
                self.fork()
                    .mask(&subscriber)?
                    .encrypt(
                        keyload.author_id.identity_kind(),
                        subscriber.identifier_mut(),
                        &keyload.key,
                        &mut keyload.cache,
                    )
                    .await?;
            }
        }

        self.absorb(n_psks)?;
        // Loop through provided pskids, masking the shared key for each one
        for (pskid, psk) in psks {
            self.fork()
                .mask(pskid)?
                .absorb(External::new(&NBytes::new(psk)))?
                .commit()?
                .mask(NBytes::new(&keyload.key))?;
        }
        self.absorb(External::new(&NBytes::new(&keyload.key)))?
            .sign(keyload.author_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

/// A struct that holds the placeholders needed for keyload message decoding
pub(crate) struct Unwrap<'a> {
    /// The base [`Spongos`] state that the message will be joined to
    initial_state: &'a mut Spongos,
    /// The permissions granted by the admin
    pub(crate) subscribers: Vec<Permissioned<Identifier>>,
    /// Successfully found [`PskId`]'s in store
    pub(crate) psks: Vec<PskId>,
    /// A reference to user stored [`PskId`] to [`Psk`] mapping
    psk_store: &'a HashMap<PskId, Psk>,
    /// The [`Identifier`] of the admin
    author_id: &'a Identifier,
    /// The [`Identity`] of the reader
    user_id: Option<&'a mut Identity>,
    #[cfg(feature = "did")]
    /// A cache for DID documents
    cache: IdentityDocCache,
}

impl<'a> Unwrap<'a> {
    /// Creates a new [`Unwrap`] struct for a keyload message
    ///
    /// # Arguments
    /// * `initial_state`: The base [`Spongos`] state that the message will be joined to
    /// * `user_id`: The optional [`Identity`] of the reading user
    /// * `author_id`: The [`Identifier`] of the author of the stream
    pub(crate) fn new(
        initial_state: &'a mut Spongos,
        user_id: Option<&'a mut Identity>,
        author_id: &'a Identifier,
        psk_store: &'a HashMap<PskId, Psk>,
        #[cfg(feature = "did")] 
        cache: IdentityDocCache,
    ) -> Self {
        Self {
            initial_state,
            subscribers: Vec::default(),
            psks: Vec::default(),
            psk_store,
            author_id,
            user_id,
            #[cfg(feature = "did")]
            cache,
        }
    }

    /// Returns a reference to the list of granted [`Permissioned`] subscribers
    pub(crate) fn subscribers(&self) -> &[Permissioned<Identifier>] {
        &self.subscribers
    }
}

#[async_trait]
impl<'a, IS> message::ContentUnwrap<Unwrap<'a>> for unwrap::Context<IS>
where
    IS: io::IStream,
{
    async fn unwrap(&mut self, keyload: &mut Unwrap<'a>) -> Result<&mut Self> {
        let mut nonce = [0u8; NONCE_SIZE];
        let mut key: Option<[u8; KEY_SIZE]> = None;
        let mut n_psks = Size::default();
        self.join(keyload.initial_state)?
            .absorb(NBytes::new(&mut nonce))?;

        #[cfg(not(feature = "did"))]
        {
            let mut n_subscribers = Size::default();
            self.absorb(&mut n_subscribers)?;
            unwrap_subscribers(
                self,
                keyload,
                n_subscribers,
                &mut key,
                SubscriberKind::Ed25519,
            )
            .await?;
        }

        #[cfg(feature = "did")]
        {
            let mut n_did_subscribers = Size::default();
            let mut n_ed_subscribers = Size::default();

            self.absorb(&mut n_did_subscribers)?;
            let mut cache = keyload.cache.clone();
            unwrap_subscribers(
                self,
                keyload,
                n_did_subscribers,
                &mut key,
                SubscriberKind::DID,
                &mut cache,
            )
            .await?;

            self.absorb(&mut n_ed_subscribers)?;
            unwrap_subscribers(
                self,
                keyload,
                n_ed_subscribers,
                &mut key,
                SubscriberKind::Ed25519,
                &mut cache,
            )
            .await?;
        }
        self.absorb(&mut n_psks)?;

        for _ in 0..n_psks.inner() {
            let mut fork = self.fork();

            // Loop thorugh provided psks and keys
            let mut psk_id = PskId::default();
            fork.mask(&mut psk_id)?;

            if key.is_some() {
                fork.drop(KEY_SIZE)?;
            } else {
                let mut masked_key = [0u8; KEY_SIZE];
                if let Some(psk) = keyload.psk_store.get(&psk_id) {
                    fork.absorb(External::new(&NBytes::new(psk)))?
                        .commit()?
                        .mask(NBytes::new(&mut masked_key))?;
                    key = Some(masked_key);

                    keyload.psks.push(psk_id);
                } else {
                    fork.drop(KEY_SIZE)?;
                }
            }
        }

        if let Some(key) = key {
            self.absorb(External::new(&NBytes::new(&key)))?
                .verify(keyload.author_id, #[cfg(feature = "did")] &mut keyload.cache)
                .await?;
        }
        self.commit()?;
        Ok(self)
    }
}

enum SubscriberKind {
    Ed25519,
    #[cfg(feature = "did")]
    #[allow(clippy::upper_case_acronyms)]
    DID,
}
async fn unwrap_subscribers<IS: io::IStream>(
    ctx: &mut unwrap::Context<IS>,
    keyload: &mut Unwrap<'_>,
    num_subscribers: Size,
    key: &mut Option<[u8; KEY_SIZE]>,
    kind: SubscriberKind,
    #[cfg(feature = "did")] cache: &mut IdentityDocCache,
) -> Result<()> {
    let drop_len = match kind {
        SubscriberKind::Ed25519 => KEY_SIZE + x25519::PUBLIC_KEY_LENGTH,
        #[cfg(feature = "did")]
        SubscriberKind::DID => DID_ENCRYPTED_DATA_SIZE,
    };

    for _ in 0..num_subscribers.inner() {
        let mut fork = ctx.fork();
        // Loop through provided number of identifiers and subsequent keys
        let mut subscriber_id = Permissioned::<Identifier>::default();
        fork.mask(&mut subscriber_id)?;

        if key.is_none() && keyload.user_id.is_some() {
            // Can unwrap if user_id is some
            let user_id = keyload.user_id.as_mut().unwrap();
            if subscriber_id.identifier() == user_id.identifier() {
                fork.decrypt(
                    user_id.identity_kind(),
                    key.get_or_insert([0u8; KEY_SIZE]),
                    #[cfg(feature = "did")] cache
                )
                .await?;
            } else {
                fork.drop(drop_len)?;
            }
        } else {
            fork.drop(drop_len)?;
        }
        keyload.subscribers.push(subscriber_id);
    }
    Ok(())
}
