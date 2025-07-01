use core::fmt::Debug;
// Rust
use core::hash::Hash;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
// IOTA
use identity_demia::{
    demia::{DemiaDID, DemiaDocument, IotaIdentityClientExt},
    verification::VerificationMethod,
};
use iota_sdk::client::Client as DIDClient;
use tokio::sync::RwLock;
// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
    },
    error::{Error as SpongosError, Result as SpongosResult},
    PRP,
};

use crate::{
    alloc::string::ToString,
    error::{Error, Result},
    id::did::DIDUrlInfo,
};
use crate::id::cache::IdentityCache;

/// Fetch the `DID` document from the tangle
///
/// # Arguments
/// * `url_info`: The document details
/// * `cache`: The cache to use for storing and retrieving documents
pub(crate) async fn resolve_document<C: IdentityCache>(url_info: &DIDUrlInfo, cache: &mut C) -> Result<DemiaDocument> {
    let did_url = DemiaDID::parse(url_info.did()).map_err(|e| Error::did("parse did url", e))?;
    if let Some(doc) = cache.get_did_document(&did_url).await {
        Ok(doc.clone())
    } else {
        let client = DIDClient::builder()
            .with_primary_node(url_info.client_url(), None)
            .map_err(|e| Error::did("DIDClient set primary node", e))?
            .finish()
            .await
            .map_err(|e| Error::did("build DID Client", e))?;
        let doc = client
            .resolve_did(&did_url)
            .await
            .map_err(|e| Error::did("read DID document", e))?;
        cache.set_did_document(did_url, doc.clone()).await;
        Ok(doc)
    }
}

pub(crate) async fn get_exchange_method<C: IdentityCache>(info: &DIDUrlInfo, cache: &mut C) -> SpongosResult<VerificationMethod> {
    let exchange_fragment = info.exchange_fragment().to_string();
    let doc = resolve_document(info, cache)
        .await
        .map_err(|e| SpongosError::Context("ContentEncrypt", e.to_string()))?;
    doc.resolve_method(&exchange_fragment, None)
        .ok_or(SpongosError::Context(
            "ContentEncrypt",
            "failed to resolve method".to_string(),
        ))
        .cloned()
}

// TODO: Remove redundant layerings now that accounts don't exist
/// Type of `DID` implementation
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DID {
    /// Private Key based [`DIDInfo`], manually specifying key pairs
    PrivateKey(DIDInfo),
}

impl DID {
    /// Returns a reference to the [`DIDInfo`] if present
    pub(crate) fn info(&self) -> &DIDInfo {
        match self {
            Self::PrivateKey(did_info) => did_info,
        }
    }

    /// Returns a mutable reference to the [`DIDInfo`] if present
    pub(crate) fn info_mut(&mut self) -> &mut DIDInfo {
        match self {
            Self::PrivateKey(did_info) => did_info,
        }
    }
}

impl Default for DID {
    fn default() -> Self {
        DID::PrivateKey(DIDInfo::new(DIDUrlInfo::default()))
    }
}

impl Mask<&DID> for sizeof::Context {
    fn mask(&mut self, did: &DID) -> SpongosResult<&mut Self> {
        self.mask(did.info().url_info())
    }
}

impl<OS, F> Mask<&DID> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, did: &DID) -> SpongosResult<&mut Self> {
        self.mask(did.info().url_info())
    }
}

impl<IS, F> Mask<&mut DID> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, did: &mut DID) -> SpongosResult<&mut Self> {
        let mut url_info = DIDUrlInfo::default();
        self.mask(&mut url_info)?;
        *did = DID::PrivateKey(DIDInfo::new(url_info));

        Ok(self)
    }
}

/// Details of a `DID` implementation
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DIDInfo {
    /// Document retrieval information
    url_info: DIDUrlInfo,
}

impl DIDInfo {
    /// Creates a new [`DIDInfo`] wrapper around the provided details
    ///
    /// # Arguments
    /// * `url_info`: Document retrieval information
    /// * `keypair`: DID KeyPair for signatures
    /// * `exchange_keypair`: DID KeyPair for key exchange
    pub fn new(url_info: DIDUrlInfo) -> Self {
        Self { url_info }
    }

    /// Returns a reference to the [`DIDUrlInfo`]
    pub fn url_info(&self) -> &DIDUrlInfo {
        &self.url_info
    }

    /// Returns a mutable reference to the [`DIDUrlInfo`]
    pub fn url_info_mut(&mut self) -> &mut DIDUrlInfo {
        &mut self.url_info
    }
}

#[derive(Default, Clone)]
pub struct IdentityDocCache {
    pub docs: Arc<RwLock<HashMap<DemiaDID, DemiaDocument>>>,
}

#[async_trait::async_trait]
impl IdentityCache for IdentityDocCache {
    async fn get_did_document(&self, did: &DemiaDID) -> Option<DemiaDocument> {
        self.docs.read().await.get(&did).map(|doc| doc.clone())
    }
    
    async fn set_did_document(&mut self, did: DemiaDID, doc: DemiaDocument) {
        let _ = self.docs.write().await.insert(did, doc);
    }
    
    async fn size(&self) -> usize {
        self.docs.read().await.len()
    }
}

impl PartialEq for IdentityDocCache {
    fn eq(&self, other: &Self) -> bool {
        true
    }
}

impl Eq for IdentityDocCache {}

impl Hash for IdentityDocCache {
    fn hash<H: core::hash::Hasher>(&self, _state: &mut H) {
        ()
    }
}

impl Debug for IdentityDocCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdentityDocCache")
    }
}


/*
/// Wrapper for a `DID` based KeyPair
struct KeyPair(identity_demia::crypto::Jwk);

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.0.type_() == other.0.type_() && self.0.private().as_ref() == other.0.private().as_ref()
    }
}

impl Eq for KeyPair {}

impl PartialOrd for KeyPair {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyPair {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.0.type_(), self.0.private().as_ref())
            .cmp(&(other.0.type_(), other.0.private().as_ref()))
    }
}

impl Hash for KeyPair {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.type_().hash(state);
        self.0.private().as_ref().hash(state);
    }
}
 */
