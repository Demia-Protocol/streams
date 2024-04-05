// Rust
use core::hash::Hash;

// IOTA
use identity_iota::{
    iota::{IotaDID, IotaDocument, IotaIdentityClientExt},
    verification::VerificationMethod,
};
use iota_client::Client as DIDClient;

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

/// Fetch the `DID` document from the tangle
///
/// # Arguments
/// * `url_info`: The document details
pub(crate) async fn resolve_document(url_info: &DIDUrlInfo) -> Result<IotaDocument> {
    let did_url = IotaDID::parse(url_info.did()).map_err(|e| Error::did("parse did url", e))?;
    let client = DIDClient::builder()
        .with_primary_node(url_info.client_url(), None)
        .map_err(|e| Error::did("DIDClient set primary node", e))?
        .finish()
        .map_err(|e| Error::did("build DID Client", e))?;
    let doc = client
        .resolve_did(&did_url)
        .await
        .map_err(|e| Error::did("read DID document", e))?;
    Ok(doc)
}

pub(crate) async fn get_exchange_method(info: &DIDUrlInfo) -> SpongosResult<VerificationMethod> {
    let exchange_fragment = info.exchange_fragment().to_string();
    let doc = resolve_document(info)
        .await
        .map_err(|e| SpongosError::Context("ContentEncrypt", e.to_string()))?;
    doc.resolve_method(&exchange_fragment, None)
        .ok_or(SpongosError::Context(
            "ContentEncrypt",
            "failed to resolve method".to_string(),
        ))
        .map(|method| method.clone())
}

// TODO: Remove redundant layerings now that accounts don't exist
/// Type of `DID` implementation
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Wrapper for a `DID` based KeyPair
struct KeyPair(identity_iota::crypto::KeyPair);

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
