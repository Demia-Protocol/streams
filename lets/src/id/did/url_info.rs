// Rust
use alloc::{string::String, vec::Vec};
use core::{
    cmp::Ordering,
    fmt::{Debug, Formatter},
    hash::Hasher
};

// IOTA
use identity_iota::{core::BaseEncoding, iota::IotaDID, verification::MethodData};

use crate::{
    alloc::string::ToString,
    error::{Error, Result},
    id::did::StrongholdSecretManager
};

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::Bytes,
    },
    error::{Error as SpongosError, Result as SpongosResult},
    PRP,
};

/// `DID` Document details
pub struct DIDUrlInfo {
    /// `DID` string
    did: String,
    /// URL of the node endpoint
    client_url: String,
    /// Fragment label for exchange key method
    exchange_fragment: String,
    /// Fragment label for signature key method
    signing_fragment: String,
    /// Stronghold Adapter
    stronghold: Option<StrongholdSecretManager>,
}

impl Default for DIDUrlInfo {
    fn default() -> Self {
        DIDUrlInfo::new(
            IotaDID::new(&[0_u8; 32], &"dflt".try_into().unwrap()),
            String::new(),
            String::new(),
            String::new(),
        )
    }
}

impl Clone for DIDUrlInfo {
    fn clone(&self) -> Self {
        DIDUrlInfo {
            did: self.did.clone(),
            client_url: self.client_url.clone(),
            exchange_fragment: self.exchange_fragment.clone(),
            signing_fragment: self.signing_fragment.clone(),
            stronghold: None,
        }
    }
}

impl core::hash::Hash for DIDUrlInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.did.hash(state);
        self.client_url.hash(state);
        self.exchange_fragment.hash(state);
        self.signing_fragment.hash(state);
    }
}

impl PartialEq for DIDUrlInfo {
    fn eq(&self, other: &Self) -> bool {
        self.did == other.did
            && self.client_url == other.client_url
            && self.exchange_fragment == other.exchange_fragment
            && self.signing_fragment == other.signing_fragment
    }
}

impl Eq for DIDUrlInfo {}

impl PartialOrd for DIDUrlInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for DIDUrlInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.did.cmp(&other.did)
    }
}

impl Debug for DIDUrlInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(&format!(
            "{{\n\tdid: {},\n\tclient_url: {},\n\texchange_fragment{},\n\tsigning_fragment{}\n}}",
            self.did, self.client_url, self.exchange_fragment, self.signing_fragment
        ))
    }
}

impl DIDUrlInfo {
    /// Creates a new [`DIDUrlInfo`] wrapper around the provided values
    ///
    /// # Arguments
    /// * `did`: DID string
    /// * `client_url`: Node endpoint URL
    /// * `stronghold`: Stronghold path
    /// * `exchange_fragment`: Label for exchange key methods
    /// * `signing_fragment`: Label for signature key methods
    pub fn new<T: Into<String>>(did: IotaDID, client_url: T, exchange_fragment: T, signing_fragment: T) -> Self {
        Self {
            did: did.to_string(),
            client_url: client_url.into(),
            exchange_fragment: exchange_fragment.into(),
            signing_fragment: signing_fragment.into(),
            stronghold: None,
        }
    }

    pub fn with_stronghold(mut self, stronghold: StrongholdSecretManager) -> Self {
        self.stronghold = Some(stronghold);
        self
    }

    pub fn stronghold(&mut self) -> Result<&mut StrongholdSecretManager> {
        self.stronghold
            .as_mut()
            .ok_or(Error::did("fetching stronghold", "stronghold not found".to_string()))
    }

    /// Authenticates a hash value and the associated signature using the publisher [`DIDUrlInfo`]
    ///
    /// # Arguments
    /// * `signing_fragment`: Label for exchange key methods
    /// * `signature_bytes`: Raw bytes for signature
    /// * `hash`: Hash value used for signature
    pub(crate) async fn verify(&self, signing_fragment: &str, signature_bytes: &[u8], hash: &[u8]) -> Result<()> {
        let doc = super::resolve_document(self).await?;
        let method = doc.resolve_method(signing_fragment, None).unwrap();
        match method.data() {
            MethodData::PublicKeyMultibase(pk) => {
                // Multibase is 32 bytes long there should be no errors unwrapping conversion
                let pk_bytes: [u8; 32] = BaseEncoding::decode_multibase(&pk)
                    .map_err(|e| Error::did("verify data from document", e.to_string()))?
                    .try_into()
                    .unwrap();
                let sig = crypto::signatures::ed25519::Signature::from_bytes(signature_bytes.try_into().unwrap());
                if crypto::signatures::ed25519::PublicKey::try_from(pk_bytes)
                    .unwrap()
                    .verify(&sig, hash)
                {
                    Ok(())
                } else {
                    Err(Error::did("verify data from document", "failed to verify".to_string()))
                }
            }
            _ => Err(Error::did(
                "verify data from document",
                "not the right method data".to_string(),
            )),
        }
    }

    /// Returns the `DID` string
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Returns the node endpoint URL string
    pub fn client_url(&self) -> &str {
        &self.client_url
    }

    /// Returns the label for key exchange methods
    pub fn exchange_fragment(&self) -> &str {
        &self.exchange_fragment
    }

    /// Returns the label for signature methods
    pub fn signing_fragment(&self) -> &str {
        &self.signing_fragment
    }

    /// Returns a mutable reference to `DID` string
    pub(crate) fn did_mut(&mut self) -> &mut String {
        &mut self.did
    }

    /// Returns a mutable reference to the node endoint URL string
    pub(crate) fn client_url_mut(&mut self) -> &mut String {
        &mut self.client_url
    }

    /// Returns a mutable reference to the label for key exchange methods
    pub(crate) fn exchange_fragment_mut(&mut self) -> &mut String {
        &mut self.exchange_fragment
    }

    /// Returns a mutable reference to the label for signature methods
    pub(crate) fn signing_fragment_mut(&mut self) -> &mut String {
        &mut self.signing_fragment
    }
}

impl AsRef<[u8]> for DIDUrlInfo {
    fn as_ref(&self) -> &[u8] {
        // TODO how to make a ref to all fields without permanently storing?
        // For now we assume someone wont be using the same DID twice
        self.did().as_bytes()
    }
}

impl Mask<&DIDUrlInfo> for sizeof::Context {
    fn mask(&mut self, url_info: &DIDUrlInfo) -> SpongosResult<&mut Self> {
        self.mask(Bytes::new(url_info.did()))?
            .mask(Bytes::new(url_info.client_url()))?
            .mask(Bytes::new(url_info.exchange_fragment()))?
            .mask(Bytes::new(url_info.signing_fragment()))
    }
}

impl<OS, F> Mask<&DIDUrlInfo> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, url_info: &DIDUrlInfo) -> SpongosResult<&mut Self> {
        self.mask(Bytes::new(url_info.did()))?
            .mask(Bytes::new(url_info.client_url()))?
            .mask(Bytes::new(url_info.exchange_fragment()))?
            .mask(Bytes::new(url_info.signing_fragment()))
    }
}

impl<IS, F> Mask<&mut DIDUrlInfo> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, url_info: &mut DIDUrlInfo) -> SpongosResult<&mut Self> {
        let mut did_bytes = Vec::new();
        let mut client_url = Vec::new();
        let mut exchange_fragment_bytes = Vec::new();
        let mut signing_fragment_bytes = Vec::new();
        self.mask(Bytes::new(&mut did_bytes))?
            .mask(Bytes::new(&mut client_url))?
            .mask(Bytes::new(&mut exchange_fragment_bytes))?
            .mask(Bytes::new(&mut signing_fragment_bytes))?;

        // Errors read as: "Context failed to perform the message command "Mask DIDUrlInfo"; Error: {TAG} is
        // not encoded in utf8 or the encoding is incorrect: External error: {utf8Error}""
        *url_info.did_mut() = String::from_utf8(did_bytes)
            .map_err(|e| SpongosError::Context("Mask DIDUrlInfo", Error::utf("did", e).to_string()))?;
        *url_info.client_url_mut() = String::from_utf8(client_url)
            .map_err(|e| SpongosError::Context("Mask DIDUrlInfo", Error::utf("client url", e).to_string()))?;
        *url_info.exchange_fragment_mut() = String::from_utf8(exchange_fragment_bytes)
            .map_err(|e| SpongosError::Context("Mask DIDUrlInfo", Error::utf("exchange fragment", e).to_string()))?;
        *url_info.signing_fragment_mut() = String::from_utf8(signing_fragment_bytes)
            .map_err(|e| SpongosError::Context("Mask DIDUrlInfo", Error::utf("signing fragment", e).to_string()))?;
        Ok(self)
    }
}
