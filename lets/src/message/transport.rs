// Rust
use alloc::vec::Vec;

// IOTA

// Streams
use spongos::{ddml::commands::unwrap, PRP};

// Local
use crate::{
    error::Result,
    message::{content::ContentUnwrap, hdf::HDF, preparsed::PreparsedMessage},
};

/// Binary network Message representation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransportMessage {
    body: Vec<u8>,
    pk: Vec<u8>,
    sig: Vec<u8>,
}

impl TransportMessage {
    /// Creates a new [`TransportMessage`] wrapper for the provided bytes
    ///
    /// # Arguments
    /// * `body`: The body of the message
    pub fn new(body: Vec<u8>) -> Self {
        Self {
            body,
            pk: vec![],
            sig: vec![],
        }
    }

    /// Insert public key
    pub fn with_pk(mut self, pk: Vec<u8>) -> Self {
        self.pk = pk;
        self
    }

    /// Insert signature
    pub fn with_sig(mut self, sig: Vec<u8>) -> Self {
        self.sig = sig;
        self
    }

    /// Returns a reference to the body of the message
    pub fn body(&self) -> &Vec<u8> {
        &self.body
    }

    /// Returns a reference to the public key of the message
    pub fn pk(&self) -> &Vec<u8> {
        &self.pk
    }

    /// Returns a reference to the signature of the message
    pub fn sig(&self) -> &Vec<u8> {
        &self.sig
    }

    /// Consumes the [`TransportMessage`], returning the body of the message
    pub(crate) fn into_body(self) -> Vec<u8> {
        self.body
    }
}

impl TransportMessage {
    /// Creates a new [`unwrap::Context`] for the message body and decodes the [`HDF`].
    /// The remaining context [`spongos::Spongos`] and cursor position are then wrapped with the
    /// [`HDF`] into a [`PreparsedMessage`] for content processing and returned.
    pub async fn parse_header<F>(self) -> Result<PreparsedMessage<F>>
    where
        F: PRP + Default + Send,
    {
        let mut ctx = unwrap::Context::new(self.body().as_ref());
        let mut header = HDF::default();

        ctx.unwrap(&mut header).await?;

        let (spongos, cursor) = ctx.finalize();

        Ok(PreparsedMessage::new(self, header, spongos, cursor))
    }
}

impl From<TransportMessage> for Vec<u8> {
    fn from(message: TransportMessage) -> Self {
        message.into_body()
    }
}

impl AsRef<[u8]> for TransportMessage {
    fn as_ref(&self) -> &[u8] {
        self.body().as_ref()
    }
}
