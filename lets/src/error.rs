//! Stream Errors

// Rust
use alloc::{
    boxed::Box,
    string::{FromUtf8Error, String},
};
use core::fmt::Debug;

// 3rd-party
use hex::FromHexError;
use thiserror_no_std::Error;

// IOTA
use spongos::error::Error as SpongosError;

use crate::address::Address;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
#[cfg(feature = "did")]
pub enum IdentityError {
    #[error("{0}")]
    Core(identity_iota::core::Error),
    #[error("{0}")]
    DIDError(identity_iota::did::Error),
    #[error("{0}")]
    Verification(identity_iota::verification::Error),
    #[error("{0}")]
    IotaClient(iota_client::Error),
    #[error("{0}")]
    Iota(identity_iota::iota::Error),
    #[error("{0}")]
    Doc(identity_iota::document::Error),
    #[error("{0}")]
    Other(String),
}

#[cfg(feature = "did")]
impl From<identity_iota::core::Error> for IdentityError {
    fn from(error: identity_iota::core::Error) -> Self {
        Self::Core(error)
    }
}

#[cfg(feature = "did")]
impl From<identity_iota::did::Error> for IdentityError {
    fn from(error: identity_iota::did::Error) -> Self {
        Self::DIDError(error)
    }
}

#[cfg(feature = "did")]
impl From<identity_iota::verification::Error> for IdentityError {
    fn from(error: identity_iota::verification::Error) -> Self {
        Self::Verification(error)
    }
}

#[cfg(feature = "did")]
impl From<identity_iota::document::Error> for IdentityError {
    fn from(error: identity_iota::document::Error) -> Self {
        Self::Doc(error)
    }
}

#[cfg(feature = "did")]
impl From<identity_iota::iota::Error> for IdentityError {
    fn from(error: identity_iota::iota::Error) -> Self {
        Self::Iota(error)
    }
}

#[cfg(feature = "did")]
impl From<iota_client::Error> for IdentityError {
    fn from(error: iota_client::Error) -> Self {
        Self::IotaClient(error)
    }
}

#[cfg(feature = "did")]
impl From<String> for IdentityError {
    fn from(error: String) -> Self {
        Self::Other(error)
    }
}

#[derive(Debug, Error)]
/// Error type of the LETS crate.
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[error("Crypto error while attempting to {0}: {1}")]
    Crypto(&'static str, crypto::Error),

    #[cfg(feature = "did")]
    #[error("Encountered DID error while trying to {0}; Error: {1}")]
    Did(&'static str, IdentityError),

    #[error("{0} is not encoded in {1} or the encoding is incorrect: {2:?}")]
    Encoding(&'static str, &'static str, Box<Error>),

    #[error("External error: {0:?}")]
    External(anyhow::Error),

    #[error("{0} must be {1} bytes long, but is {2} bytes long instead")]
    InvalidSize(&'static str, usize, u64),

    #[error("Malformed {0}: missing '{1}' for {2}")]
    Malformed(&'static str, &'static str, String),

    #[error("There was an issue with {0} the signature, cannot {1}")]
    Signature(&'static str, &'static str),

    #[error("Internal Spongos error: {0}")]
    Spongos(SpongosError),

    /// Transport

    #[error("Transport error for address {1}: {0}")]
    AddressError(&'static str, Address),

    #[cfg(any(feature = "tangle-client", feature = "tangle-client-wasm"))]
    #[error("Iota client error for {0}: {1}")]
    IotaClient(&'static str, iota_client::Error),

    #[cfg(feature = "mysql-client")]
    #[error("MySql client error for {0}: {1}")]
    MySqlClient(&'static str, sqlx::Error),

    #[cfg(feature = "mysql-client")]
    #[error("MySql client failed to insert message into db")]
    MySqlNotInserted,

    #[error("message '{0}' not found in {1}")]
    MessageMissing(Address, &'static str),

    #[error("Nonce is not in the range 0..u32::MAX range for target score: {0}")]
    Nonce(f64),

    #[cfg(feature = "utangle-client")]
    #[error("Request HTTP error: {0}")]
    Request(reqwest::Error),
}

impl Error {
    #[cfg(feature = "did")]
    pub fn did<T: Into<IdentityError>>(did: &'static str, e: T) -> Self {
        Self::Did(did, e.into())
    }

    pub fn utf(m: &'static str, error: FromUtf8Error) -> Self {
        Self::Encoding(m, "utf8", Box::new(Self::External(error.into())))
    }
}

impl From<SpongosError> for Error {
    fn from(error: SpongosError) -> Self {
        Self::Spongos(error)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(error: FromUtf8Error) -> Self {
        Self::utf("string", error)
    }
}

impl From<FromHexError> for Error {
    fn from(error: FromHexError) -> Self {
        Self::Encoding(
            "string",
            "hex",
            Box::new(Self::External(anyhow::anyhow!(error))),
        )
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Encoding(
            "string",
            "serde_json",
            Box::new(Self::External(anyhow::anyhow!(error))),
        )
    }
}

impl From<prefix_hex::Error> for Error {
    fn from(error: prefix_hex::Error) -> Self {
        Self::Encoding(
            "string",
            "prefix_hex",
            Box::new(Self::External(anyhow::anyhow!(error))),
        )
    }
}

#[cfg(feature = "mysql-client")]
impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        Self::MySqlClient("undefined", error)
    }
}

#[cfg(feature = "utangle-client")]
impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::Request(error)
    }
}

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
impl std::error::Error for Error {}
