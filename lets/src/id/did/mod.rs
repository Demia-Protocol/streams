/// Base `DID` functionality and types
mod did;
/// Details required for `DID` resolution
mod url_info;
///
//mod keypair;
pub use did::{DIDInfo, IdentityDocCache, DID};
pub use url_info::DIDUrlInfo;
//pub use keypair::{KeyPair};

pub(crate) use did::{get_exchange_method, resolve_document};

pub const STREAMS_VAULT: &[u8] = b"streams-secrets-vault";
// 32 pub key + 12 nonce + 16 tag + 32 ciphertext
pub const DID_ENCRYPTED_DATA_SIZE: usize = 92;

// 3rd party
pub use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
