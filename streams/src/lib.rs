//! High-level Implementation of the Streams Protocol. Streams users will generate a [`User`]
//! instance to interact with a provided transport layer (existing Client implementations can be
//! found in the [LETS] crate, and custom Clients can be created so long as they implement the
//! [`Transport`] trait).
//!
//! Uses functionality from the [LETS](lets) crate, using the sponge/crypto operations present in
//! the [Spongos](spongos) crate.
//!
//! API functions can be found through the [`User`]
//!
//! User implementations will require a Transport (the default implementation is the
//! [uTangle Client](`lets::transport::utangle::Client`)
//!
//! ## Starting a new Channel
//! ```
//! use streams::{
//!     transport::utangle,
//!     id::Ed25519,
//!     User, Result
//! };
//! # use streams::transport::bucket;
//! #[tokio::main]
//! async fn main() -> Result<()> {
//! let transport: utangle::Client = utangle::Client::new("https://chrysalis-nodes.iota.org");
//! # let test_transport = bucket::Client::new();
//! let mut author = User::builder()
//!     .with_identity(Ed25519::from_seed("A cryptographically secure seed"))
//!     .with_transport(transport)
//! #     .with_transport(test_transport)
//!     .build();
//!
//! // A new stream, or branch within a stream will require a Topic label
//! let announcement = author.create_stream("BASE_BRANCH").await?;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

// Uncomment to enable printing for development
// #[macro_use]
// extern crate std;

#[macro_use]
extern crate alloc;

/// Protocol message types and encodings.
mod message;

/// High level API including [`User`], [`UserBuilder`], Message [`retrieval`](`Messages`) and
/// [`sending`](`MessageBuilder`).
mod api;

pub use api::{
    message::*, message_builder::MessageBuilder, messages::Messages, selector::Selector,
    send_response::SendResponse, user::User, user_builder::UserBuilder,
};

/// Errors for Streams
mod error;
pub use error::{Error, Result};

pub use lets::{
    address::{Address, AppAddr, MsgId},
    error::Error as LetsError,
    id,
    message::{Topic, TopicHash, TransportMessage},
    transport,
};
