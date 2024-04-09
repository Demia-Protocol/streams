// Rust
use core::{fmt::Formatter, ops::Range};

// IOTA

// Streams
use lets::{
    address::Address,
    id::Identifier,
    message::{TopicHash, HDF},
};

use crate::Message;

/// An enum that is used to select messages from a stream.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Selector {
    Address(Address),
    Topic(TopicHash),
    Identifier(Identifier),
    Level(Range<usize>),
    Time(u128),
}

impl Selector {
    /// > If the selector is an address, check if the message address is equal to the selector
    /// > address.
    /// If the selector is a topic, check if the message topic is equal to the selector topic. If
    /// the selector is an identifier, check if the message publisher is equal to the selector
    /// identifier. If the selector is a level, check if the message sequence is contained in
    /// the selector level
    ///
    /// # Arguments
    ///
    /// * `message`: The message to check against the selector.
    ///
    /// Returns:
    ///
    /// A boolean value.
    pub fn is(&self, message: &Message) -> bool {
        self.is_from_header(message.header(), Some(message.address))
    }

    pub fn is_from_header(&self, header: &HDF, address: Option<Address>) -> bool {
        match self {
            Selector::Address(a) => {
                if let Some(address) = address {
                    &address == a
                } else {
                    false
                }
            }
            Selector::Topic(topic) => header.topic_hash() == topic,
            Selector::Identifier(identifier) => header.publisher() == identifier,
            Selector::Level(range) => range.contains(&header.sequence()),
            Selector::Time(stamp) => header.timestamp as u128 > *stamp,
        }
    }
}

impl core::fmt::Display for Selector {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", &self)
    }
}
