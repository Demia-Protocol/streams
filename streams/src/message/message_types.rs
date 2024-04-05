use lets::id::PermissionType;

/// Announcement Message Type
pub(crate) const ANNOUNCEMENT: u8 = 0;
/// Branch Announcement Message Type
pub(crate) const BRANCH_ANNOUNCEMENT: u8 = 1;
/// Keyload Message Type
pub(crate) const KEYLOAD: u8 = 2;
/// Signed Packet Message Type
pub(crate) const SIGNED_PACKET: u8 = 3;
/// Tagged Packet Message Type
pub(crate) const TAGGED_PACKET: u8 = 4;
/// Subscribe Message Type
pub(crate) const SUBSCRIPTION: u8 = 5;
/// Unsubscribe Message Type
pub(crate) const UNSUBSCRIPTION: u8 = 6;

/// Enum representing different message types
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MessageType {
    /// Announcement Message Type
    Announcement,
    /// Branch Announcement Message Type
    BranchAnnouncement,
    /// Keyload Message Type
    Keyload,
    /// Signed Packet Message Type
    SignedPacket,
    /// Tagged Packet Message Type
    TaggedPacket,
    /// Subscribe Message Type
    Subscription,
    /// Unsubscribe Message Type
    Unsubscription,
}

impl Into<PermissionType> for MessageType {
    fn into(self) -> PermissionType {
        match self {
            Self::SignedPacket | Self::TaggedPacket => PermissionType::ReadWrite,
            Self::Announcement | Self::BranchAnnouncement | Self::Keyload => PermissionType::Admin,
            _ => PermissionType::Read,
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = crate::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            ANNOUNCEMENT => Ok(Self::Announcement),
            BRANCH_ANNOUNCEMENT => Ok(Self::BranchAnnouncement),
            KEYLOAD => Ok(Self::Keyload),
            SIGNED_PACKET => Ok(Self::SignedPacket),
            TAGGED_PACKET => Ok(Self::TaggedPacket),
            SUBSCRIPTION => Ok(Self::Subscription),
            UNSUBSCRIPTION => Ok(Self::Unsubscription),
            unknown => Err(Self::Error::MessageTypeUnknown(unknown)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from() {
        assert_eq!(MessageType::try_from(0), Some(MessageType::Announcement));
        assert_eq!(MessageType::try_from(3), Some(MessageType::SignedPacket));
        assert_eq!(MessageType::try_from(7), None);
    }

    #[test]
    fn test_into() {
        assert_eq!(MessageType::Announcement.into(), 0);
        assert_eq!(MessageType::TaggedPacket.into(), 4);
    }
}
