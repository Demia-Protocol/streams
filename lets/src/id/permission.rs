// Rust
use core::ops::Deref;

// IOTA

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::{Uint32, Uint64, Uint8},
    },
    error::{Error as SpongosError, Result as SpongosResult},
    PRP,
};

// Local
use crate::id::identifier::Identifier;

/// Duration with which a `ReadWrite` [`Permissioned`] will be valid for
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PermissionDuration {
    /// Indefinite `ReadWrite`
    Perpetual,
    /// `ReadWrite` until (including) the internal `Unix` timestamp elapses
    Unix(u64),
    /// `ReadWrite` until (including) the specified number of messages has been parsed from the branch
    NumBranchMsgs(u32),
    /// `ReadWrite` until (including) the specified number of messages has been parsed from the channel
    NumPublishedmsgs(u32),
}

impl PermissionDuration {
    pub fn seconds_from_now(secs: u64) -> Self {
        let now = chrono::Utc::now();
        let milis: u64 = now.timestamp_millis().try_into().unwrap();
        Self::Unix(milis + secs * 1000_u64)
    }

    pub fn timestamp(self) -> u64 {
        if let PermissionDuration::Unix(t) = self {
            t
        } else {
            panic!("Not a Unix type")
        }
    }

    pub fn num_branches(self) -> u32 {
        if let PermissionDuration::NumBranchMsgs(t) = self {
            t
        } else {
            panic!("Not a NumBranchMsgs type")
        }
    }

    pub fn num_published_messages(self) -> u32 {
        if let PermissionDuration::NumPublishedmsgs(t) = self {
            t
        } else {
            panic!("Not a NumPublishedmsgs type")
        }
    }
}

impl Default for PermissionDuration {
    fn default() -> Self {
        Self::Perpetual
    }
}

impl Mask<&PermissionDuration> for sizeof::Context {
    fn mask(&mut self, duration: &PermissionDuration) -> SpongosResult<&mut Self> {
        match duration {
            PermissionDuration::Perpetual => {
                self.mask(Uint8::new(0))?;
                Ok(self)
            }
            PermissionDuration::Unix(_) => {
                self.mask(Uint8::new(1))?;
                self.mask(Uint64::new(0))?;
                Ok(self)
            }
            PermissionDuration::NumBranchMsgs(_) => {
                self.mask(Uint8::new(2))?;
                self.mask(Uint32::new(0))?;
                Ok(self)
            }
            PermissionDuration::NumPublishedmsgs(_) => {
                self.mask(Uint8::new(3))?;
                self.mask(Uint32::new(0))?;
                Ok(self)
            }
        }
    }
}

impl<OS, F> Mask<&PermissionDuration> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, duration: &PermissionDuration) -> SpongosResult<&mut Self> {
        match &duration {
            PermissionDuration::Perpetual => {
                self.mask(Uint8::new(0))?;
                Ok(self)
            }
            PermissionDuration::Unix(timestamp) => {
                self.mask(Uint8::new(1))?;
                self.mask(Uint64::new(*timestamp))?;
                Ok(self)
            }
            PermissionDuration::NumBranchMsgs(num_branch_msgs) => {
                self.mask(Uint8::new(2))?;
                self.mask(Uint32::new(*num_branch_msgs))?;
                Ok(self)
            }
            PermissionDuration::NumPublishedmsgs(num_published_msgs) => {
                self.mask(Uint8::new(3))?;
                self.mask(Uint32::new(*num_published_msgs))?;
                Ok(self)
            }
        }
    }
}

impl<IS, F> Mask<&mut PermissionDuration> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, duration: &mut PermissionDuration) -> SpongosResult<&mut Self> {
        let mut oneof = Uint8::new(0);
        self.mask(&mut oneof)?;
        match oneof.inner() {
            0 => {
                *duration = PermissionDuration::Perpetual;
            }
            1 => {
                let mut timestamp = Uint64::new(0);
                self.mask(&mut timestamp)?;
                *duration = PermissionDuration::Unix(timestamp.inner());
            }
            2 => {
                let mut num_branch_msgs = Uint32::new(0);
                self.mask(&mut num_branch_msgs)?;
                *duration = PermissionDuration::NumBranchMsgs(num_branch_msgs.inner());
            }
            3 => {
                let mut num_published_msgs = Uint32::new(0);
                self.mask(&mut num_published_msgs)?;
                *duration = PermissionDuration::NumPublishedmsgs(num_published_msgs.inner());
            }
            o => return Err(SpongosError::InvalidOption("identifier", o)),
        }
        Ok(self)
    }
}

// Constants representing permission types
pub(crate) const READ_PERMISSION: u8 = 0;
pub(crate) const READ_WRITE_PERMISSION: u8 = 1;
pub(crate) const ADMIN_PERMISSION: u8 = 2;

/// Enum representing different permission types
#[derive(Debug, PartialEq, Eq)]
pub enum PermissionType {
    /// Read Access for the assigned branch
    Read,
    /// Read and Write Access for the branch. May send packets within the [`PermissionDuration`].
    ReadWrite,
    /// Read, Write, and Administrative privileges. Allows the User to send Keyloads to manage Read
    /// and Write privileges for other members of the Stream
    Admin,
}

/// Converts a u8 value into a PermissionType
///
/// # Arguments
///
/// * `value` - The u8 value representing the permission type
///
/// # Returns
///
/// Returns Some(PermissionType) if the conversion is successful,
/// otherwise returns None.
impl Into<u8> for PermissionType {
    fn into(self) -> u8 {
        match self {
            PermissionType::Read => READ_PERMISSION,
            PermissionType::ReadWrite => READ_WRITE_PERMISSION,
            PermissionType::Admin => ADMIN_PERMISSION,
        }
    }
}

impl TryFrom<u8> for PermissionType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            READ_PERMISSION => Ok(PermissionType::Read),
            READ_WRITE_PERMISSION => Ok(PermissionType::ReadWrite),
            ADMIN_PERMISSION => Ok(PermissionType::Admin),
            _ => Err(()),
        }
    }
}

impl<T> From<&Permissioned<T>> for PermissionType {
    fn from(value: &Permissioned<T>) -> Self {
        match value {
            Permissioned::Read(_) => PermissionType::Read,
            Permissioned::ReadWrite(..) => PermissionType::ReadWrite,
            Permissioned::Admin(_) => PermissionType::Admin,
        }
    }
}

/// Used to assign Read and Write access to branches within a Stream
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Permissioned<Identifier> {
    /// Read Access for the assigned branch
    Read(Identifier),
    /// Read and Write Access for the branch. May send packets within the [`PermissionDuration`].
    ReadWrite(Identifier, PermissionDuration),
    /// Read, Write and Administrative privileges. Allows the User to send Keyloads to manage Read
    /// and Write privileges for other members of the Stream
    Admin(Identifier),
}

impl<Identifier> Permissioned<Identifier> {
    /// Returns a reference to the internal `Identifier` of the permission
    pub fn identifier(&self) -> &Identifier {
        match self {
            Permissioned::Read(id) => id,
            Permissioned::ReadWrite(id, _) => id,
            Permissioned::Admin(id) => id,
        }
    }

    /// Returns a mutable reference to the internal `Identifier` of the permission
    pub fn identifier_mut(&mut self) -> &mut Identifier {
        match self {
            Permissioned::Read(id) => id,
            Permissioned::ReadWrite(id, _) => id,
            Permissioned::Admin(id) => id,
        }
    }

    /// Returns a new [`Permissioned`] wrapper for a reference to the inner values of the current
    /// [`Permissioned`].
    pub fn as_ref(&self) -> Permissioned<&Identifier> {
        match self {
            Self::Read(id) => Permissioned::Read(id),
            Self::ReadWrite(id, duration) => Permissioned::ReadWrite(id, *duration),
            Self::Admin(id) => Permissioned::Admin(id),
        }
    }

    /// Returns if the [`Permissioned`] is [`Permissioned::Read`].
    pub fn is_readonly(&self) -> bool {
        matches!(self, Permissioned::Read(..))
    }

    /// Returns if the [`Permissioned`] is [`Permissioned::Admin`].
    pub fn is_admin(&self) -> bool {
        matches!(self, Permissioned::Admin(..))
    }

    pub fn r#type(&self) -> PermissionType {
        self.into()
    }
}

// Implementing Deref for Permissioned
impl<Identifier> Deref for Permissioned<Identifier> {
    type Target = Identifier;

    fn deref(&self) -> &Self::Target {
        self.identifier()
    }
}

impl From<Permissioned<&Identifier>> for Permissioned<Identifier> {
    fn from(perm: Permissioned<&Identifier>) -> Self {
        match perm {
            Permissioned::Read(id) => Permissioned::Read(id.clone()),
            Permissioned::ReadWrite(id, duration) => Permissioned::ReadWrite(id.clone(), duration),
            Permissioned::Admin(id) => Permissioned::Admin(id.clone()),
        }
    }
}

impl<Identifier> AsRef<Identifier> for Permissioned<Identifier> {
    fn as_ref(&self) -> &Identifier {
        self.identifier()
    }
}

impl<Identifier> AsMut<Identifier> for Permissioned<Identifier> {
    fn as_mut(&mut self) -> &mut Identifier {
        self.identifier_mut()
    }
}

impl<Identifier> Default for Permissioned<Identifier>
where
    Identifier: Default,
{
    fn default() -> Self {
        Permissioned::Read(Identifier::default())
    }
}

impl Mask<&Permissioned<Identifier>> for sizeof::Context {
    fn mask(&mut self, permission: &Permissioned<Identifier>) -> SpongosResult<&mut Self> {
        self.mask(&permission.as_ref())
    }
}

impl<OS, F> Mask<&Permissioned<Identifier>> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, permission: &Permissioned<Identifier>) -> SpongosResult<&mut Self> {
        self.mask(&permission.as_ref())
    }
}

impl<IS, F> Mask<&mut Permissioned<Identifier>> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, permission: &mut Permissioned<Identifier>) -> SpongosResult<&mut Self> {
        let mut oneof = Uint8::new(0);
        self.mask(&mut oneof)?;
        match oneof.inner() {
            0 => {
                let mut identifier = Identifier::default();
                self.mask(&mut identifier)?;
                *permission = Permissioned::Read(identifier);
            }
            1 => {
                let mut identifier = Identifier::default();
                let mut duration = PermissionDuration::default();
                self.mask(&mut duration)?.mask(&mut identifier)?;
                *permission = Permissioned::ReadWrite(identifier, duration);
            }
            2 => {
                let mut identifier = Identifier::default();
                self.mask(&mut identifier)?;
                *permission = Permissioned::Admin(identifier);
            }
            o => return Err(SpongosError::InvalidOption("permission", o)),
        }
        Ok(self)
    }
}

impl Mask<&Permissioned<&Identifier>> for sizeof::Context {
    fn mask(&mut self, permission: &Permissioned<&Identifier>) -> SpongosResult<&mut Self> {
        match permission {
            Permissioned::Read(identifier) => {
                let oneof = Uint8::new(0);
                self.mask(oneof)?.mask(*identifier)?;
                Ok(self)
            }
            Permissioned::ReadWrite(identifier, duration) => {
                let oneof = Uint8::new(1);
                self.mask(oneof)?.mask(duration)?.mask(*identifier)?;
                Ok(self)
            }
            Permissioned::Admin(identifier) => {
                let oneof = Uint8::new(2);
                self.mask(oneof)?.mask(*identifier)?;
                Ok(self)
            }
        }
    }
}

impl<OS, F> Mask<&Permissioned<&Identifier>> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, permission: &Permissioned<&Identifier>) -> SpongosResult<&mut Self> {
        match permission {
            Permissioned::Read(identifier) => {
                let oneof = Uint8::new(0);
                self.mask(oneof)?.mask(*identifier)?;
                Ok(self)
            }
            Permissioned::ReadWrite(identifier, duration) => {
                let oneof = Uint8::new(1);
                self.mask(oneof)?.mask(duration)?.mask(*identifier)?;
                Ok(self)
            }
            Permissioned::Admin(identifier) => {
                let oneof = Uint8::new(2);
                self.mask(oneof)?.mask(*identifier)?;
                Ok(self)
            }
        }
    }
}
