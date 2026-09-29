mod keyring;
mod material;

pub use keyring::{BlindIndexKeyring, EncryptionKeyring};
pub use material::{BlindIndexKey, EncryptionKey, IndexKeyId, KeyId};

/// A key or keyring could not be created.
///
/// It converts into the same variant of [`Error`](crate::Error), so `?` works in
/// functions that return the crate's error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The operating-system random source failed.
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    /// Encoded root key material is malformed or does not decode to 32 bytes.
    #[error("encoded key material is invalid")]
    InvalidKeyEncoding,
    /// A keyring contains the same encryption key ID more than once.
    #[error("duplicate encryption key ID {0}")]
    DuplicateEncryptionKey(KeyId),
    /// A keyring contains the same blind-index key ID more than once.
    #[error("duplicate blind-index key ID {0}")]
    DuplicateBlindIndexKey(IndexKeyId),
}

/// An encryption keyring and an optional blind-index keyring, passed together.
///
/// `Keys` is a source for both roles, so it can be passed to any operation
/// (`Sealed::seal`, `Sealed::open`, `probes_with`, …). It is also what
/// [`keys::install`](crate::keys::install) installs for the global conveniences.
///
/// Blind-index operations fail with [`Error::BlindIndexKeysNotConfigured`](crate::Error::BlindIndexKeysNotConfigured) when
/// `blind_indexes` is `None`.
///
/// `Keys` serves every field and scope alike. To keep fields or scopes under
/// separate keys, pass each its own `Keys`, or implement a key source; see
/// [choosing keyrings].
///
#[doc = concat!(
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/choosing-keyrings.md",
)]
///
/// # Examples
///
/// ```
/// use cryptbox::{BlindIndexKey, BlindIndexKeyring, EncryptionKey, EncryptionKeyring, Keys};
///
/// # fn main() -> Result<(), cryptbox::Error> {
/// let keys = Keys::new(EncryptionKeyring::new(EncryptionKey::generate()?, [])?)
///     .with_blind_indexes(BlindIndexKeyring::new(BlindIndexKey::generate()?, [])?);
/// # let _ = keys;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Keys {
    /// The keyring that seals and opens values.
    pub encryption: EncryptionKeyring,
    /// The separately keyed blind-index keyring, if blind indexes are used.
    pub blind_indexes: Option<BlindIndexKeyring>,
}

impl Keys {
    /// Creates keys with an encryption keyring only.
    #[must_use]
    pub const fn new(encryption: EncryptionKeyring) -> Self {
        Self {
            encryption,
            blind_indexes: None,
        }
    }

    /// Adds the separately keyed blind-index keyring.
    #[must_use]
    pub fn with_blind_indexes(mut self, keyring: BlindIndexKeyring) -> Self {
        self.blind_indexes = Some(keyring);
        self
    }
}
