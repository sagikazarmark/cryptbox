mod keyring;
mod material;

pub use keyring::{BlindIndexKeyring, EncryptionKeyring};
pub use material::{BlindIndexKey, EncryptionKey, IndexKeyId, KeyId};

/// An encryption keyring and an optional blind-index keyring, passed together.
///
/// `Keys` serves both roles, so it can be passed to any operation
/// (`Sealed::seal`, `Sealed::open`, `BlindIndex::probes`, …).
///
/// Blind-index operations fail with
/// [`Error::BlindIndexKeysNotConfigured`](crate::Error::BlindIndexKeysNotConfigured)
/// for keys without a blind-index keyring.
///
/// `Keys` serves every seal and record alike. To keep seals or tenants under
/// separate keys, pass each its own `Keys`; see [choosing keyrings].
///
#[doc = concat!(
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/docs/guide.md#choosing-keyrings",
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
    encryption: EncryptionKeyring,
    blind_indexes: Option<BlindIndexKeyring>,
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

    /// Returns the keyring that seals and opens values.
    #[must_use]
    pub const fn encryption(&self) -> &EncryptionKeyring {
        &self.encryption
    }

    /// Returns the separately keyed blind-index keyring, if blind indexes are
    /// used.
    #[must_use]
    pub const fn blind_indexes(&self) -> Option<&BlindIndexKeyring> {
        self.blind_indexes.as_ref()
    }
}
