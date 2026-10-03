//! The keys an operation takes: [`Keys`] or a keyring, passed in.
//!
//! Key material and keyrings live in `key`, below the cryptographic cores.
//! Which keys protect which values is application code: the library takes the
//! keys to use and never asks for them.

use crate::{BlindIndexKeyring, EncryptionKeyring, Error, Keys};

/// Keys that seal and open values: an [`EncryptionKeyring`], or [`Keys`].
///
/// Sealing with the wrong keyring succeeds and is only noticed when reading;
/// see [choosing keyrings]. This trait is sealed.
///
#[doc = concat!(
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/guide.md#choosing-keyrings",
)]
#[diagnostic::on_unimplemented(
    message = "`{Self}` are not encryption keys",
    label = "pass an `EncryptionKeyring` or `Keys`"
)]
pub trait EncryptionKeys: sealed::Sealed + Send + Sync {
    /// Returns the encryption keyring.
    fn encryption_keyring(&self) -> &EncryptionKeyring;
}

/// Keys that derive blind indexes: a [`BlindIndexKeyring`], or [`Keys`] with
/// one. This trait is sealed.
#[diagnostic::on_unimplemented(
    message = "`{Self}` are not blind-index keys",
    label = "pass a `BlindIndexKeyring` or `Keys`"
)]
pub trait BlindIndexKeys: sealed::Sealed + Send + Sync {
    /// Returns the blind-index keyring.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BlindIndexKeysNotConfigured`] for [`Keys`] without one.
    fn blind_index_keyring(&self) -> Result<&BlindIndexKeyring, Error>;
}

/// Keys that seal and open a [`Record`](crate::Record): an
/// [`EncryptionKeyring`] for a record without blind indexes, or [`Keys`]. This
/// trait is sealed.
#[diagnostic::on_unimplemented(
    message = "`{Self}` are not a record's keys",
    label = "pass an `EncryptionKeyring`, or `Keys` when the record has blind indexes"
)]
pub trait RecordKeys: EncryptionKeys {
    /// Returns the blind-index keyring.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BlindIndexKeysNotConfigured`] for an
    /// [`EncryptionKeyring`], or [`Keys`] without one.
    fn record_blind_index_keyring(&self) -> Result<&BlindIndexKeyring, Error>;
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for crate::EncryptionKeyring {}
    impl Sealed for crate::BlindIndexKeyring {}
    impl Sealed for crate::Keys {}
}

impl EncryptionKeys for EncryptionKeyring {
    fn encryption_keyring(&self) -> &EncryptionKeyring {
        self
    }
}

impl EncryptionKeys for Keys {
    fn encryption_keyring(&self) -> &EncryptionKeyring {
        self.encryption()
    }
}

impl BlindIndexKeys for BlindIndexKeyring {
    fn blind_index_keyring(&self) -> Result<&BlindIndexKeyring, Error> {
        Ok(self)
    }
}

impl BlindIndexKeys for Keys {
    fn blind_index_keyring(&self) -> Result<&BlindIndexKeyring, Error> {
        self.blind_indexes()
            .ok_or(Error::BlindIndexKeysNotConfigured)
    }
}

impl RecordKeys for EncryptionKeyring {
    fn record_blind_index_keyring(&self) -> Result<&BlindIndexKeyring, Error> {
        Err(Error::BlindIndexKeysNotConfigured)
    }
}

impl RecordKeys for Keys {
    fn record_blind_index_keyring(&self) -> Result<&BlindIndexKeyring, Error> {
        self.blind_index_keyring()
    }
}
