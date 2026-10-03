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
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/choosing-keyrings.md",
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
        &self.encryption
    }
}

impl BlindIndexKeys for BlindIndexKeyring {
    fn blind_index_keyring(&self) -> Result<&BlindIndexKeyring, Error> {
        Ok(self)
    }
}

impl BlindIndexKeys for Keys {
    fn blind_index_keyring(&self) -> Result<&BlindIndexKeyring, Error> {
        self.blind_indexes
            .as_ref()
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

/// The keys of an automatic `SQLx` column, `Plain<F, K>`.
///
/// `SQLx` encoding and decoding receive no context, so the column names its
/// keys in its type. The default, [`GlobalKeys`], reads the keys installed with
/// [`keys::install`](crate::keys::install). Implement this trait over your own
/// static to use other keys (a second deployment, a test fixture) without
/// installing the global. Like the column, it serves only
/// standalone values: a tenant's values are sealed explicitly with that
/// tenant's keys.
///
/// # Examples
///
/// ```
/// use std::sync::LazyLock;
///
/// use cryptbox::{
///     EncryptionKey, EncryptionKeyring, Error, Seal, SealId, ColumnKeys, Keys,
///     Padding, Plain, Utf8,
/// };
///
/// struct UserEmail;
///
/// impl Seal for UserEmail {
///     const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Indexes = ();
/// }
///
/// struct ArchiveKeys;
///
/// impl ColumnKeys for ArchiveKeys {
///     fn keys() -> Result<&'static Keys, Error> {
///         // Load durable key material here; a generated key is for demonstration only.
///         static KEYS: LazyLock<Result<Keys, Error>> = LazyLock::new(|| {
///             Ok(Keys::new(EncryptionKeyring::new(EncryptionKey::generate()?, [])?))
///         });
///
///         KEYS.as_ref().map_err(Clone::clone)
///     }
/// }
///
/// // A column that seals and opens with `ArchiveKeys`, never the installed keys.
/// let email = Plain::<UserEmail, ArchiveKeys>::new("user@example.com");
/// # let _ = email;
/// ```
pub trait ColumnKeys: 'static {
    /// Returns these keys.
    ///
    /// # Errors
    ///
    /// Returns an error when the keys are unavailable, such as
    /// [`Error::KeysNotInstalled`] for [`GlobalKeys`] before installation.
    fn keys() -> Result<&'static Keys, Error>;
}

/// The column keys installed with
/// [`keys::install`](crate::keys::install).
///
/// These are the default keys of [`Plain`](crate::Plain).
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalKeys;

impl ColumnKeys for GlobalKeys {
    fn keys() -> Result<&'static Keys, Error> {
        crate::keys::installed()
    }
}
