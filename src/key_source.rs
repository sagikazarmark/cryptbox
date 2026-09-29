//! Key selection: which keyring protects a seal or blind index in a key scope.
//!
//! Key material and keyrings live in `key`, below the cryptographic cores; this
//! layer sits above bindings, because a key source is asked by [`KeyScope`].

use std::sync::Arc;

use crate::{BlindIndexKeyring, EncryptionKeyring, Error, IndexId, KeyScope, Keys, SealId};

/// Supplies the encryption keyring for each operation.
///
/// Operations pass the source the seal they act on and the [`KeyScope`] of the
/// binding arguments. [`EncryptionKeyring`] and [`Keys`] ignore both and return
/// themselves, so which keyring protects which seal or scope is application
/// code: pass that keyring to the call, or implement this trait to choose it.
/// See [choosing keyrings] for the mistakes a source must avoid, since sealing
/// with the wrong keyring succeeds and is only noticed when reading.
///
/// A source is synchronous. Load keys from a KMS and refresh them outside
/// these calls, and fail closed with [`Error::KeysUnavailable`] when they are
/// not loaded. It returns the keyring by value: cloning a keyring shares its
/// keys, so a source can hand out a keyring from behind a lock, a swapped
/// snapshot, or a cache of per-scope keyrings.
///
#[doc = concat!(
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/choosing-keyrings.md",
)]
pub trait EncryptionKeySource: Send + Sync {
    /// Returns the keyring that protects `seal` in `scope`.
    ///
    /// # Errors
    ///
    /// Returns an error when this source cannot supply that keyring.
    fn encryption_keyring(
        &self,
        seal: SealId,
        scope: &KeyScope,
    ) -> Result<EncryptionKeyring, Error>;
}

/// Supplies the blind-index keyring for each operation.
///
/// Operations pass the source the blind index they act on and the
/// [`KeyScope`] it is derived in. [`BlindIndexKeyring`] and [`Keys`] ignore both
/// and return themselves. The rules of [`EncryptionKeySource`] apply alike; see
/// [choosing keyrings].
///
#[doc = concat!(
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/choosing-keyrings.md",
)]
pub trait BlindIndexKeySource: Send + Sync {
    /// Returns the keyring that protects `index` in `scope`.
    ///
    /// # Errors
    ///
    /// Returns an error when this source cannot supply that keyring, such as
    /// [`Error::BlindIndexKeysNotConfigured`] for [`Keys`] without one.
    fn blind_index_keyring(
        &self,
        index: IndexId,
        scope: &KeyScope,
    ) -> Result<BlindIndexKeyring, Error>;
}

impl EncryptionKeySource for EncryptionKeyring {
    fn encryption_keyring(&self, _: SealId, _: &KeyScope) -> Result<EncryptionKeyring, Error> {
        Ok(self.clone())
    }
}

impl BlindIndexKeySource for BlindIndexKeyring {
    fn blind_index_keyring(&self, _: IndexId, _: &KeyScope) -> Result<BlindIndexKeyring, Error> {
        Ok(self.clone())
    }
}

impl EncryptionKeySource for Keys {
    fn encryption_keyring(&self, _: SealId, _: &KeyScope) -> Result<EncryptionKeyring, Error> {
        Ok(self.encryption.clone())
    }
}

impl BlindIndexKeySource for Keys {
    fn blind_index_keyring(&self, _: IndexId, _: &KeyScope) -> Result<BlindIndexKeyring, Error> {
        self.blind_indexes
            .clone()
            .ok_or(Error::BlindIndexKeysNotConfigured)
    }
}

impl<S: EncryptionKeySource + ?Sized> EncryptionKeySource for &S {
    fn encryption_keyring(
        &self,
        seal: SealId,
        scope: &KeyScope,
    ) -> Result<EncryptionKeyring, Error> {
        (**self).encryption_keyring(seal, scope)
    }
}

impl<S: BlindIndexKeySource + ?Sized> BlindIndexKeySource for &S {
    fn blind_index_keyring(
        &self,
        index: IndexId,
        scope: &KeyScope,
    ) -> Result<BlindIndexKeyring, Error> {
        (**self).blind_index_keyring(index, scope)
    }
}

impl<S: EncryptionKeySource + ?Sized> EncryptionKeySource for Arc<S> {
    fn encryption_keyring(
        &self,
        seal: SealId,
        scope: &KeyScope,
    ) -> Result<EncryptionKeyring, Error> {
        (**self).encryption_keyring(seal, scope)
    }
}

impl<S: BlindIndexKeySource + ?Sized> BlindIndexKeySource for Arc<S> {
    fn blind_index_keyring(
        &self,
        index: IndexId,
        scope: &KeyScope,
    ) -> Result<BlindIndexKeyring, Error> {
        (**self).blind_index_keyring(index, scope)
    }
}

/// The key source of an automatic `SQLx` column, `Plain<F, K>`.
///
/// `SQLx` encoding and decoding receive no context, so the column names its
/// keys in its type. The default, [`GlobalKeys`], reads the keys installed with
/// [`keys::install`](crate::keys::install). Implement this trait over your own
/// static to use other keys (a second deployment, a test fixture) without
/// installing the global. Like the column, it serves only
/// unscoped seals: a value bound to a tenant is sealed
/// explicitly with that tenant's keys.
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
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Scope = ();
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
    /// Returns the keys of this key source.
    ///
    /// # Errors
    ///
    /// Returns an error when the keys are unavailable, such as
    /// [`Error::KeysNotInstalled`] for [`GlobalKeys`] before installation.
    fn keys() -> Result<&'static Keys, Error>;
}

/// The key source that reads the keys installed with
/// [`keys::install`](crate::keys::install).
///
/// This is the default key source of [`Plain`](crate::Plain).
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalKeys;

impl ColumnKeys for GlobalKeys {
    fn keys() -> Result<&'static Keys, Error> {
        crate::keys::installed()
    }
}
