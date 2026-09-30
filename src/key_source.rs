//! Key selection: which keyring protects a seal or blind index for a keys view.
//!
//! Key material and keyrings live in `key`, below the cryptographic cores; this
//! layer sits above scopes, because a key source is asked by a seal's
//! [keys view](crate::Seal::Keys).

use std::sync::Arc;

use crate::{BlindIndexKeyring, EncryptionKeyring, Error, IndexId, Keys, SealId};

/// Supplies the encryption keyring for each operation, by keys view `K`.
///
/// Operations pass the source the seal they act on and the values of its
/// [keys view](crate::Seal::Keys), projected from the binding arguments: the
/// parts of the seal's scope that key custody follows, such as the org of an
/// org and workspace. [`EncryptionKeyring`] and [`Keys`] ignore both and return
/// themselves for every `K`, so which keyring protects which seal or scope is
/// application code: pass that keyring to the call, or implement this trait to
/// choose it. A keys view is a [`Scope`](crate::Scope), so it is `Hash + Eq`
/// and can key a map or cache of keyrings itself. See [choosing keyrings] for
/// the mistakes a source must avoid, since sealing with the wrong keyring
/// succeeds and is only noticed when reading.
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
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not an encryption key source for keys view `{K}`",
    label = "cannot supply keyrings for `{K}`",
    note = "a seal asks its key source by its keys view, `Seal::Keys`; implement `EncryptionKeySource<{K}>`, or pass an `EncryptionKeyring`"
)]
pub trait EncryptionKeySource<K>: Send + Sync {
    /// Returns the keyring that protects `seal` for the keys view `keys`.
    ///
    /// # Errors
    ///
    /// Returns an error when this source cannot supply that keyring.
    fn encryption_keyring(&self, seal: SealId, keys: &K) -> Result<EncryptionKeyring, Error>;
}

/// Supplies the blind-index keyring for each operation, by keys view `K`.
///
/// Operations pass the source the blind index they act on and the values of
/// its seal's [keys view](crate::Seal::Keys), projected from the index scope,
/// which holds every part of the keys view. [`BlindIndexKeyring`] and [`Keys`]
/// ignore both and return themselves for every `K`. The rules of
/// [`EncryptionKeySource`] apply alike; see [choosing keyrings].
///
#[doc = concat!(
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/choosing-keyrings.md",
)]
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a blind-index key source for keys view `{K}`",
    label = "cannot supply blind-index keyrings for `{K}`",
    note = "a blind index asks its key source by its seal's keys view, `Seal::Keys`; implement `BlindIndexKeySource<{K}>`, or pass a `BlindIndexKeyring`"
)]
pub trait BlindIndexKeySource<K>: Send + Sync {
    /// Returns the keyring that protects `index` for the keys view `keys`.
    ///
    /// # Errors
    ///
    /// Returns an error when this source cannot supply that keyring, such as
    /// [`Error::BlindIndexKeysNotConfigured`] for [`Keys`] without one.
    fn blind_index_keyring(&self, index: IndexId, keys: &K) -> Result<BlindIndexKeyring, Error>;
}

impl<K> EncryptionKeySource<K> for EncryptionKeyring {
    fn encryption_keyring(&self, _: SealId, _: &K) -> Result<EncryptionKeyring, Error> {
        Ok(self.clone())
    }
}

impl<K> BlindIndexKeySource<K> for BlindIndexKeyring {
    fn blind_index_keyring(&self, _: IndexId, _: &K) -> Result<BlindIndexKeyring, Error> {
        Ok(self.clone())
    }
}

impl<K> EncryptionKeySource<K> for Keys {
    fn encryption_keyring(&self, _: SealId, _: &K) -> Result<EncryptionKeyring, Error> {
        Ok(self.encryption.clone())
    }
}

impl<K> BlindIndexKeySource<K> for Keys {
    fn blind_index_keyring(&self, _: IndexId, _: &K) -> Result<BlindIndexKeyring, Error> {
        self.blind_indexes
            .clone()
            .ok_or(Error::BlindIndexKeysNotConfigured)
    }
}

impl<K, S: EncryptionKeySource<K> + ?Sized> EncryptionKeySource<K> for &S {
    fn encryption_keyring(&self, seal: SealId, keys: &K) -> Result<EncryptionKeyring, Error> {
        (**self).encryption_keyring(seal, keys)
    }
}

impl<K, S: BlindIndexKeySource<K> + ?Sized> BlindIndexKeySource<K> for &S {
    fn blind_index_keyring(&self, index: IndexId, keys: &K) -> Result<BlindIndexKeyring, Error> {
        (**self).blind_index_keyring(index, keys)
    }
}

impl<K, S: EncryptionKeySource<K> + ?Sized> EncryptionKeySource<K> for Arc<S> {
    fn encryption_keyring(&self, seal: SealId, keys: &K) -> Result<EncryptionKeyring, Error> {
        (**self).encryption_keyring(seal, keys)
    }
}

impl<K, S: BlindIndexKeySource<K> + ?Sized> BlindIndexKeySource<K> for Arc<S> {
    fn blind_index_keyring(&self, index: IndexId, keys: &K) -> Result<BlindIndexKeyring, Error> {
        (**self).blind_index_keyring(index, keys)
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
///     type Value = String;
///     type Codec = Utf8;
///     type Scope = ();
///     type Keys = ();
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
