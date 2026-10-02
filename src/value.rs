use std::{fmt, marker::PhantomData};

use crate::{
    Codec, EncryptionKeys, Error, GlobalKeys, KeyId, Prepared, Seal, bound,
    envelope::validated_key_id, keys, seal_context::SealContext,
};

/// A value sealed with seal `F`: an encrypted envelope bound to the seal and,
/// for a record field, its record.
///
/// This is what applications store. [`Self::seal`] encodes, pads, and encrypts a
/// value; [`Self::open`] authenticates and decrypts it, and returns the bare
/// [`Seal::Value`]. Plaintext
/// hygiene comes from the value type, such as [`Secret`](crate::Secret).
///
/// Construction from bytes validates only the envelope structure. Authenticity
/// is established by opening. `F` is not encoded in the envelope, so the type
/// parameter expresses caller intent rather than proving that stored bytes were
/// sealed with that seal. With the `serde` feature, this type serializes only
/// the binary envelope; deserialization performs the same structural checks as
/// [`Self::from_bytes`], uses no keys, and leaves the bytes unauthenticated.
///
/// # Examples
///
/// ```
/// use cryptbox::{
///     EncryptionKey, Seal, SealId, EncryptionKeyring, Padding, Sealed, Utf8,
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
/// let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
///
/// let sealed = Sealed::<UserEmail>::seal(&"user@example.com".into(), &keys)?;
/// assert_eq!(sealed.open(&keys)?, "user@example.com");
/// # Ok::<(), cryptbox::Error>(())
/// ```
pub struct Sealed<F: Seal> {
    bytes: Vec<u8>,
    marker: PhantomData<fn() -> F>,
}

impl<F: Seal> Sealed<F> {
    /// Validates and wraps a binary `CryptBox` envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not a supported, structurally valid
    /// `CryptBox` envelope. Authentication, context, and codec compatibility are
    /// deferred until the value is opened.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        crate::inspect_ciphertext(&bytes)?;

        Ok(Self::from_validated_bytes(bytes))
    }

    pub(crate) fn from_validated_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            marker: PhantomData,
        }
    }

    /// Returns the binary envelope.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the typed wrapper and returns the binary envelope.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the encryption-key generation named by the envelope.
    ///
    /// The ID is unauthenticated until the value is opened.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        validated_key_id(&self.bytes)
    }

    /// Encodes and encrypts `value`, bound to the seal.
    ///
    /// A record field's seal is sealed by its record, with
    /// [`Record::seal`](crate::Record::seal); calling this with one fails the
    /// build.
    ///
    /// ```compile_fail,E0080
    /// # use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Seal, SealId, Sealed, Utf8};
    /// # use cryptbox::__private::{RecordKey, RecordKind};
    /// # struct CustomerEmail;
    /// # impl Seal for CustomerEmail {
    /// #     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
    /// #     const PADDING: Padding = Padding::NONE;
    /// #     type Value = String;
    /// #     type Codec = Utf8;
    /// #     type Indexes = ();
    /// #     const RECORD: Option<RecordKind> = Some(<i64 as RecordKey>::KIND);
    /// # }
    /// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
    /// // `CustomerEmail` is the seal of a record's field.
    /// let sealed = Sealed::<CustomerEmail>::seal(&"ada@example.com".into(), &keys)?;
    /// # Ok::<(), cryptbox::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when encoding, padding, key lookup, randomness, or
    /// encryption fails.
    pub fn seal(value: &F::Value, keys: &(impl EncryptionKeys + ?Sized)) -> Result<Self, Error> {
        Self::seal_in(value, &SealContext::standalone::<F>(), keys)
    }

    pub(crate) fn seal_in(
        value: &F::Value,
        context: &SealContext,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Self, Error> {
        let plaintext = F::Codec::encode(value)?;
        let sealed = bound::seal(context, F::PADDING, &plaintext, keys.encryption_keyring())?;

        Ok(Self::from_validated_bytes(sealed))
    }

    /// Authenticates, decrypts, and decodes this value.
    ///
    /// Success establishes authenticity under the supplied key and the seal `F`,
    /// valid padding, and successful decoding with the seal's codec. Apply
    /// application-level validation separately. This does not establish
    /// freshness or consistency with a separately stored blind index. A record
    /// field's value is opened by its record, with
    /// [`Record::open`](crate::Record::open).
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthenticationFailed`] for another seal or modified
    /// bytes, and [`Error::ContextMismatch`] for a value sealed under another
    /// kind of context, such as a record field's. Also returns an error for
    /// unknown keys, unavailable keys, invalid padding, or codec failure.
    pub fn open(&self, keys: &(impl EncryptionKeys + ?Sized)) -> Result<F::Value, Error> {
        self.open_in(&SealContext::standalone::<F>(), keys)
    }

    pub(crate) fn open_in(
        &self,
        context: &SealContext,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<F::Value, Error> {
        let plaintext = bound::open(context, &self.bytes, keys.encryption_keyring())?;

        Ok(F::Codec::decode(&plaintext)?)
    }

    /// Seals `value` into a prepared storage representation that blind indexes
    /// can be added to.
    ///
    /// Indexes are then derived from the same borrowed value with
    /// [`Prepared::with_index_with`].
    ///
    /// # Errors
    ///
    /// Returns any error of [`Self::seal`].
    pub fn prepare<'a>(
        value: &'a F::Value,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Prepared<'a, F>, Error> {
        Ok(Prepared::new(value, Self::seal(value, keys)?))
    }

    /// Reports whether this envelope differs from what `F` currently writes.
    ///
    /// That is a non-current suite or key, or a padding flag that disagrees
    /// with [`Seal::PADDING`].
    ///
    /// Envelope metadata is unauthenticated until the value is opened. A `false`
    /// result does not establish authenticated readability or codec validity.
    /// See the complete [key-rotation example] and [maintenance sweep example].
    ///
    #[doc = concat!(
        "[key-rotation example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/key_rotation.rs\n",
        "[maintenance sweep example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/reencryption_sweep.rs",
    )]
    ///
    /// # Errors
    ///
    /// Returns [`Error::ContextMismatch`] for a value sealed under another
    /// kind of context, or an error for unavailable keys.
    pub fn needs_reseal(&self, keys: &(impl EncryptionKeys + ?Sized)) -> Result<bool, Error> {
        bound::needs_reseal(
            &SealContext::standalone::<F>(),
            F::PADDING,
            &self.bytes,
            keys.encryption_keyring(),
        )
    }

    /// Opens and reseals this value as `F` currently writes it, with the same
    /// keys.
    ///
    /// The rewrite uses the current suite, key, and [`Seal::PADDING`],
    /// so a sweep can enable or disable padding. This authenticates the value
    /// and checks padding, but does not decode it with the seal's codec or
    /// check any stored blind indexes. Use [`Self::open`] when decoded-value
    /// readability is required.
    ///
    /// # Errors
    ///
    /// Returns any opening, padding, or encryption error.
    pub fn reseal(&self, keys: &(impl EncryptionKeys + ?Sized)) -> Result<Self, Error> {
        self.reseal_across(keys, keys)
    }

    /// Opens this value with `from_keys` and reseals it with `to_keys`.
    ///
    /// Use this to move a value to other keys, such as a tenant's data moving
    /// to another residency's keyring. Like [`Self::reseal`], it authenticates
    /// and checks padding without decoding the value.
    ///
    /// # Errors
    ///
    /// Returns any opening error with `from_keys`, or padding or encryption
    /// error with `to_keys`.
    pub fn reseal_across(
        &self,
        from_keys: &(impl EncryptionKeys + ?Sized),
        to_keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Self, Error> {
        let context = SealContext::standalone::<F>();
        let (_, sealed) = bound::reseal(
            (&context, from_keys.encryption_keyring()),
            (&context, to_keys.encryption_keyring()),
            F::PADDING,
            &self.bytes,
        )?;

        Ok(Self::from_validated_bytes(sealed))
    }
}

impl<F: Seal> Sealed<F> {
    /// Seals `value` with the [installed keys](keys::installed).
    ///
    /// This is exactly `Self::seal(value, keys::installed()?)`. The
    /// process-wide keys serve only standalone seals.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeysNotInstalled`] before installation, or any error of
    /// [`Self::seal`].
    pub fn seal_global(value: &F::Value) -> Result<Self, Error> {
        Self::seal(value, keys::installed()?)
    }

    /// Opens this value with the [installed keys](keys::installed).
    ///
    /// This is exactly `self.open(keys::installed()?)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeysNotInstalled`] before installation, or any error of
    /// [`Self::open`].
    pub fn open_global(&self) -> Result<F::Value, Error> {
        self.open(keys::installed()?)
    }
}

impl<F: Seal> TryFrom<Vec<u8>> for Sealed<F> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

// Stores the envelope through `Vec<u8>`, as an ORM's `serialize_as` does.
impl<F: Seal> From<Sealed<F>> for Vec<u8> {
    fn from(sealed: Sealed<F>) -> Self {
        sealed.into_bytes()
    }
}

impl<F: Seal> AsRef<[u8]> for Sealed<F> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<F: Seal> Clone for Sealed<F> {
    fn clone(&self) -> Self {
        Self::from_validated_bytes(self.bytes.clone())
    }
}

impl<F: Seal> PartialEq for Sealed<F> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<F: Seal> Eq for Sealed<F> {}

impl<F: Seal> fmt::Debug for Sealed<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sealed([REDACTED])")
    }
}

/// A plaintext value of seal `F` that an automatic `SQLx` column seals on
/// encode and opens on decode.
///
/// A column decoder does not see the row, so `Plain` serves only seals without
/// blind indexes, `F::Indexes = ()`, and a record field's seal fails the build.
/// Use [`Sealed`] explicitly for every other seal.
///
/// `K` names the column's keys. The default, [`GlobalKeys`], reads the keys
/// installed with [`keys::install`]; name another
/// [`ColumnKeys`](crate::ColumnKeys) to use application-owned keys instead.
///
/// `Plain` contains plaintext while it is in application memory. It redacts
/// `Debug`, does not implement `Display`, `Deref`, `PartialEq`, or Serde, and
/// requires explicit access through [`Self::expose_secret`]. It does not
/// zeroize arbitrary values; use [`Secret`](crate::Secret) when the value supports [`Zeroize`](zeroize::Zeroize).
///
/// ```
/// use cryptbox::{Seal, SealId, Padding, Plain, Utf8};
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
/// let email = Plain::<UserEmail>::new("user@example.com");
/// assert_eq!(email.expose_secret(), "user@example.com");
/// ```
///
/// A seal with blind indexes is rejected, which the column would not write:
///
/// ```compile_fail,E0271
/// use cryptbox::{
///     BlindIndexError, BlindIndexSpec, Seal, SealId, IndexId, Padding, Plain, Utf8,
/// };
/// use zeroize::Zeroizing;
///
/// struct UserEmail;
///
/// impl Seal for UserEmail {
///     const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Indexes = (EmailLookup,);
/// }
///
/// struct EmailLookup;
///
/// impl BlindIndexSpec for EmailLookup {
///     type Seal = UserEmail;
///     const ID: IndexId = cryptbox::index_id!("2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53");
///     const BITS: u16 = 32;
///     const NORMALIZER: &'static str = "exact/1";
///     type Query = str;
///
///     fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
///         Ok(Zeroizing::new(query.as_bytes().to_vec()))
///     }
///
///     fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
///         Self::normalize_query(value)
///     }
/// }
///
/// let email = Plain::<UserEmail>::new("user@example.com");
/// ```
///
/// Plaintext comparison must also be explicit:
///
/// ```compile_fail,E0369
/// # use cryptbox::{Seal, SealId, Padding, Plain, Utf8};
/// # struct UserEmail;
/// # impl Seal for UserEmail {
/// #     const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Indexes = ();
/// # }
/// let left = Plain::<UserEmail>::new("secret");
/// let right = Plain::<UserEmail>::new("secret");
/// let _ = left == right;
/// ```
///
#[doc = concat!(
    "See the [ownership reference].\n\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
pub struct Plain<F: Seal, K = GlobalKeys> {
    value: F::Value,
    marker: PhantomData<fn() -> (F, K)>,
}

impl<F, K> Plain<F, K>
where
    F: Seal<Indexes = ()>,
{
    /// Wraps a plaintext value.
    ///
    /// Accepts anything convertible into the seal's value type, so a `&str`
    /// can initialize a `String` value.
    pub fn new(value: impl Into<F::Value>) -> Self {
        Self::from_value(value.into())
    }

    const fn from_value(value: F::Value) -> Self {
        Self {
            value,
            marker: PhantomData,
        }
    }

    /// Explicitly exposes the plaintext value.
    #[must_use]
    pub const fn expose_secret(&self) -> &F::Value {
        &self.value
    }

    /// Consumes the wrapper and returns the plaintext value.
    #[must_use]
    pub fn into_inner(self) -> F::Value {
        self.value
    }

    /// Moves this value into the column type that reads its keys from `K2`.
    ///
    /// This moves the plaintext; it neither copies nor reseals it.
    #[must_use]
    pub fn with_column_keys<K2>(self) -> Plain<F, K2> {
        Plain::from_value(self.value)
    }
}

// The automatic SQLx columns seal and open with their keys `K`.
#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
impl<F, K> Plain<F, K>
where
    F: Seal<Indexes = ()>,
    K: crate::ColumnKeys,
{
    pub(crate) fn seal_for_column(&self) -> Result<Sealed<F>, Error> {
        Sealed::seal(&self.value, K::keys()?)
    }

    pub(crate) fn open_column(bytes: Vec<u8>) -> Result<Self, Error> {
        let value = Sealed::<F>::from_bytes(bytes)?.open(K::keys()?)?;

        Ok(Self::from_value(value))
    }
}

impl<F, K> Clone for Plain<F, K>
where
    F: Seal,
    F::Value: Clone,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            marker: PhantomData,
        }
    }
}

impl<F: Seal, K> fmt::Debug for Plain<F, K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Plain([REDACTED])")
    }
}
