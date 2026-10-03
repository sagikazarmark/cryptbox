use std::{fmt, marker::PhantomData};

use crate::{
    Codec, Context, ContextKind, EncryptionKeys, Error, GlobalKeys, KeyId, Prepared, Seal, bound,
    envelope::validated_key_id,
    keys,
    seal_context::{self, SealContext},
};

/// A value sealed with seal `F` in context `C`: an encrypted envelope bound to
/// the seal and, in a [`Context`], to the context's value.
///
/// This is what applications store. [`Self::seal`] encodes, pads, and encrypts a
/// value; [`Self::open`] authenticates and decrypts it, and returns the bare
/// [`Seal::Value`]. Plaintext
/// hygiene comes from the value type, such as [`Secret`](crate::Secret).
///
/// `C` is the context besides the seal ID: `()`, the default, for a standalone
/// value, or a [`Context`], such as [`InRecord`](crate::InRecord) for a record's
/// field. A value in a context is sealed with [`Self::seal_in`] and opened with
/// [`Self::open_in`], which take the context's value, such as the record ID;
/// `#[derive(Record)]` calls them for its sealed fields. A value fails to open in
/// another context, with [`Error::ContextMismatch`], or with another value.
///
/// Construction from bytes validates only the envelope structure. Authenticity
/// is established by opening. Neither `F` nor `C` is encoded in the envelope, so
/// the type parameters express caller intent rather than proving that stored
/// bytes were sealed with that seal. With the `serde` feature, this type
/// serializes only the binary envelope; deserialization performs the same
/// structural checks as [`Self::from_bytes`], uses no keys, and leaves the bytes
/// unauthenticated.
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
pub struct Sealed<F: Seal, C = ()> {
    bytes: Vec<u8>,
    marker: PhantomData<fn() -> (F, C)>,
}

impl<F: Seal, C> Sealed<F, C> {
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

    fn seal_under(
        value: &F::Value,
        context: &SealContext,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Self, Error> {
        let plaintext = F::Codec::encode(value)?;
        let sealed = bound::seal(context, F::PADDING, &plaintext, keys.encryption_keyring())?;

        Ok(Self::from_validated_bytes(sealed))
    }

    fn open_under(
        &self,
        context: &SealContext,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<F::Value, Error> {
        let plaintext = bound::open(context, &self.bytes, keys.encryption_keyring())?;

        Ok(F::Codec::decode(&plaintext)?)
    }

    fn reseal_under(
        &self,
        context: &SealContext,
        from_keys: &(impl EncryptionKeys + ?Sized),
        to_keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Self, Error> {
        let (_, sealed) = bound::reseal(
            (context, from_keys.encryption_keyring()),
            (context, to_keys.encryption_keyring()),
            F::PADDING,
            &self.bytes,
        )?;

        Ok(Self::from_validated_bytes(sealed))
    }
}

impl<F: Seal, C: ContextKind> Sealed<F, C> {
    /// Reports whether this envelope differs from what `F` currently writes.
    ///
    /// That is a non-current suite or key, or a padding flag that disagrees
    /// with [`Seal::PADDING`]. It needs no context value: it compares the
    /// context's kind, never its value.
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
            seal_context::fingerprint(C::RECORD),
            F::PADDING,
            &self.bytes,
            keys.encryption_keyring(),
        )
    }
}

impl<F: Seal> Sealed<F> {
    /// Encodes and encrypts `value`, bound to the seal.
    ///
    /// The value is standalone: it opens with [`Self::open`], and not in a
    /// [`Context`]. A record field's value is sealed by its record, with
    /// [`Record::seal`](crate::Record::seal), or with [`Self::seal_in`]; sealed
    /// here, it fails to open as the record's.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding, padding, key lookup, randomness, or
    /// encryption fails.
    pub fn seal(value: &F::Value, keys: &(impl EncryptionKeys + ?Sized)) -> Result<Self, Error> {
        Self::seal_under(value, &SealContext::standalone::<F>(), keys)
    }

    /// Authenticates, decrypts, and decodes this value.
    ///
    /// Success establishes authenticity under the supplied key and the seal `F`,
    /// valid padding, and successful decoding with the seal's codec. Apply
    /// application-level validation separately. This does not establish
    /// freshness or consistency with a separately stored blind index. A record
    /// field's value is opened by its record, with
    /// [`Record::open`](crate::Record::open), or with [`Self::open_in`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthenticationFailed`] for another seal or modified
    /// bytes, and [`Error::ContextMismatch`] for a value sealed in a
    /// [`Context`], such as a record field's. Also returns an error for unknown
    /// keys, unavailable keys, invalid padding, or codec failure.
    pub fn open(&self, keys: &(impl EncryptionKeys + ?Sized)) -> Result<F::Value, Error> {
        self.open_under(&SealContext::standalone::<F>(), keys)
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
        self.reseal_under(&SealContext::standalone::<F>(), from_keys, to_keys)
    }

    /// Seals `value` with the [installed keys](keys::installed).
    ///
    /// This is exactly `Self::seal(value, keys::installed()?)`. The
    /// process-wide keys serve only standalone values.
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

impl<F: Seal, C: Context> Sealed<F, C> {
    /// Encodes and encrypts `value`, bound to the seal and to `context`, the
    /// value of context `C`, such as a record ID.
    ///
    /// `#[derive(Record)]` seals its fields with this, under the record's ID:
    /// prefer [`Record::seal`](crate::Record::seal) for a whole record.
    ///
    /// ```
    /// use cryptbox::{
    ///     EncryptionKey, EncryptionKeyring, Error, InRecord, Padding, Seal, SealId, Sealed, Utf8,
    /// };
    ///
    /// struct CustomerEmail;
    ///
    /// impl Seal for CustomerEmail {
    ///     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
    ///     const PADDING: Padding = Padding::NONE;
    ///     type Value = String;
    ///     type Codec = Utf8;
    ///     type Indexes = ();
    /// }
    ///
    /// let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
    /// let email = "ada@example.com".to_owned();
    ///
    /// // The field of the record whose ID is 7.
    /// let sealed = Sealed::<CustomerEmail, InRecord<i64>>::seal_in(&email, &7, &keys)?;
    ///
    /// assert_eq!(sealed.open_in(&7, &keys)?, email);
    /// assert!(matches!(sealed.open_in(&8, &keys), Err(Error::AuthenticationFailed)));
    /// # Ok::<(), cryptbox::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when encoding, padding, key lookup, randomness, or
    /// encryption fails, or for a bytes record ID longer than `u32::MAX` bytes.
    pub fn seal_in(
        value: &F::Value,
        context: &C::Value,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Self, Error> {
        Self::seal_under(value, &SealContext::of::<F, C>(context)?, keys)
    }

    /// Authenticates, decrypts, and decodes this value under `context`, the
    /// value of context `C`, such as the record ID the row stores.
    ///
    /// Read `context` from where the value is stored, never from the request
    /// that asks for it: opening proves the value was sealed with it, not that
    /// the caller may read it. [`Record::open`](crate::Record::open) opens a
    /// whole record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthenticationFailed`] for another seal, another
    /// context value, or modified bytes, and [`Error::ContextMismatch`] for a
    /// value sealed in another kind of context, such as a standalone value.
    /// Also returns any error of [`Sealed::open`].
    pub fn open_in(
        &self,
        context: &C::Value,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<F::Value, Error> {
        self.open_under(&SealContext::of::<F, C>(context)?, keys)
    }

    /// Seals `value` in `context` into a prepared storage representation that
    /// blind indexes can be added to.
    ///
    /// Indexes are derived under their seal alone, as for [`Sealed::prepare`].
    ///
    /// # Errors
    ///
    /// Returns any error of [`Self::seal_in`].
    pub fn prepare_in<'a>(
        value: &'a F::Value,
        context: &C::Value,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Prepared<'a, F, C>, Error> {
        Ok(Prepared::new(value, Self::seal_in(value, context, keys)?))
    }

    /// Opens and reseals this value in `context` as `F` currently writes it,
    /// with the same keys, as [`Sealed::reseal`] does.
    ///
    /// # Errors
    ///
    /// Returns any opening, padding, or encryption error.
    pub fn reseal_in(
        &self,
        context: &C::Value,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Self, Error> {
        self.reseal_across_in(context, keys, keys)
    }

    /// Opens this value in `context` with `from_keys` and reseals it with
    /// `to_keys`, as [`Sealed::reseal_across`] does.
    ///
    /// # Errors
    ///
    /// Returns any opening error with `from_keys`, or padding or encryption
    /// error with `to_keys`.
    pub fn reseal_across_in(
        &self,
        context: &C::Value,
        from_keys: &(impl EncryptionKeys + ?Sized),
        to_keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Self, Error> {
        self.reseal_under(&SealContext::of::<F, C>(context)?, from_keys, to_keys)
    }
}

impl<F: Seal, C> TryFrom<Vec<u8>> for Sealed<F, C> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

// Stores the envelope through `Vec<u8>`, as an ORM's `serialize_as` does.
impl<F: Seal, C> From<Sealed<F, C>> for Vec<u8> {
    fn from(sealed: Sealed<F, C>) -> Self {
        sealed.into_bytes()
    }
}

impl<F: Seal, C> AsRef<[u8]> for Sealed<F, C> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<F: Seal, C> Clone for Sealed<F, C> {
    fn clone(&self) -> Self {
        Self::from_validated_bytes(self.bytes.clone())
    }
}

impl<F: Seal, C> PartialEq for Sealed<F, C> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<F: Seal, C> Eq for Sealed<F, C> {}

impl<F: Seal, C> fmt::Debug for Sealed<F, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sealed([REDACTED])")
    }
}

/// A plaintext value of seal `F` that an automatic `SQLx` column seals on
/// encode and opens on decode.
///
/// A column decoder does not see the row, so `Plain` serves only standalone
/// values of seals without blind indexes, `F::Indexes = ()`: it seals and opens
/// them as [`Sealed<F>`]. Use [`Sealed`] explicitly for every other seal, and
/// for a value in a [`Context`], such as a record's field.
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
