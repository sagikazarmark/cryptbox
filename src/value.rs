use std::{fmt, marker::PhantomData};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    Args, BindingDomain, Codec, EncryptionKeySource, Error, Field, FieldOnly, GlobalKeys, KeyId,
    Prepared,
    binding::{domain, domains},
    bound,
    envelope::validated_key_id,
    keys,
};

/// A sealed value of field `F`: an encrypted envelope bound to the field, its
/// binding values, and its record.
///
/// This is what applications store. [`Self::seal`] encodes, pads, and encrypts a
/// value; [`Self::open`] authenticates and decrypts it under the same
/// [binding arguments](Args), and returns the bare [`Field::Value`]. Plaintext
/// hygiene comes from the value type, such as [`Secret`].
///
/// Construction from bytes validates only the envelope structure. Authenticity
/// is established by opening. `F` is not encoded in the envelope, so the type
/// parameter expresses caller intent rather than proving that stored bytes were
/// sealed for that field. With the `serde` feature, this type serializes only
/// the binary envelope; deserialization performs the same structural checks as
/// [`Self::from_bytes`], uses no keys, and leaves the bytes unauthenticated.
///
/// # Examples
///
/// ```
/// use cryptbox::{
///     EncryptionKey, Field, FieldId, FieldOnly, EncryptionKeyring, Padding, Sealed, Utf8,
/// };
///
/// struct UserEmail;
///
/// impl Field for UserEmail {
///     const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = ();
/// }
///
/// let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
///
/// let sealed = Sealed::<UserEmail>::seal(&"user@example.com".into(), (), &keys)?;
/// assert_eq!(sealed.open((), &keys)?, "user@example.com");
/// # Ok::<(), cryptbox::Error>(())
/// ```
pub struct Sealed<F: Field> {
    bytes: Vec<u8>,
    marker: PhantomData<fn() -> F>,
}

impl<F: Field> Sealed<F> {
    /// Validates and wraps a binary `CryptBox` envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not a supported, structurally valid
    /// `CryptBox` envelope. Authentication, binding, and codec compatibility are
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

    /// Encodes and encrypts `value`, binding it to `args`.
    ///
    /// # Errors
    ///
    /// Returns an error when the binding values are invalid, or when encoding,
    /// padding, key lookup, randomness, or encryption fails.
    pub fn seal(
        value: &F::Value,
        args: impl Args<F>,
        keys: &(impl EncryptionKeySource + ?Sized),
    ) -> Result<Self, Error> {
        Self::seal_in(value, &domain(args)?, keys)
    }

    pub(crate) fn seal_in(
        value: &F::Value,
        domain: &BindingDomain,
        keys: &(impl EncryptionKeySource + ?Sized),
    ) -> Result<Self, Error> {
        let plaintext = F::Codec::encode(value)?;
        let sealed = bound::seal(domain, F::PADDING, &plaintext, keys)?;

        Ok(Self::from_validated_bytes(sealed))
    }

    /// Authenticates, decrypts, and decodes this value under `args`.
    ///
    /// Success establishes authenticity under the supplied key, the field `F`,
    /// and the binding values and record in `args`, valid padding, and
    /// successful decoding with the field's codec. Apply application-level
    /// validation separately. This does not establish freshness or consistency
    /// with a separately stored blind index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthenticationFailed`] for another field, other binding
    /// values, another record, or modified bytes, and
    /// [`Error::BindingMismatch`] for a value sealed with another binding declaration.
    /// Also returns an error for invalid binding values, unknown keys,
    /// unavailable keys, invalid padding, or codec failure.
    pub fn open(
        &self,
        args: impl Args<F>,
        keys: &(impl EncryptionKeySource + ?Sized),
    ) -> Result<F::Value, Error> {
        let plaintext = bound::open(&domain(args)?, &self.bytes, keys)?;

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
        args: impl Args<F>,
        keys: &(impl EncryptionKeySource + ?Sized),
    ) -> Result<Prepared<'a, F>, Error> {
        let (domain, index_domain) = domains(args)?;

        Ok(Prepared::new(
            value,
            Self::seal_in(value, &domain, keys)?,
            index_domain,
        ))
    }

    /// Reports whether this envelope differs from what `F` currently writes.
    ///
    /// That is a non-current suite or key, or a padding flag that disagrees
    /// with [`Field::PADDING`].
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
    /// Returns [`Error::BindingMismatch`] for a value sealed with another binding
    /// declaration, or an error for invalid binding values or unavailable keys.
    pub fn needs_reseal(
        &self,
        args: impl Args<F>,
        keys: &(impl EncryptionKeySource + ?Sized),
    ) -> Result<bool, Error> {
        bound::needs_reseal(&domain(args)?, F::PADDING, &self.bytes, keys)
    }

    /// Opens and reseals this value as `F` currently writes it, under the same
    /// binding and keys.
    ///
    /// The rewrite uses the current suite, key, and [`Field::PADDING`],
    /// so a sweep can enable or disable padding. This authenticates the value
    /// and checks padding, but does not decode it with the field's codec or
    /// check any stored blind indexes. Use [`Self::open`] when decoded-value
    /// readability is required.
    ///
    /// # Errors
    ///
    /// Returns any opening, padding, or encryption error.
    pub fn reseal(
        &self,
        args: impl Args<F>,
        keys: &(impl EncryptionKeySource + ?Sized),
    ) -> Result<Self, Error> {
        let domain = domain(args)?;
        let (_, sealed) = bound::reseal((&domain, keys), (&domain, keys), F::PADDING, &self.bytes)?;

        Ok(Self::from_validated_bytes(sealed))
    }

    /// Opens this value under `from` and reseals it under `to`.
    ///
    /// Use this to move a value to other binding values or other keys, such as
    /// moving a record to another workspace or its data to another residency.
    /// Like [`Self::reseal`], it authenticates and checks padding without
    /// decoding the value.
    ///
    /// # Errors
    ///
    /// Returns any opening error under `from`, or padding or encryption error
    /// under `to`.
    pub fn reseal_across(
        &self,
        from: impl Args<F>,
        from_keys: &(impl EncryptionKeySource + ?Sized),
        to: impl Args<F>,
        to_keys: &(impl EncryptionKeySource + ?Sized),
    ) -> Result<Self, Error> {
        let (_, sealed) = bound::reseal(
            (&domain(from)?, from_keys),
            (&domain(to)?, to_keys),
            F::PADDING,
            &self.bytes,
        )?;

        Ok(Self::from_validated_bytes(sealed))
    }
}

// Panics become build errors in `const` context. The process-wide keys and the
// automatic column see no record, so a field that binds one never reaches them.
const fn check_no_record(record: bool) {
    assert!(
        !record,
        "this field binds a record: the installed keys and the automatic column serve only fields without one"
    );
}

impl<F: Field<Binding = FieldOnly>> Sealed<F> {
    /// Seals `value` with the [installed keys](keys::installed).
    ///
    /// This is exactly `Self::seal(value, (), keys::installed()?)`. The
    /// process-wide keys serve only [`FieldOnly`] fields without a record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeysNotInstalled`] before installation, or any error of
    /// [`Self::seal`].
    pub fn seal_global(value: &F::Value) -> Result<Self, Error> {
        const { check_no_record(F::RECORD) };
        Self::seal(value, (), keys::installed()?)
    }

    /// Opens this value with the [installed keys](keys::installed).
    ///
    /// This is exactly `self.open((), keys::installed()?)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeysNotInstalled`] before installation, or any error of
    /// [`Self::open`].
    pub fn open_global(&self) -> Result<F::Value, Error> {
        const { check_no_record(F::RECORD) };
        self.open((), keys::installed()?)
    }
}

impl<F: Field> TryFrom<Vec<u8>> for Sealed<F> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl<F: Field> AsRef<[u8]> for Sealed<F> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<F: Field> Clone for Sealed<F> {
    fn clone(&self) -> Self {
        Self::from_validated_bytes(self.bytes.clone())
    }
}

impl<F: Field> PartialEq for Sealed<F> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<F: Field> Eq for Sealed<F> {}

impl<F: Field> fmt::Debug for Sealed<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sealed([REDACTED])")
    }
}

/// A plaintext value of field `F` that an automatic `SQLx` column seals on
/// encode and opens on decode.
///
/// A column decoder sees neither a row nor a scope, so `Plain` serves only
/// [`FieldOnly`] fields without a record or blind indexes: its constructors
/// and column impls require `F::Binding = FieldOnly` and `F::Indexes = ()`, and a
/// field that binds a record fails the build.
/// Seal every other field explicitly with [`Sealed`].
///
/// `K` is the column's key source. The default, [`GlobalKeys`], reads the keys
/// installed with [`keys::install`]; name another
/// [`KeyContext`](crate::KeyContext) to use application-owned keys instead.
///
/// `Plain` contains plaintext while it is in application memory. It redacts
/// `Debug`, does not implement `Display`, `Deref`, `PartialEq`, or Serde, and
/// requires explicit access through [`Self::expose_secret`]. It does not
/// zeroize arbitrary values; use [`Secret`] when the value supports [`Zeroize`].
///
/// ```
/// use cryptbox::{Field, FieldId, FieldOnly, Padding, Plain, Utf8};
///
/// struct UserEmail;
///
/// impl Field for UserEmail {
///     const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = ();
/// }
///
/// let email = Plain::<UserEmail>::new("user@example.com");
/// assert_eq!(email.expose_secret(), "user@example.com");
/// ```
///
/// A bound field is rejected:
///
/// ```compile_fail,E0271
/// use cryptbox::{Field, FieldId, Padding, Plain, Tenant, Utf8};
///
/// struct CustomerEmail;
///
/// impl Field for CustomerEmail {
///     const ID: FieldId = cryptbox::field_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = Tenant;
///     type Indexes = ();
/// }
///
/// let email = Plain::<CustomerEmail>::new("user@example.com");
/// ```
///
/// So is a field with blind indexes, which the column would not write:
///
/// ```compile_fail,E0271
/// use cryptbox::{
///     BlindIndexError, BlindIndexSpec, Field, FieldId, FieldOnly, IndexId, Padding, Plain, Utf8,
/// };
/// use zeroize::Zeroizing;
///
/// struct UserEmail;
///
/// impl Field for UserEmail {
///     const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = (EmailLookup,);
/// }
///
/// struct EmailLookup;
///
/// impl BlindIndexSpec for EmailLookup {
///     type Field = UserEmail;
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
/// And a field that binds a record fails the build:
///
/// ```compile_fail,E0080
/// # use cryptbox::{Field, FieldId, FieldOnly, Padding, Plain, Utf8};
/// struct RowNote;
///
/// impl Field for RowNote {
///     const ID: FieldId = cryptbox::field_id!("9e2d4b71-3c8a-4f05-b6e1-7a0c5d3f8b24");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = true;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = ();
/// }
///
/// let note = Plain::<RowNote>::new("note");
/// ```
///
/// Plaintext comparison must also be explicit:
///
/// ```compile_fail,E0369
/// # use cryptbox::{Field, FieldId, FieldOnly, Padding, Plain, Utf8};
/// # struct UserEmail;
/// # impl Field for UserEmail {
/// #     const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = false;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Binding = FieldOnly;
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
pub struct Plain<F: Field, K = GlobalKeys> {
    value: F::Value,
    marker: PhantomData<fn() -> (F, K)>,
}

impl<F, K> Plain<F, K>
where
    F: Field<Binding = FieldOnly, Indexes = ()>,
{
    /// Wraps a plaintext value.
    ///
    /// Accepts anything convertible into the field's value type, so a `&str`
    /// can initialize a `String` field.
    pub fn new(value: impl Into<F::Value>) -> Self {
        Self::from_value(value.into())
    }

    const fn from_value(value: F::Value) -> Self {
        const { check_no_record(F::RECORD) };
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

    /// Moves this value into the column type of another key context.
    ///
    /// This moves the plaintext; it neither copies nor reseals it.
    #[must_use]
    pub fn with_key_context<K2>(self) -> Plain<F, K2> {
        Plain::from_value(self.value)
    }
}

// The automatic SQLx columns seal and open with their key source `K`.
#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
impl<F, K> Plain<F, K>
where
    F: Field<Binding = FieldOnly, Indexes = ()>,
    K: crate::KeyContext,
{
    pub(crate) fn seal_for_column(&self) -> Result<Sealed<F>, Error> {
        Sealed::seal(&self.value, (), K::keys()?)
    }

    pub(crate) fn open_column(bytes: Vec<u8>) -> Result<Self, Error> {
        let value = Sealed::<F>::from_bytes(bytes)?.open((), K::keys()?)?;

        Ok(Self::from_value(value))
    }
}

impl<F, K> Clone for Plain<F, K>
where
    F: Field,
    F::Value: Clone,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            marker: PhantomData,
        }
    }
}

impl<F: Field, K> fmt::Debug for Plain<F, K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Plain([REDACTED])")
    }
}

/// Plaintext with zeroization on drop and explicit access semantics.
///
/// Drop invokes `T`'s [`Zeroize`] implementation. Cloning creates a separate `T`
/// with its own lifetime; it does not share a single erasure boundary. This cannot
/// erase previous copies, superseded allocations, or OS copies. For an opened
/// `String`, use `Secret::new(sealed.open(args, keys)?)`.
/// A field can also store `Secret<String>` or `Secret<Vec<u8>>` directly: their
/// [`crate::Plaintext`] codecs ([`crate::Utf8`], [`crate::Raw`]) write the same bytes.
/// See the [custom-field example] and [ownership reference].
///
#[doc = concat!(
    "[custom-field example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_field/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
pub struct Secret<T: Zeroize> {
    value: Zeroizing<T>,
}

impl<T: Zeroize> Secret<T> {
    /// Wraps plaintext that will be zeroized on drop.
    pub fn new(value: T) -> Self {
        Self {
            value: Zeroizing::new(value),
        }
    }

    /// Explicitly exposes the plaintext value.
    #[must_use]
    pub fn expose_secret(&self) -> &T {
        &self.value
    }
}

impl<T: Clone + Zeroize> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self::new((*self.value).clone())
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}
