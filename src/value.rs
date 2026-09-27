use std::{fmt, marker::PhantomData};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    Codec, EncryptionKeyProvider, Error, Field, GlobalKeyContext, KeyContext, decrypt, encrypt,
    needs_reencryption,
};

/// A plaintext application value that must be encrypted at storage boundaries.
///
/// This type contains plaintext while it is in application memory. It redacts
/// `Debug`, does not implement `Display` or `Deref`, and requires explicit
/// access through [`Self::expose_secret`]. It does not zeroize arbitrary values;
/// use [`Secret`] when the application value supports [`Zeroize`].
/// It deliberately has no Serde implementation: encrypt to [`Ciphertext`] before
/// serialization, then deserialize and decrypt explicitly when reading.
/// Encryption/preparation borrows and retains this source. Cloning clones the
/// value, potentially creating another plaintext allocation; decryption creates
/// another owned value. See the [ownership reference].
///
/// The field selects the value type: `Encrypted<UserEmail>` contains the
/// `String` declared by `UserEmail`.
///
/// ```
/// use cryptbox::{Field, FieldId, Padding, Utf8};
///
/// struct UserEmail;
///
/// impl Field for UserEmail {
///     const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
/// }
///
/// let email = cryptbox::Encrypted::<UserEmail>::new("user@example.com");
/// let plaintext: &String = email.expose_secret();
/// assert_eq!(plaintext, "user@example.com");
/// ```
///
/// Plaintext comparison must also be explicit:
///
/// ```compile_fail
/// use cryptbox::{Field, FieldId, Padding, Utf8};
///
/// struct UserEmail;
///
/// impl Field for UserEmail {
///     const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
/// }
///
/// let left = cryptbox::Encrypted::<UserEmail>::new("secret");
/// let right = cryptbox::Encrypted::<UserEmail>::new("secret");
/// let _ = left == right;
/// ```
///
#[doc = concat!(
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
pub struct Encrypted<F: Field> {
    value: F::Value,
    field: PhantomData<fn() -> F>,
}

impl<F: Field> Encrypted<F> {
    /// Wraps a plaintext application value.
    ///
    /// Accepts anything convertible into the field's value type, so a `&str`
    /// can initialize a `String` field.
    pub fn new(value: impl Into<F::Value>) -> Self {
        Self::from_value(value.into())
    }

    pub(crate) const fn from_value(value: F::Value) -> Self {
        Self {
            value,
            field: PhantomData,
        }
    }

    /// Explicitly exposes the plaintext application value.
    #[must_use]
    pub const fn expose_secret(&self) -> &F::Value {
        &self.value
    }

    /// Consumes the wrapper and returns the plaintext application value.
    ///
    /// The name does not mean it creates a [`Secret`]. For a decoded `String`,
    /// use `Secret::new(decrypted.into_secret())` to move it into zeroizing ownership.
    #[must_use]
    pub fn into_secret(self) -> F::Value {
        self.value
    }
}

impl<F> Clone for Encrypted<F>
where
    F: Field,
    F::Value: Clone,
{
    fn clone(&self) -> Self {
        Self::from_value(self.value.clone())
    }
}

impl<F: Field> fmt::Debug for Encrypted<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Encrypted([REDACTED])")
    }
}

/// An encrypted envelope with a phantom field type.
///
/// Construction validates only the envelope structure. Authenticity is
/// established by decryption. `F` is not encoded in the envelope, so the
/// type parameter expresses caller intent rather than proving that stored bytes
/// were created for that field. With the `serde` feature, this type
/// serializes only the binary envelope. [`Encrypted`] deliberately has no Serde
/// implementation because it contains plaintext.
/// Deserialization performs the same structural checks as [`Self::from_bytes`];
/// it uses no keys and leaves the bytes and their metadata unauthenticated.
pub struct Ciphertext<F: Field> {
    bytes: Vec<u8>,
    marker: PhantomData<fn() -> F>,
}

impl<F: Field> Ciphertext<F> {
    /// Validates and wraps a binary `CryptBox` envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not a supported, structurally valid
    /// `CryptBox` envelope. Authentication, field binding, and codec
    /// compatibility are deferred until decryption.
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

    /// Returns the binary ciphertext envelope.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the typed wrapper and returns the binary envelope.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl<F: Field> TryFrom<Vec<u8>> for Ciphertext<F> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl<F: Field> AsRef<[u8]> for Ciphertext<F> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<F: Field> Clone for Ciphertext<F> {
    fn clone(&self) -> Self {
        Self::from_validated_bytes(self.bytes.clone())
    }
}

impl<F: Field> PartialEq for Ciphertext<F> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<F: Field> Eq for Ciphertext<F> {}

impl<F: Field> fmt::Debug for Ciphertext<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ciphertext([REDACTED])")
    }
}

impl<F: Field> Encrypted<F> {
    /// Encodes and encrypts this value with an explicitly injected provider.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding, padding, key lookup, randomness, or
    /// encryption fails.
    pub fn encrypt_with(&self, keys: &dyn EncryptionKeyProvider) -> Result<Ciphertext<F>, Error> {
        let plaintext = F::Codec::encode(&self.value)?;
        let plaintext = F::PADDING.pad(plaintext)?;
        let ciphertext = encrypt(F::ID, &plaintext, keys)?;

        Ok(Ciphertext::from_validated_bytes(ciphertext))
    }

    /// Encodes and encrypts this value with the process-wide [`GlobalKeyContext`].
    ///
    /// # Errors
    ///
    /// Returns an error when providers are uninitialized or when encoding or
    /// encryption fails.
    pub fn encrypt(&self) -> Result<Ciphertext<F>, Error> {
        self.encrypt_with(GlobalKeyContext::encryption_keys()?)
    }
}

impl<F: Field> Ciphertext<F> {
    /// Authenticates, decrypts, and decodes this value with an injected provider.
    ///
    /// Success establishes ciphertext authenticity under the supplied key and
    /// the field `F`, valid padding, and successful decoding with the
    /// selected codec. Apply application-level validation separately. This does
    /// not establish freshness, row identity, or consistency with a separately
    /// stored blind index.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid envelopes, unknown keys, authentication
    /// failure, unavailable providers, invalid padding, or codec failure.
    pub fn decrypt_with(&self, keys: &dyn EncryptionKeyProvider) -> Result<Encrypted<F>, Error> {
        let plaintext = decrypt(F::ID, &self.bytes, keys)?;
        let plaintext = F::PADDING.unpad(plaintext)?;
        let value = F::Codec::decode(&plaintext)?;

        Ok(Encrypted::from_value(value))
    }

    /// Decrypts this value with the process-wide [`GlobalKeyContext`].
    ///
    /// # Errors
    ///
    /// Returns an error when providers are uninitialized or decryption fails.
    pub fn decrypt(&self) -> Result<Encrypted<F>, Error> {
        self.decrypt_with(GlobalKeyContext::encryption_keys()?)
    }

    /// Reports whether this envelope uses a non-current suite or key.
    ///
    /// Envelope metadata is unauthenticated until decryption succeeds.
    /// A `false` result does not establish authenticated readability or codec validity.
    /// See the complete [key-rotation example] and [maintenance sweep example].
    ///
    #[doc = concat!(
        "[key-rotation example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/key_rotation.rs\n",
        "[maintenance sweep example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/reencryption_sweep.rs",
    )]
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed or unsupported envelope, or unavailable
    /// provider.
    pub fn needs_reencryption_with(&self, keys: &dyn EncryptionKeyProvider) -> Result<bool, Error> {
        needs_reencryption(F::ID, &self.bytes, keys)
    }

    /// Decrypts and rewrites this envelope with the active suite and current key.
    ///
    /// This authenticates the ciphertext and checks padding, but does not decode
    /// the value with the field's codec or check any stored blind indexes.
    /// Use [`Self::decrypt_with`] when decoded-value readability is required.
    ///
    /// # Errors
    ///
    /// Returns any decryption, padding, or encryption error.
    pub fn reencrypt_with(&self, keys: &dyn EncryptionKeyProvider) -> Result<Self, Error> {
        let plaintext = decrypt(F::ID, &self.bytes, keys)?;
        let plaintext = F::PADDING.unpad(plaintext)?;
        let plaintext = F::PADDING.pad(plaintext)?;

        encrypt(F::ID, &plaintext, keys).map(Self::from_validated_bytes)
    }
}

/// Plaintext with zeroization on drop and explicit access semantics.
///
/// Drop invokes `T`'s [`Zeroize`] implementation. Cloning creates a separate `T`
/// with its own lifetime; it does not share a single erasure boundary. This cannot
/// erase previous copies, superseded allocations, or OS copies. For a decrypted
/// `Encrypted<F>` over `String`, use `Secret::new(decrypted.into_secret())`.
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
