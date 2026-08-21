use std::{fmt, marker::PhantomData};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    Binding, Codec, EncryptionKeyProvider, EncryptionProfile, Error, KeyContext, decrypt, encrypt,
    needs_reencryption, reencrypt,
};

/// The runtime binding context selected by an encryption profile.
pub type ProfileContext<T, Profile> =
    <<Profile as EncryptionProfile<T>>::Binding as Binding>::Context;

/// A plaintext application value that must be encrypted at storage boundaries.
///
/// This type contains plaintext while it is in application memory. It redacts
/// `Debug`, does not implement `Display` or `Deref`, and requires explicit
/// access through [`Self::expose_secret`]. It does not zeroize arbitrary `T`;
/// use [`Secret`] when the application value supports [`Zeroize`].
pub struct Encrypted<T, Profile> {
    value: T,
    profile: PhantomData<fn() -> Profile>,
}

impl<T, Profile> Encrypted<T, Profile> {
    /// Wraps a plaintext application value.
    pub const fn new(value: T) -> Self {
        Self {
            value,
            profile: PhantomData,
        }
    }

    /// Explicitly exposes the plaintext application value.
    #[must_use]
    pub const fn expose_secret(&self) -> &T {
        &self.value
    }

    /// Consumes the wrapper and returns the plaintext application value.
    #[must_use]
    pub fn into_secret(self) -> T {
        self.value
    }
}

impl<T: Clone, Profile> Clone for Encrypted<T, Profile> {
    fn clone(&self) -> Self {
        Self::new(self.value.clone())
    }
}

impl<T: PartialEq, Profile> PartialEq for Encrypted<T, Profile> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq, Profile> Eq for Encrypted<T, Profile> {}

impl<T, Profile> From<T> for Encrypted<T, Profile> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T, Profile> fmt::Debug for Encrypted<T, Profile> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Encrypted([REDACTED])")
    }
}

/// An encrypted envelope with phantom plaintext and profile types.
///
/// Construction validates only the envelope structure. Authenticity is
/// established by decryption. `T` and `Profile` are not encoded in the envelope,
/// so the type parameters express caller intent rather than proving that stored
/// bytes were created for that profile.
pub struct Ciphertext<T, Profile> {
    bytes: Vec<u8>,
    marker: PhantomData<fn() -> (T, Profile)>,
}

impl<T, Profile> Ciphertext<T, Profile> {
    /// Validates and wraps a binary `CryptBox` envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not a supported, structurally valid
    /// `CryptBox` envelope. Authentication, profile binding, and codec
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

impl<T, Profile> Clone for Ciphertext<T, Profile> {
    fn clone(&self) -> Self {
        Self::from_validated_bytes(self.bytes.clone())
    }
}

impl<T, Profile> PartialEq for Ciphertext<T, Profile> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<T, Profile> Eq for Ciphertext<T, Profile> {}

impl<T, Profile> fmt::Debug for Ciphertext<T, Profile> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ciphertext([REDACTED])")
    }
}

impl<T, Profile> Encrypted<T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    /// Encodes and encrypts this value with an explicitly injected provider.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding, key lookup, randomness, or encryption
    /// fails.
    pub fn encrypt_with(
        &self,
        context: &ProfileContext<T, Profile>,
        keys: &dyn EncryptionKeyProvider,
    ) -> Result<Ciphertext<T, Profile>, Error> {
        let plaintext = Profile::Codec::encode(&self.value)?;
        let ciphertext = encrypt::<Profile::Binding>(&plaintext, context, keys)?;
        Ok(Ciphertext::from_validated_bytes(ciphertext))
    }
}

impl<T, Profile> Encrypted<T, Profile>
where
    Profile: EncryptionProfile<T>,
    Profile::Binding: Binding<Context = ()>,
{
    /// Encodes and encrypts this value with the profile's global key context.
    ///
    /// # Errors
    ///
    /// Returns an error when providers are uninitialized or when encoding or
    /// encryption fails.
    pub fn encrypt(&self) -> Result<Ciphertext<T, Profile>, Error> {
        self.encrypt_with(&(), Profile::Keys::encryption_keys()?)
    }
}

impl<T, Profile> Ciphertext<T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    /// Authenticates, decrypts, and decodes this value with an injected provider.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid envelopes, unknown keys, authentication
    /// failure, unavailable providers, or codec failure.
    pub fn decrypt_with(
        &self,
        context: &ProfileContext<T, Profile>,
        keys: &dyn EncryptionKeyProvider,
    ) -> Result<Encrypted<T, Profile>, Error> {
        let plaintext = decrypt::<Profile::Binding>(&self.bytes, context, keys)?;
        let value = Profile::Codec::decode(&plaintext)?;
        Ok(Encrypted::new(value))
    }

    /// Reports whether this envelope uses a non-current suite or key.
    ///
    /// Envelope metadata is unauthenticated until decryption succeeds.
    /// See the complete [key-rotation example].
    ///
    /// [key-rotation example]: https://docs.rs/crate/cryptbox/latest/source/examples/key_rotation.rs
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid envelope or unavailable provider.
    pub fn needs_reencryption_with(&self, keys: &dyn EncryptionKeyProvider) -> Result<bool, Error> {
        needs_reencryption(&self.bytes, keys)
    }

    /// Decrypts and rewrites this envelope with the active suite and current key.
    ///
    /// # Errors
    ///
    /// Returns any decryption or encryption error.
    pub fn reencrypt_with(
        &self,
        context: &ProfileContext<T, Profile>,
        keys: &dyn EncryptionKeyProvider,
    ) -> Result<Self, Error> {
        reencrypt::<Profile::Binding>(&self.bytes, context, keys).map(Self::from_validated_bytes)
    }
}

impl<T, Profile> Ciphertext<T, Profile>
where
    Profile: EncryptionProfile<T>,
    Profile::Binding: Binding<Context = ()>,
{
    /// Decrypts this value with the profile's global key context.
    ///
    /// # Errors
    ///
    /// Returns an error when providers are uninitialized or decryption fails.
    pub fn decrypt(&self) -> Result<Encrypted<T, Profile>, Error> {
        self.decrypt_with(&(), Profile::Keys::encryption_keys()?)
    }
}

/// Plaintext with zeroization on drop and explicit access semantics.
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
