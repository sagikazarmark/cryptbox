use std::fmt;

use zeroize::Zeroizing;

use crate::{
    Binding, Ciphertext, Codec, Encrypted, EncryptionKeyProvider, EncryptionProfile, Error,
    value::ProfileContext,
};

/// A permissive read of a stored value that may still hold legacy plaintext.
///
/// This type exists for the bounded window in which a column is being migrated
/// from plaintext to encryption. Classification keys on the envelope magic
/// alone: bytes without it are treated as legacy plaintext and decoded through
/// the profile's codec, while bytes that carry the magic but fail structural
/// validation remain hard errors rather than falling back to plaintext.
///
/// Reads are permissive; writes never are. `MaybeEncrypted` implements no
/// storage `Encode` and no Serde: the only forward path is an [`Encrypted`]
/// value, which always encrypts when stored.
///
/// Legacy binary plaintext that happens to begin with the 4-byte envelope
/// magic is classified as ciphertext and then fails structurally or on
/// authentication — a hard error, never silently wrong data. Stores that
/// reject interior NUL bytes in text cannot produce such values. Deployments
/// holding arbitrary binary legacy data must track encryption state out of
/// band and construct this type through [`Self::from_plaintext`] or
/// [`From<Ciphertext>`](Self::from) instead of byte classification.
///
/// ```
/// use cryptbox::{
///     Encrypted, EncryptionKey, EncryptionProfile, Field, FieldBound,
///     GlobalKeyContext, LocalEncryptionKeyring, Utf8, field_id, key_id,
///     migrate::MaybeEncrypted,
/// };
///
/// struct UserEmail;
/// impl Field for UserEmail {
///     const ID: cryptbox::FieldId =
///         field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const NAME: &'static str = "user-email";
/// }
/// impl EncryptionProfile<String> for UserEmail {
///     type Codec = Utf8;
///     type Binding = FieldBound<Self>;
///     type Keys = GlobalKeyContext;
/// }
///
/// // Fixed key material is for this doctest only; load production keys securely.
/// let keys = LocalEncryptionKeyring::new(
///     EncryptionKey::new(
///         key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50"),
///         [0x42; 32],
///     ),
///     [],
/// )?;
///
/// // A legacy column value without the envelope magic reads as plaintext.
/// let legacy = MaybeEncrypted::<String, UserEmail>::from_bytes(
///     b"mark@example.com".to_vec(),
/// )?;
/// assert!(legacy.is_plaintext());
///
/// // The only forward path is an `Encrypted` value, which always encrypts.
/// let value = legacy.decrypt_with(&(), &keys)?;
/// let stored = value.encrypt_with(&(), &keys)?;
/// let read = MaybeEncrypted::<String, UserEmail>::from_bytes(stored.into_bytes())?;
/// assert!(!read.is_plaintext());
/// # Ok::<(), cryptbox::Error>(())
/// ```
pub struct MaybeEncrypted<T, Profile> {
    state: State<T, Profile>,
}

enum State<T, Profile> {
    Ciphertext(Ciphertext<T, Profile>),
    Plaintext(Encrypted<T, Profile>),
}

impl<T, Profile> MaybeEncrypted<T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    /// Classifies stored bytes as an envelope or legacy plaintext.
    ///
    /// Legacy plaintext is decoded through the profile's codec immediately, in
    /// a zeroizing buffer. Empty input classifies as legacy plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error when bytes carrying the envelope magic are not a
    /// supported, structurally valid envelope, or when legacy plaintext cannot
    /// be decoded by the profile's codec.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();

        match crate::inspect_ciphertext(&bytes) {
            Ok(_) => Ok(Self {
                state: State::Ciphertext(Ciphertext::from_validated_bytes(bytes)),
            }),
            Err(Error::NotCiphertext) => {
                let bytes = Zeroizing::new(bytes);
                let value = <Profile::Codec as Codec<T>>::decode(&bytes)?;

                Ok(Self::from_plaintext(Encrypted::new(value)))
            }
            Err(error) => Err(error),
        }
    }

    /// Wraps a value whose storage is known out of band to hold plaintext.
    pub const fn from_plaintext(value: Encrypted<T, Profile>) -> Self {
        Self {
            state: State::Plaintext(value),
        }
    }

    /// Consumes the read and returns the plaintext value marker.
    ///
    /// A legacy plaintext read is returned directly; an envelope is
    /// authenticated, decrypted, and decoded with the injected provider.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid envelopes, unknown keys, authentication
    /// failure, unavailable providers, or codec failure.
    pub fn decrypt_with(
        self,
        context: &ProfileContext<T, Profile>,
        keys: &dyn EncryptionKeyProvider,
    ) -> Result<Encrypted<T, Profile>, Error> {
        match self.state {
            State::Ciphertext(ciphertext) => ciphertext.decrypt_with(context, keys),
            State::Plaintext(value) => Ok(value),
        }
    }
}

impl<T, Profile> MaybeEncrypted<T, Profile>
where
    Profile: EncryptionProfile<T>,
    Profile::Binding: Binding<Context = ()>,
{
    /// Consumes the read and decrypts with the profile's global key context.
    ///
    /// A legacy plaintext read is returned directly without touching the
    /// providers.
    ///
    /// # Errors
    ///
    /// Returns an error when providers are uninitialized or decryption fails.
    pub fn decrypt(self) -> Result<Encrypted<T, Profile>, Error> {
        match self.state {
            State::Ciphertext(ciphertext) => ciphertext.decrypt(),
            State::Plaintext(value) => Ok(value),
        }
    }
}

impl<T, Profile> MaybeEncrypted<T, Profile> {
    /// Returns whether the stored bytes were classified as legacy plaintext.
    #[must_use]
    pub const fn is_plaintext(&self) -> bool {
        matches!(self.state, State::Plaintext(_))
    }

    /// Returns the envelope when the stored bytes were classified as one.
    #[must_use]
    pub fn as_ciphertext(&self) -> Option<&Ciphertext<T, Profile>> {
        match &self.state {
            State::Ciphertext(ciphertext) => Some(ciphertext),
            State::Plaintext(_) => None,
        }
    }
}

impl<T, Profile> From<Ciphertext<T, Profile>> for MaybeEncrypted<T, Profile> {
    fn from(ciphertext: Ciphertext<T, Profile>) -> Self {
        Self {
            state: State::Ciphertext(ciphertext),
        }
    }
}

impl<T, Profile> fmt::Debug for MaybeEncrypted<T, Profile> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaybeEncrypted([REDACTED])")
    }
}
