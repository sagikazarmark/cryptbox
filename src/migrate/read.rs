use std::fmt;

use zeroize::Zeroizing;

use crate::{
    Binding, Ciphertext, Codec, Encrypted, EncryptionKeyProvider, EncryptionProfile, Error,
    value::ProfileContext,
};

use super::{LegacyFormat, legacy};

/// A permissive read of a stored value that may still use a legacy format.
///
/// This type exists for the bounded window in which a column is being migrated
/// from plaintext or a previous encryption solution. Classification keys on
/// the envelope magic alone: bytes without it are retained in a zeroizing
/// buffer and recovered at decrypt time. Bytes that carry the magic but fail
/// structural validation remain hard errors rather than falling back to a
/// legacy handler.
///
/// [`Self::decrypt_with`] and [`Self::decrypt`] use identity recovery for
/// plaintext-only migrations. [`Self::decrypt_with_legacy`] and
/// [`Self::decrypt_legacy`] first invoke a [`LegacyFormat`] handler for foreign
/// ciphertext. Valid `CryptBox` envelopes ignore the handler.
///
/// Reads are permissive; writes never are. `MaybeEncrypted` implements no
/// storage `Encode` and no Serde: the only forward path is an [`Encrypted`]
/// value, which always encrypts when stored.
///
/// Legacy data that happens to begin with the 4-byte envelope magic is
/// classified as ciphertext and then fails structurally or on authentication,
/// a hard error rather than silently wrong data. Deployments that track the
/// storage format out of band can bypass classification with
/// [`Self::from_legacy_bytes`].
///
/// ```
/// use cryptbox::{
///     Encrypted, EncryptionKey, EncryptionProfile, Field, FieldBound,
///     GlobalKeyContext, LocalEncryptionKeyring, Utf8, field_id, key_id,
///     migrate::{LegacyError, LegacyFormat, MaybeEncrypted},
/// };
/// use zeroize::Zeroizing;
///
/// struct PreviousFormat;
/// impl LegacyFormat for PreviousFormat {
///     fn recover(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, LegacyError> {
///         Ok(Zeroizing::new(
///             bytes.strip_prefix(b"previous:").unwrap_or(bytes).to_vec(),
///         ))
///     }
/// }
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
/// // The handler accepts both plaintext and the previous format.
/// let plaintext = MaybeEncrypted::<String, UserEmail>::from_bytes(
///     b"mark@example.com".to_vec(),
/// )?;
/// assert!(plaintext.is_legacy());
/// assert_eq!(
///     plaintext
///         .decrypt_with_legacy(&(), &keys, &PreviousFormat)?
///         .expose_secret(),
///     "mark@example.com",
/// );
///
/// let foreign = MaybeEncrypted::<String, UserEmail>::from_bytes(
///     b"previous:other@example.com".to_vec(),
/// )?;
/// let value = foreign.decrypt_with_legacy(&(), &keys, &PreviousFormat)?;
/// let stored = value.encrypt_with(&(), &keys)?;
/// let read = MaybeEncrypted::<String, UserEmail>::from_bytes(stored.into_bytes())?;
/// assert!(!read.is_legacy());
/// # Ok::<(), cryptbox::Error>(())
/// ```
pub struct MaybeEncrypted<T, Profile> {
    state: State<T, Profile>,
}

enum State<T, Profile> {
    Ciphertext(Ciphertext<T, Profile>),
    Plaintext(Encrypted<T, Profile>),
    Legacy(Zeroizing<Vec<u8>>),
}

fn decode_legacy<T, Profile>(
    bytes: &[u8],
    legacy: Option<&dyn LegacyFormat>,
) -> Result<Encrypted<T, Profile>, Error>
where
    Profile: EncryptionProfile<T>,
{
    let plaintext = legacy::recover(bytes, legacy)?;
    Ok(Encrypted::new(<Profile::Codec as Codec<T>>::decode(
        &plaintext,
    )?))
}

impl<T, Profile> MaybeEncrypted<T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    /// Classifies stored bytes as a `CryptBox` envelope or legacy data.
    ///
    /// Non-envelope bytes are retained in a zeroizing buffer and decoded when
    /// the value is decrypted. Empty input classifies as legacy data.
    ///
    /// # Errors
    ///
    /// Returns an error when bytes carrying the envelope magic are not a
    /// supported, structurally valid envelope.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();

        match crate::inspect_ciphertext(&bytes) {
            Ok(_) => Ok(Self {
                state: State::Ciphertext(Ciphertext::from_validated_bytes(bytes)),
            }),
            Err(Error::NotCiphertext) => Ok(Self {
                state: State::Legacy(Zeroizing::new(bytes)),
            }),
            Err(error) => Err(error),
        }
    }

    /// Wraps a value whose storage is known out of band to hold plaintext.
    pub const fn from_plaintext(value: Encrypted<T, Profile>) -> Self {
        Self {
            state: State::Plaintext(value),
        }
    }

    /// Wraps bytes known out of band to use a legacy storage format.
    ///
    /// This bypasses envelope classification and is the escape hatch for a
    /// legacy value that begins with the `CryptBox` envelope magic.
    ///
    /// ```
    /// use cryptbox::{EncryptionProfile, GlobalKeyContext, Raw, Unbound};
    /// use cryptbox::migrate::MaybeEncrypted;
    ///
    /// struct LegacyBlob;
    /// impl EncryptionProfile<Vec<u8>> for LegacyBlob {
    ///     type Codec = Raw;
    ///     type Binding = Unbound;
    ///     type Keys = GlobalKeyContext;
    /// }
    ///
    /// // A discriminator column established that these bytes are legacy, even
    /// // though they collide with CryptBox's envelope magic.
    /// let read = MaybeEncrypted::<Vec<u8>, LegacyBlob>::from_legacy_bytes(
    ///     b"CBX\0previous-format".to_vec(),
    /// );
    /// assert!(read.is_legacy());
    /// assert!(read.as_ciphertext().is_none());
    /// ```
    #[must_use]
    pub fn from_legacy_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            state: State::Legacy(Zeroizing::new(bytes.into())),
        }
    }

    /// Consumes the read and returns the plaintext value marker.
    ///
    /// Legacy bytes use identity recovery and decode through the profile's
    /// codec; an envelope is authenticated and decrypted with the provider.
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
            State::Legacy(bytes) => decode_legacy(&bytes, None),
        }
    }

    /// Consumes the read, recovering non-envelope bytes with `legacy` before
    /// decoding them through the profile's codec.
    ///
    /// Valid `CryptBox` envelopes ignore the legacy handler and use the normal
    /// authenticated decryption path.
    ///
    /// # Errors
    ///
    /// Returns an error when legacy recovery, codec decoding, or envelope
    /// decryption fails.
    pub fn decrypt_with_legacy(
        self,
        context: &ProfileContext<T, Profile>,
        keys: &dyn EncryptionKeyProvider,
        legacy: &dyn LegacyFormat,
    ) -> Result<Encrypted<T, Profile>, Error> {
        match self.state {
            State::Ciphertext(ciphertext) => ciphertext.decrypt_with(context, keys),
            State::Plaintext(value) => Ok(value),
            State::Legacy(bytes) => decode_legacy(&bytes, Some(legacy)),
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
    /// Legacy bytes use identity recovery without touching the providers.
    ///
    /// # Errors
    ///
    /// Returns an error when providers are uninitialized, decryption fails, or
    /// legacy bytes cannot be decoded by the profile's codec.
    pub fn decrypt(self) -> Result<Encrypted<T, Profile>, Error> {
        match self.state {
            State::Ciphertext(ciphertext) => ciphertext.decrypt(),
            State::Plaintext(value) => Ok(value),
            State::Legacy(bytes) => decode_legacy(&bytes, None),
        }
    }

    /// Consumes the read and recovers legacy bytes with an explicit handler,
    /// using the profile's global key context for `CryptBox` envelopes.
    ///
    /// # Errors
    ///
    /// Returns an error when legacy recovery, codec decoding, provider lookup,
    /// or envelope decryption fails.
    pub fn decrypt_legacy(self, legacy: &dyn LegacyFormat) -> Result<Encrypted<T, Profile>, Error> {
        match self.state {
            State::Ciphertext(ciphertext) => ciphertext.decrypt(),
            State::Plaintext(value) => Ok(value),
            State::Legacy(bytes) => decode_legacy(&bytes, Some(legacy)),
        }
    }
}

impl<T, Profile> MaybeEncrypted<T, Profile> {
    /// Returns whether the value represents legacy, non-envelope storage.
    #[doc(alias = "is_plaintext")]
    #[must_use]
    pub const fn is_legacy(&self) -> bool {
        matches!(self.state, State::Plaintext(_) | State::Legacy(_))
    }

    /// Returns the envelope when the stored bytes were classified as one.
    #[must_use]
    pub fn as_ciphertext(&self) -> Option<&Ciphertext<T, Profile>> {
        match &self.state {
            State::Ciphertext(ciphertext) => Some(ciphertext),
            State::Plaintext(_) | State::Legacy(_) => None,
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
