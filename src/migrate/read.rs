use std::fmt;

use zeroize::Zeroizing;

use crate::{Args, Codec, EncryptionKeys, Error, Seal, Sealed};

use super::{LegacyFormat, legacy};

/// A permissive read of a stored value that may still use a legacy format.
///
/// This type exists for the bounded window in which a column is being migrated
/// from plaintext or a previous encryption solution. Classification keys on
/// the envelope magic alone: bytes without it are retained in a zeroizing
/// buffer and recovered at decrypt time. Bytes that carry the magic but fail
/// structural validation remain hard errors rather than falling back to a
/// legacy handler.
/// Construction and `SQLx` decoding only classify structure; ciphertext and its
/// metadata remain unauthenticated until decryption succeeds. Identity recovery
/// of legacy plaintext does not establish authenticity, and re-encrypting it
/// cannot retroactively establish its provenance.
///
/// [`Self::open`] and [`Self::open_global`] use identity recovery for
/// plaintext-only migrations. [`Self::open_legacy`] and
/// [`Self::open_global_legacy`] first invoke a [`LegacyFormat`] handler for foreign
/// ciphertext. Valid `CryptBox` envelopes ignore the handler.
///
/// Reads are permissive; writes never are. `MaybeEncrypted` implements no
/// storage `Encode` and no Serde: the only forward path is the opened value,
/// which is sealed again with [`Sealed::seal`].
///
/// Legacy data that happens to begin with the 4-byte envelope magic is
/// classified as ciphertext and then fails structurally or on authentication,
/// a hard error rather than silently wrong data. Deployments that track the
/// storage format out of band can bypass classification with
/// [`Self::from_legacy_bytes`].
///
/// ```
/// use cryptbox::{
///     EncryptionKey, EncryptionKeyring, Sealed, key_id,
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
///
/// impl cryptbox::Seal for UserEmail {
///     const ID: cryptbox::SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: cryptbox::Padding = cryptbox::Padding::NONE;
///     type Value = String;
///     type Codec = cryptbox::Utf8;
///     type Record = ();
///     type Indexes = ();
/// }
///
/// // Fixed key material is for this doctest only; load production keys securely.
/// let keys = EncryptionKeyring::new(
///     EncryptionKey::new(
///         key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50"),
///         [0x42; 32],
///     ),
///     [],
/// )?;
///
/// // The handler accepts both plaintext and the previous format.
/// let plaintext = MaybeEncrypted::<UserEmail>::from_bytes(
///     b"mark@example.com".to_vec(),
/// )?;
/// assert!(plaintext.is_legacy());
/// assert_eq!(
///     plaintext
///         .open_legacy((), &keys, &PreviousFormat)?,
///     "mark@example.com",
/// );
///
/// let foreign = MaybeEncrypted::<UserEmail>::from_bytes(
///     b"previous:other@example.com".to_vec(),
/// )?;
/// let value = foreign.open_legacy((), &keys, &PreviousFormat)?;
/// let stored = Sealed::<UserEmail>::seal(&value, (), &keys)?;
/// let read = MaybeEncrypted::<UserEmail>::from_bytes(stored.into_bytes())?;
/// assert!(!read.is_legacy());
/// # Ok::<(), cryptbox::Error>(())
/// ```
pub struct MaybeEncrypted<F: Seal> {
    state: State<F>,
}

enum State<F: Seal> {
    Sealed(Sealed<F>),
    Plaintext(F::Value),
    Legacy(Zeroizing<Vec<u8>>),
}

fn decode_legacy<F: Seal>(
    bytes: &[u8],
    legacy: Option<&dyn LegacyFormat>,
) -> Result<F::Value, Error> {
    let plaintext = legacy::recover(bytes, legacy)?;
    Ok(F::Codec::decode(&plaintext)?)
}

impl<F> MaybeEncrypted<F>
where
    F: Seal,
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
                state: State::Sealed(Sealed::from_validated_bytes(bytes)),
            }),
            Err(Error::NotCiphertext) => Ok(Self {
                state: State::Legacy(Zeroizing::new(bytes)),
            }),
            Err(error) => Err(error),
        }
    }

    /// Wraps a value whose storage is known out of band to hold plaintext.
    pub const fn from_plaintext(value: F::Value) -> Self {
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
    /// use cryptbox::migrate::MaybeEncrypted;
    ///
    /// struct LegacyBlob;
    ///
    /// impl cryptbox::Seal for LegacyBlob {
    ///     const ID: cryptbox::SealId = cryptbox::seal_id!("3f0e8f5c-2d4b-4e7a-9c1d-6b5a4f3e2d1c");
    ///     const PADDING: cryptbox::Padding = cryptbox::Padding::NONE;
    ///     type Value = Vec<u8>;
    ///     type Codec = cryptbox::Raw;
    ///     type Record = ();
    ///     type Indexes = ();
    /// }
    ///
    /// // A discriminator column established that these bytes are legacy, even
    /// // though they collide with CryptBox's envelope magic.
    /// let read = MaybeEncrypted::<LegacyBlob>::from_legacy_bytes(
    ///     b"CBX\0previous-format".to_vec(),
    /// );
    /// assert!(read.is_legacy());
    /// assert!(read.as_sealed().is_none());
    /// ```
    #[must_use]
    pub fn from_legacy_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            state: State::Legacy(Zeroizing::new(bytes.into())),
        }
    }

    /// Consumes the read and returns the plaintext value.
    ///
    /// Legacy bytes use identity recovery and decode through the seal's
    /// codec; an envelope is opened under `args` with `keys`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid envelopes, invalid binding values, unknown
    /// or unavailable keys, authentication failure, or codec failure.
    pub fn open(
        self,
        args: impl Args<F>,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<F::Value, Error> {
        match self.state {
            State::Sealed(sealed) => sealed.open(args, keys),
            State::Plaintext(value) => Ok(value),
            State::Legacy(bytes) => decode_legacy::<F>(&bytes, None),
        }
    }

    /// Consumes the read, recovering non-envelope bytes with `legacy` before
    /// decoding them through the seal's codec.
    ///
    /// Valid `CryptBox` envelopes ignore the legacy handler and are opened
    /// under `args`.
    ///
    /// # Errors
    ///
    /// Returns an error when legacy recovery, codec decoding, or opening the
    /// envelope fails.
    pub fn open_legacy(
        self,
        args: impl Args<F>,
        keys: &(impl EncryptionKeys + ?Sized),
        legacy: &dyn LegacyFormat,
    ) -> Result<F::Value, Error> {
        match self.state {
            State::Sealed(sealed) => sealed.open(args, keys),
            State::Plaintext(value) => Ok(value),
            State::Legacy(bytes) => decode_legacy::<F>(&bytes, Some(legacy)),
        }
    }
}

impl<F> MaybeEncrypted<F>
where
    F: Seal<Record = ()>,
{
    /// Consumes the read and opens it with the [installed keys](crate::keys::installed).
    ///
    /// Legacy bytes use identity recovery without touching the keys.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeysNotInstalled`] before installation, or an error when
    /// opening fails or legacy bytes cannot be decoded by the seal's codec.
    pub fn open_global(self) -> Result<F::Value, Error> {
        match self.state {
            State::Sealed(sealed) => sealed.open_global(),
            State::Plaintext(value) => Ok(value),
            State::Legacy(bytes) => decode_legacy::<F>(&bytes, None),
        }
    }

    /// Consumes the read and recovers legacy bytes with an explicit handler,
    /// using the [installed keys](crate::keys::installed) for `CryptBox` envelopes.
    ///
    /// # Errors
    ///
    /// Returns an error when legacy recovery, codec decoding, key lookup,
    /// or opening the envelope fails.
    pub fn open_global_legacy(self, legacy: &dyn LegacyFormat) -> Result<F::Value, Error> {
        match self.state {
            State::Sealed(sealed) => sealed.open_global(),
            State::Plaintext(value) => Ok(value),
            State::Legacy(bytes) => decode_legacy::<F>(&bytes, Some(legacy)),
        }
    }
}

impl<F: Seal> MaybeEncrypted<F> {
    /// Returns whether the value represents legacy, non-envelope storage.
    #[doc(alias = "is_plaintext")]
    #[must_use]
    pub const fn is_legacy(&self) -> bool {
        matches!(self.state, State::Plaintext(_) | State::Legacy(_))
    }

    /// Returns the envelope when the stored bytes were classified as one.
    #[must_use]
    pub fn as_sealed(&self) -> Option<&Sealed<F>> {
        match &self.state {
            State::Sealed(sealed) => Some(sealed),
            State::Plaintext(_) | State::Legacy(_) => None,
        }
    }
}

impl<F: Seal> From<Sealed<F>> for MaybeEncrypted<F> {
    fn from(sealed: Sealed<F>) -> Self {
        Self {
            state: State::Sealed(sealed),
        }
    }
}

impl<F: Seal> fmt::Debug for MaybeEncrypted<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaybeEncrypted([REDACTED])")
    }
}
