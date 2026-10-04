use crate::{IndexKeyId, KeyId, crypto};

/// The non-sensitive category of a codec failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CodecErrorKind {
    /// A value could not be encoded.
    Encoding,
    /// Bytes could not be decoded into a value.
    Decoding,
    /// Bytes expected to contain UTF-8 were invalid.
    InvalidUtf8,
}

/// A codec failure that never retains the value or plaintext bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("codec {kind}")]
pub struct CodecError {
    kind: CodecErrorKind,
}

impl CodecError {
    /// Creates a sanitized codec error.
    #[must_use]
    pub const fn new(kind: CodecErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the failure category.
    #[must_use]
    pub const fn kind(self) -> CodecErrorKind {
        self.kind
    }
}

impl std::fmt::Display for CodecErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding => formatter.write_str("encoding failed"),
            Self::Decoding => formatter.write_str("decoding failed"),
            Self::InvalidUtf8 => formatter.write_str("contains invalid UTF-8"),
        }
    }
}

/// A non-sensitive blind-index normalization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
#[error("blind-index normalization failed")]
pub struct BlindIndexError;

impl BlindIndexError {
    /// Creates a sanitized normalization error.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for BlindIndexError {
    fn default() -> Self {
        Self::new()
    }
}

/// An error returned by `CryptBox` operations.
///
/// Errors carry a category and public IDs only, never a value, plaintext, or an
/// upstream error, which could quote its input, so any error is safe to log.
/// Codecs and normalizers report failures the same way, through [`CodecError`]
/// and [`BlindIndexError`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input does not start with the `CryptBox` envelope magic.
    #[error("input is not CryptBox ciphertext")]
    NotCiphertext,
    /// The envelope is structurally invalid.
    #[error("ciphertext envelope is invalid")]
    InvalidEnvelope,
    /// The envelope uses an unknown format version.
    #[error("unsupported ciphertext format version {0}")]
    UnsupportedFormatVersion(u8),
    /// The envelope uses an unavailable suite.
    #[error("unsupported encryption suite {0}")]
    UnsupportedSuite(u8),
    /// The envelope names a key that the keyring does not hold.
    #[error("unknown encryption key {0}")]
    UnknownEncryptionKey(KeyId),
    /// A blind index names a key that the keyring does not hold.
    #[error("unknown blind-index key {0}")]
    UnknownBlindIndexKey(IndexKeyId),
    /// Ciphertext authentication failed.
    #[error("ciphertext authentication failed")]
    AuthenticationFailed,
    /// The envelope was sealed under a different kind of context than the
    /// reader's, such as a record field's value read as a standalone value.
    ///
    /// Reported from the envelope's context fingerprint before any key lookup or
    /// authentication. Another seal ID or record ID under the same kind of
    /// context reports [`Error::AuthenticationFailed`].
    #[error("ciphertext context does not match the seal")]
    ContextMismatch,
    /// Encoding or decoding the typed value failed.
    #[error("codec failed: {0}")]
    CodecFailed(#[from] CodecError),
    /// Normalizing a blind-index input failed.
    #[error(transparent)]
    BlindIndexNormalizationFailed(#[from] BlindIndexError),
    /// A blind-index operation used [`Keys`](crate::Keys) without a
    /// blind-index keyring; add one with
    /// [`Keys::with_blind_indexes`](crate::Keys::with_blind_indexes).
    #[error("no blind-index keyring is configured")]
    BlindIndexKeysNotConfigured,
    /// A stored row is not the one the caller expected, so it was not
    /// decrypted; see [`Record::open_expecting`](crate::Record::open_expecting).
    #[error("stored record is not the one expected")]
    UnexpectedRecord,
    /// A keyring contains the same encryption key ID more than once.
    #[error("duplicate encryption key ID {0}")]
    DuplicateEncryptionKey(KeyId),
    /// A keyring contains the same blind-index key ID more than once.
    #[error("duplicate blind-index key ID {0}")]
    DuplicateBlindIndexKey(IndexKeyId),
    /// The operating-system random source failed.
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    /// Encoded root key material is malformed or does not decode to 32 bytes.
    #[error("encoded key material is invalid")]
    InvalidKeyEncoding,
    /// An internal invariant was violated.
    #[error("internal error")]
    Internal,
    /// The input exceeds the suite's message-size limit.
    #[error("message is too long")]
    MessageTooLong,
    /// The encoded plaintext does not fit the seal's fixed padding length.
    #[error("encoded plaintext exceeds the padding length")]
    PaddingOverflow,
    /// Authenticated plaintext does not carry valid padding.
    ///
    /// The envelope records padding, so this indicates a defective writer.
    /// Padding is checked only after successful authenticated decryption.
    #[error("plaintext padding is invalid")]
    InvalidPadding,
    /// A blind-index representation or bit count is invalid.
    #[error("blind index is invalid")]
    InvalidBlindIndex,
    /// A sweep row supplied a different number of blind-index columns than the
    /// planner registered.
    #[cfg(feature = "migrate")]
    #[error("row has {actual} blind-index columns, but {expected} are planned")]
    IndexColumnMismatch {
        /// The number of blind-index columns the planner registered.
        expected: usize,
        /// The number of blind-index columns the row supplied.
        actual: usize,
    },
    /// A previous encryption format could not recover the stored value.
    #[cfg(feature = "migrate")]
    #[error("legacy recovery failed: {0}")]
    LegacyRecoveryFailed(#[from] crate::migrate::LegacyError),
}

impl From<crypto::Error> for Error {
    fn from(error: crypto::Error) -> Self {
        match error {
            crypto::Error::Internal => Self::Internal,
            crypto::Error::RandomnessUnavailable => Self::RandomnessUnavailable,
        }
    }
}
