use crate::{IndexId, IndexKeyId, KeyId, SuiteId};

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

/// An error returned while resolving local key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyProviderError {
    /// The provider is temporarily or permanently unavailable.
    #[error("key provider is unavailable")]
    Unavailable,
    /// The process-global provider has not been installed.
    #[error("key provider is not initialized")]
    NotInitialized,
}

/// An error returned by `CryptBox` operations.
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
    UnsupportedSuite(SuiteId),
    /// The envelope names a key that the provider cannot resolve.
    #[error("unknown encryption key {0}")]
    UnknownEncryptionKey(KeyId),
    /// A blind index names a key that the provider cannot resolve.
    #[error("unknown blind-index key {0}")]
    UnknownBlindIndexKey(IndexKeyId),
    /// Ciphertext authentication failed.
    #[error("ciphertext authentication failed")]
    AuthenticationFailed,
    /// Encoding or decoding the typed value failed.
    #[error("codec failed: {0}")]
    CodecFailed(#[from] CodecError),
    /// Normalizing a blind-index input failed.
    #[error("blind-index normalization failed")]
    BlindIndexNormalizationFailed,
    /// A local key provider was unavailable.
    #[error("key provider is unavailable")]
    KeyProviderUnavailable,
    /// A required process-global provider was not installed.
    #[error("key provider is not initialized")]
    KeyProviderNotInitialized,
    /// Process-global providers were already installed.
    #[error("key providers are already initialized")]
    KeyProviderAlreadyInitialized,
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
    /// The encoded plaintext does not fit the profile's fixed padding length.
    #[error("encoded plaintext exceeds the padding length")]
    PaddingOverflow,
    /// Authenticated plaintext does not carry valid padding.
    ///
    /// This indicates a profile/schema mismatch, such as enabling padding for
    /// existing unpadded ciphertext. Padding is checked only after successful
    /// authenticated decryption.
    #[error("plaintext padding is invalid")]
    InvalidPadding,
    /// A blind-index representation or bit count is invalid.
    #[error("blind index is invalid")]
    InvalidBlindIndex,
    /// The same logical index was added to a prepared value twice.
    #[error("blind index {0} was prepared more than once")]
    DuplicatePreparedIndex(IndexId),
    /// The requested logical index was not prepared.
    #[error("blind index {0} was not prepared")]
    BlindIndexNotPrepared(IndexId),
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

impl From<KeyProviderError> for Error {
    fn from(error: KeyProviderError) -> Self {
        match error {
            KeyProviderError::Unavailable => Self::KeyProviderUnavailable,
            KeyProviderError::NotInitialized => Self::KeyProviderNotInitialized,
        }
    }
}

impl From<BlindIndexError> for Error {
    fn from(_: BlindIndexError) -> Self {
        Self::BlindIndexNormalizationFailed
    }
}
