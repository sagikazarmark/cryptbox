use std::fmt;

use zeroize::Zeroizing;

/// Recovers plaintext bytes from a previous application encryption format.
///
/// Implement this trait on an application-owned handler that closes over the
/// key material and state required by the previous solution. Implementations
/// must not retain plaintext in errors and are responsible for zeroizing their
/// own intermediate values and key material. The handler is explicit and
/// synchronous so it can be removed and its keys destroyed after the bounded
/// migration window.
///
/// A handler can support mixed foreign ciphertext and plaintext by recognizing
/// its previous format and using identity recovery otherwise:
///
/// ```
/// use cryptbox::migrate::{LegacyError, LegacyErrorKind, LegacyFormat};
/// use zeroize::Zeroizing;
///
/// struct PreviousFormat;
///
/// impl LegacyFormat for PreviousFormat {
///     fn recover(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, LegacyError> {
///         if let Some(plaintext) = bytes.strip_prefix(b"previous:v1:") {
///             return Ok(Zeroizing::new(plaintext.to_vec()));
///         }
///         if bytes.starts_with(b"previous:") {
///             return Err(LegacyError::new(LegacyErrorKind::Malformed));
///         }
///
///         Ok(Zeroizing::new(bytes.to_vec()))
///     }
/// }
///
/// let recovered = PreviousFormat.recover(b"previous:v1:hello")?;
/// assert_eq!(&*recovered, b"hello");
/// # Ok::<(), LegacyError>(())
/// ```
pub trait LegacyFormat {
    /// Recovers the plaintext bytes of one stored legacy value.
    ///
    /// The caller decodes the returned bytes through the profile's codec.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when the legacy value cannot be recovered.
    fn recover(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, LegacyError>;
}

/// The non-sensitive category of a legacy recovery failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LegacyErrorKind {
    /// The legacy representation is malformed or unsupported.
    Malformed,
    /// The legacy representation failed authentication.
    AuthenticationFailed,
    /// The legacy key material is unavailable.
    KeyUnavailable,
}

/// A legacy recovery failure that never retains bytes or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{kind}")]
pub struct LegacyError {
    kind: LegacyErrorKind,
}

impl LegacyError {
    /// Creates a sanitized legacy recovery error.
    #[must_use]
    pub const fn new(kind: LegacyErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the failure category.
    #[must_use]
    pub const fn kind(self) -> LegacyErrorKind {
        self.kind
    }
}

impl fmt::Display for LegacyErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => formatter.write_str("value is malformed"),
            Self::AuthenticationFailed => formatter.write_str("authentication failed"),
            Self::KeyUnavailable => formatter.write_str("key is unavailable"),
        }
    }
}

pub(crate) fn recover(
    bytes: &[u8],
    legacy: Option<&dyn LegacyFormat>,
) -> Result<Zeroizing<Vec<u8>>, LegacyError> {
    match legacy {
        Some(legacy) => legacy.recover(bytes),
        None => Ok(Zeroizing::new(bytes.to_vec())),
    }
}
