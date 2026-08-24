pub(super) mod xchacha20_poly1305;

use xchacha20_poly1305::XChaCha20Poly1305;

use zeroize::Zeroizing;

use super::format::{FORMAT_VERSION, ParsedEnvelope, SuiteId, envelope_header};
use crate::crypto;
use crate::{EncryptionKey, Error, Padding};

// Labels, including NULs, are persistent domain separators, not display strings.
// See ../../docs/wire-format.md#encryption-recipe.
const ENCRYPTION_KEY_LABEL: &[u8] = b"cryptbox/encryption-key/v1\0";
const ENVELOPE_AAD_LABEL: &[u8] = b"cryptbox/envelope-aad/v1\0";

/// What an envelope binds a value to: opaque bytes and their fingerprint.
///
/// Key derivation and the AAD both take the bytes, which are never stored; the
/// header stores the fingerprint, and opening compares it before any key
/// lookup. The envelope interprets neither: the layer above encodes them, and
/// for a sealed value they are its seal context's encoding and fingerprint.
///
/// The header is stored in plaintext, so the fingerprint must name only what
/// kind of context this is, never the values in its bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Context<'a> {
    bytes: &'a [u8],
    fingerprint: [u8; 8],
}

impl<'a> Context<'a> {
    pub(crate) const fn new(bytes: &'a [u8], fingerprint: [u8; 8]) -> Self {
        Self { bytes, fingerprint }
    }

    /// The fingerprint a reader compares with the one stored in the header.
    pub(crate) const fn fingerprint(&self) -> [u8; 8] {
        self.fingerprint
    }
}

/// Encoded plaintext as the AEAD seals it: the codec's bytes, or those bytes padded.
///
/// The envelope's padded flag comes from the variant, so it cannot disagree
/// with the bytes.
pub(super) enum AeadPlaintext<'a> {
    Unpadded(&'a [u8]),
    Padded(Zeroizing<Vec<u8>>),
}

impl<'a> AeadPlaintext<'a> {
    /// Applies `padding` to `plaintext`.
    ///
    /// Without padding the result borrows `plaintext`, so it is encrypted
    /// without a copy.
    pub(super) fn new(padding: Padding, plaintext: &'a [u8]) -> Result<Self, Error> {
        Ok(match padding.pad(plaintext)? {
            Some(padded) => Self::Padded(padded),
            None => Self::Unpadded(plaintext),
        })
    }

    pub(super) fn bytes(&self) -> &[u8] {
        match self {
            Self::Unpadded(bytes) => bytes,
            Self::Padded(bytes) => bytes,
        }
    }

    pub(super) const fn is_padded(&self) -> bool {
        matches!(self, Self::Padded(_))
    }
}

/// A complete encryption construction over the envelope format: how it derives
/// its key, what it authenticates, and which AEAD seals the payload.
///
/// Suites carry no state, so every operation is an associated function and
/// dispatch is static. A suite's parameters, such as its nonce size, are its own.
pub(super) trait Suite {
    /// The suite ID the envelope header records.
    const ID: SuiteId;

    /// Checks that `payload`, everything after the header, can be this suite's.
    fn validate_payload(payload: &[u8]) -> Result<(), Error>;

    /// Seals `plaintext` into a complete envelope.
    ///
    /// The header is built from [`Self::ID`] and the key's ID, so neither can
    /// disagree with the key it seals under.
    fn seal(
        context: Context<'_>,
        plaintext: &AeadPlaintext<'_>,
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error>;

    /// Authenticates `envelope` under `context` and `key` and returns its payload.
    ///
    /// The envelope has already matched `context`'s fingerprint; only the bytes
    /// are used here.
    fn open(
        context: Context<'_>,
        envelope: &ParsedEnvelope<'_>,
        key: &EncryptionKey,
    ) -> Result<Zeroizing<Vec<u8>>, Error>;
}

/// The suites this library reads and writes, chosen by the header's suite ID.
///
/// The set is closed: suites are built in and applications cannot add one. A
/// new variant fails to compile until every dispatch below handles it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SupportedSuite {
    XChaCha20Poly1305,
}

impl SupportedSuite {
    /// The suite new values are sealed with.
    pub(super) const ACTIVE: Self = Self::XChaCha20Poly1305;

    pub(super) fn from_id(id: SuiteId) -> Result<Self, Error> {
        match id {
            XChaCha20Poly1305::ID => Ok(Self::XChaCha20Poly1305),
            _ => Err(Error::UnsupportedSuite(id.get())),
        }
    }

    pub(super) const fn id(self) -> SuiteId {
        match self {
            Self::XChaCha20Poly1305 => XChaCha20Poly1305::ID,
        }
    }

    pub(super) fn validate_payload(self, payload: &[u8]) -> Result<(), Error> {
        match self {
            Self::XChaCha20Poly1305 => XChaCha20Poly1305::validate_payload(payload),
        }
    }

    pub(super) fn seal(
        self,
        context: Context<'_>,
        plaintext: &AeadPlaintext<'_>,
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::XChaCha20Poly1305 => XChaCha20Poly1305::seal(context, plaintext, key),
        }
    }

    pub(super) fn open(
        self,
        context: Context<'_>,
        envelope: &ParsedEnvelope<'_>,
        key: &EncryptionKey,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        match self {
            Self::XChaCha20Poly1305 => XChaCha20Poly1305::open(context, envelope, key),
        }
    }
}

fn derive_encryption_key(
    root: &EncryptionKey,
    context: &[u8],
    format_version: u8,
    suite_id: SuiteId,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    // Preserve this canonical order: changing it makes stored ciphertext unreadable.
    // See ../../docs/wire-format.md#encryption-recipe.
    let key = crypto::hkdf_sha256_32(
        root.bytes(),
        &[
            ENCRYPTION_KEY_LABEL,
            &[format_version, suite_id.get()],
            root.id().as_bytes(),
            context,
        ],
    )?;

    Ok(key)
}

fn envelope_aad(prefix: &[u8], context: &[u8]) -> Vec<u8> {
    // Authenticate the exact stored prefix together with the caller's expected context.
    // The envelope must not choose its own context: ../../docs/wire-format.md#encryption-recipe.
    let mut aad = Vec::with_capacity(ENVELOPE_AAD_LABEL.len() + prefix.len() + context.len());
    aad.extend_from_slice(ENVELOPE_AAD_LABEL);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(context);

    aad
}
