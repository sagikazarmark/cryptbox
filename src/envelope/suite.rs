pub(super) mod xchacha20_poly1305;

use xchacha20_poly1305::XChaCha20Poly1305;

use zeroize::Zeroizing;

use super::format::{FORMAT_VERSION, ParsedEnvelope, SuiteId, envelope_header};
use crate::crypto;
use crate::padding::AeadPlaintext;
use crate::{EncryptionKey, Error, ShapeFingerprint};

// Labels, including NULs, are persistent domain separators, not display strings.
// See ../../docs/wire-format.md#encryption-recipe.
const ENCRYPTION_KEY_LABEL: &[u8] = b"cryptbox/encryption-key/v1\0";
const ENVELOPE_AAD_LABEL: &[u8] = b"cryptbox/envelope-aad/v1\0";

/// The provisional suite ID for HKDF-SHA-256 plus XChaCha20-Poly1305.
///
/// This construction and its wire format are experimental pending focused
/// cryptographic review and independently verified test vectors.
pub const EXPERIMENTAL_XCHACHA20_POLY1305: SuiteId = SuiteId::new(1);

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
        plaintext: &AeadPlaintext<'_>,
        fingerprint: ShapeFingerprint,
        binding: &[u8],
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error>;

    /// Authenticates `envelope` under `binding` and `key` and returns its payload.
    fn open(
        envelope: &ParsedEnvelope<'_>,
        binding: &[u8],
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
        plaintext: &AeadPlaintext<'_>,
        fingerprint: ShapeFingerprint,
        binding: &[u8],
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::XChaCha20Poly1305 => {
                XChaCha20Poly1305::seal(plaintext, fingerprint, binding, key)
            }
        }
    }

    pub(super) fn open(
        self,
        envelope: &ParsedEnvelope<'_>,
        binding: &[u8],
        key: &EncryptionKey,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        match self {
            Self::XChaCha20Poly1305 => XChaCha20Poly1305::open(envelope, binding, key),
        }
    }
}

fn derive_encryption_key(
    root: &EncryptionKey,
    binding: &[u8],
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
            binding,
        ],
    )?;

    Ok(key)
}

fn envelope_aad(prefix: &[u8], binding: &[u8]) -> Vec<u8> {
    // Authenticate the exact stored prefix together with the caller's expected binding.
    // The envelope must not choose its own binding: ../../docs/wire-format.md#encryption-recipe.
    let mut aad = Vec::with_capacity(ENVELOPE_AAD_LABEL.len() + prefix.len() + binding.len());
    aad.extend_from_slice(ENVELOPE_AAD_LABEL);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(binding);

    aad
}
