use zeroize::Zeroizing;

use super::format::{FORMAT_VERSION, ParsedEnvelope, envelope_header};
use crate::crypto;
use crate::padding::AeadPlaintext;
use crate::{EncryptionKey, Error, ShapeFingerprint, SuiteId};

// Labels, including NULs, are persistent domain separators, not display strings.
// See ../../docs/wire-format.md#encryption-recipe.
const ENCRYPTION_KEY_LABEL: &[u8] = b"cryptbox/encryption-key/v1\0";
const ENVELOPE_AAD_LABEL: &[u8] = b"cryptbox/envelope-aad/v1\0";

/// The provisional suite ID for HKDF-SHA-256 plus XChaCha20-Poly1305.
///
/// This construction and its wire format are experimental pending focused
/// cryptographic review and independently verified test vectors.
pub const EXPERIMENTAL_XCHACHA20_POLY1305: SuiteId = SuiteId::new(1);

/// The encryption suites this library reads and writes.
///
/// The set is closed: suites are built in and applications cannot add one. A
/// new variant fails to compile until every dispatch below handles it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Suite {
    XChaCha20Poly1305,
}

impl Suite {
    /// The suite new values are sealed with.
    pub(super) const ACTIVE: Self = Self::XChaCha20Poly1305;

    pub(super) fn from_id(id: SuiteId) -> Result<Self, Error> {
        match id {
            EXPERIMENTAL_XCHACHA20_POLY1305 => Ok(Self::XChaCha20Poly1305),
            _ => Err(Error::UnsupportedSuite(id)),
        }
    }

    pub(super) const fn id(self) -> SuiteId {
        match self {
            Self::XChaCha20Poly1305 => EXPERIMENTAL_XCHACHA20_POLY1305,
        }
    }

    pub(super) fn validate_payload(self, payload: &[u8]) -> Result<(), Error> {
        match self {
            Self::XChaCha20Poly1305 => xchacha20_poly1305::validate_payload(payload),
        }
    }

    // Builds the header from its own suite ID and the key's ID, so neither can
    // disagree with the key it seals under.
    pub(super) fn seal(
        self,
        plaintext: &AeadPlaintext<'_>,
        fingerprint: Option<ShapeFingerprint>,
        binding: &[u8],
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::XChaCha20Poly1305 => {
                xchacha20_poly1305::seal(plaintext, fingerprint, binding, key)
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
            Self::XChaCha20Poly1305 => xchacha20_poly1305::open(envelope, binding, key),
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
    let mut info = Vec::with_capacity(ENCRYPTION_KEY_LABEL.len() + 18 + binding.len());
    info.extend_from_slice(ENCRYPTION_KEY_LABEL);
    info.push(format_version);
    info.push(suite_id.get());
    info.extend_from_slice(root.id().as_bytes());
    info.extend_from_slice(binding);

    Ok(crypto::hkdf_sha256_32(root.bytes(), &info)?)
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

/// Suite 1: HKDF-SHA-256 and XChaCha20-Poly1305 over the format 2 envelope.
// See ../../docs/wire-format.md#encryption-suite-1.
mod xchacha20_poly1305 {
    use zeroize::Zeroizing;

    use super::{
        EXPERIMENTAL_XCHACHA20_POLY1305, FORMAT_VERSION, ParsedEnvelope, derive_encryption_key,
        envelope_aad, envelope_header,
    };
    use crate::crypto::{self, NONCE_LEN, TAG_LEN};
    use crate::padding::AeadPlaintext;
    use crate::{EncryptionKey, Error, ShapeFingerprint};

    pub(super) fn validate_payload(payload: &[u8]) -> Result<(), Error> {
        let minimum_len = NONCE_LEN
            .checked_add(TAG_LEN)
            .ok_or(Error::InvalidEnvelope)?;

        if payload.len() < minimum_len {
            return Err(Error::InvalidEnvelope);
        }

        Ok(crypto::check_message_len(payload.len() - minimum_len)?)
    }

    pub(super) fn seal(
        plaintext: &AeadPlaintext<'_>,
        fingerprint: Option<ShapeFingerprint>,
        binding: &[u8],
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error> {
        seal_with_nonce(
            plaintext,
            fingerprint,
            binding,
            key,
            crypto::random_nonce()?,
        )
    }

    pub(super) fn seal_with_nonce(
        plaintext: &AeadPlaintext<'_>,
        fingerprint: Option<ShapeFingerprint>,
        binding: &[u8],
        key: &EncryptionKey,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Vec<u8>, Error> {
        let suite = EXPERIMENTAL_XCHACHA20_POLY1305;
        let header = envelope_header(suite, plaintext.is_padded(), key.id(), fingerprint);
        let mut prefix = Vec::with_capacity(header.len() + NONCE_LEN);
        prefix.extend_from_slice(&header);
        prefix.extend_from_slice(&nonce);

        let operational_key = derive_encryption_key(key, binding, FORMAT_VERSION, suite)?;
        let aad = envelope_aad(&prefix, binding);
        let sealed = crypto::seal(&operational_key, &nonce, &aad, plaintext.bytes())?;

        let capacity = prefix
            .len()
            .checked_add(sealed.len())
            .ok_or(Error::MessageTooLong)?;
        let mut envelope = Vec::with_capacity(capacity);
        envelope.extend_from_slice(&prefix);
        envelope.extend_from_slice(&sealed);

        Ok(envelope)
    }

    pub(super) fn open(
        envelope: &ParsedEnvelope<'_>,
        binding: &[u8],
        key: &EncryptionKey,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let header = envelope.header;
        let (nonce, ciphertext) = envelope
            .suite_payload
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(Error::InvalidEnvelope)?;
        let mut prefix = Vec::with_capacity(header.len() + NONCE_LEN);
        prefix.extend_from_slice(header);
        prefix.extend_from_slice(nonce);

        let operational_key = derive_encryption_key(
            key,
            binding,
            envelope.info.format_version(),
            EXPERIMENTAL_XCHACHA20_POLY1305,
        )?;
        let aad = envelope_aad(&prefix, binding);

        Ok(crypto::open(&operational_key, nonce, &aad, ciphertext)?)
    }
}

#[cfg(test)]
pub(super) fn seal_with_nonce(
    plaintext: &[u8],
    padding: crate::Padding,
    domain: &crate::BindingDomain,
    key: &EncryptionKey,
    nonce: [u8; crypto::NONCE_LEN],
) -> Result<Vec<u8>, Error> {
    xchacha20_poly1305::seal_with_nonce(
        &padding.pad(plaintext)?,
        domain.fingerprint(),
        domain.as_bytes(),
        key,
        nonce,
    )
}
