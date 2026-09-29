//! Suite 1: HKDF-SHA-256 and XChaCha20-Poly1305 over the format 2 envelope.
//!
//! The suite owns its AEAD: the recipe that builds the key and AAD, and the
//! calls that seal and open with them, read together.
// See ../../../docs/wire-format.md#encryption-suite-1.

use chacha20poly1305::aead::array::typenum::Unsigned;
use chacha20poly1305::aead::{AeadCore, AeadInOut, inout::InOutBuf};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305 as Cipher};
use zeroize::Zeroizing;

use super::{
    EnvelopeBinding, FORMAT_VERSION, ParsedEnvelope, Suite, SuiteId, derive_encryption_key,
    envelope_aad, envelope_header,
};
use crate::crypto;
use crate::padding::AeadPlaintext;
use crate::{EncryptionKey, Error};

pub(in crate::envelope) const NONCE_LEN: usize = <Cipher as AeadCore>::NonceSize::USIZE;
const TAG_LEN: usize = <Cipher as AeadCore>::TagSize::USIZE;
// One byte below RFC 8439's `(2^32 - 1) * 64`: chacha20poly1305 rejects a message of
// exactly that length, which would otherwise surface as Error::Internal.
const MAX_MESSAGE_LEN: u64 = 274_877_906_879;

/// The provisional suite ID for HKDF-SHA-256 plus XChaCha20-Poly1305.
///
/// This construction and its wire format are experimental pending focused
/// cryptographic review and independently verified test vectors.
pub const EXPERIMENTAL_XCHACHA20_POLY1305: SuiteId = SuiteId::new(1);

/// Suite 1: HKDF-SHA-256 and XChaCha20-Poly1305 over the format 2 envelope.
pub(in crate::envelope) struct XChaCha20Poly1305;

impl Suite for XChaCha20Poly1305 {
    const ID: SuiteId = EXPERIMENTAL_XCHACHA20_POLY1305;

    fn validate_payload(payload: &[u8]) -> Result<(), Error> {
        let minimum_len = NONCE_LEN
            .checked_add(TAG_LEN)
            .ok_or(Error::InvalidEnvelope)?;

        if payload.len() < minimum_len {
            return Err(Error::InvalidEnvelope);
        }

        check_message_len(payload.len() - minimum_len)
    }

    fn seal(
        binding: EnvelopeBinding<'_>,
        plaintext: &AeadPlaintext<'_>,
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error> {
        // Fresh OS randomness avoids caller-managed nonce reuse; failure must stop encryption.
        // See ../../../docs/wire-format.md#encryption-recipe.
        let nonce = crypto::random_bytes()?;

        Self::seal_with_nonce(binding, plaintext, key, nonce)
    }

    fn open(
        binding: EnvelopeBinding<'_>,
        envelope: &ParsedEnvelope<'_>,
        key: &EncryptionKey,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        // The AAD covers the stored header and nonce exactly as they were read.
        let prefix_len = envelope.header.len() + NONCE_LEN;
        let (prefix, ciphertext) = envelope
            .bytes
            .split_at_checked(prefix_len)
            .ok_or(Error::InvalidEnvelope)?;
        let nonce = prefix
            .last_chunk::<NONCE_LEN>()
            .ok_or(Error::InvalidEnvelope)?;

        let operational_key =
            derive_encryption_key(key, binding.bytes, envelope.info.format_version(), Self::ID)?;
        let aad = envelope_aad(prefix, binding.bytes);

        decrypt(&operational_key, nonce, &aad, ciphertext)
    }
}

impl XChaCha20Poly1305 {
    /// Seals with `nonce` instead of a fresh random one; [`Suite::seal`] and
    /// the known-answer tests call this.
    pub(in crate::envelope) fn seal_with_nonce(
        binding: EnvelopeBinding<'_>,
        plaintext: &AeadPlaintext<'_>,
        key: &EncryptionKey,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Vec<u8>, Error> {
        let suite = Self::ID;
        let header = envelope_header(suite, plaintext.is_padded(), key.id(), binding.fingerprint);
        let capacity = (header.len() + NONCE_LEN + TAG_LEN)
            .checked_add(plaintext.bytes().len())
            .ok_or(Error::MessageTooLong)?;
        let mut envelope = Vec::with_capacity(capacity);
        envelope.extend_from_slice(&header);
        envelope.extend_from_slice(&nonce);

        let operational_key = derive_encryption_key(key, binding.bytes, FORMAT_VERSION, suite)?;
        let aad = envelope_aad(&envelope, binding.bytes);
        encrypt_into(
            &operational_key,
            &nonce,
            &aad,
            plaintext.bytes(),
            &mut envelope,
        )?;

        Ok(envelope)
    }
}

/// Rejects a message longer than XChaCha20-Poly1305 can encrypt under one nonce.
fn check_message_len(len: usize) -> Result<(), Error> {
    let len = u64::try_from(len).map_err(|_| Error::MessageTooLong)?;

    if len > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLong);
    }

    Ok(())
}

/// Encrypts `plaintext` and appends the ciphertext and its tag to `out`.
///
/// The AEAD reads `plaintext` and writes ciphertext straight into `out`, so no
/// working copy of the plaintext is made.
fn encrypt_into(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    check_message_len(plaintext.len())?;

    let cipher = Cipher::new(key.into());
    let start = out.len();
    let end = start
        .checked_add(plaintext.len())
        .ok_or(Error::MessageTooLong)?;
    out.resize(end, 0);
    let buffer = InOutBuf::new(plaintext, &mut out[start..]).map_err(|_| Error::Internal)?;
    let tag = cipher
        .encrypt_inout_detached(nonce.into(), aad, buffer)
        .map_err(|_| Error::Internal)?;
    out.extend_from_slice(&tag);

    Ok(())
}

/// Authenticates `ciphertext`, which ends with its tag, and returns the plaintext.
///
/// The AEAD verifies the tag before it writes any plaintext, so a failure
/// returns no bytes.
fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (ciphertext, tag) = ciphertext
        .split_last_chunk::<TAG_LEN>()
        .ok_or(Error::AuthenticationFailed)?;
    let cipher = Cipher::new(key.into());
    // Plaintext is only ever written here; erase it on drop.
    // See ../../../docs/wire-format.md#key-and-buffer-lifetime.
    let mut plaintext = Zeroizing::new(vec![0_u8; ciphertext.len()]);
    let buffer = InOutBuf::new(ciphertext, &mut plaintext[..]).map_err(|_| Error::Internal)?;
    cipher
        .decrypt_inout_detached(nonce.into(), aad, buffer, tag.into())
        .map_err(|_| Error::AuthenticationFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::{NONCE_LEN, check_message_len, decrypt, encrypt_into};
    use crate::Error;

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn message_len_limit_matches_the_aead() {
        assert_eq!(check_message_len(274_877_906_879), Ok(()));
        assert_eq!(
            check_message_len(274_877_906_880),
            Err(Error::MessageTooLong)
        );
    }

    #[test]
    fn decrypt_rejects_a_changed_aad() {
        let key = [0x11; 32];
        let nonce = [0x22; NONCE_LEN];
        let mut sealed = Vec::new();
        encrypt_into(&key, &nonce, b"aad", b"secret", &mut sealed).unwrap();

        assert_eq!(
            decrypt(&key, &nonce, b"aad", &sealed).unwrap().as_slice(),
            b"secret"
        );
        assert_eq!(
            decrypt(&key, &nonce, b"other", &sealed).unwrap_err(),
            Error::AuthenticationFailed
        );
    }
}
