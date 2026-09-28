//! Cryptographic primitives: HKDF-SHA-256, HMAC-SHA-256, and XChaCha20-Poly1305.
//!
//! This module depends on no other module of the crate, so every use of a
//! primitive, and every way one can fail, is reviewable in one place. Callers
//! own the recipes: which labels, key material, and AAD go in.

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInOut};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;
const MAX_MESSAGE_LEN: u64 = 274_877_906_880;

// Labels, including NULs, are persistent domain separators, not display strings.
// See ../docs/wire-format.md#encryption-recipe.
const HKDF_SALT: &[u8] = b"cryptbox/hkdf-sha256/v1\0";

/// A primitive failure; it never carries key material or plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Internal,
    MessageTooLong,
    AuthenticationFailed,
    RandomnessUnavailable,
}

/// Returns a fresh nonce from the operating-system random source.
pub(crate) fn random_nonce() -> Result<[u8; NONCE_LEN], Error> {
    // Fresh OS randomness avoids caller-managed nonce reuse; failure must stop encryption.
    // See ../docs/wire-format.md#encryption-recipe.
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    Ok(nonce)
}

/// Rejects a message longer than XChaCha20-Poly1305 can encrypt under one nonce.
pub(crate) fn check_message_len(len: usize) -> Result<(), Error> {
    let len = u64::try_from(len).map_err(|_| Error::MessageTooLong)?;

    if len > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLong);
    }

    Ok(())
}

/// Encrypts `plaintext` and returns the ciphertext followed by its tag.
pub(crate) fn seal(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    check_message_len(plaintext.len())?;

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Internal)?;
    // The working copy can still contain plaintext if sealing fails; erase on every exit.
    // See ../docs/wire-format.md#key-and-buffer-lifetime.
    let mut sealed = Zeroizing::new(plaintext.to_vec());
    cipher
        .encrypt_in_place(&XNonce::from(*nonce), aad, &mut *sealed)
        .map_err(|_| Error::Internal)?;

    Ok(std::mem::take(&mut *sealed))
}

/// Authenticates and decrypts `ciphertext`, which ends with its tag.
pub(crate) fn open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Internal)?;
    // Never return unauthenticated bytes, even if the AEAD mutates before failing.
    // Zeroizing also covers that error path: ../docs/wire-format.md#key-and-buffer-lifetime.
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place(&XNonce::from(*nonce), aad, &mut *plaintext)
        .map_err(|_| Error::AuthenticationFailed)?;

    Ok(plaintext)
}

/// Derives 32 bytes with HKDF-SHA-256 under the crate's fixed salt.
pub(crate) fn hkdf_sha256_32(
    input_key_material: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    hkdf_sha256_32_with_salt(input_key_material, HKDF_SALT, info)
}

fn hkdf_sha256_32_with_salt(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let (mut pseudo_random_key, hkdf) = Hkdf::<Sha256>::extract(Some(salt), input_key_material);
    // HKDF retains keyed expansion state, so the separately returned PRK is no longer needed.
    // Keep outputs zeroizing too: ../docs/wire-format.md#key-and-buffer-lifetime.
    pseudo_random_key.as_mut_slice().zeroize();
    let mut output = Zeroizing::new([0_u8; 32]);

    hkdf.expand(info, &mut output[..])
        .map_err(|_| Error::Internal)?;

    Ok(output)
}

/// Computes HMAC-SHA-256 over the concatenation of `input`.
pub(crate) fn hmac_sha256(key: &[u8], input: &[&[u8]]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Internal)?;

    for component in input {
        hmac.update(component);
    }

    let digest = hmac.finalize();
    let mut output = Zeroizing::new([0_u8; 32]);
    output.copy_from_slice(digest.as_bytes());

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{Error, NONCE_LEN, hkdf_sha256_32_with_salt, open, seal};

    #[test]
    fn hkdf_matches_rfc_5869_case_one() {
        let input_key_material = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let output = hkdf_sha256_32_with_salt(&input_key_material, &salt, &info).unwrap();

        assert_eq!(
            hex::encode(output.as_slice()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn open_rejects_a_changed_aad() {
        let key = [0x11; 32];
        let nonce = [0x22; NONCE_LEN];
        let sealed = seal(&key, &nonce, b"aad", b"secret").unwrap();

        assert_eq!(
            open(&key, &nonce, b"aad", &sealed).unwrap().as_slice(),
            b"secret"
        );
        assert_eq!(
            open(&key, &nonce, b"other", &sealed).unwrap_err(),
            Error::AuthenticationFailed
        );
    }
}
