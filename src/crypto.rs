//! Primitives shared by the envelope's suites and blind indexes: HKDF-SHA-256,
//! HMAC-SHA-256, and operating-system randomness.
//!
//! This module depends on no other module of the crate. Callers own the recipes:
//! which labels, key material, and inputs go in. Each envelope suite owns its
//! AEAD, next to the recipe that calls it.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

// Labels, including NULs, are persistent domain separators, not display strings.
// See ../docs/wire-format.md#encryption-recipe.
const HKDF_SALT: &[u8] = b"cryptbox/hkdf-sha256/v1\0";

/// A primitive failure; it never carries key material or plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Internal,
    RandomnessUnavailable,
}

/// Returns `N` bytes from the operating-system random source.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| Error::RandomnessUnavailable)?;

    Ok(bytes)
}

/// Derives 32 bytes with HKDF-SHA-256 under the crate's fixed salt, with the
/// concatenation of `info` as its info.
pub(crate) fn hkdf_sha256_32(
    input_key_material: &[u8],
    info: &[&[u8]],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    hkdf_sha256_32_with_salt(input_key_material, HKDF_SALT, info)
}

fn hkdf_sha256_32_with_salt(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[&[u8]],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let (mut pseudo_random_key, hkdf) = Hkdf::<Sha256>::extract(Some(salt), input_key_material);
    // HKDF retains keyed expansion state, so the separately returned PRK is no longer needed.
    // Keep outputs zeroizing too: ../docs/wire-format.md#key-and-buffer-lifetime.
    pseudo_random_key.as_mut_slice().zeroize();
    let mut output = Zeroizing::new([0_u8; 32]);

    hkdf.expand_multi_info(info, &mut output[..])
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
    use super::hkdf_sha256_32_with_salt;

    #[test]
    fn hkdf_matches_rfc_5869_case_one() {
        let input_key_material = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let output = hkdf_sha256_32_with_salt(&input_key_material, &salt, &[&info]).unwrap();

        assert_eq!(
            hex::encode(output.as_slice()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }
}
