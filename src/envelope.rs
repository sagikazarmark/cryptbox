//! The byte-level inspection API: what a stored value or blind index says
//! about itself, without keys or a seal.
//!
//! Use it in tools and migrations that look at stored bytes, such as telling
//! ciphertext from legacy plaintext with [`is_ciphertext`], or counting values
//! per key generation with [`inspect_ciphertext`]. Everything it reports is
//! unauthenticated until the value is opened. The [wire format] defines the
//! layouts.
//!
#![doc = concat!(
    "[wire format]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/docs/wire-format.md",
)]

mod format;
mod suite;

use zeroize::Zeroizing;

use crate::padding::unpad;
use crate::{EncryptionKeyring, Error, Padding};

pub use crate::blind::{BlindIndexInfo, inspect_blind_index};
pub(crate) use format::validated_key_id;
pub use format::{CiphertextInfo, is_ciphertext};
use format::{ParsedEnvelope, parse_envelope};
pub(crate) use suite::Context;
use suite::{AeadPlaintext, SupportedSuite};

/// Parses supported envelope metadata without authenticating it.
///
/// The bytes and returned metadata remain untrusted until authenticated
/// decryption succeeds. Parsing does not look up keys or validate a codec.
///
/// # Errors
///
/// Returns a structured error when the envelope is malformed or unsupported.
pub fn inspect_ciphertext(bytes: &[u8]) -> Result<CiphertextInfo, Error> {
    parse_supported(bytes).map(|(_, envelope)| envelope.info)
}

/// Parses an envelope whose suite is supported and whose payload fits that suite.
fn parse_supported(bytes: &[u8]) -> Result<(SupportedSuite, ParsedEnvelope<'_>), Error> {
    let envelope = parse_envelope(bytes)?;
    let suite = SupportedSuite::from_id(envelope.info.suite())?;
    suite.validate_payload(envelope.suite_payload)?;

    Ok((suite, envelope))
}

/// Pads `plaintext` with `padding` and seals it under `context` with the
/// current key of `keyring`.
///
/// The envelope records whether the payload is padded, so opening removes the
/// padding whatever policy is in effect then.
pub(crate) fn seal(
    context: Context<'_>,
    padding: Padding,
    plaintext: &[u8],
    keyring: &EncryptionKeyring,
) -> Result<Vec<u8>, Error> {
    let plaintext = AeadPlaintext::new(padding, plaintext)?;

    SupportedSuite::ACTIVE.seal(context, &plaintext, keyring.current())
}

/// An envelope that parsed and whose fingerprint matches the context a reader
/// expects, before any key is looked up.
pub(crate) struct CheckedEnvelope<'a> {
    suite: SupportedSuite,
    parsed: ParsedEnvelope<'a>,
    context: Context<'a>,
}

/// Parses `ciphertext` and compares its fingerprint with `context`'s.
// The expected fingerprint always comes from the reader, never from the
// envelope; the stored one only names the mismatch before any key or AEAD work.
// See ../docs/wire-format.md#reader-rules.
pub(crate) fn check<'a>(
    context: Context<'a>,
    ciphertext: &'a [u8],
) -> Result<CheckedEnvelope<'a>, Error> {
    let (suite, parsed) = parse_supported(ciphertext)?;
    if parsed.info.context_fingerprint() != context.fingerprint() {
        return Err(Error::ContextMismatch);
    }

    Ok(CheckedEnvelope {
        suite,
        parsed,
        context,
    })
}

impl CheckedEnvelope<'_> {
    /// Authenticates and decrypts under the key of `keyring` that the envelope
    /// names, and removes recorded padding.
    pub(crate) fn open(&self, keyring: &EncryptionKeyring) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key_id = self.parsed.info.key_id();
        let key = keyring
            .get(key_id)
            .ok_or(Error::UnknownEncryptionKey(key_id))?;
        let plaintext = self.suite.open(self.context, &self.parsed, key)?;

        // Only the authenticated flag decides unpadding; the current policy must not,
        // or policy changes would silently misread stored values.
        // See ../docs/adr/0002-authenticated-padding-flag.md.
        if self.parsed.info.padded() {
            unpad(plaintext)
        } else {
            Ok(plaintext)
        }
    }

    /// Reports whether the envelope differs from what a writer with `padding`
    /// and `keyring` seals: a non-active suite, a non-current key, or a padding
    /// flag that disagrees with `padding`.
    ///
    /// This reads unauthenticated metadata and does not decrypt the payload.
    pub(crate) fn needs_reseal(&self, padding: Padding, keyring: &EncryptionKeyring) -> bool {
        let info = self.parsed.info;

        info.suite() != SupportedSuite::ACTIVE.id()
            || info.key_id() != keyring.current().id()
            || info.padded() != padding.is_padded()
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::suite::xchacha20_poly1305::{NONCE_LEN, XChaCha20Poly1305};
    use super::{AeadPlaintext, Context, check, inspect_ciphertext, seal};
    use crate::{EncryptionKey, EncryptionKeyring, Error, Padding};

    // Seals under suite 1 with a fixed nonce, as the known-answer vectors need.
    fn seal_with_nonce(
        context: Context<'_>,
        padding: Padding,
        plaintext: &[u8],
        key: &EncryptionKey,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Vec<u8>, Error> {
        let plaintext = AeadPlaintext::new(padding, plaintext)?;

        XChaCha20Poly1305::seal_with_nonce(context, &plaintext, key, nonce)
    }

    // Fixed inputs make the known-answer vectors in docs/wire-format.md reproducible.
    // Sealing outside tests always draws a fresh nonce from `crypto::random_bytes`.
    fn vector_key() -> EncryptionKey {
        EncryptionKey::new(
            crate::key_id!("11111111-2222-4333-8444-555555555555"),
            [0x11; 32],
        )
    }

    fn vector_nonce() -> [u8; NONCE_LEN] {
        let mut nonce = [0_u8; NONCE_LEN];

        for (value, byte) in nonce.iter_mut().zip(0_u8..) {
            *value = byte;
        }

        nonce
    }

    fn keyring() -> EncryptionKeyring {
        EncryptionKeyring::new(vector_key(), []).unwrap()
    }

    fn fingerprint(value: &str) -> [u8; 8] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    // The envelope does not interpret the context: the vectors take its bytes
    // and fingerprint as given. The seal context module pins how they are encoded.
    fn context(bytes: &[u8], fingerprint: [u8; 8]) -> Context<'_> {
        Context::new(bytes, fingerprint)
    }

    fn open(
        context: Context<'_>,
        envelope: &[u8],
        keyring: &EncryptionKeyring,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        check(context, envelope)?.open(keyring)
    }

    #[test]
    fn record_vector_is_stable() {
        let bytes = hex::decode(RECORD_CONTEXT).unwrap();
        let envelope = seal_with_nonce(
            context(&bytes, fingerprint(RECORD_FINGERPRINT)),
            Padding::NONE,
            b"cryptbox vector",
            &vector_key(),
            vector_nonce(),
        )
        .unwrap();

        assert_eq!(
            hex::encode(&envelope[..55]),
            concat!(
                "4342580002010011111111222243338444555555555555",
                // Context fingerprint, then the nonce.
                "af72b9c5219cf83b",
                "000102030405060708090a0b0c0d0e0f1011121314151617",
            )
        );
        assert_eq!(hex::encode(envelope), RECORD_VECTOR);
    }

    // docs/wire-format.md#record-vector
    const UNBOUND_CONTEXT: &str = "123456781234423482341234567890ab0000";
    // The fingerprint of a context without a record ID.
    const UNBOUND_FINGERPRINT: &str = "502de8fcfb838c80";
    const RECORD_CONTEXT: &str = "123456781234423482341234567890ab000102000000080000000000000007";
    const RECORD_FINGERPRINT: &str = "af72b9c5219cf83b";
    const RECORD_VECTOR: &str = "4342580002010011111111222243338444555555555555af72b9c5219cf83b000102030405060708090a0b0c0d0e0f10111213141516173270eb8abb2f33a5b07fed7df8e4f670ee1d691d5adf05262912af97de476a";

    #[test]
    fn the_record_vector_opens_under_its_context() {
        let envelope = hex::decode(RECORD_VECTOR).unwrap();
        let bytes = hex::decode(RECORD_CONTEXT).unwrap();

        assert_eq!(
            open(
                context(&bytes, fingerprint(RECORD_FINGERPRINT)),
                &envelope,
                &keyring()
            )
            .unwrap()
            .as_slice(),
            b"cryptbox vector"
        );
    }

    #[test]
    fn a_sealed_value_round_trips_and_reports_its_fingerprint() {
        let bytes = hex::decode(RECORD_CONTEXT).unwrap();
        let context = context(&bytes, fingerprint(RECORD_FINGERPRINT));
        let envelope = seal(context, Padding::NONE, b"secret", &keyring()).unwrap();

        assert_eq!(
            inspect_ciphertext(&envelope).unwrap().context_fingerprint(),
            fingerprint(RECORD_FINGERPRINT)
        );
        assert_eq!(
            open(context, &envelope, &keyring()).unwrap().as_slice(),
            b"secret"
        );
    }

    #[test]
    fn every_header_carries_the_fingerprint() {
        let bytes = hex::decode(UNBOUND_CONTEXT).unwrap();
        let expected = fingerprint(UNBOUND_FINGERPRINT);
        let envelope = seal(
            context(&bytes, expected),
            Padding::NONE,
            b"secret",
            &keyring(),
        )
        .unwrap();

        assert_eq!(envelope.len(), 55 + 6 + 16);
        assert_eq!(
            inspect_ciphertext(&envelope).unwrap().context_fingerprint(),
            expected
        );
    }

    #[test]
    fn other_context_bytes_fail_authentication() {
        let bytes = hex::decode(RECORD_CONTEXT).unwrap();
        let expected = fingerprint(RECORD_FINGERPRINT);
        let envelope = seal(
            context(&bytes, expected),
            Padding::NONE,
            b"secret",
            &keyring(),
        )
        .unwrap();
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;

        for (case, reader) in [
            ("changed byte", changed.as_slice()),
            ("prefix", &bytes[..bytes.len() - 1]),
        ] {
            assert_eq!(
                open(context(reader, expected), &envelope, &keyring()).unwrap_err(),
                Error::AuthenticationFailed,
                "{case}"
            );
        }
    }

    #[test]
    fn a_different_fingerprint_reports_context_mismatch_before_any_key() {
        let unbound_bytes = hex::decode(UNBOUND_CONTEXT).unwrap();
        let record_bytes = hex::decode(RECORD_CONTEXT).unwrap();
        let unbound = context(&unbound_bytes, fingerprint(UNBOUND_FINGERPRINT));
        let record = context(&record_bytes, fingerprint(RECORD_FINGERPRINT));
        let other = context(&record_bytes, [7; 8]);
        let unbound_envelope = seal(unbound, Padding::NONE, b"secret", &keyring()).unwrap();
        let record_envelope = seal(record, Padding::NONE, b"secret", &keyring()).unwrap();

        // `check` takes no keyring: the mismatch is reported before any key is chosen.
        for (case, reader, envelope) in [
            ("unbound reads record", unbound, &record_envelope),
            ("record reads unbound", record, &unbound_envelope),
            ("other fingerprint", other, &record_envelope),
        ] {
            assert_eq!(
                check(reader, envelope).err(),
                Some(Error::ContextMismatch),
                "{case}"
            );
        }
    }

    #[test]
    fn a_resealed_fingerprint_fails_authentication() {
        // A fingerprint changed in the header keeps the context bytes.
        let bytes = hex::decode(RECORD_CONTEXT).unwrap();
        let other = [7; 8];
        let mut envelope = seal(
            context(&bytes, fingerprint(RECORD_FINGERPRINT)),
            Padding::NONE,
            b"secret",
            &keyring(),
        )
        .unwrap();
        envelope[23..31].copy_from_slice(&other);

        assert_eq!(
            open(context(&bytes, other), &envelope, &keyring()).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn an_unknown_key_is_reported_after_the_check() {
        let bytes = hex::decode(UNBOUND_CONTEXT).unwrap();
        let envelope = seal(
            context(&bytes, fingerprint(UNBOUND_FINGERPRINT)),
            Padding::NONE,
            b"secret",
            &keyring(),
        )
        .unwrap();
        let other = EncryptionKeyring::new(
            EncryptionKey::new(
                crate::key_id!("99999999-2222-4333-8444-555555555555"),
                [0x11; 32],
            ),
            [],
        )
        .unwrap();

        assert_eq!(
            open(
                context(&bytes, fingerprint(UNBOUND_FINGERPRINT)),
                &envelope,
                &other
            )
            .unwrap_err(),
            Error::UnknownEncryptionKey(vector_key().id())
        );
    }

    #[test]
    fn padded_format_2_vector_is_stable() {
        let bytes = hex::decode(UNBOUND_CONTEXT).unwrap();
        let envelope = seal_with_nonce(
            context(&bytes, fingerprint(UNBOUND_FINGERPRINT)),
            Padding::block(16),
            b"cryptbox vector",
            &vector_key(),
            vector_nonce(),
        )
        .unwrap();

        assert_eq!(
            hex::encode(envelope),
            "4342580002010111111111222243338444555555555555502de8fcfb838c80000102030405060708090a0b0c0d0e0f10111213141516173a8e058803722f56b0ffc9ecbbb7e3c5bd94437a46143e4373c11bdfdfbc47b4"
        );
    }

    #[test]
    fn format_2_vector_is_stable() {
        let bytes = hex::decode(UNBOUND_CONTEXT).unwrap();
        let envelope = seal_with_nonce(
            context(&bytes, fingerprint(UNBOUND_FINGERPRINT)),
            Padding::NONE,
            b"cryptbox vector",
            &vector_key(),
            vector_nonce(),
        )
        .unwrap();

        assert_eq!(
            hex::encode(envelope),
            "4342580002010011111111222243338444555555555555502de8fcfb838c80000102030405060708090a0b0c0d0e0f10111213141516173a8e058803722f56b0ffc9ecbbb7e30624c444239c62d73be5eac7459c548f"
        );
    }
}
