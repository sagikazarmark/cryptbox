mod format;
mod suite;

use zeroize::Zeroizing;

use crate::padding::unpad;
use crate::{EncryptionKeyring, Error, Padding};

pub(crate) use format::validated_key_id;
pub use format::{CiphertextInfo, SuiteId, is_ciphertext};
use format::{ParsedEnvelope, parse_envelope};
pub(crate) use suite::EnvelopeBinding;
use suite::SupportedSuite;
pub use suite::xchacha20_poly1305::EXPERIMENTAL_XCHACHA20_POLY1305;

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
    let suite = SupportedSuite::from_id(envelope.info.suite_id())?;
    suite.validate_payload(envelope.suite_payload)?;

    Ok((suite, envelope))
}

/// Pads `plaintext` with `padding` and seals it under `binding` with the
/// current key of `keyring`.
///
/// The envelope records whether the payload is padded, so opening removes the
/// padding whatever policy is in effect then.
pub(crate) fn seal(
    binding: EnvelopeBinding<'_>,
    padding: Padding,
    plaintext: &[u8],
    keyring: &EncryptionKeyring,
) -> Result<Vec<u8>, Error> {
    let plaintext = padding.pad(plaintext)?;

    SupportedSuite::ACTIVE.seal(binding, &plaintext, keyring.current())
}

/// An envelope that parsed and whose fingerprint matches the binding a reader
/// expects, before any key is looked up.
pub(crate) struct CheckedEnvelope<'a> {
    suite: SupportedSuite,
    parsed: ParsedEnvelope<'a>,
    binding: EnvelopeBinding<'a>,
}

/// Parses `ciphertext` and compares its fingerprint with `binding`'s.
// The expected fingerprint always comes from the reader, never from the
// envelope; the stored one only names the mismatch before any key or AEAD work.
// See ../docs/wire-format.md#reader-rules.
pub(crate) fn check<'a>(
    binding: EnvelopeBinding<'a>,
    ciphertext: &'a [u8],
) -> Result<CheckedEnvelope<'a>, Error> {
    let (suite, parsed) = parse_supported(ciphertext)?;
    if parsed.info.binding_fingerprint() != binding.fingerprint() {
        return Err(Error::BindingMismatch);
    }

    Ok(CheckedEnvelope {
        suite,
        parsed,
        binding,
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
        let plaintext = self.suite.open(self.binding, &self.parsed, key)?;

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

        info.suite_id() != SupportedSuite::ACTIVE.id()
            || info.key_id() != keyring.current().id()
            || info.padded() != padding.is_padded()
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::suite::xchacha20_poly1305::{NONCE_LEN, XChaCha20Poly1305};
    use super::{EnvelopeBinding, check, inspect_ciphertext, seal};
    use crate::{EncryptionKey, EncryptionKeyring, Error, Padding};

    // Seals under suite 1 with a fixed nonce, as the known-answer vectors need.
    fn seal_with_nonce(
        binding: EnvelopeBinding<'_>,
        padding: Padding,
        plaintext: &[u8],
        key: &EncryptionKey,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Vec<u8>, Error> {
        XChaCha20Poly1305::seal_with_nonce(binding, &padding.pad(plaintext)?, key, nonce)
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

    // The envelope does not interpret the binding: the vectors take its bytes
    // and fingerprint as given. The binding module pins how they are encoded.
    fn binding(bytes: &[u8], fingerprint: [u8; 8]) -> EnvelopeBinding<'_> {
        EnvelopeBinding::new(bytes, fingerprint)
    }

    fn open(
        binding: EnvelopeBinding<'_>,
        envelope: &[u8],
        keyring: &EncryptionKeyring,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        check(binding, envelope)?.open(keyring)
    }

    #[test]
    fn scoped_vector_is_stable() {
        let bytes = hex::decode(SCOPED_BINDING).unwrap();
        let envelope = seal_with_nonce(
            binding(&bytes, fingerprint(SCOPED_FINGERPRINT)),
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
                // Binding fingerprint, then the nonce.
                "81f8614d4eacb5fb",
                "000102030405060708090a0b0c0d0e0f1011121314151617",
            )
        );
        assert_eq!(hex::encode(envelope), SCOPED_VECTOR);
    }

    #[test]
    fn scoped_record_vector_is_stable() {
        let bytes = hex::decode(SCOPED_RECORD_BINDING).unwrap();
        let envelope = seal_with_nonce(
            binding(&bytes, fingerprint(SCOPED_RECORD_FINGERPRINT)),
            Padding::NONE,
            b"cryptbox vector",
            &vector_key(),
            vector_nonce(),
        )
        .unwrap();

        assert_eq!(hex::encode(&envelope[23..31]), SCOPED_RECORD_FINGERPRINT);
        assert_eq!(hex::encode(envelope), SCOPED_RECORD_VECTOR);
    }

    // docs/wire-format.md#provisional-scoped-vectors
    const FIELD_BINDING: &str = "123456781234423482341234567890ab000000";
    // The empty declaration's fingerprint, which a field-only binding carries.
    const FIELD_FINGERPRINT: &str = "5d86321261d64380";
    const SCOPED_BINDING: &str = "123456781234423482341234567890ab0000021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31";
    const SCOPED_RECORD_BINDING: &str = "123456781234423482341234567890ab0200000008000000000000000700021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31";
    const SCOPED_FINGERPRINT: &str = "81f8614d4eacb5fb";
    const SCOPED_RECORD_FINGERPRINT: &str = "58bfd20ea23bac14";
    const SCOPED_VECTOR: &str = "434258000201001111111122224333844455555555555581f8614d4eacb5fb000102030405060708090a0b0c0d0e0f1011121314151617b887bad9f184f35041b40c3cce0d45ba321676cb9f5d3c39db8f90751b842f";
    const SCOPED_RECORD_VECTOR: &str = "434258000201001111111122224333844455555555555558bfd20ea23bac14000102030405060708090a0b0c0d0e0f1011121314151617663bba5e4bb37a3df899258809ff56a6b4a7041d51f117d26698875eb9f262";

    #[test]
    fn scoped_vectors_open_under_their_binding() {
        for (vector, bytes, expected) in [
            (SCOPED_VECTOR, SCOPED_BINDING, SCOPED_FINGERPRINT),
            (
                SCOPED_RECORD_VECTOR,
                SCOPED_RECORD_BINDING,
                SCOPED_RECORD_FINGERPRINT,
            ),
        ] {
            let envelope = hex::decode(vector).unwrap();
            let bytes = hex::decode(bytes).unwrap();

            assert_eq!(
                open(
                    binding(&bytes, fingerprint(expected)),
                    &envelope,
                    &keyring()
                )
                .unwrap()
                .as_slice(),
                b"cryptbox vector"
            );
        }
    }

    #[test]
    fn a_sealed_value_round_trips_and_reports_its_fingerprint() {
        let bytes = hex::decode(SCOPED_RECORD_BINDING).unwrap();
        let binding = binding(&bytes, fingerprint(SCOPED_RECORD_FINGERPRINT));
        let envelope = seal(binding, Padding::NONE, b"secret", &keyring()).unwrap();

        assert_eq!(
            inspect_ciphertext(&envelope).unwrap().binding_fingerprint(),
            fingerprint(SCOPED_RECORD_FINGERPRINT)
        );
        assert_eq!(
            open(binding, &envelope, &keyring()).unwrap().as_slice(),
            b"secret"
        );
    }

    #[test]
    fn every_header_carries_the_fingerprint() {
        let bytes = hex::decode(FIELD_BINDING).unwrap();
        let expected = fingerprint(FIELD_FINGERPRINT);
        let envelope = seal(
            binding(&bytes, expected),
            Padding::NONE,
            b"secret",
            &keyring(),
        )
        .unwrap();

        assert_eq!(envelope.len(), 55 + 6 + 16);
        assert_eq!(
            inspect_ciphertext(&envelope).unwrap().binding_fingerprint(),
            expected
        );
    }

    #[test]
    fn other_binding_bytes_fail_authentication() {
        let bytes = hex::decode(SCOPED_RECORD_BINDING).unwrap();
        let expected = fingerprint(SCOPED_RECORD_FINGERPRINT);
        let envelope = seal(
            binding(&bytes, expected),
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
                open(binding(reader, expected), &envelope, &keyring()).unwrap_err(),
                Error::AuthenticationFailed,
                "{case}"
            );
        }
    }

    #[test]
    fn a_different_fingerprint_reports_binding_mismatch_before_any_key() {
        let field_bytes = hex::decode(FIELD_BINDING).unwrap();
        let scoped_bytes = hex::decode(SCOPED_BINDING).unwrap();
        let field_only = binding(&field_bytes, fingerprint(FIELD_FINGERPRINT));
        let scoped = binding(&scoped_bytes, fingerprint(SCOPED_FINGERPRINT));
        let with_record = binding(&scoped_bytes, fingerprint(SCOPED_RECORD_FINGERPRINT));
        let field_only_envelope = seal(field_only, Padding::NONE, b"secret", &keyring()).unwrap();
        let scoped_envelope = seal(scoped, Padding::NONE, b"secret", &keyring()).unwrap();

        // `check` takes no keyring: the mismatch is reported before any key is chosen.
        for (case, reader, envelope) in [
            ("field-only reads scoped", field_only, &scoped_envelope),
            ("scoped reads field-only", scoped, &field_only_envelope),
            ("other fingerprint", with_record, &scoped_envelope),
        ] {
            assert_eq!(
                check(reader, envelope).err(),
                Some(Error::BindingMismatch),
                "{case}"
            );
        }
    }

    #[test]
    fn a_resealed_fingerprint_fails_authentication() {
        // A role change keeps the binding bytes but changes the fingerprint.
        let bytes = hex::decode(SCOPED_BINDING).unwrap();
        let other = [7; 8];
        let mut envelope = seal(
            binding(&bytes, fingerprint(SCOPED_FINGERPRINT)),
            Padding::NONE,
            b"secret",
            &keyring(),
        )
        .unwrap();
        envelope[23..31].copy_from_slice(&other);

        assert_eq!(
            open(binding(&bytes, other), &envelope, &keyring()).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn an_unknown_key_is_reported_after_the_check() {
        let bytes = hex::decode(FIELD_BINDING).unwrap();
        let envelope = seal(
            binding(&bytes, fingerprint(FIELD_FINGERPRINT)),
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
                binding(&bytes, fingerprint(FIELD_FINGERPRINT)),
                &envelope,
                &other
            )
            .unwrap_err(),
            Error::UnknownEncryptionKey(vector_key().id())
        );
    }

    #[test]
    fn experimental_padded_format_2_vector_is_stable() {
        let bytes = hex::decode(FIELD_BINDING).unwrap();
        let envelope = seal_with_nonce(
            binding(&bytes, fingerprint(FIELD_FINGERPRINT)),
            Padding::block(16),
            b"cryptbox vector",
            &vector_key(),
            vector_nonce(),
        )
        .unwrap();

        assert_eq!(
            hex::encode(envelope),
            "43425800020101111111112222433384445555555555555d86321261d64380000102030405060708090a0b0c0d0e0f1011121314151617ef0521ab2e6f330235d572ee4da1419a17b89c9d88cb6cca540c1c17f5917f44"
        );
    }

    #[test]
    fn experimental_format_2_vector_is_stable() {
        let bytes = hex::decode(FIELD_BINDING).unwrap();
        let envelope = seal_with_nonce(
            binding(&bytes, fingerprint(FIELD_FINGERPRINT)),
            Padding::NONE,
            b"cryptbox vector",
            &vector_key(),
            vector_nonce(),
        )
        .unwrap();

        assert_eq!(
            hex::encode(envelope),
            "43425800020100111111112222433384445555555555555d86321261d64380000102030405060708090a0b0c0d0e0f1011121314151617ef0521ab2e6f330235d572ee4da1415b33cbc7bfb19bc11afc1b31e3f3075b"
        );
    }
}
