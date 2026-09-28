mod format;
mod suite;

use zeroize::Zeroizing;

use crate::padding::unpad;
use crate::{BindingDomain, EncryptionKeySource, EncryptionKeyring, Error, FieldId, Padding};

pub(crate) use format::validated_key_id;
pub use format::{CiphertextInfo, is_ciphertext};
use format::{FORMAT_VERSION, ParsedEnvelope, parse_envelope};
pub use suite::EXPERIMENTAL_XCHACHA20_POLY1305;
use suite::Suite;

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
fn parse_supported(bytes: &[u8]) -> Result<(Suite, ParsedEnvelope<'_>), Error> {
    let envelope = parse_envelope(bytes)?;
    let suite = Suite::from_id(envelope.info.suite_id())?;
    suite.validate_payload(envelope.suite_payload)?;

    Ok((suite, envelope))
}

/// Encrypts opaque plaintext bytes for `field` with the current key of its keyring.
///
/// `padding` is applied before encryption and recorded in the authenticated
/// envelope, so [`decrypt`] removes it regardless of the policy in effect when
/// the value is read.
///
/// # Errors
///
/// Returns an error for unavailable keys, plaintext that
/// does not fit fixed padding, failed OS randomness, or messages longer than
/// the active suite's 274,877,906,879-byte limit.
pub fn encrypt(
    field: FieldId,
    padding: Padding,
    plaintext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Vec<u8>, Error> {
    encrypt_bound(&BindingDomain::field(field), padding, plaintext, keys)
}

/// Encrypts under `domain`, recording a scoped binding's shape fingerprint.
pub(crate) fn encrypt_bound(
    domain: &BindingDomain,
    padding: Padding,
    plaintext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Vec<u8>, Error> {
    let key = keyring(keys, domain)?.current().clone();
    let plaintext = padding.pad(plaintext)?;

    Suite::ACTIVE.seal(&plaintext, domain.fingerprint(), domain.as_bytes(), &key)
}

/// Authenticates and decrypts opaque ciphertext bytes.
///
/// The keyring is asked only for the exact key ID named by the envelope.
/// Success authenticates the envelope under the supplied key and `field`;
/// it does not establish freshness, row identity, or codec validity.
/// Padding recorded by the envelope is removed. A format 1 envelope does not
/// record padding, so its payload is returned as stored.
/// Use [`crate::Sealed::open`] to also decode a typed value.
///
/// # Errors
///
/// Returns a structured envelope, key-source,
/// unknown-key, authentication, or padding error. A different field and
/// modified ciphertext both report authentication failure. An envelope sealed
/// with a scoped binding reports [`Error::BindingMismatch`].
pub fn decrypt(
    field: FieldId,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Zeroizing<Vec<u8>>, Error> {
    decrypt_with_policy(field, Padding::NONE, ciphertext, keys)
}

/// Decrypts and unpads, reading a format 1 payload with the field's `padding`.
pub(crate) fn decrypt_with_policy(
    field: FieldId,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Zeroizing<Vec<u8>>, Error> {
    decrypt_bound(&BindingDomain::field(field), padding, ciphertext, keys)
}

/// Decrypts under the expected `domain`, reading a format 1 payload with `padding`.
pub(crate) fn decrypt_bound(
    domain: &BindingDomain,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (suite, parsed) = parse_supported(ciphertext)?;
    check_shape(parsed.info, domain)?;
    let key = keyring(keys, domain)?
        .get(parsed.info.key_id())
        .cloned()
        .ok_or(Error::UnknownEncryptionKey(parsed.info.key_id()))?;
    let plaintext = suite.open(&parsed, domain.as_bytes(), &key)?;

    // Only the authenticated flag decides unpadding; the current policy must not,
    // or policy changes would silently misread stored values.
    // See ../../docs/adr/0002-authenticated-padding-flag.md.
    match parsed.info.padded() {
        Some(true) => unpad(plaintext),
        Some(false) => Ok(plaintext),
        None => padding.unpad(plaintext),
    }
}

// Asks the source for the keyring of the domain's field and key scope.
fn keyring(
    keys: &(impl EncryptionKeySource + ?Sized),
    domain: &BindingDomain,
) -> Result<EncryptionKeyring, Error> {
    keys.encryption_keyring(domain.field_id(), domain.key_scope())
}

// The expected shape always comes from the reader, never from the envelope; the
// fingerprint only names the mismatch before any key or AEAD work.
// See ../../docs/wire-format.md#reader-rules.
fn check_shape(info: CiphertextInfo, domain: &BindingDomain) -> Result<(), Error> {
    if info.shape_fingerprint() != domain.fingerprint() {
        return Err(Error::BindingMismatch);
    }

    Ok(())
}

/// Reports whether an envelope differs from what `field` currently writes.
///
/// That is an older format, a non-active suite, a non-current key, or a padding
/// flag that disagrees with `padding`. Padding parameters are not recorded, so
/// changing only a block size or fixed length is not reported.
///
/// This reads unauthenticated metadata and does not decrypt the payload.
/// A `false` result does not establish that the ciphertext can be
/// authenticated or decoded.
///
/// # Errors
///
/// Returns an error for malformed or unsupported envelopes, unavailable
/// keys. An envelope sealed with a scoped binding
/// reports [`Error::BindingMismatch`].
pub fn needs_reencryption(
    field: FieldId,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<bool, Error> {
    needs_reencryption_bound(&BindingDomain::field(field), padding, ciphertext, keys)
}

/// Reports whether an envelope differs from what `domain` currently writes.
pub(crate) fn needs_reencryption_bound(
    domain: &BindingDomain,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<bool, Error> {
    let (_, envelope) = parse_supported(ciphertext)?;
    let info = envelope.info;
    check_shape(info, domain)?;
    let current = keyring(keys, domain)?.current().clone();

    Ok(info.format_version() != FORMAT_VERSION
        || info.suite_id() != Suite::ACTIVE.id()
        || info.key_id() != current.id()
        || info.padded() != Some(padding.is_padded()))
}

/// Decrypts an envelope and encrypts it as `field` currently writes it.
///
/// The value is rewritten with the current format, active suite, current key,
/// and `padding`, so a sweep can enable or disable padding. A format 1 payload,
/// which does not record padding, is read with `padding`.
///
/// # Errors
///
/// Returns any decryption, padding, or encryption error.
pub fn reencrypt(
    field: FieldId,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Vec<u8>, Error> {
    let plaintext = decrypt_with_policy(field, padding, ciphertext, keys)?;

    encrypt(field, padding, &plaintext, keys)
}

#[cfg(test)]
mod tests {
    use super::suite::seal_with_nonce;
    use super::{decrypt_bound, encrypt_bound, inspect_ciphertext};
    use crate::binding::{BindingShape, PartKind, PartRole, PartSpec, PartValue};
    use crate::crypto::NONCE_LEN;
    use crate::{
        BindingDomain, EncryptionKey, EncryptionKeySource, EncryptionKeyring, Error, FieldId,
        KeyId, KeyScope, Padding,
    };

    const VECTOR_FIELD: FieldId =
        FieldId::from_uuid_literal("12345678-1234-4234-8234-1234567890ab");

    const TENANT: PartSpec = PartSpec::new([0x11; 16], PartKind::Uuid, PartRole::Keys);
    const WORKSPACE: PartSpec = PartSpec::new([0x22; 16], PartKind::Bytes, PartRole::Bound);
    const SCOPE: [PartSpec; 2] = [TENANT, WORKSPACE];

    fn vector_key() -> EncryptionKey {
        EncryptionKey::new(
            KeyId::from_uuid_literal("11111111-2222-4333-8444-555555555555"),
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

    fn scope(workspace: &[u8], record: Option<PartValue<'_>>) -> BindingDomain {
        BindingDomain::scoped(
            VECTOR_FIELD,
            BindingShape::new(&SCOPE, record.is_some()),
            &[PartValue::Uuid([0x33; 16]), PartValue::Bytes(workspace)],
            record,
        )
        .unwrap()
    }

    #[test]
    fn scoped_vector_is_stable() {
        let domain = scope(b"ws-1", None);
        let envelope = seal_with_nonce(
            b"cryptbox vector",
            Padding::NONE,
            &domain,
            &vector_key(),
            vector_nonce(),
        )
        .unwrap();

        assert_eq!(hex::encode(domain.as_bytes()), SCOPED_BINDING);
        assert_eq!(
            hex::encode(&envelope[..55]),
            concat!(
                "4342580002010211111111222243338444555555555555",
                // Shape fingerprint, then the nonce.
                "cda083fe6eae1bf1",
                "000102030405060708090a0b0c0d0e0f1011121314151617",
            )
        );
        assert_eq!(hex::encode(envelope), SCOPED_VECTOR);
    }

    #[test]
    fn scoped_record_vector_is_stable() {
        let domain = scope(b"ws-1", Some(PartValue::I64(7)));
        let envelope = seal_with_nonce(
            b"cryptbox vector",
            Padding::NONE,
            &domain,
            &vector_key(),
            vector_nonce(),
        )
        .unwrap();

        assert_eq!(hex::encode(domain.as_bytes()), SCOPED_RECORD_BINDING);
        assert_eq!(hex::encode(&envelope[23..31]), "505a9cd2bc286636");
        assert_eq!(hex::encode(envelope), SCOPED_RECORD_VECTOR);
    }

    // docs/wire-format.md#provisional-scoped-vectors
    const SCOPED_BINDING: &str = "02123456781234423482341234567890ab0000021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31";
    const SCOPED_RECORD_BINDING: &str = "02123456781234423482341234567890ab0200000008000000000000000700021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31";
    const SCOPED_VECTOR: &str = "4342580002010211111111222243338444555555555555cda083fe6eae1bf1000102030405060708090a0b0c0d0e0f1011121314151617b51d411fdf173c5725d9000dae571d2bc413649bd09198dd576ab7879aeb42";
    const SCOPED_RECORD_VECTOR: &str = "4342580002010211111111222243338444555555555555505a9cd2bc286636000102030405060708090a0b0c0d0e0f10111213141516172619b76ce657aac8910c65d99b49a02880a201078edb80702123597f908f71";

    #[test]
    fn scoped_vectors_decrypt_under_their_binding() {
        for (vector, domain) in [
            (SCOPED_VECTOR, scope(b"ws-1", None)),
            (
                SCOPED_RECORD_VECTOR,
                scope(b"ws-1", Some(PartValue::I64(7))),
            ),
        ] {
            let envelope = hex::decode(vector).unwrap();

            assert_eq!(
                decrypt_bound(&domain, Padding::NONE, &envelope, &keyring())
                    .unwrap()
                    .as_slice(),
                b"cryptbox vector"
            );
        }
    }

    #[test]
    fn scoped_value_round_trips_and_reports_its_fingerprint() {
        let domain = scope(b"ws-1", Some(PartValue::I64(7)));
        let envelope = encrypt_bound(&domain, Padding::NONE, b"secret", &keyring()).unwrap();

        assert_eq!(
            inspect_ciphertext(&envelope).unwrap().shape_fingerprint(),
            domain.fingerprint()
        );
        assert_eq!(
            decrypt_bound(&domain, Padding::NONE, &envelope, &keyring())
                .unwrap()
                .as_slice(),
            b"secret"
        );
    }

    #[test]
    fn field_only_envelopes_carry_no_fingerprint() {
        let domain = BindingDomain::field(VECTOR_FIELD);
        let envelope = encrypt_bound(&domain, Padding::NONE, b"secret", &keyring()).unwrap();

        assert_eq!(envelope.len(), 47 + 6 + 16);
        assert_eq!(
            inspect_ciphertext(&envelope).unwrap().shape_fingerprint(),
            None
        );
    }

    #[test]
    fn different_values_fail_authentication() {
        let envelope = encrypt_bound(
            &scope(b"ws-1", Some(PartValue::I64(7))),
            Padding::NONE,
            b"secret",
            &keyring(),
        )
        .unwrap();

        for (case, reader) in [
            ("part value", scope(b"ws-2", Some(PartValue::I64(7)))),
            ("record", scope(b"ws-1", Some(PartValue::I64(8)))),
            (
                "record kind",
                scope(b"ws-1", Some(PartValue::Uuid([7; 16]))),
            ),
        ] {
            assert_eq!(
                decrypt_bound(&reader, Padding::NONE, &envelope, &keyring()).unwrap_err(),
                Error::AuthenticationFailed,
                "{case}"
            );
        }
    }

    #[test]
    fn a_different_shape_reports_binding_mismatch() {
        let field_only = BindingDomain::field(VECTOR_FIELD);
        let scoped = scope(b"ws-1", None);
        let with_record = scope(b"ws-1", Some(PartValue::I64(7)));
        let field_only_envelope =
            encrypt_bound(&field_only, Padding::NONE, b"secret", &keyring()).unwrap();
        let scoped_envelope = encrypt_bound(&scoped, Padding::NONE, b"secret", &keyring()).unwrap();

        for (case, reader, envelope) in [
            ("FieldOnly reads scoped", &field_only, &scoped_envelope),
            ("scoped reads FieldOnly", &scoped, &field_only_envelope),
            ("record flag", &with_record, &scoped_envelope),
        ] {
            assert_eq!(
                decrypt_bound(reader, Padding::NONE, envelope, &keyring()).unwrap_err(),
                Error::BindingMismatch,
                "{case}"
            );
        }
    }

    #[test]
    fn a_changed_fingerprint_reports_binding_mismatch_before_key_lookup() {
        struct NoKeys;

        impl EncryptionKeySource for NoKeys {
            fn encryption_keyring(
                &self,
                _: FieldId,
                _: &KeyScope,
            ) -> Result<EncryptionKeyring, Error> {
                Err(Error::KeysUnavailable)
            }
        }

        let domain = scope(b"ws-1", None);
        let mut envelope = encrypt_bound(&domain, Padding::NONE, b"secret", &keyring()).unwrap();
        envelope[23] ^= 1;

        assert_eq!(
            decrypt_bound(&domain, Padding::NONE, &envelope, &NoKeys).unwrap_err(),
            Error::BindingMismatch
        );
    }

    #[test]
    fn a_resealed_fingerprint_fails_authentication() {
        // A role change keeps the binding bytes but changes the fingerprint.
        let index_tenant = PartSpec::new([0x11; 16], PartKind::Uuid, PartRole::Index);
        let reader_shape = [index_tenant, WORKSPACE];
        let reader = BindingDomain::scoped(
            VECTOR_FIELD,
            BindingShape::new(&reader_shape, false),
            &[PartValue::Uuid([0x33; 16]), PartValue::Bytes(b"ws-1")],
            None,
        )
        .unwrap();
        let writer = scope(b"ws-1", None);
        assert_eq!(reader.as_bytes(), writer.as_bytes());

        let mut envelope = encrypt_bound(&writer, Padding::NONE, b"secret", &keyring()).unwrap();
        envelope[23..31].copy_from_slice(reader.fingerprint().unwrap().as_bytes());

        assert_eq!(
            decrypt_bound(&reader, Padding::NONE, &envelope, &keyring()).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn experimental_padded_format_2_vector_is_stable() {
        let key = EncryptionKey::new(
            KeyId::from_uuid_literal("11111111-2222-4333-8444-555555555555"),
            [0x11; 32],
        );
        let mut nonce = [0_u8; NONCE_LEN];

        for (value, byte) in nonce.iter_mut().zip(0_u8..) {
            *value = byte;
        }

        let envelope = seal_with_nonce(
            b"cryptbox vector",
            Padding::block(16),
            &BindingDomain::field(VECTOR_FIELD),
            &key,
            nonce,
        )
        .unwrap();

        assert_eq!(
            hex::encode(envelope),
            "4342580002010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f10111213141516173f7195595232290da92d72b42bb6fd489a56ec6e125f07deaa76f7502ad2613f"
        );
    }

    #[test]
    fn experimental_format_2_vector_is_stable() {
        let key = EncryptionKey::new(
            KeyId::from_uuid_literal("11111111-2222-4333-8444-555555555555"),
            [0x11; 32],
        );
        let mut nonce = [0_u8; NONCE_LEN];

        for (value, byte) in nonce.iter_mut().zip(0_u8..) {
            *value = byte;
        }

        let envelope = seal_with_nonce(
            b"cryptbox vector",
            Padding::NONE,
            &BindingDomain::field(VECTOR_FIELD),
            &key,
            nonce,
        )
        .unwrap();

        assert_eq!(
            hex::encode(envelope),
            "4342580002010011111111222243338444555555555555000102030405060708090a0b0c0d0e0f10111213141516173f7195595232290da92d72b42bb6fd4f8e9c4e8454cd34732e7966a50994cd"
        );
    }
}
