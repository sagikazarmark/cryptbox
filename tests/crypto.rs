//! Public-boundary tests for encryption, field binding, and key rotation.

use cryptbox::EncryptionKey;
use cryptbox::{
    EncryptionKeyring, Error, Field, FieldOnly, KeyId, Padding, Raw, Sealed, Utf8, decrypt,
    encrypt, field_id, inspect_ciphertext, is_ciphertext, key_id, needs_reencryption, reencrypt,
};

const OLD_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const CURRENT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");

fn key(id: KeyId, byte: u8) -> EncryptionKey {
    EncryptionKey::new(id, [byte; 32])
}

fn keyring(current_id: KeyId, current_byte: u8) -> EncryptionKeyring {
    EncryptionKeyring::new(key(current_id, current_byte), []).unwrap()
}

struct EmailField;

impl Field for EmailField {
    const ID: cryptbox::FieldId = field_id!("30000000-0000-4000-8000-000000000003");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct PhoneField;

impl Field for PhoneField {
    const ID: cryptbox::FieldId = field_id!("40000000-0000-4000-8000-000000000004");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

#[test]
fn encryption_is_randomized_and_authenticates_the_envelope() {
    let keys = keyring(CURRENT_KEY_ID, 7);

    let first = encrypt(EmailField::ID, Padding::NONE, b"same plaintext", &keys).unwrap();
    let second = encrypt(EmailField::ID, Padding::NONE, b"same plaintext", &keys).unwrap();

    assert_ne!(first, second);
    assert_eq!(
        decrypt(EmailField::ID, &first, &keys).unwrap().as_slice(),
        b"same plaintext"
    );

    let info = inspect_ciphertext(&first).unwrap();
    assert_eq!(info.format_version(), 2);
    assert_eq!(info.padded(), Some(false));
    assert_eq!(info.suite_id().get(), 1);
    assert_eq!(info.key_id(), CURRENT_KEY_ID);

    let mut tampered = first;
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        decrypt(EmailField::ID, &tampered, &keys),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn empty_plaintext_is_a_valid_authenticated_message() {
    let keys = keyring(CURRENT_KEY_ID, 9);
    let ciphertext = encrypt(EmailField::ID, Padding::NONE, b"", &keys).unwrap();

    assert_eq!(ciphertext.len(), 63);
    assert!(is_ciphertext(&ciphertext));
    assert!(
        decrypt(EmailField::ID, &ciphertext, &keys)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn padded_encryption_records_the_flag_and_decryption_removes_the_padding() {
    let keys = keyring(CURRENT_KEY_ID, 9);
    let ciphertext = encrypt(EmailField::ID, Padding::block(16), b"padded", &keys).unwrap();

    assert_eq!(ciphertext.len(), 63 + 16);
    assert_eq!(
        inspect_ciphertext(&ciphertext).unwrap().padded(),
        Some(true)
    );
    assert_eq!(
        decrypt(EmailField::ID, &ciphertext, &keys)
            .unwrap()
            .as_slice(),
        b"padded"
    );
}

#[test]
fn flipping_the_padding_flag_fails_authentication() {
    let keys = keyring(CURRENT_KEY_ID, 9);

    for padding in [Padding::NONE, Padding::block(16)] {
        let mut ciphertext = encrypt(EmailField::ID, padding, b"flagged", &keys).unwrap();
        ciphertext[6] ^= 0x01;

        assert_eq!(
            decrypt(EmailField::ID, &ciphertext, &keys),
            Err(Error::AuthenticationFailed)
        );
    }
}

#[test]
fn reserved_flag_bits_are_rejected_before_authentication() {
    let keys = keyring(CURRENT_KEY_ID, 9);

    for bit in [0x04, 0x08, 0x10, 0x20, 0x40, 0x80] {
        let mut ciphertext = encrypt(EmailField::ID, Padding::NONE, b"flagged", &keys).unwrap();
        ciphertext[6] |= bit;

        assert_eq!(inspect_ciphertext(&ciphertext), Err(Error::InvalidEnvelope));
        assert_eq!(
            decrypt(EmailField::ID, &ciphertext, &keys),
            Err(Error::InvalidEnvelope)
        );
    }
}

#[test]
fn field_only_envelopes_carry_no_shape_fingerprint() {
    let keys = keyring(CURRENT_KEY_ID, 9);
    let ciphertext = encrypt(EmailField::ID, Padding::NONE, b"field only", &keys).unwrap();

    assert_eq!(
        inspect_ciphertext(&ciphertext).unwrap().shape_fingerprint(),
        None
    );
}

#[test]
fn a_scoped_flag_on_a_field_only_envelope_reports_binding_mismatch() {
    let keys = keyring(CURRENT_KEY_ID, 9);
    let mut ciphertext = encrypt(
        EmailField::ID,
        Padding::NONE,
        b"long enough to reparse",
        &keys,
    )
    .unwrap();
    // Reparsed as scoped: the first nonce bytes now read as a shape fingerprint.
    ciphertext[6] |= 0x02;

    assert!(
        inspect_ciphertext(&ciphertext)
            .unwrap()
            .shape_fingerprint()
            .is_some()
    );
    assert_eq!(
        decrypt(EmailField::ID, &ciphertext, &keys),
        Err(Error::BindingMismatch)
    );
    assert_eq!(
        needs_reencryption(EmailField::ID, Padding::NONE, &ciphertext, &keys),
        Err(Error::BindingMismatch)
    );
}

#[test]
fn a_scoped_flag_without_room_for_the_fingerprint_is_malformed() {
    let keys = keyring(CURRENT_KEY_ID, 9);
    let mut ciphertext = encrypt(EmailField::ID, Padding::NONE, b"", &keys).unwrap();
    ciphertext[6] |= 0x02;

    assert_eq!(inspect_ciphertext(&ciphertext), Err(Error::InvalidEnvelope));
}

#[test]
fn field_binding_rejects_cross_field_ciphertext_substitution() {
    let keys = keyring(CURRENT_KEY_ID, 11);
    let ciphertext = encrypt(EmailField::ID, Padding::NONE, b"mark@example.com", &keys).unwrap();

    assert_eq!(
        decrypt(EmailField::ID, &ciphertext, &keys)
            .unwrap()
            .as_slice(),
        b"mark@example.com"
    );
    assert_eq!(
        decrypt(PhoneField::ID, &ciphertext, &keys),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn decryption_resolves_only_the_key_named_by_the_envelope() {
    let writing_keys = keyring(OLD_KEY_ID, 13);
    let ciphertext = encrypt(EmailField::ID, Padding::NONE, b"historical", &writing_keys).unwrap();
    let unrelated_keys = keyring(CURRENT_KEY_ID, 17);

    assert_eq!(
        decrypt(EmailField::ID, &ciphertext, &unrelated_keys),
        Err(Error::UnknownEncryptionKey(OLD_KEY_ID))
    );
}

#[test]
fn changing_a_key_id_to_another_readable_generation_fails_authentication() {
    let old = key(OLD_KEY_ID, 13);
    let writing_keys = EncryptionKeyring::new(old.clone(), []).unwrap();
    let mut ciphertext = encrypt(
        EmailField::ID,
        Padding::NONE,
        b"bound to metadata",
        &writing_keys,
    )
    .unwrap();
    let current = key(CURRENT_KEY_ID, 17);
    let rotated = EncryptionKeyring::new(current, [old]).unwrap();

    ciphertext[7..23].copy_from_slice(CURRENT_KEY_ID.as_bytes());

    assert_eq!(
        decrypt(EmailField::ID, &ciphertext, &rotated),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn rotation_preserves_reads_and_reencryption_uses_the_current_key() {
    let old = key(OLD_KEY_ID, 19);
    let old_keys = EncryptionKeyring::new(old.clone(), []).unwrap();
    let ciphertext = encrypt(EmailField::ID, Padding::NONE, b"rotate me", &old_keys).unwrap();

    let rotated = EncryptionKeyring::new(key(CURRENT_KEY_ID, 23), [old]).unwrap();
    assert_eq!(
        decrypt(EmailField::ID, &ciphertext, &rotated)
            .unwrap()
            .as_slice(),
        b"rotate me"
    );
    assert!(needs_reencryption(EmailField::ID, Padding::NONE, &ciphertext, &rotated).unwrap());

    let rewritten = reencrypt(EmailField::ID, Padding::NONE, &ciphertext, &rotated).unwrap();
    assert_eq!(
        inspect_ciphertext(&rewritten).unwrap().key_id(),
        CURRENT_KEY_ID
    );
    assert!(!needs_reencryption(EmailField::ID, Padding::NONE, &rewritten, &rotated).unwrap());
}

struct TypedEmail;

impl Field for TypedEmail {
    const ID: cryptbox::FieldId = EmailField::ID;
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
    type Indexes = ();
}

#[test]
fn sealed_values_round_trip_through_the_field_codec() {
    let keys = keyring(CURRENT_KEY_ID, 29);

    let sealed: Sealed<TypedEmail> =
        Sealed::seal(&"mark@example.com".to_owned(), (), &keys).unwrap();
    assert_eq!(format!("{sealed:?}"), "Sealed([REDACTED])");
    assert_eq!(AsRef::<[u8]>::as_ref(&sealed), sealed.as_bytes());

    let sealed = Sealed::<TypedEmail>::try_from(sealed.into_bytes()).unwrap();

    assert_eq!(sealed.open((), &keys).unwrap(), "mark@example.com");
}

#[test]
fn malformed_and_unknown_envelopes_fail_strictly() {
    let keys = keyring(CURRENT_KEY_ID, 31);

    assert_eq!(
        decrypt(EmailField::ID, b"plaintext", &keys),
        Err(Error::NotCiphertext)
    );
    assert_eq!(
        Sealed::<TypedEmail>::try_from(b"plaintext".to_vec()),
        Err(Error::NotCiphertext)
    );

    let ciphertext = encrypt(EmailField::ID, Padding::NONE, b"value", &keys).unwrap();
    let mut truncated = ciphertext;
    truncated.truncate(30);
    assert_eq!(
        decrypt(EmailField::ID, &truncated, &keys),
        Err(Error::InvalidEnvelope)
    );

    let mut unsupported = encrypt(EmailField::ID, Padding::NONE, b"value", &keys).unwrap();
    unsupported[5] = 0xff;
    assert_eq!(
        decrypt(EmailField::ID, &unsupported, &keys),
        Err(Error::UnsupportedSuite(cryptbox::SuiteId::new(0xff)))
    );
}

#[test]
fn keyrings_reject_duplicate_generation_ids() {
    let duplicate = key(CURRENT_KEY_ID, 41);

    assert!(matches!(
        EncryptionKeyring::new(key(CURRENT_KEY_ID, 43), [duplicate]),
        Err(Error::DuplicateEncryptionKey(id)) if id == CURRENT_KEY_ID
    ));
}

#[test]
fn keyrings_return_the_configured_current_generation() {
    let keys = keyring(CURRENT_KEY_ID, 37);

    assert_eq!(keys.current().id(), CURRENT_KEY_ID);
}
