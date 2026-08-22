//! Public-boundary tests for encryption, binding, and key rotation.

use cryptbox::{
    Ciphertext, Encrypted, EncryptionProfile, Error, Field, FieldBound, GlobalKeyContext, KeyId,
    LocalEncryptionKeyring, Unbound, Utf8, decrypt, encrypt, field_id, inspect_ciphertext,
    is_ciphertext, key_id, needs_reencryption, reencrypt,
};
use cryptbox::{EncryptionKey, EncryptionKeyProvider};

const OLD_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const CURRENT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");

fn key(id: KeyId, byte: u8) -> EncryptionKey {
    EncryptionKey::new(id, [byte; 32])
}

fn keyring(current_id: KeyId, current_byte: u8) -> LocalEncryptionKeyring {
    LocalEncryptionKeyring::new(key(current_id, current_byte), []).unwrap()
}

struct EmailField;

impl Field for EmailField {
    const ID: cryptbox::FieldId = field_id!("30000000-0000-4000-8000-000000000003");
    const NAME: &'static str = "email";
}

struct PhoneField;

impl Field for PhoneField {
    const ID: cryptbox::FieldId = field_id!("40000000-0000-4000-8000-000000000004");
    const NAME: &'static str = "phone";
}

#[test]
fn encryption_is_randomized_and_authenticates_the_envelope() {
    let keys = keyring(CURRENT_KEY_ID, 7);

    let first = encrypt::<Unbound>(b"same plaintext", &(), &keys).unwrap();
    let second = encrypt::<Unbound>(b"same plaintext", &(), &keys).unwrap();

    assert_ne!(first, second);
    assert_eq!(
        decrypt::<Unbound>(&first, &(), &keys).unwrap().as_slice(),
        b"same plaintext"
    );

    let info = inspect_ciphertext(&first).unwrap();
    assert_eq!(info.format_version(), 1);
    assert_eq!(info.suite_id().get(), 1);
    assert_eq!(info.key_id(), CURRENT_KEY_ID);

    let mut tampered = first;
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        decrypt::<Unbound>(&tampered, &(), &keys),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn empty_plaintext_is_a_valid_authenticated_message() {
    let keys = keyring(CURRENT_KEY_ID, 9);
    let ciphertext = encrypt::<Unbound>(b"", &(), &keys).unwrap();

    assert_eq!(ciphertext.len(), 62);
    assert!(is_ciphertext(&ciphertext));
    assert!(
        decrypt::<Unbound>(&ciphertext, &(), &keys)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn field_binding_rejects_cross_field_ciphertext_substitution() {
    let keys = keyring(CURRENT_KEY_ID, 11);
    let ciphertext = encrypt::<FieldBound<EmailField>>(b"mark@example.com", &(), &keys).unwrap();

    assert_eq!(
        decrypt::<FieldBound<EmailField>>(&ciphertext, &(), &keys)
            .unwrap()
            .as_slice(),
        b"mark@example.com"
    );
    assert_eq!(
        decrypt::<FieldBound<PhoneField>>(&ciphertext, &(), &keys),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn decryption_resolves_only_the_key_named_by_the_envelope() {
    let writing_keys = keyring(OLD_KEY_ID, 13);
    let ciphertext = encrypt::<Unbound>(b"historical", &(), &writing_keys).unwrap();
    let unrelated_keys = keyring(CURRENT_KEY_ID, 17);

    assert_eq!(
        decrypt::<Unbound>(&ciphertext, &(), &unrelated_keys),
        Err(Error::UnknownEncryptionKey(OLD_KEY_ID))
    );
}

#[test]
fn changing_a_key_id_to_another_readable_generation_fails_authentication() {
    let old = key(OLD_KEY_ID, 13);
    let writing_keys = LocalEncryptionKeyring::new(old.clone(), []).unwrap();
    let mut ciphertext = encrypt::<Unbound>(b"bound to metadata", &(), &writing_keys).unwrap();
    let current = key(CURRENT_KEY_ID, 17);
    let rotated = LocalEncryptionKeyring::new(current, [old]).unwrap();

    ciphertext[6..22].copy_from_slice(CURRENT_KEY_ID.as_bytes());

    assert_eq!(
        decrypt::<Unbound>(&ciphertext, &(), &rotated),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn rotation_preserves_reads_and_reencryption_uses_the_current_key() {
    let old = key(OLD_KEY_ID, 19);
    let old_keys = LocalEncryptionKeyring::new(old.clone(), []).unwrap();
    let ciphertext = encrypt::<Unbound>(b"rotate me", &(), &old_keys).unwrap();

    let rotated = LocalEncryptionKeyring::new(key(CURRENT_KEY_ID, 23), [old]).unwrap();
    assert_eq!(
        decrypt::<Unbound>(&ciphertext, &(), &rotated)
            .unwrap()
            .as_slice(),
        b"rotate me"
    );
    assert!(needs_reencryption(&ciphertext, &rotated).unwrap());

    let rewritten = reencrypt::<Unbound>(&ciphertext, &(), &rotated).unwrap();
    assert_eq!(
        inspect_ciphertext(&rewritten).unwrap().key_id(),
        CURRENT_KEY_ID
    );
    assert!(!needs_reencryption(&rewritten, &rotated).unwrap());
}

struct EmailProfile;

impl EncryptionProfile<String> for EmailProfile {
    type Binding = FieldBound<EmailField>;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = cryptbox::NoPadding;
}

#[test]
fn typed_ciphertext_round_trips_through_the_profile_codec() {
    let keys = keyring(CURRENT_KEY_ID, 29);
    let value = Encrypted::<_, EmailProfile>::new("mark@example.com".to_owned());

    let ciphertext: Ciphertext<String, EmailProfile> = value.encrypt_with(&(), &keys).unwrap();
    assert_eq!(format!("{ciphertext:?}"), "Ciphertext([REDACTED])");
    assert_eq!(AsRef::<[u8]>::as_ref(&ciphertext), ciphertext.as_bytes());

    let ciphertext = Ciphertext::<String, EmailProfile>::try_from(ciphertext.into_bytes()).unwrap();

    let decrypted = ciphertext.decrypt_with(&(), &keys).unwrap();
    assert_eq!(decrypted.expose_secret(), "mark@example.com");
}

#[test]
fn malformed_and_unknown_envelopes_fail_strictly() {
    let keys = keyring(CURRENT_KEY_ID, 31);

    assert_eq!(
        decrypt::<Unbound>(b"plaintext", &(), &keys),
        Err(Error::NotCiphertext)
    );
    assert_eq!(
        Ciphertext::<String, EmailProfile>::try_from(b"plaintext".to_vec()),
        Err(Error::NotCiphertext)
    );

    let ciphertext = encrypt::<Unbound>(b"value", &(), &keys).unwrap();
    let mut truncated = ciphertext;
    truncated.truncate(30);
    assert_eq!(
        decrypt::<Unbound>(&truncated, &(), &keys),
        Err(Error::InvalidEnvelope)
    );

    let mut unsupported = encrypt::<Unbound>(b"value", &(), &keys).unwrap();
    unsupported[5] = 0xff;
    assert_eq!(
        decrypt::<Unbound>(&unsupported, &(), &keys),
        Err(Error::UnsupportedSuite(cryptbox::SuiteId::new(0xff)))
    );
}

#[test]
fn keyrings_reject_duplicate_generation_ids() {
    let duplicate = key(CURRENT_KEY_ID, 41);

    assert!(matches!(
        LocalEncryptionKeyring::new(key(CURRENT_KEY_ID, 43), [duplicate]),
        Err(Error::DuplicateEncryptionKey(id)) if id == CURRENT_KEY_ID
    ));
}

#[test]
fn providers_return_the_configured_current_generation() {
    let keys = keyring(CURRENT_KEY_ID, 37);

    assert_eq!(keys.current_key().unwrap().id(), CURRENT_KEY_ID);
}
