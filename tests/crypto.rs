//! Public-boundary tests for encryption, seal binding, and key rotation.

use cryptbox::EncryptionKey;
use cryptbox::envelope::{inspect_ciphertext, is_ciphertext};
use cryptbox::{
    EncryptionKeyring, Error, KeyId, Padding, Raw, Seal, Sealed, Utf8, key_id, seal_id,
};

const OLD_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const CURRENT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");

fn key(id: KeyId, byte: u8) -> EncryptionKey {
    EncryptionKey::new(id, [byte; 32])
}

fn keyring(current_id: KeyId, current_byte: u8) -> EncryptionKeyring {
    EncryptionKeyring::new(key(current_id, current_byte), []).unwrap()
}

struct EmailSeal;

impl Seal for EmailSeal {
    const ID: cryptbox::SealId = seal_id!("30000000-0000-4000-8000-000000000003");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
}

struct PaddedEmailSeal;

impl Seal for PaddedEmailSeal {
    const ID: cryptbox::SealId = EmailSeal::ID;
    const PADDING: Padding = Padding::block(16);
    type Value = Vec<u8>;
    type Codec = Raw;
}

// Raw seals carry opaque bytes through `Sealed`, as the byte-level API did.
fn encrypt<F: Seal<Value = Vec<u8>>>(plaintext: &[u8], keys: &EncryptionKeyring) -> Vec<u8> {
    Sealed::<F>::seal(&plaintext.to_vec(), keys)
        .unwrap()
        .into_bytes()
}

fn decrypt<F: Seal<Value = Vec<u8>>>(
    ciphertext: &[u8],
    keys: &EncryptionKeyring,
) -> Result<Vec<u8>, Error> {
    Sealed::<F>::from_bytes(ciphertext)?.open(keys)
}

struct PhoneSeal;

impl Seal for PhoneSeal {
    const ID: cryptbox::SealId = seal_id!("40000000-0000-4000-8000-000000000004");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
}

#[test]
fn encryption_is_randomized_and_authenticates_the_envelope() {
    let keys = keyring(CURRENT_KEY_ID, 7);

    let first = encrypt::<EmailSeal>(b"same plaintext", &keys);
    let second = encrypt::<EmailSeal>(b"same plaintext", &keys);

    assert_ne!(first, second);
    assert_eq!(
        decrypt::<EmailSeal>(&first, &keys).unwrap().as_slice(),
        b"same plaintext"
    );

    let info = inspect_ciphertext(&first).unwrap();
    assert_eq!(info.format_version(), 2);
    assert!(!info.padded());
    assert_eq!(info.suite_id(), 1);
    assert_eq!(info.key_id(), CURRENT_KEY_ID);

    let mut tampered = first;
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        decrypt::<EmailSeal>(&tampered, &keys),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn empty_plaintext_is_a_valid_authenticated_message() {
    let keys = keyring(CURRENT_KEY_ID, 9);
    let ciphertext = encrypt::<EmailSeal>(b"", &keys);

    assert_eq!(ciphertext.len(), 71);
    assert!(is_ciphertext(&ciphertext));
    assert_eq!(decrypt::<EmailSeal>(&ciphertext, &keys).unwrap(), b"");
}

#[test]
fn padded_encryption_records_the_flag_and_decryption_removes_the_padding() {
    let keys = keyring(CURRENT_KEY_ID, 9);
    let ciphertext = encrypt::<PaddedEmailSeal>(b"padded", &keys);

    assert_eq!(ciphertext.len(), 71 + 16);
    assert!(inspect_ciphertext(&ciphertext).unwrap().padded());
    assert_eq!(decrypt::<EmailSeal>(&ciphertext, &keys).unwrap(), b"padded");
}

#[test]
fn flipping_the_padding_flag_fails_authentication() {
    let keys = keyring(CURRENT_KEY_ID, 9);

    for mut ciphertext in [
        encrypt::<EmailSeal>(b"flagged", &keys),
        encrypt::<PaddedEmailSeal>(b"flagged", &keys),
    ] {
        ciphertext[6] ^= 0x01;

        assert_eq!(
            decrypt::<EmailSeal>(&ciphertext, &keys),
            Err(Error::AuthenticationFailed)
        );
    }
}

#[test]
fn reserved_flag_bits_are_rejected_before_authentication() {
    let keys = keyring(CURRENT_KEY_ID, 9);

    for bit in [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80] {
        let mut ciphertext = encrypt::<EmailSeal>(b"flagged", &keys);
        ciphertext[6] |= bit;

        assert_eq!(inspect_ciphertext(&ciphertext), Err(Error::InvalidEnvelope));
        assert_eq!(
            decrypt::<EmailSeal>(&ciphertext, &keys),
            Err(Error::InvalidEnvelope)
        );
    }
}

#[test]
fn unscoped_envelopes_carry_the_empty_declaration_fingerprint() {
    let keys = keyring(CURRENT_KEY_ID, 9);
    let ciphertext = encrypt::<EmailSeal>(b"field only", &keys);

    // docs/wire-format.md#context-fingerprint
    assert_eq!(
        hex::encode(
            inspect_ciphertext(&ciphertext)
                .unwrap()
                .context_fingerprint()
        ),
        "502de8fcfb838c80"
    );
}

#[test]
fn a_changed_fingerprint_reports_binding_mismatch() {
    let keys = keyring(CURRENT_KEY_ID, 9);
    let mut ciphertext = encrypt::<EmailSeal>(b"field only", &keys);
    ciphertext[23] ^= 1;

    assert_eq!(
        decrypt::<EmailSeal>(&ciphertext, &keys),
        Err(Error::ContextMismatch)
    );
    // `from_bytes` checks structure only, so the changed header still parses.
    assert_eq!(
        Sealed::<EmailSeal>::from_bytes(ciphertext)
            .unwrap()
            .needs_reseal(&keys),
        Err(Error::ContextMismatch)
    );
}

#[test]
fn seal_binding_rejects_cross_seal_ciphertext_substitution() {
    let keys = keyring(CURRENT_KEY_ID, 11);
    let ciphertext = encrypt::<EmailSeal>(b"mark@example.com", &keys);

    assert_eq!(
        decrypt::<EmailSeal>(&ciphertext, &keys).unwrap().as_slice(),
        b"mark@example.com"
    );
    assert_eq!(
        decrypt::<PhoneSeal>(&ciphertext, &keys),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn decryption_resolves_only_the_key_named_by_the_envelope() {
    let writing_keys = keyring(OLD_KEY_ID, 13);
    let ciphertext = encrypt::<EmailSeal>(b"historical", &writing_keys);
    let unrelated_keys = keyring(CURRENT_KEY_ID, 17);

    assert_eq!(
        decrypt::<EmailSeal>(&ciphertext, &unrelated_keys),
        Err(Error::UnknownEncryptionKey(OLD_KEY_ID))
    );
}

#[test]
fn changing_a_key_id_to_another_readable_generation_fails_authentication() {
    let old = key(OLD_KEY_ID, 13);
    let writing_keys = EncryptionKeyring::new(old.clone(), []).unwrap();
    let mut ciphertext = encrypt::<EmailSeal>(b"bound to metadata", &writing_keys);
    let current = key(CURRENT_KEY_ID, 17);
    let rotated = EncryptionKeyring::new(current, [old]).unwrap();

    ciphertext[7..23].copy_from_slice(CURRENT_KEY_ID.as_bytes());

    assert_eq!(
        decrypt::<EmailSeal>(&ciphertext, &rotated),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn rotation_preserves_reads_and_reencryption_uses_the_current_key() {
    let old = key(OLD_KEY_ID, 19);
    let old_keys = EncryptionKeyring::new(old.clone(), []).unwrap();
    let ciphertext = encrypt::<EmailSeal>(b"rotate me", &old_keys);

    let rotated = EncryptionKeyring::new(key(CURRENT_KEY_ID, 23), [old]).unwrap();
    assert_eq!(
        decrypt::<EmailSeal>(&ciphertext, &rotated)
            .unwrap()
            .as_slice(),
        b"rotate me"
    );
    let sealed = Sealed::<EmailSeal>::from_bytes(ciphertext).unwrap();
    assert!(sealed.needs_reseal(&rotated).unwrap());

    let rewritten = sealed.reseal(&rotated).unwrap();
    assert_eq!(rewritten.key_id(), CURRENT_KEY_ID);
    assert!(!rewritten.needs_reseal(&rotated).unwrap());
}

struct TypedEmail;

impl Seal for TypedEmail {
    const ID: cryptbox::SealId = EmailSeal::ID;
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

#[test]
fn sealed_values_round_trip_through_the_seal_codec() {
    let keys = keyring(CURRENT_KEY_ID, 29);

    let sealed: Sealed<TypedEmail> = Sealed::seal(&"mark@example.com".to_owned(), &keys).unwrap();
    assert_eq!(format!("{sealed:?}"), "Sealed([REDACTED])");
    assert_eq!(AsRef::<[u8]>::as_ref(&sealed), sealed.as_bytes());

    let sealed = Sealed::<TypedEmail>::try_from(sealed.into_bytes()).unwrap();

    assert_eq!(sealed.open(&keys).unwrap(), "mark@example.com");
}

#[test]
fn malformed_and_unknown_envelopes_fail_strictly() {
    let keys = keyring(CURRENT_KEY_ID, 31);

    assert_eq!(
        decrypt::<EmailSeal>(b"plaintext", &keys),
        Err(Error::NotCiphertext)
    );
    assert_eq!(
        Sealed::<TypedEmail>::try_from(b"plaintext".to_vec()),
        Err(Error::NotCiphertext)
    );

    let ciphertext = encrypt::<EmailSeal>(b"value", &keys);
    let mut truncated = ciphertext;
    truncated.truncate(30);
    assert_eq!(inspect_ciphertext(&truncated), Err(Error::InvalidEnvelope));
    assert_eq!(
        decrypt::<EmailSeal>(&truncated, &keys),
        Err(Error::InvalidEnvelope)
    );

    let mut unsupported = encrypt::<EmailSeal>(b"value", &keys);
    unsupported[5] = 0xff;
    assert_eq!(
        inspect_ciphertext(&unsupported),
        Err(Error::UnsupportedSuite(0xff))
    );
    assert_eq!(
        decrypt::<EmailSeal>(&unsupported, &keys),
        Err(Error::UnsupportedSuite(0xff))
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
