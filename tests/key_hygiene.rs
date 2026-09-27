//! Public-boundary tests for safe key construction.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyProvider, BlindIndexSpec, EncryptionKey, Error,
    Field, FieldId, IndexId, LocalBlindIndexKeyring, LocalEncryptionKeyring, Padding, Raw, decrypt,
    encrypt, index_id, index_key_id, key_id,
};
use zeroize::Zeroizing;

struct TestField;

impl Field for TestField {
    const ID: FieldId = cryptbox::field_id!("5d3a1f7e-2b8c-4e69-a0d4-7f1b3c5e9a82");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
}

struct ExactValue;

impl BlindIndexSpec for ExactValue {
    type Field = TestField;
    const ID: IndexId = index_id!("abcdefab-cdef-4abc-8def-abcdefabcdef");
    const BITS: u16 = 128;
    type Query = [u8];

    fn normalize_query(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(input.to_vec()))
    }

    fn normalize_value(value: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

#[test]
fn encryption_keys_can_be_generated_for_immediate_use() {
    let first = EncryptionKey::generate().unwrap();
    let second = EncryptionKey::generate().unwrap();
    assert_ne!(first.id(), second.id());

    let keys = LocalEncryptionKeyring::new(first, []).unwrap();
    let ciphertext = encrypt(TestField::ID, b"generated key", &keys).unwrap();

    assert_eq!(
        decrypt(TestField::ID, &ciphertext, &keys)
            .unwrap()
            .as_slice(),
        b"generated key"
    );
}

#[test]
fn blind_index_keys_can_be_generated_for_immediate_use() {
    let first = BlindIndexKey::generate().unwrap();
    let second = BlindIndexKey::generate().unwrap();
    assert_ne!(first.id(), second.id());

    let expected_id = first.id();
    let keys = LocalBlindIndexKeyring::new(first, []).unwrap();

    assert_eq!(keys.current_key(TestField::ID).unwrap().id(), expected_id);
}

#[test]
fn encryption_keys_load_from_hex_and_base64() {
    let id = key_id!("12345678-1234-4234-8234-1234567890ab");
    let hex_key = EncryptionKey::from_hex(
        id,
        "4242424242424242424242424242424242424242424242424242424242424242",
    )
    .unwrap();
    let base64_key =
        EncryptionKey::from_base64(id, "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=").unwrap();

    let writing_keys = LocalEncryptionKeyring::new(hex_key, []).unwrap();
    let reading_keys = LocalEncryptionKeyring::new(base64_key, []).unwrap();
    let ciphertext = encrypt(TestField::ID, b"loaded key", &writing_keys).unwrap();

    assert_eq!(
        decrypt(TestField::ID, &ciphertext, &reading_keys)
            .unwrap()
            .as_slice(),
        b"loaded key"
    );
}

#[test]
fn blind_index_keys_load_from_hex_and_base64() {
    let id = index_key_id!("87654321-4321-4321-8321-ba0987654321");
    let hex_key = BlindIndexKey::from_hex(
        id,
        "4242424242424242424242424242424242424242424242424242424242424242",
    )
    .unwrap();
    let base64_key =
        BlindIndexKey::from_base64(id, "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=").unwrap();

    let hex_keys = LocalBlindIndexKeyring::new(hex_key, []).unwrap();
    let base64_keys = LocalBlindIndexKeyring::new(base64_key, []).unwrap();

    assert_eq!(
        ExactValue::derive_with(&b"loaded key".to_vec(), &hex_keys).unwrap(),
        ExactValue::derive_with(&b"loaded key".to_vec(), &base64_keys).unwrap(),
    );
}

#[test]
fn encoded_keys_must_decode_to_exactly_32_bytes() {
    let encryption_id = key_id!("12345678-1234-4234-8234-1234567890ab");
    let index_id = index_key_id!("87654321-4321-4321-8321-ba0987654321");

    assert!(matches!(
        EncryptionKey::from_hex(encryption_id, "00"),
        Err(Error::InvalidKeyEncoding)
    ));
    assert!(matches!(
        EncryptionKey::from_base64(encryption_id, "AA=="),
        Err(Error::InvalidKeyEncoding)
    ));
    assert!(matches!(
        BlindIndexKey::from_hex(index_id, "not hexadecimal"),
        Err(Error::InvalidKeyEncoding)
    ));
    assert!(matches!(
        BlindIndexKey::from_base64(index_id, "not base64"),
        Err(Error::InvalidKeyEncoding)
    ));
}
