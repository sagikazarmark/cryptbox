//! Public-boundary tests for safe key construction.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyProvider, BlindIndexMetadata, BlindIndexSpec,
    EncryptionKey, Error, IndexId, LocalBlindIndexKeyring, LocalEncryptionKeyring, Unbound,
    decrypt, derive_blind_index, encrypt, index_id, index_key_id, key_id,
};
use zeroize::Zeroizing;

struct ExactValue;

impl BlindIndexMetadata for ExactValue {
    const ID: IndexId = index_id!("abcdefab-cdef-4abc-8def-abcdefabcdef");
    const BITS: usize = 128;
}

impl BlindIndexSpec<str> for ExactValue {
    fn normalize(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(input.as_bytes().to_vec()))
    }
}

#[test]
fn encryption_keys_can_be_generated_for_immediate_use() {
    let first = EncryptionKey::generate().unwrap();
    let second = EncryptionKey::generate().unwrap();
    assert_ne!(first.id(), second.id());

    let keys = LocalEncryptionKeyring::new(first, []).unwrap();
    let ciphertext = encrypt::<Unbound>(b"generated key", &(), &keys).unwrap();

    assert_eq!(
        decrypt::<Unbound>(&ciphertext, &(), &keys)
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

    assert_eq!(keys.current_key().unwrap().id(), expected_id);
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
    let ciphertext = encrypt::<Unbound>(b"loaded key", &(), &writing_keys).unwrap();

    assert_eq!(
        decrypt::<Unbound>(&ciphertext, &(), &reading_keys)
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
        derive_blind_index::<ExactValue, str, Unbound>("loaded key", &(), &hex_keys).unwrap(),
        derive_blind_index::<ExactValue, str, Unbound>("loaded key", &(), &base64_keys).unwrap(),
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
