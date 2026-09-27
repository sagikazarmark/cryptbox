//! Provisional compatibility vectors for the experimental v0.1 formats.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Ciphertext, EncryptionKey,
    Error, Field, IndexId, IndexKeyId, KeyId, LocalBlindIndexKeyring, LocalEncryptionKeyring,
    Padding, Raw, Utf8, decrypt, derive_blind_index, field_id, index_id, index_key_id, key_id,
};
use zeroize::Zeroizing;

struct PaddedVectorField;

impl Field for PaddedVectorField {
    const ID: cryptbox::FieldId = VectorField::ID;
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
}

#[test]
fn experimental_padded_envelope_vector_decrypts() {
    let key_id: KeyId = key_id!("11111111-2222-4333-8444-555555555555");
    let keys = LocalEncryptionKeyring::new(EncryptionKey::new(key_id, [0x11; 32]), []).unwrap();
    let envelope = hex::decode(
        "43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f101112131415161790fc94db1267819912c4b5abc48bfce28615aa60f3cc8e8475dbf73c2d43d9f6",
    )
    .unwrap();
    let ciphertext = Ciphertext::<PaddedVectorField>::from_bytes(envelope).unwrap();

    assert_eq!(
        ciphertext.decrypt_with(&keys).unwrap().expose_secret(),
        "cryptbox vector"
    );
}

#[test]
fn unpadded_envelope_vector_is_invalid_for_a_padded_field() {
    let key_id: KeyId = key_id!("11111111-2222-4333-8444-555555555555");
    let keys = LocalEncryptionKeyring::new(EncryptionKey::new(key_id, [0x11; 32]), []).unwrap();
    let envelope = hex::decode(
        "43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f101112131415161790fc94db1267819912c4b5abc48bfceb1074e9691ed9f65c6b1ee8ddf1219d",
    )
    .unwrap();
    let ciphertext = Ciphertext::<PaddedVectorField>::from_bytes(envelope).unwrap();

    assert!(matches!(
        ciphertext.decrypt_with(&keys),
        Err(Error::InvalidPadding)
    ));
}

struct VectorField;

impl Field for VectorField {
    const ID: cryptbox::FieldId = field_id!("12345678-1234-4234-8234-1234567890ab");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
}

#[test]
fn experimental_envelope_vector_decrypts() {
    let key_id: KeyId = key_id!("11111111-2222-4333-8444-555555555555");
    let keys = LocalEncryptionKeyring::new(EncryptionKey::new(key_id, [0x11; 32]), []).unwrap();
    let envelope = hex::decode(
        "43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f101112131415161790fc94db1267819912c4b5abc48bfceb1074e9691ed9f65c6b1ee8ddf1219d",
    )
    .unwrap();

    assert_eq!(
        decrypt(VectorField::ID, &envelope, &keys)
            .unwrap()
            .as_slice(),
        b"cryptbox vector"
    );
}

struct VectorIndex;

impl BlindIndexMetadata for VectorIndex {
    const BITS: usize = 13;
    const ID: IndexId = index_id!("abcdefab-cdef-4def-8def-abcdefabcdef");
}

impl BlindIndexSpec<str> for VectorIndex {
    fn normalize(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(input.as_bytes().to_vec()))
    }
}

#[test]
fn experimental_blind_index_vector_is_stable() {
    let key_id: IndexKeyId = index_key_id!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    let keys = LocalBlindIndexKeyring::new(BlindIndexKey::new(key_id, [0x22; 32]), []).unwrap();

    let index =
        derive_blind_index::<VectorIndex, str, VectorField>("normalized@example.com", &keys)
            .unwrap();

    assert_eq!(
        hex::encode(index.as_bytes()),
        "01aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000d71e0"
    );
}
