//! Provisional compatibility vectors for the experimental v0.1 formats.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, EncryptionKey, Field,
    FieldBound, IndexId, IndexKeyId, KeyId, LocalBlindIndexKeyring, LocalEncryptionKeyring,
    Unbound, decrypt, derive_blind_index, field_id, index_id, index_key_id, key_id,
};
use zeroize::Zeroizing;

#[test]
fn experimental_envelope_vector_decrypts() {
    let key_id: KeyId = key_id!("11111111-2222-4333-8444-555555555555");
    let keys = LocalEncryptionKeyring::new(EncryptionKey::new(key_id, [0x11; 32]), []).unwrap();
    let envelope = hex::decode(
        "43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f1011121314151617c5ecf67a1ebf136378025485a1e4b961044c53838d7bf1c05cc81b81ae89d5",
    )
    .unwrap();

    assert_eq!(
        decrypt::<Unbound>(&envelope, &(), &keys)
            .unwrap()
            .as_slice(),
        b"cryptbox vector"
    );
}

struct VectorField;

impl Field for VectorField {
    const ID: cryptbox::FieldId = field_id!("12345678-1234-4234-8234-1234567890ab");
}

#[test]
fn experimental_field_bound_envelope_vector_decrypts() {
    let key_id: KeyId = key_id!("11111111-2222-4333-8444-555555555555");
    let keys = LocalEncryptionKeyring::new(EncryptionKey::new(key_id, [0x11; 32]), []).unwrap();
    let envelope = hex::decode(
        "43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f101112131415161790fc94db1267819912c4b5abc48bfceb1074e9691ed9f65c6b1ee8ddf1219d",
    )
    .unwrap();

    assert_eq!(
        decrypt::<FieldBound<VectorField>>(&envelope, &(), &keys)
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

    let index = derive_blind_index::<VectorIndex, str, FieldBound<VectorField>>(
        "normalized@example.com",
        &(),
        &keys,
    )
    .unwrap();

    assert_eq!(
        hex::encode(index.as_bytes()),
        "01aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000d71e0"
    );
}
