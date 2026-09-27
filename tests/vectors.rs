//! Provisional compatibility vectors for the experimental formats.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexSpec, Ciphertext, EncryptionKey, Error, Field,
    IndexId, IndexKeyId, KeyId, LocalBlindIndexKeyring, LocalEncryptionKeyring, Padding, Raw, Utf8,
    decrypt, field_id, index_id, index_key_id, inspect_ciphertext, key_id,
};
use zeroize::Zeroizing;

// docs/wire-format.md#provisional-envelope-vectors
const UNPADDED: &str = "4342580002010011111111222243338444555555555555000102030405060708090a0b0c0d0e0f10111213141516173f7195595232290da92d72b42bb6fd4f8e9c4e8454cd34732e7966a50994cd";
const PADDED: &str = "4342580002010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f10111213141516173f7195595232290da92d72b42bb6fd489a56ec6e125f07deaa76f7502ad2613f";
// docs/wire-format.md#format-1
const FORMAT_1_UNPADDED: &str = "43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f101112131415161790fc94db1267819912c4b5abc48bfceb1074e9691ed9f65c6b1ee8ddf1219d";
const FORMAT_1_PADDED: &str = "43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f101112131415161790fc94db1267819912c4b5abc48bfce28615aa60f3cc8e8475dbf73c2d43d9f6";

fn keys() -> LocalEncryptionKeyring {
    let key_id: KeyId = key_id!("11111111-2222-4333-8444-555555555555");

    LocalEncryptionKeyring::new(EncryptionKey::new(key_id, [0x11; 32]), []).unwrap()
}

fn read<F: Field>(vector: &str) -> Result<F::Value, Error> {
    Ciphertext::<F>::from_bytes(hex::decode(vector).unwrap())
        .unwrap()
        .decrypt_with(&keys())
        .map(cryptbox::Encrypted::into_secret)
}

struct VectorField;

impl Field for VectorField {
    const ID: cryptbox::FieldId = field_id!("12345678-1234-4234-8234-1234567890ab");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
}

struct PaddedVectorField;

impl Field for PaddedVectorField {
    const ID: cryptbox::FieldId = VectorField::ID;
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
}

#[test]
fn experimental_envelope_vectors_record_their_padding() {
    for (vector, padded) in [(UNPADDED, false), (PADDED, true)] {
        let envelope = hex::decode(vector).unwrap();
        let info = inspect_ciphertext(&envelope).unwrap();

        assert_eq!(info.format_version(), 2);
        assert_eq!(info.padded(), Some(padded));
        assert_eq!(
            decrypt(VectorField::ID, &envelope, &keys())
                .unwrap()
                .as_slice(),
            b"cryptbox vector"
        );
    }
}

#[test]
fn experimental_envelope_vectors_decrypt_under_either_padding_policy() {
    for vector in [UNPADDED, PADDED] {
        assert_eq!(read::<VectorField>(vector).unwrap(), b"cryptbox vector");
        assert_eq!(
            read::<PaddedVectorField>(vector).unwrap(),
            "cryptbox vector"
        );
    }
}

#[test]
fn format_1_vectors_are_read_with_the_field_padding_policy() {
    assert_eq!(
        read::<VectorField>(FORMAT_1_UNPADDED).unwrap(),
        b"cryptbox vector"
    );
    assert_eq!(
        read::<PaddedVectorField>(FORMAT_1_PADDED).unwrap(),
        "cryptbox vector"
    );
    // Format 1 does not record padding: a policy change before a sweep misreads it.
    assert_eq!(
        read::<VectorField>(FORMAT_1_PADDED).unwrap(),
        b"cryptbox vector\x80"
    );
    assert_eq!(
        read::<PaddedVectorField>(FORMAT_1_UNPADDED),
        Err(Error::InvalidPadding)
    );
}

#[test]
fn format_1_vectors_are_stale_and_reencrypt_to_format_2() {
    let keys = keys();
    let legacy =
        Ciphertext::<PaddedVectorField>::from_bytes(hex::decode(FORMAT_1_PADDED).unwrap()).unwrap();

    assert!(legacy.needs_reencryption_with(&keys).unwrap());

    let current = legacy.reencrypt_with(&keys).unwrap();
    let info = inspect_ciphertext(current.as_bytes()).unwrap();
    assert_eq!(info.format_version(), 2);
    assert_eq!(info.padded(), Some(true));
    assert!(!current.needs_reencryption_with(&keys).unwrap());
    assert_eq!(
        current.decrypt_with(&keys).unwrap().expose_secret(),
        "cryptbox vector"
    );
}

struct VectorIndex;

impl BlindIndexSpec for VectorIndex {
    type Field = VectorField;
    const ID: IndexId = index_id!("abcdefab-cdef-4def-8def-abcdefabcdef");
    const BITS: u16 = 13;
    const NORMALIZER: &'static str = "exact/1";
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(query.as_bytes().to_vec()))
    }

    fn normalize_value(value: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(value.clone()))
    }
}

#[test]
fn experimental_blind_index_vector_is_stable() {
    const VECTOR: &str = "01aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000d71e0";
    let key_id: IndexKeyId = index_key_id!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    let keys = LocalBlindIndexKeyring::new(BlindIndexKey::new(key_id, [0x22; 32]), []).unwrap();

    let index = VectorIndex::derive_with(&b"normalized@example.com".to_vec(), &keys).unwrap();
    let probes = VectorIndex::probes_with("normalized@example.com", &keys).unwrap();

    assert_eq!(hex::encode(index.as_bytes()), VECTOR);
    assert_eq!(probes.len(), 1);
    assert_eq!(hex::encode(probes[0].as_bytes()), VECTOR);
}
