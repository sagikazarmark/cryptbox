//! Provisional compatibility vectors for the experimental formats.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, Field, FieldOnly, IndexId, IndexKeyId, KeyId, Padding, Raw, Sealed,
    Tenant, TenantId, Utf8, field_id, index_id, index_key_id, inspect_ciphertext, key_id,
};
use zeroize::Zeroizing;

// docs/wire-format.md#provisional-envelope-vectors
const UNPADDED: &str = "4342580002010011111111222243338444555555555555000102030405060708090a0b0c0d0e0f10111213141516173f7195595232290da92d72b42bb6fd4f8e9c4e8454cd34732e7966a50994cd";
const PADDED: &str = "4342580002010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f10111213141516173f7195595232290da92d72b42bb6fd489a56ec6e125f07deaa76f7502ad2613f";

fn keys() -> EncryptionKeyring {
    let key_id: KeyId = key_id!("11111111-2222-4333-8444-555555555555");

    EncryptionKeyring::new(EncryptionKey::new(key_id, [0x11; 32]), []).unwrap()
}

fn read<F: Field<Binding = FieldOnly>>(vector: &str) -> Result<F::Value, Error> {
    Sealed::<F>::from_bytes(hex::decode(vector).unwrap())
        .unwrap()
        .open((), &keys())
}

struct VectorField;

impl Field for VectorField {
    const ID: cryptbox::FieldId = field_id!("12345678-1234-4234-8234-1234567890ab");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct PaddedVectorField;

impl Field for PaddedVectorField {
    const ID: cryptbox::FieldId = VectorField::ID;
    const PADDING: Padding = Padding::block(16);
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
    type Indexes = ();
}

#[test]
fn experimental_envelope_vectors_record_their_padding() {
    for (vector, padded) in [(UNPADDED, false), (PADDED, true)] {
        let envelope = hex::decode(vector).unwrap();
        let info = inspect_ciphertext(&envelope).unwrap();

        assert_eq!(info.format_version(), 2);
        assert_eq!(info.padded(), padded);
        assert_eq!(info.shape_fingerprint(), None);
        assert_eq!(read::<VectorField>(vector).unwrap(), b"cryptbox vector");
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
fn format_1_envelopes_are_not_read() {
    let mut envelope = hex::decode(UNPADDED).unwrap();
    envelope[4] = 1;

    assert_eq!(
        inspect_ciphertext(&envelope).unwrap_err(),
        Error::UnsupportedFormatVersion(1)
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
    let keys = BlindIndexKeyring::new(BlindIndexKey::new(key_id, [0x22; 32]), []).unwrap();

    let index = VectorIndex::derive_with(&b"normalized@example.com".to_vec(), &(), &keys).unwrap();
    let probes = VectorIndex::probes_with("normalized@example.com", &(), &keys).unwrap();

    assert_eq!(hex::encode(index.as_bytes()), VECTOR);
    assert_eq!(probes.len(), 1);
    assert_eq!(hex::encode(probes[0].as_bytes()), VECTOR);
}

struct TenantVectorField;

impl Field for TenantVectorField {
    const ID: cryptbox::FieldId = VectorField::ID;
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = Tenant;
    type Indexes = ();
}

struct TenantVectorIndex;

impl BlindIndexSpec for TenantVectorIndex {
    type Field = TenantVectorField;
    const ID: IndexId = VectorIndex::ID;
    const BITS: u16 = VectorIndex::BITS;
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
fn experimental_scoped_blind_index_vector_is_stable() {
    // docs/wire-format.md#scoped-blind-index-vector
    const VECTOR: &str = "01aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000d35b8";
    let key_id: IndexKeyId = index_key_id!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    let keys = BlindIndexKeyring::new(BlindIndexKey::new(key_id, [0x22; 32]), []).unwrap();
    let acme = Tenant(TenantId::new(b"acme".to_vec()).unwrap());

    let index =
        TenantVectorIndex::derive_with(&b"normalized@example.com".to_vec(), &acme, &keys).unwrap();
    let probes = TenantVectorIndex::probes_with("normalized@example.com", &acme, &keys).unwrap();

    assert_eq!(hex::encode(index.as_bytes()), VECTOR);
    assert_eq!(probes.len(), 1);
    assert_eq!(hex::encode(probes[0].as_bytes()), VECTOR);
}
