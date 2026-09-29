//! Provisional compatibility vectors for the experimental formats.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, FieldOnly, IndexId, IndexKeyId, KeyId, Padding, Raw, Seal, Sealed,
    Tenant, TenantId, Utf8, index_id, index_key_id, inspect_blind_index, inspect_ciphertext,
    key_id, seal_id,
};
use zeroize::Zeroizing;

// docs/wire-format.md#provisional-envelope-vectors
const UNPADDED: &str = "43425800020100111111112222433384445555555555555d86321261d64380000102030405060708090a0b0c0d0e0f1011121314151617ef0521ab2e6f330235d572ee4da1415b33cbc7bfb19bc11afc1b31e3f3075b";
const PADDED: &str = "43425800020101111111112222433384445555555555555d86321261d64380000102030405060708090a0b0c0d0e0f1011121314151617ef0521ab2e6f330235d572ee4da1419a17b89c9d88cb6cca540c1c17f5917f44";

fn keys() -> EncryptionKeyring {
    let key_id: KeyId = key_id!("11111111-2222-4333-8444-555555555555");

    EncryptionKeyring::new(EncryptionKey::new(key_id, [0x11; 32]), []).unwrap()
}

fn read<F: Seal<Binding = FieldOnly>>(vector: &str) -> Result<F::Value, Error> {
    Sealed::<F>::from_bytes(hex::decode(vector).unwrap())
        .unwrap()
        .open((), &keys())
}

struct VectorField;

impl Seal for VectorField {
    const ID: cryptbox::SealId = seal_id!("12345678-1234-4234-8234-1234567890ab");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct PaddedVectorField;

impl Seal for PaddedVectorField {
    const ID: cryptbox::SealId = VectorField::ID;
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
        // The empty declaration's fingerprint: docs/wire-format.md#binding-fingerprint
        assert_eq!(hex::encode(info.context_fingerprint()), "5d86321261d64380");
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
    type Seal = VectorField;
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
    const VECTOR: &str = "02aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000df040";
    let key_id: IndexKeyId = index_key_id!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    let keys = BlindIndexKeyring::new(BlindIndexKey::new(key_id, [0x22; 32]), []).unwrap();

    let index = VectorIndex::derive_with(&b"normalized@example.com".to_vec(), &(), &keys).unwrap();
    let probes = VectorIndex::probes_with("normalized@example.com", &(), &keys).unwrap();

    assert_eq!(hex::encode(index.as_bytes()), VECTOR);
    assert_eq!(probes.len(), 1);
    assert_eq!(hex::encode(probes[0].as_bytes()), VECTOR);
}

#[test]
fn format_1_blind_indexes_are_rejected() {
    // The format 1 vector: derived under the tagged binding layout, so it is
    // rejected rather than silently matching nothing.
    let format_1 = hex::decode("01aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000d71e0").unwrap();

    assert_eq!(
        inspect_blind_index(&format_1).unwrap_err(),
        Error::InvalidBlindIndex
    );
}

struct TenantVectorField;

impl Seal for TenantVectorField {
    const ID: cryptbox::SealId = VectorField::ID;
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = Tenant;
    type Indexes = ();
}

struct TenantVectorIndex;

impl BlindIndexSpec for TenantVectorIndex {
    type Seal = TenantVectorField;
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
    const VECTOR: &str = "02aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000d28c0";
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
