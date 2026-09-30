//! Provisional compatibility vectors for the experimental formats.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, IndexId, IndexKeyId, KeyId, Padding, Raw, Seal, Sealed, Tenant,
    TenantId, Utf8, index_id, index_key_id, inspect_blind_index, inspect_ciphertext, key_id,
    seal_id,
};
use zeroize::Zeroizing;

// docs/wire-format.md#provisional-envelope-vectors
const UNPADDED: &str = "434258000201001111111122224333844455555555555565640fc8333534b9000102030405060708090a0b0c0d0e0f10111213141516173a8e058803722f56b0ffc9ecbbb7e330da90830136eec9273c8315c1f22b7b";
const PADDED: &str = "434258000201011111111122224333844455555555555565640fc8333534b9000102030405060708090a0b0c0d0e0f10111213141516173a8e058803722f56b0ffc9ecbbb7e3c5e74a10b924aec9355f18b42c5b131fa0";

fn keys() -> EncryptionKeyring {
    let key_id: KeyId = key_id!("11111111-2222-4333-8444-555555555555");

    EncryptionKeyring::new(EncryptionKey::new(key_id, [0x11; 32]), []).unwrap()
}

fn read<F: Seal<Scope = ()>>(vector: &str) -> Result<F::Value, Error> {
    Sealed::<F>::from_bytes(hex::decode(vector).unwrap())
        .unwrap()
        .open((), &keys())
}

struct VectorSeal;

impl Seal for VectorSeal {
    const ID: cryptbox::SealId = seal_id!("12345678-1234-4234-8234-1234567890ab");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Scope = ();
    type Keys = ();
    type Indexes = ();
}

struct PaddedVectorSeal;

impl Seal for PaddedVectorSeal {
    const ID: cryptbox::SealId = VectorSeal::ID;
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
    type Scope = ();
    type Keys = ();
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
        assert_eq!(hex::encode(info.context_fingerprint()), "65640fc8333534b9");
        assert_eq!(read::<VectorSeal>(vector).unwrap(), b"cryptbox vector");
    }
}

#[test]
fn experimental_envelope_vectors_decrypt_under_either_padding_policy() {
    for vector in [UNPADDED, PADDED] {
        assert_eq!(read::<VectorSeal>(vector).unwrap(), b"cryptbox vector");
        assert_eq!(read::<PaddedVectorSeal>(vector).unwrap(), "cryptbox vector");
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
    type Seal = VectorSeal;
    type Scope = ();
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
    const VECTOR: &str = "02aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000de800";
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

struct TenantVectorSeal;

impl Seal for TenantVectorSeal {
    const ID: cryptbox::SealId = VectorSeal::ID;
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Scope = Tenant;
    type Keys = Tenant;
    type Indexes = ();
}

struct TenantVectorIndex;

impl BlindIndexSpec for TenantVectorIndex {
    type Seal = TenantVectorSeal;
    type Scope = Tenant;
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
    const VECTOR: &str = "02aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000d8b88";
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
