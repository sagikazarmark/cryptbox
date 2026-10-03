//! Compatibility vectors for the stable formats: ciphertext format 2 and
//! blind-index format 2.

use cryptbox::envelope::{inspect_blind_index, inspect_ciphertext};
use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, InRecord, IndexId, IndexKeyId, KeyId, Padding, Raw, Seal, Sealed,
    Utf8, index_id, index_key_id, key_id, seal_id,
};
use zeroize::Zeroizing;

// docs/wire-format.md#envelope-vectors
const UNPADDED: &str = "434258000201001111111122224333844455555555555565640fc8333534b9000102030405060708090a0b0c0d0e0f10111213141516173a8e058803722f56b0ffc9ecbbb7e330da90830136eec9273c8315c1f22b7b";
const PADDED: &str = "434258000201011111111122224333844455555555555565640fc8333534b9000102030405060708090a0b0c0d0e0f10111213141516173a8e058803722f56b0ffc9ecbbb7e3c5e74a10b924aec9355f18b42c5b131fa0";

fn keys() -> EncryptionKeyring {
    let key_id: KeyId = key_id!("11111111-2222-4333-8444-555555555555");

    EncryptionKeyring::new(EncryptionKey::new(key_id, [0x11; 32]), []).unwrap()
}

fn read<F: Seal>(vector: &str) -> Result<F::Value, Error> {
    Sealed::<F>::from_bytes(hex::decode(vector).unwrap())
        .unwrap()
        .open(&keys())
}

struct VectorSeal;

impl Seal for VectorSeal {
    const ID: cryptbox::SealId = seal_id!("12345678-1234-4234-8234-1234567890ab");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
}

struct PaddedVectorSeal;

impl Seal for PaddedVectorSeal {
    const ID: cryptbox::SealId = VectorSeal::ID;
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
}

#[test]
fn envelope_vectors_record_their_padding() {
    for (vector, padded) in [(UNPADDED, false), (PADDED, true)] {
        let envelope = hex::decode(vector).unwrap();
        let info = inspect_ciphertext(&envelope).unwrap();

        assert_eq!(info.format_version(), 2);
        assert_eq!(info.padded(), padded);
        // A standalone value's context fingerprint: docs/wire-format.md#context-fingerprint
        assert_eq!(hex::encode(info.context_fingerprint()), "65640fc8333534b9");
        assert_eq!(read::<VectorSeal>(vector).unwrap(), b"cryptbox vector");
    }
}

#[test]
fn envelope_vectors_decrypt_under_either_padding_policy() {
    for vector in [UNPADDED, PADDED] {
        assert_eq!(read::<VectorSeal>(vector).unwrap(), b"cryptbox vector");
        assert_eq!(read::<PaddedVectorSeal>(vector).unwrap(), "cryptbox vector");
    }
}

// docs/wire-format.md#record-vector
const RECORD: &str = "434258000201001111111122224333844455555555555576081b730530f822000102030405060708090a0b0c0d0e0f1011121314151617c899d84358bcff6b35f9bb49eea2c2e906efc22bcad85fd463c7217135fe97";

#[test]
fn the_record_vector_opens_only_as_its_record_field() {
    let field =
        Sealed::<VectorSeal, InRecord<i64>>::from_bytes(hex::decode(RECORD).unwrap()).unwrap();

    assert_eq!(
        hex::encode(
            inspect_ciphertext(field.as_bytes())
                .unwrap()
                .context_fingerprint()
        ),
        "76081b730530f822"
    );
    assert_eq!(field.open_in(&7, &keys()).unwrap(), b"cryptbox vector");
    assert_eq!(
        field.open_in(&8, &keys()).unwrap_err(),
        Error::AuthenticationFailed
    );
    assert_eq!(
        read::<VectorSeal>(RECORD).unwrap_err(),
        Error::ContextMismatch
    );
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
fn blind_index_vector_is_stable() {
    const VECTOR: &str = "02aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000de800";
    let key_id: IndexKeyId = index_key_id!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    let keys = BlindIndexKeyring::new(BlindIndexKey::new(key_id, [0x22; 32]), []).unwrap();

    let index =
        BlindIndex::<VectorIndex>::derive(&b"normalized@example.com".to_vec(), &keys).unwrap();
    let probes = BlindIndex::<VectorIndex>::probes("normalized@example.com", &keys).unwrap();

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
