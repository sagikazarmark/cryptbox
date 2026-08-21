//! Public-boundary tests for blind indexes and prepared storage values.

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Encrypted,
    EncryptionKey, EncryptionProfile, Field, FieldBound, GlobalKeyContext, IndexId, IndexKeyId,
    KeyId, LocalBlindIndexKeyring, LocalEncryptionKeyring, Utf8, blind_index_probes,
    derive_blind_index, field_id, index_id, index_key_id, inspect_blind_index, key_id,
    verify_blind_index_candidate,
};
use zeroize::Zeroizing;

const ENCRYPTION_KEY_ID: KeyId = key_id!("50000000-0000-4000-8000-000000000005");
const OLD_INDEX_KEY_ID: IndexKeyId = index_key_id!("60000000-0000-4000-8000-000000000006");
const CURRENT_INDEX_KEY_ID: IndexKeyId = index_key_id!("70000000-0000-4000-8000-000000000007");

struct EmailField;

impl Field for EmailField {
    const ID: cryptbox::FieldId = field_id!("80000000-0000-4000-8000-000000000008");
}

struct PhoneField;

impl Field for PhoneField {
    const ID: cryptbox::FieldId = field_id!("90000000-0000-4000-8000-000000000009");
}

struct EmailExact;

impl BlindIndexMetadata for EmailExact {
    const BITS: usize = 13;
    const ID: IndexId = index_id!("a0000000-0000-4000-8000-00000000000a");
}

impl BlindIndexSpec<str> for EmailExact {
    fn normalize(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(
            input.trim().to_ascii_lowercase().into_bytes(),
        ))
    }
}

impl BlindIndexSpec<String> for EmailExact {
    fn normalize(input: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        <Self as BlindIndexSpec<str>>::normalize(input)
    }
}

fn index_key(id: IndexKeyId, byte: u8) -> BlindIndexKey {
    BlindIndexKey::new(id, [byte; 32])
}

fn index_keys() -> LocalBlindIndexKeyring {
    LocalBlindIndexKeyring::new(index_key(CURRENT_INDEX_KEY_ID, 41), []).unwrap()
}

#[test]
fn blind_indexes_are_deterministic_normalized_and_explicitly_truncated() {
    let keys = index_keys();

    let first = derive_blind_index::<EmailExact, str, FieldBound<EmailField>>(
        " Mark@Example.com ",
        &(),
        &keys,
    )
    .unwrap();
    let second = derive_blind_index::<EmailExact, str, FieldBound<EmailField>>(
        "mark@example.com",
        &(),
        &keys,
    )
    .unwrap();

    assert_eq!(first, second);
    assert_eq!(format!("{first:?}"), "BlindIndex([REDACTED])");
    assert_eq!(first.as_bytes().len(), 21);
    assert_eq!(first.as_bytes().last().unwrap() & 0b0000_0111, 0);

    let info = inspect_blind_index(first.as_bytes()).unwrap();
    assert_eq!(info.index_key_id(), CURRENT_INDEX_KEY_ID);
    assert_eq!(info.bits(), 13);
}

#[test]
fn field_and_index_domains_are_cryptographically_separated() {
    let keys = index_keys();
    let email = derive_blind_index::<EmailExact, str, FieldBound<EmailField>>(
        "mark@example.com",
        &(),
        &keys,
    )
    .unwrap();
    let phone = derive_blind_index::<EmailExact, str, FieldBound<PhoneField>>(
        "mark@example.com",
        &(),
        &keys,
    )
    .unwrap();

    assert_ne!(email, phone);
}

#[test]
fn query_probes_cover_current_and_historical_index_generations() {
    let old = index_key(OLD_INDEX_KEY_ID, 43);
    let keys = LocalBlindIndexKeyring::new(index_key(CURRENT_INDEX_KEY_ID, 47), [old]).unwrap();

    let probes = blind_index_probes::<EmailExact, str, FieldBound<EmailField>>(
        "mark@example.com",
        &(),
        &keys,
    )
    .unwrap();

    assert_eq!(probes.len(), 2);
    assert_eq!(
        inspect_blind_index(probes[0].as_bytes())
            .unwrap()
            .index_key_id(),
        CURRENT_INDEX_KEY_ID
    );
    assert_eq!(
        inspect_blind_index(probes[1].as_bytes())
            .unwrap()
            .index_key_id(),
        OLD_INDEX_KEY_ID
    );
}

#[test]
fn candidate_hits_require_normalized_plaintext_verification() {
    assert!(
        verify_blind_index_candidate::<EmailExact, str>(" Mark@Example.com ", "mark@example.com")
            .unwrap()
    );
    assert!(
        !verify_blind_index_candidate::<EmailExact, str>("mark@example.com", "other@example.com")
            .unwrap()
    );
}

struct EmailProfile;

impl EncryptionProfile<String> for EmailProfile {
    type Binding = FieldBound<EmailField>;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
}

#[test]
fn prepared_values_derive_ciphertext_and_indexes_from_one_source() {
    let encryption_keys =
        LocalEncryptionKeyring::new(EncryptionKey::new(ENCRYPTION_KEY_ID, [53; 32]), []).unwrap();
    let index_keys = index_keys();
    let value = Encrypted::<_, EmailProfile>::new("Mark@Example.com".to_owned());

    let prepared = value
        .prepare_with(&(), &encryption_keys)
        .unwrap()
        .with_index_with::<EmailExact>(&index_keys)
        .unwrap();

    assert!(!prepared.ciphertext().as_bytes().is_empty());
    let prepared_index = prepared.index::<EmailExact>().unwrap();
    let direct = derive_blind_index::<EmailExact, String, FieldBound<EmailField>>(
        value.expose_secret(),
        &(),
        &index_keys,
    )
    .unwrap();
    assert_eq!(prepared_index.as_bytes(), direct.as_bytes());
}

struct NameAndPostalCode;

impl BlindIndexMetadata for NameAndPostalCode {
    const BITS: usize = 128;
    const ID: IndexId = index_id!("b0000000-0000-4000-8000-00000000000b");
}

impl<'a> BlindIndexSpec<(&'a str, &'a str)> for NameAndPostalCode {
    fn normalize(input: &(&'a str, &'a str)) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(
            format!("{}\0{}", input.0.to_ascii_lowercase(), input.1).into_bytes(),
        ))
    }
}

#[test]
fn a_blind_index_input_can_be_compound() {
    let keys = index_keys();
    let input = ("Ada Lovelace", "SW1A 1AA");

    let index =
        derive_blind_index::<NameAndPostalCode, _, FieldBound<EmailField>>(&input, &(), &keys)
            .unwrap();

    assert_eq!(inspect_blind_index(index.as_bytes()).unwrap().bits(), 128);
}

#[test]
fn typed_indexes_reject_noncanonical_storage_bytes() {
    let keys = index_keys();
    let index = derive_blind_index::<EmailExact, str, FieldBound<EmailField>>(
        "mark@example.com",
        &(),
        &keys,
    )
    .unwrap();
    let mut bytes = index.into_bytes();
    *bytes.last_mut().unwrap() |= 1;

    assert!(BlindIndex::<EmailExact>::from_bytes(bytes).is_err());
}

macro_rules! truncation_spec {
    ($name:ident, $bits:expr, $id_byte:expr) => {
        struct $name;

        impl BlindIndexMetadata for $name {
            const BITS: usize = $bits;
            const ID: IndexId = IndexId::from_bytes([$id_byte; 16]);
        }

        impl BlindIndexSpec<str> for $name {
            fn normalize(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
                Ok(Zeroizing::new(input.as_bytes().to_vec()))
            }
        }
    };
}

truncation_spec!(OneBit, 1, 1);
truncation_spec!(EightBits, 8, 2);
truncation_spec!(ThirteenBits, 13, 3);
truncation_spec!(TwoHundredFiftyFiveBits, 255, 4);
truncation_spec!(TwoHundredFiftySixBits, 256, 5);

fn assert_canonical_truncation<Spec>(expected_bytes: usize)
where
    Spec: BlindIndexMetadata + BlindIndexSpec<str>,
{
    let index = derive_blind_index::<Spec, str, FieldBound<EmailField>>(
        "truncation vector",
        &(),
        &index_keys(),
    )
    .unwrap();
    assert_eq!(index.as_bytes().len(), 19 + expected_bytes);
    if Spec::BITS % 8 != 0 {
        let unused_bits = 8 - Spec::BITS % 8;
        let unused_mask = (1_u8 << unused_bits) - 1;
        assert_eq!(index.as_bytes().last().unwrap() & unused_mask, 0);
    }
}

#[test]
fn truncation_is_canonical_at_supported_bit_boundaries() {
    assert_canonical_truncation::<OneBit>(1);
    assert_canonical_truncation::<EightBits>(1);
    assert_canonical_truncation::<ThirteenBits>(2);
    assert_canonical_truncation::<TwoHundredFiftyFiveBits>(32);
    assert_canonical_truncation::<TwoHundredFiftySixBits>(32);
}
