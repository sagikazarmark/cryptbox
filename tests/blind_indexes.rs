//! Public-boundary tests for blind indexes and prepared storage values.

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, IndexId, IndexKeyId, KeyId, Padding, Seal, Sealed, Utf8, index_id,
    index_key_id, inspect_blind_index, key_id, seal_id,
};
use zeroize::Zeroizing;

const ENCRYPTION_KEY_ID: KeyId = key_id!("50000000-0000-4000-8000-000000000005");
const OLD_INDEX_KEY_ID: IndexKeyId = index_key_id!("60000000-0000-4000-8000-000000000006");
const CURRENT_INDEX_KEY_ID: IndexKeyId = index_key_id!("70000000-0000-4000-8000-000000000007");

struct EmailSeal;

impl Seal for EmailSeal {
    const ID: cryptbox::SealId = seal_id!("80000000-0000-4000-8000-000000000008");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Indexes = ();
}

struct PhoneSeal;

impl Seal for PhoneSeal {
    const ID: cryptbox::SealId = seal_id!("90000000-0000-4000-8000-000000000009");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Indexes = ();
}

fn normalize_email(input: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(input.trim().to_ascii_lowercase().into_bytes())
}

struct EmailExact;

impl BlindIndexSpec for EmailExact {
    type Seal = EmailSeal;
    const ID: IndexId = index_id!("a0000000-0000-4000-8000-00000000000a");
    const BITS: u16 = 13;
    const NORMALIZER: &'static str = "email/1";
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(normalize_email(query))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(normalize_email(value))
    }
}

/// The same index ID and normalization over another seal.
struct PhoneExact;

impl BlindIndexSpec for PhoneExact {
    type Seal = PhoneSeal;
    const ID: IndexId = EmailExact::ID;
    const BITS: u16 = EmailExact::BITS;
    const NORMALIZER: &'static str = "email/1";
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(normalize_email(query))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(normalize_email(value))
    }
}

fn index_key(id: IndexKeyId, byte: u8) -> BlindIndexKey {
    BlindIndexKey::new(id, [byte; 32])
}

fn index_keys() -> BlindIndexKeyring {
    BlindIndexKeyring::new(index_key(CURRENT_INDEX_KEY_ID, 41), []).unwrap()
}

fn email(value: &str) -> String {
    value.to_owned()
}

#[test]
fn blind_indexes_are_deterministic_normalized_and_explicitly_truncated() {
    let keys = index_keys();

    let first = EmailExact::derive_with(&email(" Mark@Example.com "), &keys).unwrap();
    let second = EmailExact::derive_with(&email("mark@example.com"), &keys).unwrap();

    assert_eq!(first, second);
    assert_eq!(format!("{first:?}"), "BlindIndex([REDACTED])");
    assert_eq!(AsRef::<[u8]>::as_ref(&first), first.as_bytes());
    assert_eq!(first.as_bytes().len(), 21);
    assert_eq!(first.as_bytes().last().unwrap() & 0b0000_0111, 0);

    let stored = BlindIndex::<EmailExact>::try_from(first.as_bytes().to_vec()).unwrap();
    assert_eq!(stored, first);

    let info = inspect_blind_index(first.as_bytes()).unwrap();
    assert_eq!(info.index_key_id(), CURRENT_INDEX_KEY_ID);
    assert_eq!(info.bits(), 13);
}

#[test]
fn seal_and_index_domains_are_cryptographically_separated() {
    let keys = index_keys();
    let email_index = EmailExact::derive_with(&email("mark@example.com"), &keys).unwrap();
    let phone_index = PhoneExact::derive_with(&email("mark@example.com"), &keys).unwrap();

    assert_ne!(email_index.as_bytes(), phone_index.as_bytes());
}

#[test]
fn query_probes_cover_current_and_historical_index_generations() {
    let old = index_key(OLD_INDEX_KEY_ID, 43);
    let keys = BlindIndexKeyring::new(index_key(CURRENT_INDEX_KEY_ID, 47), [old]).unwrap();

    let probes = EmailExact::probes_with("mark@example.com", &keys).unwrap();

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
fn query_probes_match_indexes_derived_from_values() {
    let keys = index_keys();
    let stored = EmailExact::derive_with(&email("mark@example.com"), &keys).unwrap();

    let probes = EmailExact::probes_with(" Mark@Example.com ", &keys).unwrap();

    assert_eq!(probes, vec![stored]);
}

#[test]
fn candidate_hits_require_normalized_plaintext_verification() {
    assert!(
        EmailExact::verify_candidate(" Mark@Example.com ", &email("mark@example.com")).unwrap()
    );
    assert!(!EmailExact::verify_candidate("mark@example.com", &email("mask@example.com")).unwrap());
    assert!(!EmailExact::verify_candidate("mark@example.com", &email("short")).unwrap());
}

#[test]
fn prepared_values_derive_the_sealed_value_and_indexes_from_one_source() {
    let encryption_keys =
        EncryptionKeyring::new(EncryptionKey::new(ENCRYPTION_KEY_ID, [53; 32]), []).unwrap();
    let index_keys = index_keys();
    let value = email("Mark@Example.com");

    let prepared = Sealed::<EmailSeal>::prepare(&value, &encryption_keys)
        .unwrap()
        .with_index_with::<EmailExact>(&index_keys)
        .unwrap();

    assert!(!prepared.sealed().as_bytes().is_empty());
    let prepared_index = prepared.index::<EmailExact>().unwrap();
    let direct = EmailExact::derive_with(&value, &index_keys).unwrap();
    assert_eq!(prepared_index.as_bytes(), direct.as_bytes());
    assert_eq!(AsRef::<[u8]>::as_ref(&prepared_index), direct.as_bytes());
}

/// A computed index over part of the value.
struct EmailDomain;

impl BlindIndexSpec for EmailDomain {
    type Seal = EmailSeal;
    const ID: IndexId = index_id!("c0000000-0000-4000-8000-00000000000c");
    const BITS: u16 = 16;
    const NORMALIZER: &'static str = "email-domain/1";
    type Query = str;

    fn normalize_query(domain: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(domain.to_ascii_lowercase().into_bytes()))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        let (_, domain) = value.rsplit_once('@').ok_or(BlindIndexError::new())?;

        Self::normalize_query(domain)
    }
}

#[test]
fn a_blind_index_can_be_computed_from_part_of_the_value() {
    let keys = index_keys();
    let stored = EmailDomain::derive_with(&email("mark@Example.com"), &keys).unwrap();

    assert_eq!(
        EmailDomain::probes_with("example.com", &keys).unwrap(),
        vec![stored]
    );
    assert!(EmailDomain::verify_candidate("EXAMPLE.com", &email("ada@example.com")).unwrap());
    assert!(EmailDomain::derive_with(&email("no domain"), &keys).is_err());
}

struct Person {
    name: String,
    postal_code: String,
}

struct PersonSeal;

impl Seal for PersonSeal {
    const ID: cryptbox::SealId = seal_id!("d0000000-0000-4000-8000-00000000000d");
    const PADDING: Padding = Padding::NONE;
    type Value = Person;
    type Codec = PersonCodec;
    type Indexes = ();
}

struct PersonCodec;

impl cryptbox::Codec<Person> for PersonCodec {
    const ID: &'static str = "person/1";

    fn encode(value: &Person) -> Result<Zeroizing<Vec<u8>>, cryptbox::CodecError> {
        Ok(Zeroizing::new(
            format!("{}\0{}", value.name, value.postal_code).into_bytes(),
        ))
    }

    fn decode(_: &[u8]) -> Result<Person, cryptbox::CodecError> {
        unimplemented!("indexes never decode")
    }
}

/// A composite index over two parts of the value.
struct NameAndPostalCode;

impl BlindIndexSpec for NameAndPostalCode {
    type Seal = PersonSeal;
    const ID: IndexId = index_id!("b0000000-0000-4000-8000-00000000000b");
    const BITS: u16 = 128;
    const NORMALIZER: &'static str = "name-postal-code/1";
    type Query = (&'static str, &'static str);

    fn normalize_query(query: &Self::Query) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(
            format!("{}\0{}", query.0.to_ascii_lowercase(), query.1).into_bytes(),
        ))
    }

    fn normalize_value(value: &Person) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(
            format!("{}\0{}", value.name.to_ascii_lowercase(), value.postal_code).into_bytes(),
        ))
    }
}

#[test]
fn a_blind_index_can_combine_several_parts_of_the_value() {
    let keys = index_keys();
    let person = Person {
        name: "Ada Lovelace".to_owned(),
        postal_code: "SW1A 1AA".to_owned(),
    };

    let index = NameAndPostalCode::derive_with(&person, &keys).unwrap();

    assert_eq!(inspect_blind_index(index.as_bytes()).unwrap().bits(), 128);
    assert_eq!(
        NameAndPostalCode::probes_with(&("ada lovelace", "SW1A 1AA"), &keys).unwrap(),
        vec![index]
    );
}

#[test]
fn typed_indexes_reject_noncanonical_storage_bytes() {
    let keys = index_keys();
    let index = EmailExact::derive_with(&email("mark@example.com"), &keys).unwrap();
    let mut bytes = index.into_bytes();
    *bytes.last_mut().unwrap() |= 1;

    assert!(BlindIndex::<EmailExact>::try_from(bytes).is_err());
}

#[test]
fn inspection_rejects_untrusted_out_of_range_precisions() {
    let index = EmailExact::derive_with(&email("mark@example.com"), &index_keys()).unwrap();
    let mut bytes = index.into_bytes();

    bytes[17..19].copy_from_slice(&0_u16.to_be_bytes());
    bytes.truncate(19);
    assert!(inspect_blind_index(&bytes).is_err());

    bytes[17..19].copy_from_slice(&257_u16.to_be_bytes());
    bytes.resize(19 + 257_usize.div_ceil(8), 0);
    assert!(inspect_blind_index(&bytes).is_err());
}

macro_rules! truncation_spec {
    ($name:ident, $bits:expr, $id_byte:expr) => {
        struct $name;

        impl BlindIndexSpec for $name {
            type Seal = EmailSeal;
            const ID: IndexId = IndexId::from_bytes([$id_byte; 16]);
            const BITS: u16 = $bits;
            const NORMALIZER: &'static str = "exact/1";
            type Query = str;

            fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
                Ok(Zeroizing::new(query.as_bytes().to_vec()))
            }

            fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
                Self::normalize_query(value)
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
    Spec: BlindIndexSpec<Seal = EmailSeal>,
{
    let index = Spec::derive_with(&email("truncation vector"), &index_keys()).unwrap();

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

#[test]
fn a_stored_index_is_consistent_with_the_value_it_was_derived_from() {
    let keys = index_keys();
    let stored = EmailExact::derive_with(&email("mark@example.com"), &keys).unwrap();

    assert!(EmailExact::is_consistent_with(&email(" Mark@Example.com "), &stored, &keys).unwrap());
}

#[test]
fn a_stored_index_from_a_historical_generation_is_consistent_with_its_value() {
    let old = index_key(OLD_INDEX_KEY_ID, 43);
    let before_rotation = BlindIndexKeyring::new(old.clone(), []).unwrap();
    let stored = EmailExact::derive_with(&email("mark@example.com"), &before_rotation).unwrap();
    let keys = BlindIndexKeyring::new(index_key(CURRENT_INDEX_KEY_ID, 47), [old]).unwrap();

    assert!(EmailExact::is_consistent_with(&email("mark@example.com"), &stored, &keys).unwrap());
}

#[test]
fn a_stored_index_for_another_value_is_inconsistent() {
    let keys = index_keys();
    let stored = EmailExact::derive_with(&email("other@example.com"), &keys).unwrap();

    assert!(!EmailExact::is_consistent_with(&email("mark@example.com"), &stored, &keys).unwrap());
}

#[test]
fn a_stored_index_from_an_unknown_generation_cannot_be_checked() {
    let retired = BlindIndexKeyring::new(index_key(OLD_INDEX_KEY_ID, 43), []).unwrap();
    let stored = EmailExact::derive_with(&email("mark@example.com"), &retired).unwrap();

    assert_eq!(
        EmailExact::is_consistent_with(&email("mark@example.com"), &stored, &index_keys())
            .unwrap_err(),
        Error::UnknownBlindIndexKey(OLD_INDEX_KEY_ID)
    );
}

#[test]
fn a_computed_index_is_consistent_with_any_value_sharing_the_computed_part() {
    let keys = index_keys();
    let stored = EmailDomain::derive_with(&email("mark@Example.com"), &keys).unwrap();

    assert!(EmailDomain::is_consistent_with(&email("ada@example.com"), &stored, &keys).unwrap());
    assert!(!EmailDomain::is_consistent_with(&email("mark@example.org"), &stored, &keys).unwrap());
}

#[test]
fn a_composite_index_is_consistent_only_when_every_part_matches() {
    let keys = index_keys();
    let person = |name: &str, postal_code: &str| Person {
        name: name.to_owned(),
        postal_code: postal_code.to_owned(),
    };
    let stored =
        NameAndPostalCode::derive_with(&person("Ada Lovelace", "SW1A 1AA"), &keys).unwrap();

    assert!(
        NameAndPostalCode::is_consistent_with(&person("ada lovelace", "SW1A 1AA"), &stored, &keys)
            .unwrap()
    );
    assert!(
        !NameAndPostalCode::is_consistent_with(&person("Ada Lovelace", "EC1A 1BB"), &stored, &keys)
            .unwrap()
    );
}

struct TicketEmail;

impl Seal for TicketEmail {
    const ID: cryptbox::SealId = seal_id!("c0000000-0000-4000-8000-00000000000c");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Indexes = (TicketEmailExact,);
}

struct TicketEmailExact;

impl BlindIndexSpec for TicketEmailExact {
    type Seal = TicketEmail;
    const ID: IndexId = index_id!("d0000000-0000-4000-8000-00000000000d");
    const BITS: u16 = 32;
    const NORMALIZER: &'static str = "email/1";
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(normalize_email(query))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(normalize_email(value))
    }
}

fn ticket_keys() -> EncryptionKeyring {
    EncryptionKeyring::new(EncryptionKey::new(ENCRYPTION_KEY_ID, [42; 32]), []).unwrap()
}

#[test]
fn prepared_indexes_match_derived_ones() {
    let keys = ticket_keys();
    let index_keys = index_keys();
    let value = email("mark@example.com");
    let prepared = Sealed::<TicketEmail>::prepare(&value, &keys)
        .unwrap()
        .with_index_with::<TicketEmailExact>(&index_keys)
        .unwrap();

    assert_eq!(
        prepared.index::<TicketEmailExact>().unwrap().as_bytes(),
        TicketEmailExact::derive_with(&value, &index_keys)
            .unwrap()
            .into_bytes()
    );
}

#[test]
fn separate_index_keys_separate_equal_values() {
    let acme = index_keys();
    let globex = BlindIndexKeyring::new(BlindIndexKey::generate().unwrap(), []).unwrap();
    let value = email("mark@example.com");
    let stored = TicketEmailExact::derive_with(&value, &acme).unwrap();

    assert_ne!(
        stored,
        TicketEmailExact::derive_with(&value, &globex).unwrap()
    );
    assert!(
        !TicketEmailExact::probes_with(" Mark@Example.com ", &globex)
            .unwrap()
            .contains(&stored)
    );
    assert_eq!(
        TicketEmailExact::probes_with(" Mark@Example.com ", &acme).unwrap(),
        [stored]
    );
}
