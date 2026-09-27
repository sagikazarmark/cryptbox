//! Public-boundary tests for the derives: each behaves exactly like its manual impl.
#![cfg(feature = "derive")]

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexSpec, Ciphertext, Codec, CodecError, CodecErrorKind,
    Encrypted, EncryptionKey, Field, FieldId, IndexId, IndexKeyId, LocalBlindIndexKeyring,
    LocalEncryptionKeyring, Padding, Plaintext, Utf8, field_id, index_id, index_key_id,
};
use zeroize::Zeroizing;

fn keyring() -> LocalEncryptionKeyring {
    LocalEncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap()
}

fn assert_codec<F: Field<Codec = C>, C>() {}

fn assert_value<F: Field<Value = V>, V>() {}

/// Primary contact address.
#[derive(Field)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
struct UserEmail;

/// The manual equivalent of [`UserEmail`].
struct ManualUserEmail;

impl Field for ManualUserEmail {
    const ID: FieldId = field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = <String as Plaintext>::Codec;
}

#[test]
fn a_derived_field_declares_its_id_value_and_default_codec_without_padding() {
    assert_eq!(
        UserEmail::ID,
        field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25")
    );
    assert_eq!(UserEmail::PADDING, Padding::NONE);
    assert_value::<UserEmail, String>();
    assert_codec::<UserEmail, Utf8>();
}

#[test]
fn a_derived_field_reads_ciphertext_of_its_manual_equivalent() {
    let keys = keyring();
    let manual = Encrypted::<ManualUserEmail>::new("mark@example.com".to_owned())
        .encrypt_with(&keys)
        .unwrap();

    let derived = Ciphertext::<UserEmail>::from_bytes(manual.into_bytes()).unwrap();
    assert_eq!(
        derived.decrypt_with(&keys).unwrap().expose_secret(),
        "mark@example.com"
    );
}

/// An application value type with a hand-written codec, stored as `street\0city`.
#[derive(Clone, Debug, PartialEq)]
struct Address {
    street: String,
    city: String,
}

struct AddressCodec;

impl Codec<Address> for AddressCodec {
    fn encode(value: &Address) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        Ok(Zeroizing::new(
            format!("{}\0{}", value.street, value.city).into_bytes(),
        ))
    }

    fn decode(bytes: &[u8]) -> Result<Address, CodecError> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| CodecError::new(CodecErrorKind::InvalidUtf8))?;
        let (street, city) = text
            .split_once('\0')
            .ok_or(CodecError::new(CodecErrorKind::Decoding))?;

        Ok(Address {
            street: street.to_owned(),
            city: city.to_owned(),
        })
    }
}

fn address() -> Address {
    Address {
        street: "1 Main Street".to_owned(),
        city: "Springfield".to_owned(),
    }
}

#[derive(Field)]
#[cryptbox(
    id = "5D2E8A17-4C6B-4F93-8E0A-7B1C9D3F6A25",
    value = Address,
    codec = AddressCodec,
    padding = block(16),
)]
struct BillingAddress;

#[derive(Field)]
#[cryptbox(id = "5d2e8a17-4c6b-4f93-8e0a-7b1c9d3f6a25")]
#[cryptbox(value = Address, codec = AddressCodec, padding = length(64usize))]
struct FixedBillingAddress;

#[test]
fn a_derived_field_uses_its_named_codec_and_padding() {
    assert_eq!(
        BillingAddress::ID,
        field_id!("5d2e8a17-4c6b-4f93-8e0a-7b1c9d3f6a25")
    );
    assert_eq!(BillingAddress::PADDING, Padding::block(16));
    assert_value::<BillingAddress, Address>();
    assert_codec::<BillingAddress, AddressCodec>();

    let keys = keyring();
    let ciphertext = Encrypted::<BillingAddress>::new(address())
        .encrypt_with(&keys)
        .unwrap();
    assert_eq!(
        ciphertext.decrypt_with(&keys).unwrap().expose_secret(),
        &address()
    );
}

#[test]
fn attributes_can_be_split_and_literal_suffixes_are_accepted() {
    assert_eq!(FixedBillingAddress::ID, BillingAddress::ID);
    assert_eq!(FixedBillingAddress::PADDING, Padding::length(64));
}

fn index_keys() -> LocalBlindIndexKeyring {
    LocalBlindIndexKeyring::new(BlindIndexKey::new(INDEX_KEY_ID, [0x42; 32]), []).unwrap()
}

const INDEX_KEY_ID: IndexKeyId = index_key_id!("60000000-0000-4000-8000-000000000006");

#[allow(clippy::unnecessary_wraps)] // Normalizers are fallible by contract.
fn normalize_text(text: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(
        text.trim().to_ascii_lowercase().into_bytes(),
    ))
}

#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
    field = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_text,
)]
struct EmailLookup;

/// The manual equivalent of [`EmailLookup`].
struct ManualEmailLookup;

impl BlindIndexSpec for ManualEmailLookup {
    type Field = ManualUserEmail;
    const ID: IndexId = index_id!("2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53");
    const BITS: u16 = 32;
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        normalize_text(query)
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        normalize_text(value)
    }
}

#[test]
fn a_derived_blind_index_derives_the_same_index_as_its_manual_equivalent() {
    let keys = index_keys();
    let email = "Mark@Example.com ".to_owned();

    assert_eq!(EmailLookup::ID, ManualEmailLookup::ID);
    assert_eq!(EmailLookup::BITS, 32);
    assert_eq!(
        EmailLookup::derive_with(&email, &keys).unwrap().as_bytes(),
        ManualEmailLookup::derive_with(&email, &keys)
            .unwrap()
            .as_bytes()
    );
    assert_eq!(
        EmailLookup::probes_with("mark@example.com", &keys).unwrap()[0].as_bytes(),
        ManualEmailLookup::probes_with("mark@example.com", &keys).unwrap()[0].as_bytes()
    );
    assert!(EmailLookup::verify_candidate("MARK@example.com", &email).unwrap());
}

fn street(address: &Address) -> &str {
    &address.street
}

#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "3f5d8c2b-6e40-4b97-8c31-8a2f7d9e5b64",
    field = BillingAddress,
    bits = 64,
    query = str,
    normalize = normalize_text,
    project = street,
)]
struct StreetLookup;

/// The manual equivalent of [`StreetLookup`].
struct ManualStreetLookup;

impl BlindIndexSpec for ManualStreetLookup {
    type Field = BillingAddress;
    const ID: IndexId = index_id!("3f5d8c2b-6e40-4b97-8c31-8a2f7d9e5b64");
    const BITS: u16 = 64;
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        normalize_text(query)
    }

    fn normalize_value(value: &Address) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        normalize_text(&value.street)
    }
}

#[test]
fn a_projected_blind_index_normalizes_part_of_the_value() {
    let keys = index_keys();

    assert_eq!(
        StreetLookup::derive_with(&address(), &keys)
            .unwrap()
            .as_bytes(),
        ManualStreetLookup::derive_with(&address(), &keys)
            .unwrap()
            .as_bytes()
    );
    assert!(StreetLookup::verify_candidate("1 MAIN STREET", &address()).unwrap());
    assert!(!StreetLookup::verify_candidate("Springfield", &address()).unwrap());
}

/// A transparent newtype: stored with exactly the bytes of its inner `String`.
#[derive(Debug, PartialEq, cryptbox::Plaintext)]
struct Email(String);

#[derive(Field)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = Email)]
struct TypedUserEmail;

#[test]
fn a_transparent_value_type_stores_its_inner_values_bytes() {
    let keys = keyring();

    let typed = Encrypted::<TypedUserEmail>::new(Email("mark@example.com".to_owned()))
        .encrypt_with(&keys)
        .unwrap();
    let as_string = Ciphertext::<ManualUserEmail>::from_bytes(typed.into_bytes()).unwrap();
    assert_eq!(
        as_string.decrypt_with(&keys).unwrap().expose_secret(),
        "mark@example.com"
    );

    let plain = Encrypted::<ManualUserEmail>::new("ada@example.com".to_owned())
        .encrypt_with(&keys)
        .unwrap();
    let as_email = Ciphertext::<TypedUserEmail>::from_bytes(plain.into_bytes()).unwrap();
    assert_eq!(
        as_email.decrypt_with(&keys).unwrap().expose_secret(),
        &Email("ada@example.com".to_owned())
    );
}

#[test]
fn a_transparent_value_type_rejects_what_its_inner_codec_rejects() {
    let error = <Email as Plaintext>::Codec::decode(&[0xff]).unwrap_err();

    assert_eq!(error.kind(), CodecErrorKind::InvalidUtf8);
}

/// A value type that names its default codec.
#[derive(Clone, Debug, PartialEq, cryptbox::Plaintext)]
#[cryptbox(codec = PostcodeCodec)]
struct Postcode {
    code: String,
}

struct PostcodeCodec;

impl Codec<Postcode> for PostcodeCodec {
    fn encode(value: &Postcode) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        Ok(Zeroizing::new(value.code.as_bytes().to_vec()))
    }

    fn decode(bytes: &[u8]) -> Result<Postcode, CodecError> {
        Ok(Postcode {
            code: String::from_utf8(bytes.to_vec())
                .map_err(|_| CodecError::new(CodecErrorKind::InvalidUtf8))?,
        })
    }
}

#[test]
fn a_derived_plaintext_names_its_codec() {
    fn assert_plaintext<T: Plaintext<Codec = C>, C>() {}

    assert_plaintext::<Postcode, PostcodeCodec>();
}

mod renamed {
    pub use cryptbox as encryption;
}

#[derive(Field)]
#[cryptbox(
    crate = "renamed::encryption",
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = Postcode,
)]
struct RenamedCratePostcode;

#[test]
fn derives_can_name_cryptbox_through_another_path() {
    assert_eq!(RenamedCratePostcode::ID, UserEmail::ID);
    assert_codec::<RenamedCratePostcode, PostcodeCodec>();
}
