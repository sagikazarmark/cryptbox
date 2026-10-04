//! Public-boundary tests for the derives: each behaves exactly like its manual impl.
#![cfg(feature = "derive")]

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, Codec,
    CodecError, CodecErrorKind, EncryptionKey, EncryptionKeyring, IndexId, IndexKeyId, Padding,
    Seal, SealId, Sealed, Utf8, index_id, index_key_id, seal_id,
};
use zeroize::Zeroizing;

fn keyring() -> EncryptionKeyring {
    EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap()
}

fn assert_codec<F: Seal<Codec = C>, C>() {}

fn assert_value<F: Seal<Value = V>, V>() {}

/// Primary contact address.
#[derive(Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
struct UserEmail;

/// The manual equivalent of [`UserEmail`].
struct ManualUserEmail;

impl Seal for ManualUserEmail {
    const ID: SealId = seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

#[test]
fn a_derived_seal_declares_its_id_value_and_default_codec_without_padding() {
    assert_eq!(
        UserEmail::ID,
        seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25")
    );
    assert_eq!(UserEmail::PADDING, Padding::NONE);
    assert_value::<UserEmail, String>();
    assert_codec::<UserEmail, Utf8>();
}

#[test]
fn a_derived_seal_opens_values_of_its_manual_equivalent() {
    let keys = keyring();
    let manual = Sealed::<ManualUserEmail>::seal(&"mark@example.com".to_owned(), &keys).unwrap();

    let derived = Sealed::<UserEmail>::from_bytes(manual.into_bytes()).unwrap();
    assert_eq!(derived.open(&keys).unwrap(), "mark@example.com");
}

/// [`UserEmail`] as its own value: the same ID, stored as its inner `String`.
#[derive(Debug, PartialEq, Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", transparent)]
struct SelfValuedEmail(String);

#[test]
fn a_transparent_seal_is_its_own_value_stored_as_its_field() {
    assert_value::<SelfValuedEmail, SelfValuedEmail>();
    assert_codec::<SelfValuedEmail, SelfValuedEmail>();
    assert_eq!(
        <SelfValuedEmail as Codec<SelfValuedEmail>>::ID,
        <Utf8 as Codec<String>>::ID
    );
}

#[test]
fn a_transparent_seal_and_a_marker_read_each_other_s_values() {
    let keys = keyring();
    let email = SelfValuedEmail("mark@example.com".to_owned());

    let marker = Sealed::<UserEmail>::seal(&email.0, &keys).unwrap();
    let as_self_valued = Sealed::<SelfValuedEmail>::from_bytes(marker.into_bytes()).unwrap();
    assert_eq!(as_self_valued.open(&keys).unwrap(), email);

    let self_valued = Sealed::<SelfValuedEmail>::seal(&email, &keys).unwrap();
    let as_marker = Sealed::<UserEmail>::from_bytes(self_valued.into_bytes()).unwrap();
    assert_eq!(as_marker.open(&keys).unwrap(), email.0);
}

/// A transparent seal over a named field, with an explicit codec.
#[derive(Debug, PartialEq, Seal)]
#[cryptbox(id = "3f5b7d91-2a4c-4e6f-8b1d-5c7e9f1a3b5d", transparent, codec = Utf8)]
struct Nickname {
    nickname: String,
}

#[test]
fn a_transparent_seal_stores_a_named_field_with_its_codec() {
    let keys = keyring();
    let nickname = Nickname {
        nickname: "ada".to_owned(),
    };

    let sealed = Sealed::<Nickname>::seal(&nickname, &keys).unwrap();

    assert_eq!(sealed.open(&keys).unwrap(), nickname);
    assert_eq!(
        <Nickname as Codec<Nickname>>::ID,
        <Utf8 as Codec<String>>::ID
    );
}

#[cfg(feature = "json")]
mod self_valued_json {
    use cryptbox::{Json, Seal, Sealed};
    use serde::{Deserialize, Serialize};

    use super::{assert_codec, assert_value, keyring};

    /// A whole response sealed as one JSON document.
    #[derive(Debug, PartialEq, Serialize, Deserialize, Seal)]
    #[cryptbox(id = "8c0e2a46-5b7d-4f91-a3c5-7e9b1d3f5a70", codec = Json)]
    struct Profile {
        name: String,
        email: String,
    }

    #[test]
    fn a_self_valued_seal_encodes_the_whole_type_with_its_codec() {
        assert_value::<Profile, Profile>();
        assert_codec::<Profile, Json>();

        let keys = keyring();
        let profile = Profile {
            name: "Ada".to_owned(),
            email: "ada@example.com".to_owned(),
        };
        let sealed = Sealed::<Profile>::seal(&profile, &keys).unwrap();

        assert_eq!(sealed.open(&keys).unwrap(), profile);
    }
}

/// An application value type with a hand-written codec, stored as `street\0city`.
#[derive(Clone, Debug, PartialEq)]
struct Address {
    street: String,
    city: String,
}

struct AddressCodec;

impl Codec<Address> for AddressCodec {
    const ID: &'static str = "address/1";

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

#[derive(Seal)]
#[cryptbox(
    id = "5D2E8A17-4C6B-4F93-8E0A-7B1C9D3F6A25",
    value = Address,
    codec = AddressCodec,
    padding = block(16),
)]
struct BillingAddress;

#[derive(Seal)]
#[cryptbox(id = "5d2e8a17-4c6b-4f93-8e0a-7b1c9d3f6a25")]
#[cryptbox(value = Address, codec = AddressCodec, padding = length(64usize))]
struct FixedBillingAddress;

#[test]
fn a_derived_seal_uses_its_named_codec_and_padding() {
    assert_eq!(
        BillingAddress::ID,
        seal_id!("5d2e8a17-4c6b-4f93-8e0a-7b1c9d3f6a25")
    );
    assert_eq!(BillingAddress::PADDING, Padding::block(16));
    assert_value::<BillingAddress, Address>();
    assert_codec::<BillingAddress, AddressCodec>();

    let keys = keyring();
    let sealed = Sealed::<BillingAddress>::seal(&address(), &keys).unwrap();
    assert_eq!(sealed.open(&keys).unwrap(), address());
}

#[test]
fn attributes_can_be_split_and_literal_suffixes_are_accepted() {
    assert_eq!(FixedBillingAddress::ID, BillingAddress::ID);
    assert_eq!(FixedBillingAddress::PADDING, Padding::length(64));
}

fn index_keys() -> BlindIndexKeyring {
    BlindIndexKeyring::new(BlindIndexKey::new(INDEX_KEY_ID, [0x42; 32]), []).unwrap()
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
    seal = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_text,
    normalizer = "text/1",
)]
struct EmailLookup;

/// The manual equivalent of [`EmailLookup`].
struct ManualEmailLookup;

impl BlindIndexSpec for ManualEmailLookup {
    type Seal = ManualUserEmail;
    const ID: IndexId = index_id!("2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53");
    const BITS: u16 = 32;
    const NORMALIZER: &'static str = "text/1";
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
        BlindIndex::<EmailLookup>::derive(&email, &keys)
            .unwrap()
            .as_bytes(),
        BlindIndex::<ManualEmailLookup>::derive(&email, &keys)
            .unwrap()
            .as_bytes()
    );
    assert_eq!(
        BlindIndex::<EmailLookup>::probes("mark@example.com", &keys).unwrap()[0].as_bytes(),
        BlindIndex::<ManualEmailLookup>::probes("mark@example.com", &keys).unwrap()[0].as_bytes()
    );
    assert!(BlindIndex::<EmailLookup>::verify_candidate("MARK@example.com", &email).unwrap());
}

#[test]
fn a_transparent_seal_rejects_what_its_inner_codec_rejects() {
    let error = <SelfValuedEmail as Codec<SelfValuedEmail>>::decode(&[0xff]).unwrap_err();

    assert_eq!(error.kind(), CodecErrorKind::InvalidUtf8);
}

#[test]
fn a_derived_blind_index_names_its_normalizer() {
    assert_eq!(EmailLookup::NORMALIZER, ManualEmailLookup::NORMALIZER);
}

#[derive(Seal)]
#[cryptbox(
    id = "4b8e2d6f-1a3c-4e57-b9d0-6f2a4c8e1b35",
    value = String,
)]
struct ProjectEmail;

#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "9c1e5a3d-7f2b-4d48-a6e0-3b5d9f1c7e24",
    seal = ProjectEmail,
    bits = 32,
    query = str,
    normalize = normalize_text,
    normalizer = "text/1",
)]
struct ProjectEmailLookup;

#[test]
fn a_derived_blind_index_matches_its_probes() {
    let keys = index_keys();
    let email = "Mark@Example.com".to_owned();
    let derived = BlindIndex::<ProjectEmailLookup>::derive(&email, &keys).unwrap();

    let probes = BlindIndex::<ProjectEmailLookup>::probes("mark@example.com", &keys).unwrap();

    assert_eq!(derived, probes[0]);
}

mod uuid_records {
    use cryptbox::{Record, Sealed};
    use uuid::Uuid;

    #[derive(Debug, PartialEq, Record)]
    struct ByUuid {
        #[cryptbox(record_id)]
        id: Uuid,
        #[cryptbox(seal = "6d1b3f5a-7c9e-4b2d-8f0a-1c3e5a7b9d2f")]
        body: String,
    }

    #[derive(Debug, PartialEq, Record)]
    struct ByBytes {
        #[cryptbox(record_id)]
        id: [u8; 16],
        #[cryptbox(seal = "6d1b3f5a-7c9e-4b2d-8f0a-1c3e5a7b9d2f")]
        body: String,
    }

    #[test]
    fn a_uuid_record_id_binds_its_sixteen_bytes() {
        let keys = super::keyring();
        let id = Uuid::from_u128(0x0192_3a4b_5c6d_7e8f_9a0b_1c2d_3e4f_5a6b);
        let stored = ByUuid {
            id,
            body: "ship it".to_owned(),
        }
        .seal(&keys)
        .unwrap();

        let as_bytes = StoredByBytes {
            id: *id.as_bytes(),
            body: Sealed::from_bytes(stored.body.into_bytes()).unwrap(),
        };
        assert_eq!(ByBytes::open(as_bytes, &keys).unwrap().body, "ship it");
    }
}
