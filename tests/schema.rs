//! Public-boundary tests for the schema manifest and unique-ID checks.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexSpec, EncryptionKey, Field, FieldId, IndexId, Keys,
    LocalBlindIndexKeyring, LocalEncryptionKeyring, Padding, Raw, Router, Utf8, field_id, index_id,
    schema::{Duplicate, Manifest},
};
use zeroize::Zeroizing;

struct Nickname;

impl Field for Nickname {
    const ID: FieldId = field_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct Avatar;

impl Field for Avatar {
    const ID: FieldId = field_id!("9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e");
    const PADDING: Padding = Padding::block(64);
    type Value = Vec<u8>;
    type Codec = Raw;
}

#[test]
fn manifest_lists_each_field() {
    let manifest = Manifest::new().field::<Nickname>().field::<Avatar>();

    assert_eq!(
        manifest.to_string(),
        "\
field 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01 schema::Nickname
  value: alloc::string::String
  codec: utf8
  padding: none
field 9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e schema::Avatar
  value: alloc::vec::Vec<u8>
  codec: raw
  padding: block(64)
"
    );
}

struct NicknameLookup;

impl BlindIndexSpec for NicknameLookup {
    type Field = Nickname;
    const ID: IndexId = index_id!("3d8b1f4e-6a2c-4e71-9f05-8c7d6b5a4e3f");
    const BITS: u16 = 24;
    const NORMALIZER: &'static str = "trim-lowercase/1";
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(query.trim().to_lowercase().into_bytes()))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

#[test]
fn manifest_lists_each_index() {
    let manifest = Manifest::new().index::<NicknameLookup>();

    assert_eq!(
        manifest.to_string(),
        "\
index 3d8b1f4e-6a2c-4e71-9f05-8c7d6b5a4e3f schema::NicknameLookup
  field: 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  bits: 24
  normalizer: trim-lowercase/1
"
    );
}

#[test]
fn manifest_reports_routes_and_fallbacks_from_keys() {
    let encryption = LocalEncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let blind_indexes =
        LocalBlindIndexKeyring::new(BlindIndexKey::generate().unwrap(), []).unwrap();
    let keys = Keys::new(Router::strict().route::<Nickname>(encryption).unwrap())
        .with_blind_indexes(Router::new(blind_indexes));

    let manifest = Manifest::new()
        .field::<Nickname>()
        .field::<Avatar>()
        .index::<NicknameLookup>()
        .keys(&keys);

    assert_eq!(
        manifest.to_string(),
        "\
field 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01 schema::Nickname
  value: alloc::string::String
  codec: utf8
  padding: none
  encryption key: routed
field 9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e schema::Avatar
  value: alloc::vec::Vec<u8>
  codec: raw
  padding: block(64)
  encryption key: unrouted
index 3d8b1f4e-6a2c-4e71-9f05-8c7d6b5a4e3f schema::NicknameLookup
  field: 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  bits: 24
  normalizer: trim-lowercase/1
  blind-index key: fallback
"
    );
}

/// Copied from [`Nickname`] without generating a fresh ID.
struct DisplayName;

impl Field for DisplayName {
    const ID: FieldId = field_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

#[test]
fn manifest_reports_duplicate_ids() {
    let unique = Manifest::new().field::<Nickname>().field::<Avatar>();
    let duplicated = Manifest::new()
        .field::<Nickname>()
        .field::<Avatar>()
        .field::<DisplayName>();

    assert!(unique.duplicates().is_empty());
    assert_eq!(
        duplicated
            .duplicates()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["duplicate field ID 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01: \
             schema::Nickname, schema::DisplayName"]
    );
    assert!(duplicated.to_string().ends_with(
        "duplicate field ID 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01: \
         schema::Nickname, schema::DisplayName\n"
    ));
}

/// Copied from [`NicknameLookup`] without generating a fresh ID.
struct DisplayNameLookup;

impl BlindIndexSpec for DisplayNameLookup {
    type Field = Nickname;
    const ID: IndexId = index_id!("3d8b1f4e-6a2c-4e71-9f05-8c7d6b5a4e3f");
    const BITS: u16 = 16;
    const NORMALIZER: &'static str = "exact/1";
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(query.as_bytes().to_vec()))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

#[test]
fn manifest_reports_duplicate_index_ids() {
    let manifest = Manifest::new()
        .index::<NicknameLookup>()
        .index::<DisplayNameLookup>();

    assert_eq!(
        manifest.duplicates(),
        [Duplicate::Index {
            id: NicknameLookup::ID,
            markers: vec!["schema::NicknameLookup", "schema::DisplayNameLookup"],
        }]
    );
}

// Distinct IDs pass the compile-time check; its doctests show duplicates failing.
cryptbox::assert_unique_ids!(Nickname, Avatar);
cryptbox::assert_unique_ids!(indexes: NicknameLookup);

#[cfg(any(feature = "json", feature = "postcard"))]
mod serde_codecs {
    use cryptbox::{Field, FieldId, Padding, field_id, schema::Manifest};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Address {
        street: String,
    }

    #[cfg(feature = "json")]
    struct HomeAddress;

    #[cfg(feature = "json")]
    impl Field for HomeAddress {
        const ID: FieldId = field_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
        const PADDING: Padding = Padding::length(256);
        type Value = Address;
        type Codec = cryptbox::Json;
    }

    #[cfg(feature = "json")]
    #[test]
    fn manifest_names_the_json_codec() {
        assert_eq!(
            Manifest::new().field::<HomeAddress>().to_string(),
            "\
field 0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64 schema::serde_codecs::HomeAddress
  value: schema::serde_codecs::Address
  codec: json/1
  padding: length(256)
"
        );
    }

    #[cfg(feature = "postcard")]
    struct BillingAddress;

    #[cfg(feature = "postcard")]
    impl Field for BillingAddress {
        const ID: FieldId = field_id!("7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13");
        const PADDING: Padding = Padding::NONE;
        type Value = Address;
        type Codec = cryptbox::Postcard;
    }

    #[cfg(feature = "postcard")]
    #[test]
    fn manifest_names_the_postcard_codec() {
        assert_eq!(
            Manifest::new().field::<BillingAddress>().to_string(),
            "\
field 7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13 schema::serde_codecs::BillingAddress
  value: schema::serde_codecs::Address
  codec: postcard/1
  padding: none
"
        );
    }
}
