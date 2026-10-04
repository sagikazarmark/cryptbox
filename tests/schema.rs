//! Public-boundary tests for the schema manifest and unique-ID checks.

use cryptbox::envelope::inspect_ciphertext;
use cryptbox::{
    BlindIndexError, BlindIndexSpec, EncryptionKey, EncryptionKeyring, InRecord, IndexId, Padding,
    Raw, Seal, SealId, Sealed, Utf8, index_id,
    schema::{Duplicate, Manifest},
    seal_id,
};
use zeroize::Zeroizing;

struct Nickname;

impl Seal for Nickname {
    const ID: SealId = seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct Avatar;

impl Seal for Avatar {
    const ID: SealId = seal_id!("9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e");
    const PADDING: Padding = Padding::block(64);
    type Value = Vec<u8>;
    type Codec = Raw;
}

#[test]
fn manifest_lists_each_seal() {
    // A seal lists the contexts it is registered in: standalone for `Nickname`,
    // none for `Avatar`.
    let manifest = Manifest::new()
        .sealed::<Nickname, ()>()
        .seal::<Avatar>()
        .seal::<Nickname>();

    assert_eq!(
        manifest.to_string(),
        "\
seal 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  codec: utf8
  padding: none
  context: 502de8fcfb838c80
seal 9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e
  codec: raw
  padding: block(64)
"
    );
}

struct RowNote;

impl Seal for RowNote {
    const ID: SealId = seal_id!("6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51");
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
}

#[test]
fn manifest_shows_the_context_a_seal_is_stored_in() {
    // As a record with an `i64` record ID stores it.
    let snapshot = Manifest::new()
        .sealed::<RowNote, InRecord<i64>>()
        .to_string();

    assert_eq!(
        snapshot,
        "\
seal 6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51
  codec: utf8
  padding: block(16)
  context: af72b9c5219cf83b
"
    );

    // The fingerprint, computed with shasum from docs/wire-format.md#context-fingerprint,
    // is the one a sealed value's header carries.
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let sealed = Sealed::<RowNote, InRecord<i64>>::seal_in(&"hi".to_owned(), &1, &keys).unwrap();
    let header = inspect_ciphertext(sealed.as_bytes()).unwrap();
    assert!(snapshot.contains(&format!(
        "  context: {}\n",
        hex::encode(header.context_fingerprint())
    )));
}

struct NicknameLookup;

impl BlindIndexSpec for NicknameLookup {
    type Seal = Nickname;
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
index 3d8b1f4e-6a2c-4e71-9f05-8c7d6b5a4e3f
  seal: 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  bits: 24
  normalizer: trim-lowercase/1
"
    );
}

/// Copied from [`Nickname`] without generating a fresh ID.
struct DisplayName;

impl Seal for DisplayName {
    const ID: SealId = seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

#[test]
fn manifest_reports_duplicate_ids() {
    let unique = Manifest::new().seal::<Nickname>().seal::<Avatar>();
    let duplicated = Manifest::new()
        .seal::<Nickname>()
        .seal::<Avatar>()
        .seal::<DisplayName>();

    assert_eq!(unique.duplicates(), []);
    assert_eq!(
        duplicated
            .duplicates()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["duplicate seal ID 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01: \
             schema::Nickname, schema::DisplayName"]
    );
    // The snapshot flags the ID without naming types.
    assert!(
        duplicated
            .to_string()
            .ends_with("duplicate seal ID 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01\n")
    );
}

/// Copied from [`NicknameLookup`] without generating a fresh ID.
struct DisplayNameLookup;

impl BlindIndexSpec for DisplayNameLookup {
    type Seal = Nickname;
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

#[test]
fn manifest_reports_a_seal_in_several_contexts() {
    let manifest = Manifest::new()
        .sealed::<RowNote, InRecord<i64>>()
        .sealed::<RowNote, ()>()
        .sealed::<RowNote, InRecord<i64>>();

    assert_eq!(
        manifest.duplicates(),
        [Duplicate::Context {
            id: RowNote::ID,
            contexts: vec![
                hex::decode("af72b9c5219cf83b").unwrap().try_into().unwrap(),
                hex::decode("502de8fcfb838c80").unwrap().try_into().unwrap(),
            ],
        }]
    );
    assert!(manifest.to_string().ends_with(
        "  context: 502de8fcfb838c80\n\
         seal ID 6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51 in several contexts\n"
    ));
    assert_eq!(
        Manifest::new()
            .sealed::<RowNote, InRecord<i64>>()
            .sealed::<RowNote, InRecord<i64>>()
            .duplicates(),
        []
    );
}

// Distinct IDs pass the compile-time check; its doctests show duplicates failing.
cryptbox::assert_unique_ids!(Nickname, Avatar);
cryptbox::assert_unique_ids!(indexes: NicknameLookup);

#[cfg(feature = "json")]
mod serde_codecs {
    use cryptbox::{Padding, Seal, SealId, schema::Manifest, seal_id};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Address {
        street: String,
    }

    struct HomeAddress;

    impl Seal for HomeAddress {
        const ID: SealId = seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
        const PADDING: Padding = Padding::length(256);
        type Value = Address;
        type Codec = cryptbox::Json;
    }

    #[test]
    fn manifest_names_the_json_codec() {
        assert_eq!(
            Manifest::new().seal::<HomeAddress>().to_string(),
            "\
seal 0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64
  codec: json/1
  padding: length(256)
"
        );
    }
}

#[cfg(feature = "derive")]
mod records {
    use cryptbox::{Seal, schema::Manifest};

    /// A record whose stored form takes its default name, `StoredCustomer`.
    #[derive(cryptbox::Record)]
    pub struct Customer {
        #[cryptbox(record_id)]
        pub id: i64,
        #[cryptbox(plaintext)]
        pub tenant: Vec<u8>,
        #[cryptbox(seal = "dd965aff-c187-49ed-86fe-b75e63fd228d")]
        pub email: String,
        #[cryptbox(plaintext)]
        pub created_at: i64,
        #[cryptbox(plaintext)]
        pub r#type: String,
        #[cryptbox(seal = "c173ce33-731d-4051-b1d7-e5dd549c5371")]
        pub note: String,
    }

    #[test]
    fn manifest_lists_a_records_seals_and_fields() {
        let manifest = Manifest::new().record::<Customer>().record::<Customer>();

        assert_eq!(
            manifest.to_string(),
            "\
record
  seals: dd965aff-c187-49ed-86fe-b75e63fd228d, c173ce33-731d-4051-b1d7-e5dd549c5371
  record id: id
  record kind: i64
  context: af72b9c5219cf83b
  plaintext: tenant, created_at, type
"
        );
        assert_eq!(
            <CustomerEmail as Seal>::ID.to_string(),
            "dd965aff-c187-49ed-86fe-b75e63fd228d"
        );
    }

    #[test]
    fn a_record_without_plaintext_fields_says_so() {
        #[derive(cryptbox::Record)]
        struct Note {
            #[cryptbox(record_id)]
            id: i64,
            #[cryptbox(seal = "4f3ca6a2-a683-49b7-8d1a-718b790f7154")]
            body: String,
        }

        assert!(
            Manifest::new()
                .record::<Note>()
                .to_string()
                .ends_with("  context: af72b9c5219cf83b\n  plaintext: none\n")
        );
    }

    #[test]
    fn a_record_field_s_seal_also_stored_standalone_is_reported() {
        let manifest = Manifest::new()
            .record::<Customer>()
            .sealed::<CustomerEmail, ()>();

        assert!(matches!(
            manifest.duplicates().as_slice(),
            [cryptbox::schema::Duplicate::Context { id, .. }] if *id == CustomerEmail::ID
        ));
    }

    #[test]
    fn a_seal_id_in_two_records_is_reported() {
        #[derive(cryptbox::Record)]
        struct Supplier {
            #[cryptbox(record_id)]
            id: i64,
            #[cryptbox(seal = "4f3ca6a2-a683-49b7-8d1a-718b790f7154")]
            email: String,
        }

        #[derive(cryptbox::Record)]
        struct Partner {
            #[cryptbox(record_id)]
            id: i64,
            // Copied from `Supplier`: a supplier's email opens as partner 7's.
            #[cryptbox(seal = "4f3ca6a2-a683-49b7-8d1a-718b790f7154")]
            email: String,
        }

        let manifest = Manifest::new().record::<Supplier>().record::<Partner>();

        assert!(matches!(
            manifest.duplicates().as_slice(),
            [cryptbox::schema::Duplicate::RecordField { records, .. }] if records.len() == 2
        ));
        assert!(
            manifest.to_string().ends_with(
                "seal ID 4f3ca6a2-a683-49b7-8d1a-718b790f7154 in several record fields\n"
            )
        );
    }

    #[test]
    fn a_records_stored_form_defaults_to_stored_and_its_name() {
        fn stored<R: cryptbox::Record<Stored = StoredCustomer>>() {}

        stored::<Customer>();
    }
}
