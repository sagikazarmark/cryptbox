//! Public-boundary tests for the schema manifest and unique-ID checks.

use cryptbox::{
    BlindIndexError, BlindIndexSpec, BoundId, EncryptionKey, EncryptionKeyring, IndexId, Padding,
    PartId, PartKind, PartType, PartValue, Raw, Seal, SealId, Sealed, TenantId, Utf8, index_id,
    inspect_ciphertext, part_id,
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
    type Bound = ();
    type Record = ();
    type Indexes = ();
}

struct Avatar;

impl Seal for Avatar {
    const ID: SealId = seal_id!("9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e");
    const PADDING: Padding = Padding::block(64);
    type Value = Vec<u8>;
    type Codec = Raw;
    type Bound = ();
    type Record = ();
    type Indexes = ();
}

#[test]
fn manifest_lists_each_seal() {
    let manifest = Manifest::new().seal::<Nickname>().seal::<Avatar>();

    assert_eq!(
        manifest.to_string(),
        "\
seal 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  codec: utf8
  padding: none
  record: no
  binding: 65640fc8333534b9
seal 9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e
  codec: raw
  padding: block(64)
  record: no
  binding: 65640fc8333534b9
"
    );
}

struct TenantNote;

impl Seal for TenantNote {
    const ID: SealId = seal_id!("4b1e7c2d-9a3f-4e68-b0d5-2c8f6a1e9b37");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Bound = (TenantId,);
    type Record = ();
    type Indexes = ();
}

#[test]
fn manifest_shows_a_scoped_binding() {
    // The tenant part and its binding fingerprint are in docs/wire-format.md#presets.
    assert_eq!(
        Manifest::new().seal::<TenantNote>().to_string(),
        "\
seal 4b1e7c2d-9a3f-4e68-b0d5-2c8f6a1e9b37
  codec: utf8
  padding: none
  record: no
  binding: 9b5379b1f03beb17
    part 1e8306bf-3135-4570-831c-6732f92550e9 bytes
"
    );
}

/// Declares a bound ID type over a part type.
macro_rules! bound_id {
    ($name:ident($inner:ty), $kind:literal) => {
        struct $name($inner);

        impl PartType for $name {
            const KIND: PartKind = <$inner as PartType>::KIND;

            fn part_value(&self) -> PartValue<'_> {
                self.0.part_value()
            }

            fn from_part_value(value: PartValue<'_>) -> Result<Self, cryptbox::Error> {
                <$inner>::from_part_value(value).map(Self)
            }
        }

        impl BoundId for $name {
            const KIND_ID: PartId = part_id!($kind);
        }
    };
}

bound_id!(RegionId(i64), "1a2b3c4d-0000-4000-8000-000000000001");
bound_id!(OrgId([u8; 16]), "2b3c4d5e-0000-4000-8000-000000000002");
bound_id!(ProjectId(Vec<u8>), "3c4d5e6f-0000-4000-8000-000000000003");
bound_id!(
    WorkspaceId([u8; 16]),
    "4d5e6f70-0000-4000-8000-000000000004"
);

struct WorkspaceNote;

impl Seal for WorkspaceNote {
    const ID: SealId = seal_id!("6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51");
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
    // Listed out of part-ID order: the manifest sorts them.
    type Bound = (WorkspaceId, ProjectId, OrgId, RegionId);
    type Record = i64;
    type Indexes = ();
}

#[test]
fn manifest_shows_every_part_and_the_record_kind() {
    let snapshot = Manifest::new().seal::<WorkspaceNote>().to_string();

    assert_eq!(
        snapshot,
        "\
seal 6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51
  codec: utf8
  padding: block(16)
  record: i64
  binding: 82a33aab775dbdb0
    part 1a2b3c4d-0000-4000-8000-000000000001 i64
    part 2b3c4d5e-0000-4000-8000-000000000002 uuid
    part 3c4d5e6f-0000-4000-8000-000000000003 bytes
    part 4d5e6f70-0000-4000-8000-000000000004 uuid
"
    );

    // The fingerprint, computed with shasum from docs/wire-format.md#binding-fingerprint,
    // is the one a sealed value's header carries.
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let bound = (
        WorkspaceId([2; 16]),
        ProjectId(b"apollo".to_vec()),
        OrgId([1; 16]),
        RegionId(7),
    );
    let args = (&bound.0, &bound.1, &bound.2, &bound.3, &1_i64);
    let sealed = Sealed::<WorkspaceNote>::seal(&"hi".to_owned(), args, &keys).unwrap();
    let header = inspect_ciphertext(sealed.as_bytes()).unwrap();
    assert!(snapshot.contains(&format!(
        "  binding: {}\n",
        hex::encode(header.context_fingerprint())
    )));
}

struct NicknameLookup;

impl BlindIndexSpec for NicknameLookup {
    type Seal = Nickname;
    type Partition = ();
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
    type Bound = ();
    type Record = ();
    type Indexes = ();
}

#[test]
fn manifest_reports_duplicate_ids() {
    let unique = Manifest::new().seal::<Nickname>().seal::<Avatar>();
    let duplicated = Manifest::new()
        .seal::<Nickname>()
        .seal::<Avatar>()
        .seal::<DisplayName>();

    assert!(unique.duplicates().is_empty());
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
    type Partition = ();
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
    use cryptbox::{Padding, Seal, SealId, schema::Manifest, seal_id};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Address {
        street: String,
    }

    #[cfg(feature = "json")]
    struct HomeAddress;

    #[cfg(feature = "json")]
    impl Seal for HomeAddress {
        const ID: SealId = seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
        const PADDING: Padding = Padding::length(256);
        type Value = Address;
        type Codec = cryptbox::Json;
        type Bound = ();
        type Record = ();
        type Indexes = ();
    }

    #[cfg(feature = "json")]
    #[test]
    fn manifest_names_the_json_codec() {
        assert_eq!(
            Manifest::new().seal::<HomeAddress>().to_string(),
            "\
seal 0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64
  codec: json/1
  padding: length(256)
  record: no
  binding: 65640fc8333534b9
"
        );
    }

    #[cfg(feature = "postcard")]
    struct BillingAddress;

    #[cfg(feature = "postcard")]
    impl Seal for BillingAddress {
        const ID: SealId = seal_id!("7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13");
        const PADDING: Padding = Padding::NONE;
        type Value = Address;
        type Codec = cryptbox::Postcard;
        type Bound = ();
        type Record = ();
        type Indexes = ();
    }

    #[cfg(feature = "postcard")]
    #[test]
    fn manifest_names_the_postcard_codec() {
        assert_eq!(
            Manifest::new().seal::<BillingAddress>().to_string(),
            "\
seal 7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13
  codec: postcard/1
  padding: none
  record: no
  binding: 65640fc8333534b9
"
        );
    }
}

#[cfg(feature = "derive")]
mod records {
    use cryptbox::{Seal, TenantId, schema::Manifest};

    /// A record whose stored struct takes its default name, `SealedCustomer`.
    #[derive(cryptbox::Record)]
    pub struct Customer {
        #[record_id]
        pub id: i64,
        #[seal(id = "dd965aff-c187-49ed-86fe-b75e63fd228d", bound(TenantId))]
        pub email: String,
        pub created_at: i64,
        pub r#type: String,
        #[seal(id = "c173ce33-731d-4051-b1d7-e5dd549c5371", bound(TenantId))]
        pub note: String,
    }

    #[test]
    fn manifest_lists_a_records_seals_and_plaintext_fields() {
        let manifest = Manifest::new().record::<Customer>().record::<Customer>();

        assert_eq!(
            manifest.to_string(),
            "\
record
  seals: dd965aff-c187-49ed-86fe-b75e63fd228d, c173ce33-731d-4051-b1d7-e5dd549c5371
  record id: id
  plaintext: created_at, type
"
        );
        assert_eq!(
            <CustomerEmail as Seal>::ID.to_string(),
            "dd965aff-c187-49ed-86fe-b75e63fd228d"
        );
    }

    #[test]
    fn a_record_without_other_plaintext_fields_says_so() {
        #[derive(cryptbox::Record)]
        struct Note {
            #[record_id]
            id: i64,
            #[seal(id = "4f3ca6a2-a683-49b7-8d1a-718b790f7154")]
            body: String,
        }

        assert!(
            Manifest::new()
                .record::<Note>()
                .to_string()
                .ends_with("  record id: id\n  plaintext: none\n")
        );
    }

    #[test]
    fn a_records_stored_struct_defaults_to_sealed_and_its_name() {
        fn stored<R: cryptbox::Record<Sealed = SealedCustomer>>() {}

        stored::<Customer>();
    }
}
