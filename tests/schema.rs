//! Public-boundary tests for the schema manifest and unique-ID checks.

use cryptbox::{
    Binding, BlindIndexError, BlindIndexSpec, EncryptionKey, EncryptionKeyring, Field, FieldId,
    FieldOnly, IndexId, Padding, PartKind, PartSpec, PartValue, PartValues, Raw, RecordId, Sealed,
    Tenant, Utf8, field_id, index_id, inspect_ciphertext, part_id,
    schema::{Duplicate, Manifest},
};
use zeroize::Zeroizing;

struct Nickname;

impl Field for Nickname {
    const ID: FieldId = field_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct Avatar;

impl Field for Avatar {
    const ID: FieldId = field_id!("9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e");
    const PADDING: Padding = Padding::block(64);
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

#[test]
fn manifest_lists_each_field() {
    let manifest = Manifest::new().field::<Nickname>().field::<Avatar>();

    assert_eq!(
        manifest.to_string(),
        "\
field 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  codec: utf8
  padding: none
  record: no
  binding: ff670aba047d77fa
  shred unit: keyring
field 9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e
  codec: raw
  padding: block(64)
  record: no
  binding: ff670aba047d77fa
  shred unit: keyring
"
    );
}

struct TenantNote;

impl Field for TenantNote {
    const ID: FieldId = field_id!("4b1e7c2d-9a3f-4e68-b0d5-2c8f6a1e9b37");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = Tenant;
    type Indexes = ();
}

#[test]
fn manifest_shows_a_scoped_binding_and_its_shred_unit() {
    // The tenant part and its binding fingerprint are in docs/wire-format.md#presets.
    assert_eq!(
        Manifest::new().field::<TenantNote>().to_string(),
        "\
field 4b1e7c2d-9a3f-4e68-b0d5-2c8f6a1e9b37
  codec: utf8
  padding: none
  record: no
  binding: f8311e0a178867bc
    part 1e8306bf-3135-4570-831c-6732f92550e9 bytes keys
  shred unit: 1e8306bf-3135-4570-831c-6732f92550e9
"
    );
}

#[test]
fn manifest_shows_custody_labels() {
    let manifest = Manifest::new()
        .field::<TenantNote>()
        .field::<Nickname>()
        .custody::<TenantNote>("per-tenant KMS key");

    assert_eq!(
        manifest.to_string(),
        "\
field 4b1e7c2d-9a3f-4e68-b0d5-2c8f6a1e9b37
  codec: utf8
  padding: none
  record: no
  binding: f8311e0a178867bc
    part 1e8306bf-3135-4570-831c-6732f92550e9 bytes keys
  shred unit: 1e8306bf-3135-4570-831c-6732f92550e9
  custody: per-tenant KMS key
field 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  codec: utf8
  padding: none
  record: no
  binding: ff670aba047d77fa
  shred unit: keyring
"
    );
}

#[test]
fn labelling_custody_registers_the_field_once() {
    let labelled_first = Manifest::new()
        .custody::<Nickname>("general KMS")
        .field::<Nickname>();
    let registered_first = Manifest::new()
        .field::<Nickname>()
        .custody::<Nickname>("payments KMS")
        .custody::<Nickname>("general KMS");

    assert_eq!(labelled_first.to_string(), registered_first.to_string());
    assert_eq!(
        labelled_first.to_string(),
        "\
field 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  codec: utf8
  padding: none
  record: no
  binding: ff670aba047d77fa
  shred unit: keyring
  custody: general KMS
"
    );
}

#[test]
fn a_custody_label_stays_on_one_line() {
    let manifest = Manifest::new().custody::<Nickname>("org's \"general\"\nKMS\u{2028}EU");

    assert!(
        manifest
            .to_string()
            .ends_with("  custody: org's \"general\"\\nKMS\\u{2028}EU\n")
    );
}

/// Two `keys` parts, an `index` part, and a bound-only part, declared by hand.
#[derive(Clone, Hash, PartialEq, Eq)]
struct ProjectScope {
    region: i64,
    org: [u8; 16],
    project: Vec<u8>,
    workspace: [u8; 16],
}

impl Binding for ProjectScope {
    const PARTS: &'static [PartSpec] = &[
        PartSpec::keys(
            part_id!("1a2b3c4d-0000-4000-8000-000000000001"),
            PartKind::I64,
        ),
        PartSpec::keys(
            part_id!("2b3c4d5e-0000-4000-8000-000000000002"),
            PartKind::Uuid,
        ),
        PartSpec::index(
            part_id!("3c4d5e6f-0000-4000-8000-000000000003"),
            PartKind::Bytes,
        ),
        PartSpec::bound(
            part_id!("4d5e6f70-0000-4000-8000-000000000004"),
            PartKind::Uuid,
        ),
    ];
    type IndexArgs = ();

    fn values(&self) -> PartValues<'_> {
        PartValues::from([
            PartValue::I64(self.region),
            PartValue::Uuid(self.org),
            PartValue::Bytes(&self.project),
            PartValue::Uuid(self.workspace),
        ])
    }

    fn index_values((): &()) -> PartValues<'_> {
        PartValues::new()
    }
}

struct WorkspaceNote;

impl Field for WorkspaceNote {
    const ID: FieldId = field_id!("6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51");
    const PADDING: Padding = Padding::block(16);
    const RECORD: bool = true;
    type Value = String;
    type Codec = Utf8;
    type Binding = ProjectScope;
    type Indexes = ();
}

#[test]
fn manifest_shows_every_part_and_the_record_flag() {
    let snapshot = Manifest::new().field::<WorkspaceNote>().to_string();

    assert_eq!(
        snapshot,
        "\
field 6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51
  codec: utf8
  padding: block(16)
  record: yes
  binding: ac519c02fd95f712
    part 1a2b3c4d-0000-4000-8000-000000000001 i64 keys
    part 2b3c4d5e-0000-4000-8000-000000000002 uuid keys
    part 3c4d5e6f-0000-4000-8000-000000000003 bytes index
    part 4d5e6f70-0000-4000-8000-000000000004 uuid bound
  shred unit: 1a2b3c4d-0000-4000-8000-000000000001 + 2b3c4d5e-0000-4000-8000-000000000002
"
    );

    // The fingerprint, computed with shasum from docs/wire-format.md#binding-fingerprint,
    // is the one a sealed value's header carries.
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let scope = ProjectScope {
        region: 7,
        org: [1; 16],
        project: b"apollo".to_vec(),
        workspace: [2; 16],
    };
    let sealed =
        Sealed::<WorkspaceNote>::seal(&"hi".to_owned(), (&scope, RecordId::I64(1)), &keys).unwrap();
    let header = inspect_ciphertext(sealed.as_bytes()).unwrap();
    assert!(snapshot.contains(&format!(
        "  binding: {}\n",
        hex::encode(header.binding_fingerprint())
    )));
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
index 3d8b1f4e-6a2c-4e71-9f05-8c7d6b5a4e3f
  field: 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  bits: 24
  normalizer: trim-lowercase/1
"
    );
}

/// Copied from [`Nickname`] without generating a fresh ID.
struct DisplayName;

impl Field for DisplayName {
    const ID: FieldId = field_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
    type Indexes = ();
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
    // The snapshot flags the ID without naming types.
    assert!(
        duplicated
            .to_string()
            .ends_with("duplicate field ID 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01\n")
    );
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
    use cryptbox::{Field, FieldId, FieldOnly, Padding, field_id, schema::Manifest};
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
        const RECORD: bool = false;
        type Value = Address;
        type Codec = cryptbox::Json;
        type Binding = FieldOnly;
        type Indexes = ();
    }

    #[cfg(feature = "json")]
    #[test]
    fn manifest_names_the_json_codec() {
        assert_eq!(
            Manifest::new().field::<HomeAddress>().to_string(),
            "\
field 0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64
  codec: json/1
  padding: length(256)
  record: no
  binding: ff670aba047d77fa
  shred unit: keyring
"
        );
    }

    #[cfg(feature = "postcard")]
    struct BillingAddress;

    #[cfg(feature = "postcard")]
    impl Field for BillingAddress {
        const ID: FieldId = field_id!("7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13");
        const PADDING: Padding = Padding::NONE;
        const RECORD: bool = false;
        type Value = Address;
        type Codec = cryptbox::Postcard;
        type Binding = FieldOnly;
        type Indexes = ();
    }

    #[cfg(feature = "postcard")]
    #[test]
    fn manifest_names_the_postcard_codec() {
        assert_eq!(
            Manifest::new().field::<BillingAddress>().to_string(),
            "\
field 7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13
  codec: postcard/1
  padding: none
  record: no
  binding: ff670aba047d77fa
  shred unit: keyring
"
        );
    }
}
