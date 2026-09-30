//! Public-boundary tests for the schema manifest and unique-ID checks.

use cryptbox::{
    BlindIndexError, BlindIndexSpec, EncryptionKey, EncryptionKeyring, FromParts, IndexId, Padding,
    PartKind, PartSpec, PartValue, PartValues, Raw, Recorded, Scope, Seal, SealId, Sealed, Tenant,
    Utf8, index_id, inspect_ciphertext, part_id,
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
    type Scope = ();
    type Keys = ();
    type Indexes = ();
}

struct Avatar;

impl Seal for Avatar {
    const ID: SealId = seal_id!("9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e");
    const PADDING: Padding = Padding::block(64);
    type Value = Vec<u8>;
    type Codec = Raw;
    type Scope = ();
    type Keys = ();
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
  shred unit: keyring
seal 9c2e4b7a-1d3f-4a58-b6e0-7f8a9b0c1d2e
  codec: raw
  padding: block(64)
  record: no
  binding: 65640fc8333534b9
  shred unit: keyring
"
    );
}

struct TenantNote;

impl Seal for TenantNote {
    const ID: SealId = seal_id!("4b1e7c2d-9a3f-4e68-b0d5-2c8f6a1e9b37");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Scope = Tenant;
    type Keys = Tenant;
    type Indexes = ();
}

#[test]
fn manifest_shows_a_scoped_binding_and_its_shred_unit() {
    // The tenant part and its binding fingerprint are in docs/wire-format.md#presets.
    assert_eq!(
        Manifest::new().seal::<TenantNote>().to_string(),
        "\
seal 4b1e7c2d-9a3f-4e68-b0d5-2c8f6a1e9b37
  codec: utf8
  padding: none
  record: no
  binding: 9b73125a52bc08d1
    part 1e8306bf-3135-4570-831c-6732f92550e9 bytes keys
  shred unit: 1e8306bf-3135-4570-831c-6732f92550e9
"
    );
}

#[test]
fn manifest_shows_custody_labels() {
    let manifest = Manifest::new()
        .seal::<TenantNote>()
        .seal::<Nickname>()
        .custody::<TenantNote>("per-tenant KMS key");

    assert_eq!(
        manifest.to_string(),
        "\
seal 4b1e7c2d-9a3f-4e68-b0d5-2c8f6a1e9b37
  codec: utf8
  padding: none
  record: no
  binding: 9b73125a52bc08d1
    part 1e8306bf-3135-4570-831c-6732f92550e9 bytes keys
  shred unit: 1e8306bf-3135-4570-831c-6732f92550e9
  custody: per-tenant KMS key
seal 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  codec: utf8
  padding: none
  record: no
  binding: 65640fc8333534b9
  shred unit: keyring
"
    );
}

#[test]
fn labelling_custody_registers_the_seal_once() {
    let labelled_first = Manifest::new()
        .custody::<Nickname>("general KMS")
        .seal::<Nickname>();
    let registered_first = Manifest::new()
        .seal::<Nickname>()
        .custody::<Nickname>("payments KMS")
        .custody::<Nickname>("general KMS");

    assert_eq!(labelled_first.to_string(), registered_first.to_string());
    assert_eq!(
        labelled_first.to_string(),
        "\
seal 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
  codec: utf8
  padding: none
  record: no
  binding: 65640fc8333534b9
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

/// Two `keys` parts and two bound-only parts, declared by hand.
#[derive(Clone, Hash, PartialEq, Eq)]
struct ProjectScope {
    region: i64,
    org: [u8; 16],
    project: Vec<u8>,
    workspace: [u8; 16],
}

impl Scope for ProjectScope {
    const PARTS: &'static [PartSpec] = &[
        PartSpec::new(
            part_id!("1a2b3c4d-0000-4000-8000-000000000001"),
            PartKind::I64,
        ),
        PartSpec::new(
            part_id!("2b3c4d5e-0000-4000-8000-000000000002"),
            PartKind::Uuid,
        ),
        PartSpec::new(
            part_id!("3c4d5e6f-0000-4000-8000-000000000003"),
            PartKind::Bytes,
        ),
        PartSpec::new(
            part_id!("4d5e6f70-0000-4000-8000-000000000004"),
            PartKind::Uuid,
        ),
    ];
    fn values(&self) -> PartValues<'_> {
        PartValues::from([
            PartValue::I64(self.region),
            PartValue::Uuid(self.org),
            PartValue::Bytes(&self.project),
            PartValue::Uuid(self.workspace),
        ])
    }
}

/// The keys view of [`ProjectScope`]: its two `keys` parts.
#[derive(Clone, Hash, PartialEq, Eq)]
struct ProjectKeys {
    region: i64,
    org: [u8; 16],
}

impl Scope for ProjectKeys {
    const PARTS: &'static [PartSpec] = &[
        PartSpec::new(
            part_id!("1a2b3c4d-0000-4000-8000-000000000001"),
            PartKind::I64,
        ),
        PartSpec::new(
            part_id!("2b3c4d5e-0000-4000-8000-000000000002"),
            PartKind::Uuid,
        ),
    ];
    fn values(&self) -> PartValues<'_> {
        PartValues::from([PartValue::I64(self.region), PartValue::Uuid(self.org)])
    }
}

impl FromParts for ProjectKeys {
    fn from_parts(values: &[PartValue<'_>]) -> Result<Self, cryptbox::Error> {
        match *values {
            [PartValue::I64(region), PartValue::Uuid(org)] => Ok(Self { region, org }),
            _ => Err(cryptbox::Error::InvalidBinding),
        }
    }
}

struct WorkspaceNote;

impl Seal for WorkspaceNote {
    const ID: SealId = seal_id!("6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51");
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
    type Scope = Recorded<ProjectScope, i64>;
    type Keys = ProjectKeys;
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
  binding: 3c900b26f1b5d5c4
    part 1a2b3c4d-0000-4000-8000-000000000001 i64 keys
    part 2b3c4d5e-0000-4000-8000-000000000002 uuid keys
    part 3c4d5e6f-0000-4000-8000-000000000003 bytes bound
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
    let sealed = Sealed::<WorkspaceNote>::seal(&"hi".to_owned(), (&scope, &1_i64), &keys).unwrap();
    let header = inspect_ciphertext(sealed.as_bytes()).unwrap();
    assert!(snapshot.contains(&format!(
        "  binding: {}\n",
        hex::encode(header.context_fingerprint())
    )));
}

struct NicknameLookup;

impl BlindIndexSpec for NicknameLookup {
    type Seal = Nickname;
    type Scope = ();
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
    type Scope = ();
    type Keys = ();
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
    type Scope = ();
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
        type Scope = ();
        type Keys = ();
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
  shred unit: keyring
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
        type Scope = ();
        type Keys = ();
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
  shred unit: keyring
"
        );
    }
}
