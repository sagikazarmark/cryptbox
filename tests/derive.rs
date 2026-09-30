//! Public-boundary tests for the derives: each behaves exactly like its manual impl.
#![cfg(feature = "derive")]

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, Codec, CodecError,
    CodecErrorKind, EncryptionKey, EncryptionKeySource, EncryptionKeyring, FromParts, IndexId,
    IndexKeyId, IndexList, Padding, PartKind, PartSpec, PartType, PartValue, PartValues, Scope,
    Seal, SealId, Sealed, Utf8, index_id, index_key_id, part_id, seal_id,
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
    type Scope = ();
    type Keys = ();
    type Indexes = ();
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
    let manual =
        Sealed::<ManualUserEmail>::seal(&"mark@example.com".to_owned(), (), &keys).unwrap();

    let derived = Sealed::<UserEmail>::from_bytes(manual.into_bytes()).unwrap();
    assert_eq!(derived.open((), &keys).unwrap(), "mark@example.com");
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

    let marker = Sealed::<UserEmail>::seal(&email.0, (), &keys).unwrap();
    let as_self_valued = Sealed::<SelfValuedEmail>::from_bytes(marker.into_bytes()).unwrap();
    assert_eq!(as_self_valued.open((), &keys).unwrap(), email);

    let self_valued = Sealed::<SelfValuedEmail>::seal(&email, (), &keys).unwrap();
    let as_marker = Sealed::<UserEmail>::from_bytes(self_valued.into_bytes()).unwrap();
    assert_eq!(as_marker.open((), &keys).unwrap(), email.0);
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

    let sealed = Sealed::<Nickname>::seal(&nickname, (), &keys).unwrap();

    assert_eq!(sealed.open((), &keys).unwrap(), nickname);
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
        let sealed = Sealed::<Profile>::seal(&profile, (), &keys).unwrap();

        assert_eq!(sealed.open((), &keys).unwrap(), profile);
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
    let sealed = Sealed::<BillingAddress>::seal(&address(), (), &keys).unwrap();
    assert_eq!(sealed.open((), &keys).unwrap(), address());
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
    type Scope = ();
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
        EmailLookup::derive_with(&email, &(), &keys)
            .unwrap()
            .as_bytes(),
        ManualEmailLookup::derive_with(&email, &(), &keys)
            .unwrap()
            .as_bytes()
    );
    assert_eq!(
        EmailLookup::probes_with("mark@example.com", &(), &keys).unwrap()[0].as_bytes(),
        ManualEmailLookup::probes_with("mark@example.com", &(), &keys).unwrap()[0].as_bytes()
    );
    assert!(EmailLookup::verify_candidate("MARK@example.com", &email).unwrap());
}

fn street(address: &Address) -> &str {
    &address.street
}

#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "3f5d8c2b-6e40-4b97-8c31-8a2f7d9e5b64",
    seal = BillingAddress,
    bits = 64,
    query = str,
    normalize = normalize_text,
    project = street,
    normalizer = "street/1",
)]
struct StreetLookup;

/// The manual equivalent of [`StreetLookup`].
struct ManualStreetLookup;

impl BlindIndexSpec for ManualStreetLookup {
    type Seal = BillingAddress;
    type Scope = ();
    const ID: IndexId = index_id!("3f5d8c2b-6e40-4b97-8c31-8a2f7d9e5b64");
    const BITS: u16 = 64;
    const NORMALIZER: &'static str = "street/1";
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
        StreetLookup::derive_with(&address(), &(), &keys)
            .unwrap()
            .as_bytes(),
        ManualStreetLookup::derive_with(&address(), &(), &keys)
            .unwrap()
            .as_bytes()
    );
    assert!(StreetLookup::verify_candidate("1 MAIN STREET", &address()).unwrap());
    assert!(!StreetLookup::verify_candidate("Springfield", &address()).unwrap());
}

#[test]
fn a_transparent_seal_rejects_what_its_inner_codec_rejects() {
    let error = <SelfValuedEmail as Codec<SelfValuedEmail>>::decode(&[0xff]).unwrap_err();

    assert_eq!(error.kind(), CodecErrorKind::InvalidUtf8);
}

/// A value type without a default codec: every seal over it names one.
#[derive(Clone, Debug, PartialEq)]
struct Postcode {
    code: String,
}

struct PostcodeCodec;

impl Codec<Postcode> for PostcodeCodec {
    const ID: &'static str = "postcode/1";

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

mod renamed {
    pub use cryptbox as encryption;
}

#[derive(Seal)]
#[cryptbox(
    crate = "renamed::encryption",
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = Postcode,
    codec = PostcodeCodec,
)]
struct RenamedCratePostcode;

#[test]
fn derives_can_name_cryptbox_through_another_path() {
    assert_eq!(RenamedCratePostcode::ID, UserEmail::ID);
    assert_codec::<RenamedCratePostcode, PostcodeCodec>();
}

#[test]
fn a_derived_blind_index_names_its_normalizer() {
    assert_eq!(EmailLookup::NORMALIZER, ManualEmailLookup::NORMALIZER);
    assert_eq!(StreetLookup::NORMALIZER, ManualStreetLookup::NORMALIZER);
}

/// An org scopes keys, and a project and a workspace are only bound. Declared
/// out of part-ID order.
#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Scope)]
struct OrgProject {
    #[cryptbox(part = "8f4a6c13-9d2e-4b57-a0c8-6e1f3a5d7b92")]
    workspace: [u8; 16],
    #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
    org: Vec<u8>,
    #[cryptbox(part = "5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61")]
    project: i64,
}

/// The keys view of [`OrgProject`]: its org.
#[derive(Clone, Debug, Hash, PartialEq, Eq, cryptbox::Scope)]
struct ProjectOrg {
    #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
    org: Vec<u8>,
}

/// A view of [`OrgProject`]: the org and the project, which a project search
/// knows.
#[derive(Clone, Debug, Hash, PartialEq, Eq, cryptbox::Scope)]
struct OrgProjectSearch {
    #[cryptbox(part = "5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61")]
    project: i64,
    #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
    org: Vec<u8>,
}

/// The manual equivalent of [`OrgProject`].
#[derive(Clone, Hash, PartialEq, Eq)]
struct ManualOrgProject {
    org: Vec<u8>,
    project: i64,
    workspace: [u8; 16],
}

impl Scope for ManualOrgProject {
    const PARTS: &'static [PartSpec] = &[
        PartSpec::new(
            part_id!("2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37"),
            PartKind::Bytes,
        ),
        PartSpec::new(
            part_id!("5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61"),
            PartKind::I64,
        ),
        PartSpec::new(
            part_id!("8f4a6c13-9d2e-4b57-a0c8-6e1f3a5d7b92"),
            PartKind::Uuid,
        ),
    ];
    fn values(&self) -> PartValues<'_> {
        PartValues::from([
            PartValue::Bytes(&self.org),
            PartValue::I64(self.project),
            PartValue::Uuid(self.workspace),
        ])
    }
}

#[test]
fn a_derived_binding_declares_its_parts_sorted_by_part_id() {
    assert_eq!(OrgProject::PARTS, ManualOrgProject::PARTS);
}

#[test]
fn a_derived_scope_is_built_back_from_its_part_values() {
    let scope = OrgProject {
        workspace: [0x42; 16],
        org: b"acme".to_vec(),
        project: 7,
    };

    assert!(OrgProject::from_parts(scope.values().as_slice()).unwrap() == scope);
    assert_eq!(
        OrgProject::from_parts(&[]).err(),
        Some(cryptbox::Error::InvalidBinding)
    );
}

#[derive(Seal)]
#[cryptbox(
    id = "7a1c3e5f-2b4d-4f68-9a0c-1e3b5d7f9a2c",
    value = String,
    scope = cryptbox::Recorded<OrgProject, i64>,
    keys = ProjectOrg,
)]
struct ProjectNote;

/// The manual equivalent of [`ProjectNote`].
struct ManualProjectNote;

impl Seal for ManualProjectNote {
    const ID: SealId = seal_id!("7a1c3e5f-2b4d-4f68-9a0c-1e3b5d7f9a2c");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Scope = cryptbox::Recorded<ManualOrgProject, i64>;
    type Keys = ProjectOrg;
    type Indexes = ();
}

#[test]
fn a_derived_bound_seal_opens_values_of_its_manual_equivalent() {
    let keys = keyring();
    let manual_scope = ManualOrgProject {
        org: b"acme".to_vec(),
        project: 7,
        workspace: [0x42; 16],
    };
    let scope = OrgProject {
        workspace: [0x42; 16],
        org: b"acme".to_vec(),
        project: 7,
    };
    let record = &9_i64;

    let manual =
        Sealed::<ManualProjectNote>::seal(&"ship it".to_owned(), (&manual_scope, record), &keys)
            .unwrap();
    let derived = Sealed::<ProjectNote>::from_bytes(manual.into_bytes()).unwrap();

    assert_eq!(derived.open((&scope, record), &keys).unwrap(), "ship it");
}

/// Records the keys views it is asked by.
struct SeenOrgs(std::sync::Mutex<Vec<ProjectOrg>>, EncryptionKeyring);

impl EncryptionKeySource<ProjectOrg> for SeenOrgs {
    fn encryption_keyring(
        &self,
        _: SealId,
        org: &ProjectOrg,
    ) -> Result<EncryptionKeyring, cryptbox::Error> {
        self.0.lock().unwrap().push(org.clone());
        Ok(self.1.clone())
    }
}

#[test]
fn a_derived_seal_asks_its_key_source_by_its_keys_view() {
    let keys = SeenOrgs(std::sync::Mutex::default(), keyring());
    let scope = |project, workspace| OrgProject {
        workspace: [workspace; 16],
        org: b"acme".to_vec(),
        project,
    };

    Sealed::<ProjectEmail>::seal(&"ada".to_owned(), &scope(7, 1), &keys).unwrap();
    Sealed::<ProjectEmail>::seal(&"ada".to_owned(), &scope(8, 2), &keys).unwrap();

    let acme = ProjectOrg {
        org: b"acme".to_vec(),
    };
    assert_eq!(*keys.0.lock().unwrap(), [acme.clone(), acme]);
}

#[derive(Seal)]
#[cryptbox(
    id = "4b8e2d6f-1a3c-4e57-b9d0-6f2a4c8e1b35",
    value = String,
    scope = OrgProject,
    keys = ProjectOrg,
    indexes(ProjectEmailLookup),
)]
struct ProjectEmail;

#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "9c1e5a3d-7f2b-4d48-a6e0-3b5d9f1c7e24",
    seal = ProjectEmail,
    scope = OrgProjectSearch,
    bits = 32,
    query = str,
    normalize = normalize_text,
    normalizer = "text/1",
)]
struct ProjectEmailLookup;

#[test]
fn a_derived_seal_declares_its_blind_indexes() {
    assert_eq!(
        <<ProjectEmail as Seal>::Indexes as IndexList<ProjectEmail>>::IDS,
        [index_id!("9c1e5a3d-7f2b-4d48-a6e0-3b5d9f1c7e24")]
    );
}

#[test]
fn a_derived_blind_index_is_scoped_by_its_index_scope() {
    let keys = index_keys();
    let email = "Mark@Example.com".to_owned();
    let scope = |org: &[u8], workspace| OrgProject {
        workspace: [workspace; 16],
        org: org.to_vec(),
        project: 7,
    };
    let search = OrgProjectSearch {
        org: b"acme".to_vec(),
        project: 7,
    };

    let probes = ProjectEmailLookup::probes_with("mark@example.com", &search, &keys).unwrap();
    let prepared = Sealed::<ProjectEmail>::prepare(&email, &scope(b"acme", 1), &keyring())
        .unwrap()
        .with_index_with::<ProjectEmailLookup>(&keys)
        .unwrap();
    let other_org = Sealed::<ProjectEmail>::prepare(&email, &scope(b"globex", 1), &keyring())
        .unwrap()
        .with_index_with::<ProjectEmailLookup>(&keys)
        .unwrap();

    assert_eq!(
        prepared.index::<ProjectEmailLookup>().unwrap().as_bytes(),
        probes[0].as_bytes()
    );
    assert_ne!(
        other_org.index::<ProjectEmailLookup>().unwrap().as_bytes(),
        probes[0].as_bytes()
    );
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, cryptbox::Scope)]
struct Org {
    #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
    id: [u8; 16],
}

#[derive(Seal)]
#[cryptbox(
    id = "3e7a9c1f-5b2d-4f60-8e14-a2c6d0b8f375",
    value = String,
    scope = OrgProject,
    keys = ProjectOrg,
    indexes(ProjectEmailByOrg),
)]
struct OrgProjectEmail;

/// Without `scope`, a derived blind index is scoped by its seal's whole scope.
#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "6d2f8b4a-0c7e-4a95-b1d3-9e5f7a2c4b86",
    seal = OrgProjectEmail,
    bits = 32,
    query = str,
    normalize = normalize_text,
    normalizer = "text/1",
)]
struct ProjectEmailByOrg;

#[test]
fn a_derived_blind_index_defaults_to_its_seals_scope() {
    fn index_scope<Spec: BlindIndexSpec<Scope = OrgProject>>() {}

    index_scope::<ProjectEmailByOrg>();
}

#[test]
fn a_derived_view_is_built_back_from_its_part_values() {
    let search = OrgProjectSearch {
        org: b"acme".to_vec(),
        project: 7,
    };
    let org = Org { id: [0x42; 16] };

    assert_eq!(
        OrgProjectSearch::from_parts(search.values().as_slice()),
        Ok(search)
    );
    assert_eq!(Org::from_parts(org.values().as_slice()), Ok(org));
}

#[test]
fn derived_views_reject_part_values_that_do_not_fit() {
    let cases: [(&str, &[PartValue<'_>]); 3] = [
        ("missing part", &[PartValue::Bytes(b"acme")]),
        (
            "extra part",
            &[
                PartValue::Bytes(b"acme"),
                PartValue::I64(7),
                PartValue::I64(8),
            ],
        ),
        (
            "wrong kind",
            &[PartValue::I64(7), PartValue::Bytes(b"acme")],
        ),
    ];

    for (case, values) in cases {
        assert_eq!(
            OrgProjectSearch::from_parts(values),
            Err(cryptbox::Error::InvalidBinding),
            "{case}"
        );
    }
}

#[cfg(feature = "uuid")]
mod uuid_parts {
    use cryptbox::{FromParts, RecordId, Scope};
    use uuid::Uuid;

    #[derive(Clone, Hash, PartialEq, Eq, cryptbox::Scope)]
    struct Org {
        #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
        id: Uuid,
    }

    #[test]
    fn a_uuid_part_binds_its_sixteen_bytes() {
        let id = Uuid::from_u128(0x0192_3a4b_5c6d_7e8f_9a0b_1c2d_3e4f_5a6b);

        assert_eq!(
            super::Org::from_parts(Org { id }.values().as_slice()),
            Ok(super::Org { id: *id.as_bytes() })
        );
        assert_eq!(RecordId::from(id), RecordId::Uuid(*id.as_bytes()));
    }
}

/// An application's own org ID, bound as a UUID part.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct OrgId([u8; 16]);

impl PartType for OrgId {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Uuid(self.0)
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, cryptbox::Error> {
        <[u8; 16]>::from_part_value(value).map(Self)
    }
}

#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Scope)]
struct TypedOrg {
    #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
    id: OrgId,
}

#[test]
fn a_newtype_part_binds_like_its_inner_value() {
    assert_eq!(TypedOrg::PARTS, Org::PARTS);
    let typed = TypedOrg {
        id: OrgId([0x42; 16]),
    };
    assert_eq!(
        Org::from_parts(typed.values().as_slice()),
        Ok(Org { id: [0x42; 16] })
    );
}

/// Declares one kind but supplies another.
#[derive(Clone, Hash, PartialEq, Eq)]
struct Mislabeled(i64);

impl PartType for Mislabeled {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::I64(self.0)
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, cryptbox::Error> {
        i64::from_part_value(value).map(Self)
    }
}

#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Scope)]
struct MislabeledScope {
    #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
    id: Mislabeled,
}

#[derive(Seal)]
#[cryptbox(
    id = "83824c94-7154-4594-97b2-eb04999e948b",
    value = String,
    scope = MislabeledScope,
)]
struct MislabeledNote;

#[test]
fn a_part_value_of_another_kind_is_rejected() {
    let scope = MislabeledScope { id: Mislabeled(1) };

    assert_eq!(
        Sealed::<MislabeledNote>::seal(&"ada".to_owned(), &scope, &keyring()),
        Err(cryptbox::Error::InvalidBinding)
    );
}
