//! Public-boundary tests for the derives: each behaves exactly like its manual impl.
#![cfg(feature = "derive")]

use cryptbox::{
    Binding, BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, Codec, CodecError,
    CodecErrorKind, EncryptionKey, EncryptionKeyring, Field, FieldId, FieldOnly, IndexId,
    IndexKeyId, IndexList, KeyScope, Padding, PartKind, PartSpec, PartType, PartValue, PartValues,
    Plaintext, RecordId, Sealed, Utf8, field_id, index_id, index_key_id, part_id,
};
use zeroize::Zeroizing;

fn keyring() -> EncryptionKeyring {
    EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap()
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
    const RECORD: bool = false;
    type Value = String;
    type Codec = <String as Plaintext>::Codec;
    type Binding = FieldOnly;
    type Indexes = ();
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
fn a_derived_field_opens_values_of_its_manual_equivalent() {
    let keys = keyring();
    let manual =
        Sealed::<ManualUserEmail>::seal(&"mark@example.com".to_owned(), (), &keys).unwrap();

    let derived = Sealed::<UserEmail>::from_bytes(manual.into_bytes()).unwrap();
    assert_eq!(derived.open((), &keys).unwrap(), "mark@example.com");
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
    field = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_text,
    normalizer = "text/1",
)]
struct EmailLookup;

/// The manual equivalent of [`EmailLookup`].
struct ManualEmailLookup;

impl BlindIndexSpec for ManualEmailLookup {
    type Field = ManualUserEmail;
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
    field = BillingAddress,
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
    type Field = BillingAddress;
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

/// A transparent newtype: stored with exactly the bytes of its inner `String`.
#[derive(Debug, PartialEq, cryptbox::Plaintext)]
struct Email(String);

#[derive(Field)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = Email)]
struct TypedUserEmail;

#[test]
fn a_transparent_value_type_stores_its_inner_values_bytes() {
    let keys = keyring();

    let typed =
        Sealed::<TypedUserEmail>::seal(&Email("mark@example.com".to_owned()), (), &keys).unwrap();
    let as_string = Sealed::<ManualUserEmail>::from_bytes(typed.into_bytes()).unwrap();
    assert_eq!(as_string.open((), &keys).unwrap(), "mark@example.com");

    let plain = Sealed::<ManualUserEmail>::seal(&"ada@example.com".to_owned(), (), &keys).unwrap();
    let as_email = Sealed::<TypedUserEmail>::from_bytes(plain.into_bytes()).unwrap();
    assert_eq!(
        as_email.open((), &keys).unwrap(),
        Email("ada@example.com".to_owned())
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

#[test]
fn a_derived_blind_index_names_its_normalizer() {
    assert_eq!(EmailLookup::NORMALIZER, ManualEmailLookup::NORMALIZER);
    assert_eq!(StreetLookup::NORMALIZER, ManualStreetLookup::NORMALIZER);
}

#[test]
fn a_transparent_value_type_shares_its_inner_codec_id() {
    assert_eq!(<<Email as Plaintext>::Codec as Codec<Email>>::ID, "utf8");
}

/// An org scopes keys, a project scopes blind indexes, and a workspace is only
/// bound. Declared out of part-ID order.
#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Binding)]
#[cryptbox(index_args = OrgProjectSearch)]
struct OrgProject {
    #[cryptbox(part = "8f4a6c13-9d2e-4b57-a0c8-6e1f3a5d7b92")]
    workspace: [u8; 16],
    #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37", keys)]
    org: Vec<u8>,
    #[cryptbox(part = "5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61", index)]
    project: i64,
}

/// The manual equivalent of [`OrgProject`].
#[derive(Clone, Hash, PartialEq, Eq)]
struct ManualOrgProject {
    org: Vec<u8>,
    project: i64,
    workspace: [u8; 16],
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct ManualOrgProjectSearch {
    org: Vec<u8>,
    project: i64,
}

impl Binding for ManualOrgProject {
    const PARTS: &'static [PartSpec] = &[
        PartSpec::keys(
            part_id!("2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37"),
            PartKind::Bytes,
        ),
        PartSpec::index(
            part_id!("5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61"),
            PartKind::I64,
        ),
        PartSpec::bound(
            part_id!("8f4a6c13-9d2e-4b57-a0c8-6e1f3a5d7b92"),
            PartKind::Uuid,
        ),
    ];
    type IndexArgs = ManualOrgProjectSearch;

    fn values(&self) -> PartValues<'_> {
        PartValues::from([
            PartValue::Bytes(&self.org),
            PartValue::I64(self.project),
            PartValue::Uuid(self.workspace),
        ])
    }

    fn index_values(args: &ManualOrgProjectSearch) -> PartValues<'_> {
        PartValues::from([PartValue::Bytes(&args.org), PartValue::I64(args.project)])
    }
}

#[test]
fn a_derived_binding_declares_its_parts_sorted_by_part_id() {
    assert_eq!(OrgProject::PARTS, ManualOrgProject::PARTS);
}

#[derive(Field)]
#[cryptbox(
    id = "7a1c3e5f-2b4d-4f68-9a0c-1e3b5d7f9a2c",
    value = String,
    binding = OrgProject,
    record,
)]
struct ProjectNote;

/// The manual equivalent of [`ProjectNote`].
struct ManualProjectNote;

impl Field for ManualProjectNote {
    const ID: FieldId = field_id!("7a1c3e5f-2b4d-4f68-9a0c-1e3b5d7f9a2c");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = true;
    type Value = String;
    type Codec = <String as Plaintext>::Codec;
    type Binding = ManualOrgProject;
    type Indexes = ();
}

#[test]
fn a_derived_bound_field_opens_values_of_its_manual_equivalent() {
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
    let record = RecordId::from(9_i64);

    let manual =
        Sealed::<ManualProjectNote>::seal(&"ship it".to_owned(), (&manual_scope, record), &keys)
            .unwrap();
    let derived = Sealed::<ProjectNote>::from_bytes(manual.into_bytes()).unwrap();

    const { assert!(ProjectNote::RECORD) };
    assert_eq!(derived.open((&scope, record), &keys).unwrap(), "ship it");
}

#[test]
fn derived_index_args_share_the_bindings_key_scope() {
    let scope = OrgProject {
        workspace: [0x42; 16],
        org: b"acme".to_vec(),
        project: 7,
    };
    let search = OrgProjectSearch {
        org: b"acme".to_vec(),
        project: 7,
    };

    assert_eq!(
        KeyScope::of_index::<OrgProject>(&search).unwrap(),
        KeyScope::of(&scope).unwrap()
    );
}

#[derive(Field)]
#[cryptbox(
    id = "4b8e2d6f-1a3c-4e57-b9d0-6f2a4c8e1b35",
    value = String,
    binding = OrgProject,
    indexes(ProjectEmailLookup),
)]
struct ProjectEmail;

#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "9c1e5a3d-7f2b-4d48-a6e0-3b5d9f1c7e24",
    field = ProjectEmail,
    bits = 32,
    query = str,
    normalize = normalize_text,
    normalizer = "text/1",
)]
struct ProjectEmailLookup;

#[test]
fn a_derived_field_declares_its_blind_indexes() {
    assert_eq!(
        <<ProjectEmail as Field>::Indexes as IndexList<ProjectEmail>>::IDS,
        [index_id!("9c1e5a3d-7f2b-4d48-a6e0-3b5d9f1c7e24")]
    );
}

#[test]
fn a_derived_blind_index_is_scoped_by_the_generated_index_args() {
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

/// Every part scopes blind indexes, so a query passes the binding itself.
#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Binding)]
struct Org {
    #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37", keys)]
    id: [u8; 16],
}

/// No part scopes blind indexes, so a query passes `()`.
#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Binding)]
struct Sequence {
    #[cryptbox(part = "8f4a6c13-9d2e-4b57-a0c8-6e1f3a5d7b92")]
    number: i64,
}

#[test]
fn derived_index_args_default_to_the_binding_or_unit() {
    let org = Org { id: [0x42; 16] };

    assert_eq!(
        KeyScope::of_index::<Org>(&org).unwrap(),
        KeyScope::of(&org).unwrap()
    );
    assert_eq!(
        KeyScope::of_index::<Sequence>(&()).unwrap(),
        KeyScope::of(&Sequence { number: 1 }).unwrap()
    );
}

#[cfg(feature = "uuid")]
mod uuid_parts {
    use cryptbox::{KeyScope, RecordId};
    use uuid::Uuid;

    #[derive(Clone, Hash, PartialEq, Eq, cryptbox::Binding)]
    struct Org {
        #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37", keys)]
        id: Uuid,
    }

    #[test]
    fn a_uuid_part_binds_its_sixteen_bytes() {
        let id = Uuid::from_u128(0x0192_3a4b_5c6d_7e8f_9a0b_1c2d_3e4f_5a6b);

        assert_eq!(
            KeyScope::of(&Org { id }).unwrap(),
            KeyScope::of(&super::Org { id: *id.as_bytes() }).unwrap()
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
}

#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Binding)]
struct TypedOrg {
    #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37", keys)]
    id: OrgId,
}

#[test]
fn a_newtype_part_binds_like_its_inner_value() {
    assert_eq!(TypedOrg::PARTS, Org::PARTS);
    assert_eq!(
        KeyScope::of(&TypedOrg {
            id: OrgId([0x42; 16])
        })
        .unwrap(),
        KeyScope::of(&Org { id: [0x42; 16] }).unwrap()
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
}

#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Binding)]
struct MislabeledScope {
    #[cryptbox(part = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37", keys)]
    id: Mislabeled,
}

#[test]
fn a_part_value_of_another_kind_is_rejected() {
    assert_eq!(
        KeyScope::of(&MislabeledScope { id: Mislabeled(1) }),
        Err(cryptbox::Error::InvalidBinding)
    );
}
