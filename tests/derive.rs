//! Public-boundary tests for the derives: each behaves exactly like its manual impl.
#![cfg(feature = "derive")]

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, BoundId, BoundList, Codec,
    CodecError, CodecErrorKind, EncryptionKey, EncryptionKeyring, IndexId, IndexKeyId, IndexList,
    Padding, PartId, PartKind, PartSpec, PartType, PartValue, RecordIdType, Seal, SealId, Sealed,
    Utf8, index_id, index_key_id, part_id, seal_id,
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
    type Bound = ();
    type Record = ();
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
    type Partition = ();
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
        EmailLookup::derive_with(&email, (), &keys)
            .unwrap()
            .as_bytes(),
        ManualEmailLookup::derive_with(&email, (), &keys)
            .unwrap()
            .as_bytes()
    );
    assert_eq!(
        EmailLookup::probes_with("mark@example.com", (), &keys).unwrap()[0].as_bytes(),
        ManualEmailLookup::probes_with("mark@example.com", (), &keys).unwrap()[0].as_bytes()
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
    type Partition = ();
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
        StreetLookup::derive_with(&address(), (), &keys)
            .unwrap()
            .as_bytes(),
        ManualStreetLookup::derive_with(&address(), (), &keys)
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

/// An org's ID, bound as bytes.
#[derive(cryptbox::BoundId, Clone, Debug, PartialEq)]
#[cryptbox(kind = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
struct OrgId(Vec<u8>);

/// A project's ID.
#[derive(cryptbox::BoundId, Clone, Copy, Debug, PartialEq)]
#[cryptbox(kind = "5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61")]
struct ProjectId(i64);

/// A workspace's ID, bound as a UUID.
#[derive(cryptbox::BoundId, Clone, Copy, Debug, PartialEq)]
#[cryptbox(kind = "8f4a6c13-9d2e-4b57-a0c8-6e1f3a5d7b92")]
struct WorkspaceId([u8; 16]);

/// The manual equivalent of [`OrgId`].
struct ManualOrgId(Vec<u8>);

impl PartType for ManualOrgId {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(&self.0)
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, cryptbox::Error> {
        Vec::<u8>::from_part_value(value).map(Self)
    }
}

impl BoundId for ManualOrgId {
    const KIND_ID: PartId = part_id!("2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37");
}

#[derive(Seal)]
#[cryptbox(
    id = "7a1c3e5f-2b4d-4f68-9a0c-1e3b5d7f9a2c",
    value = String,
    bound(OrgId, ProjectId),
    record = i64,
)]
struct ProjectNote;

/// The manual equivalent of [`ProjectNote`], its bound types in another order.
struct ManualProjectNote;

impl Seal for ManualProjectNote {
    const ID: SealId = seal_id!("7a1c3e5f-2b4d-4f68-9a0c-1e3b5d7f9a2c");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Bound = (ProjectId, ManualOrgId);
    type Record = i64;
    type Indexes = ();
}

#[test]
fn a_derived_seal_declares_its_bound_types_and_record() {
    assert_eq!(
        <<ProjectNote as Seal>::Bound as BoundList>::PARTS,
        [OrgId::PART, ProjectId::PART]
    );
    assert_eq!(
        <<ProjectNote as Seal>::Record as RecordIdType>::RECORD,
        Some(PartKind::I64)
    );
}

#[test]
fn a_derived_bound_seal_opens_values_of_its_manual_equivalent() {
    let keys = keyring();
    let record = &9_i64;

    let manual = Sealed::<ManualProjectNote>::seal(
        &"ship it".to_owned(),
        (&ProjectId(7), &ManualOrgId(b"acme".to_vec()), record),
        &keys,
    )
    .unwrap();
    let derived = Sealed::<ProjectNote>::from_bytes(manual.into_bytes()).unwrap();

    assert_eq!(
        derived
            .open((&OrgId(b"acme".to_vec()), &ProjectId(7), record), &keys)
            .unwrap(),
        "ship it"
    );
}

#[derive(Seal)]
#[cryptbox(
    id = "4b8e2d6f-1a3c-4e57-b9d0-6f2a4c8e1b35",
    value = String,
    bound(OrgId, ProjectId, WorkspaceId),
    indexes(ProjectEmailLookup),
)]
struct ProjectEmail;

#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "9c1e5a3d-7f2b-4d48-a6e0-3b5d9f1c7e24",
    seal = ProjectEmail,
    partition(OrgId, ProjectId),
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
fn a_derived_blind_index_is_partitioned_by_its_partition() {
    let keys = index_keys();
    let email = "Mark@Example.com".to_owned();
    let prepare = |org: &[u8], workspace| {
        let bound = (
            OrgId(org.to_vec()),
            ProjectId(7),
            WorkspaceId([workspace; 16]),
        );
        Sealed::<ProjectEmail>::prepare(&email, (&bound.0, &bound.1, &bound.2), &keyring())
            .unwrap()
            .with_index_with::<ProjectEmailLookup>(&keys)
            .unwrap()
            .index::<ProjectEmailLookup>()
            .unwrap()
            .to_blind_index()
    };

    let probes = ProjectEmailLookup::probes_with(
        "mark@example.com",
        (&OrgId(b"acme".to_vec()), &ProjectId(7)),
        &keys,
    )
    .unwrap();

    assert_eq!(prepare(b"acme", 1), probes[0]);
    assert_eq!(prepare(b"acme", 2), probes[0], "the workspace is spanned");
    assert_ne!(prepare(b"globex", 1), probes[0]);
}

#[derive(Seal)]
#[cryptbox(
    id = "882016eb-21d9-42df-b559-82e4a82151f6",
    value = String,
    bound(OrgId, ProjectId),
    indexes(ProjectEmailByOrg),
)]
struct OrgProjectEmail;

/// Without `partition`, a derived blind index is partitioned by every bound
/// value of its seal.
#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "ef3a8a68-92f2-4e45-bebf-c4f112c0d540",
    seal = OrgProjectEmail,
    bits = 32,
    query = str,
    normalize = normalize_text,
    normalizer = "text/1",
)]
struct ProjectEmailByOrg;

#[test]
fn a_derived_blind_index_defaults_to_its_seals_bound_list() {
    fn partition<Spec: BlindIndexSpec<Partition = (OrgId, ProjectId)>>() {}

    partition::<ProjectEmailByOrg>();
}

#[cfg(feature = "uuid")]
mod uuid_parts {
    use cryptbox::{PartType, PartValue, RecordId};
    use uuid::Uuid;

    #[derive(cryptbox::BoundId)]
    #[cryptbox(kind = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
    struct OrgId(Uuid);

    #[test]
    fn a_uuid_bound_id_binds_its_sixteen_bytes() {
        let id = Uuid::from_u128(0x0192_3a4b_5c6d_7e8f_9a0b_1c2d_3e4f_5a6b);

        assert!(
            matches!(OrgId(id).part_value(), PartValue::Uuid(bytes) if bytes == *id.as_bytes())
        );
        assert_eq!(RecordId::from(id), RecordId::Uuid(*id.as_bytes()));
    }
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

/// A bound ID over [`Mislabeled`].
#[derive(cryptbox::BoundId)]
#[cryptbox(kind = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
struct MislabeledId(Mislabeled);

#[derive(Seal)]
#[cryptbox(
    id = "83824c94-7154-4594-97b2-eb04999e948b",
    value = String,
    bound(MislabeledId),
)]
struct MislabeledNote;

#[test]
fn a_part_value_of_another_kind_is_rejected() {
    assert_eq!(
        Sealed::<MislabeledNote>::seal(&"ada".to_owned(), &MislabeledId(Mislabeled(1)), &keyring()),
        Err(cryptbox::Error::InvalidBinding)
    );
}

/// A customer ID, bound as a UUID.
#[derive(cryptbox::BoundId, Clone, Copy, Debug, PartialEq)]
#[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
struct CustomerId([u8; 16]);

#[test]
fn a_derived_bound_id_binds_as_its_field_under_its_kind() {
    let customer = CustomerId([0x42; 16]);

    assert_eq!(
        CustomerId::KIND_ID,
        part_id!("59881c28-3003-4047-847f-d7cc73b140e5")
    );
    assert_eq!(CustomerId::KIND, PartKind::Uuid);
    assert!(matches!(customer.part_value(), PartValue::Uuid([0x42, ..])));
    assert_eq!(
        CustomerId::from_part_value(customer.part_value()),
        Ok(customer)
    );
    assert_eq!(
        <(CustomerId,)>::PARTS,
        [PartSpec::new(CustomerId::KIND_ID, PartKind::Uuid)]
    );
}
