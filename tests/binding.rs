//! Public-boundary tests for declared scopes, their views, and part types.

use cryptbox::{
    EncryptionKey, EncryptionKeyring, Error, FromParts, Padding, PartKind, PartSpec, PartType,
    PartValue, PartValues, Raw, Scope, Seal, SealId, Sealed, Tenant, TenantId, part_id, seal_id,
};

/// An org scopes keys, and a project and a workspace are only bound.
#[derive(Clone, Hash, PartialEq, Eq)]
struct OrgProject {
    org: Vec<u8>,
    project: i64,
    workspace: [u8; 16],
}

impl Scope for OrgProject {
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

/// Supplies whatever values it holds, for exercising value validation.
#[derive(Clone, Hash, PartialEq, Eq)]
struct Supplied(Vec<SuppliedValue>);

#[derive(Clone, Hash, PartialEq, Eq)]
enum SuppliedValue {
    Uuid([u8; 16]),
    Bytes(Vec<u8>),
    I64(i64),
}

impl SuppliedValue {
    fn part(&self) -> PartValue<'_> {
        match self {
            Self::Uuid(uuid) => PartValue::Uuid(*uuid),
            Self::Bytes(bytes) => PartValue::Bytes(bytes),
            Self::I64(value) => PartValue::I64(*value),
        }
    }
}

impl Scope for Supplied {
    const PARTS: &'static [PartSpec] = OrgProject::PARTS;
    fn values(&self) -> PartValues<'_> {
        self.0.iter().map(SuppliedValue::part).collect()
    }
}

struct SuppliedNote;

impl Seal for SuppliedNote {
    const ID: SealId = seal_id!("2ad30df3-8b86-47cf-9115-b0c78c14aae1");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Scope = Supplied;
    type Indexes = ();
}

#[test]
fn invalid_scope_values_are_rejected() {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let seal = |values| Sealed::<SuppliedNote>::seal(&b"note".to_vec(), &values, &keys);
    let org = || SuppliedValue::Bytes(b"acme".to_vec());
    let workspace = || SuppliedValue::Uuid([1; 16]);
    let valid = Supplied(vec![org(), SuppliedValue::I64(1), workspace()]);
    assert!(seal(valid).is_ok(), "control");

    let cases = [
        ("missing part", Supplied(vec![org(), SuppliedValue::I64(1)])),
        (
            "extra part",
            Supplied(vec![
                org(),
                SuppliedValue::I64(1),
                workspace(),
                SuppliedValue::I64(2),
            ]),
        ),
        (
            "wrong kind",
            Supplied(vec![
                org(),
                SuppliedValue::Bytes(b"1".to_vec()),
                workspace(),
            ]),
        ),
    ];

    for (case, values) in cases {
        assert_eq!(seal(values), Err(Error::InvalidBinding), "{case}");
    }
}

#[test]
fn part_types_read_back_the_values_they_bind() {
    let uuid = [7; 16];
    let tenant = TenantId::new("acme").unwrap();

    assert_eq!(<[u8; 16]>::from_part_value(uuid.part_value()), Ok(uuid));
    assert_eq!(i64::from_part_value((-9_i64).part_value()), Ok(-9));
    assert_eq!(
        Vec::<u8>::from_part_value(b"acme".to_vec().part_value()),
        Ok(b"acme".to_vec())
    );
    assert_eq!(
        Box::<[u8]>::from_part_value(PartValue::Bytes(b"acme")),
        Ok(Box::from(&b"acme"[..]))
    );
    assert_eq!(TenantId::from_part_value(tenant.part_value()), Ok(tenant));
}

#[test]
fn part_types_reject_values_of_another_kind() {
    assert_eq!(
        <[u8; 16]>::from_part_value(PartValue::I64(1)),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        i64::from_part_value(PartValue::Bytes(b"1")),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        Vec::<u8>::from_part_value(PartValue::Uuid([1; 16])),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        TenantId::from_part_value(PartValue::Bytes(b"")),
        Err(Error::InvalidBinding),
        "a tenant ID is never empty"
    );
}

#[test]
fn presets_build_back_from_their_part_values() {
    let acme = Tenant(TenantId::new("acme").unwrap());

    assert_eq!(<()>::from_parts(&[]), Ok(()));
    assert_eq!(Tenant::from_parts(acme.values().as_slice()), Ok(acme));
}

#[test]
fn presets_reject_part_values_that_do_not_fit() {
    assert_eq!(
        <()>::from_parts(&[PartValue::I64(1)]),
        Err(Error::InvalidBinding)
    );
    assert_eq!(Tenant::from_parts(&[]), Err(Error::InvalidBinding));
    assert_eq!(
        Tenant::from_parts(&[PartValue::Bytes(b"acme"), PartValue::Bytes(b"globex")]),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        Tenant::from_parts(&[PartValue::Uuid([1; 16])]),
        Err(Error::InvalidBinding)
    );
}
