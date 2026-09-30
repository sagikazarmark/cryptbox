//! Public-boundary tests for declared binding scopes and their key scopes.

use cryptbox::{
    Error, FromParts, KeyScope, PartKind, PartSpec, PartType, PartValue, PartValues, Scope, Tenant,
    TenantId, part_id,
};

/// An org scopes keys, and a project and a workspace are only bound.
#[derive(Clone, Hash, PartialEq, Eq)]
struct OrgProject {
    org: Vec<u8>,
    project: i64,
    workspace: [u8; 16],
}

/// A view of `OrgProject`: the org and the project.
#[derive(Clone, Hash, PartialEq, Eq)]
struct OrgProjectSearch {
    org: Vec<u8>,
    project: i64,
}

impl Scope for OrgProject {
    const PARTS: &'static [PartSpec] = &[
        PartSpec::keys(
            part_id!("2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37"),
            PartKind::Bytes,
        ),
        PartSpec::bound(
            part_id!("5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61"),
            PartKind::I64,
        ),
        PartSpec::bound(
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

impl Scope for OrgProjectSearch {
    const PARTS: &'static [PartSpec] = &[
        PartSpec::keys(
            part_id!("2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37"),
            PartKind::Bytes,
        ),
        PartSpec::bound(
            part_id!("5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61"),
            PartKind::I64,
        ),
    ];
    fn values(&self) -> PartValues<'_> {
        PartValues::from([PartValue::Bytes(&self.org), PartValue::I64(self.project)])
    }
}

fn scope(org: &[u8], project: i64, workspace: u8) -> OrgProject {
    OrgProject {
        org: org.to_vec(),
        project,
        workspace: [workspace; 16],
    }
}

fn key_scope(org: &[u8], project: i64, workspace: u8) -> KeyScope {
    KeyScope::of(&scope(org, project, workspace)).unwrap()
}

#[test]
fn key_scope_is_the_keys_parts_only() {
    let scope = key_scope(b"acme", 1, 1);

    assert_eq!(key_scope(b"acme", 1, 2), scope, "bound-only workspace");
    assert_eq!(key_scope(b"acme", 2, 1), scope, "bound-only project");
    assert_ne!(key_scope(b"globex", 1, 1), scope, "keys org");
}

#[test]
fn key_scope_of_a_view_matches_the_scope() {
    let search = OrgProjectSearch {
        org: b"acme".to_vec(),
        project: 9,
    };

    assert_eq!(KeyScope::of(&search).unwrap(), key_scope(b"acme", 1, 1));
}

#[test]
fn key_scope_hashes_like_it_compares() {
    let scopes: std::collections::HashSet<_> = [
        key_scope(b"acme", 1, 1),
        key_scope(b"acme", 2, 2),
        key_scope(b"globex", 1, 1),
    ]
    .into();

    assert_eq!(scopes.len(), 2);
}

#[test]
fn unscoped_bindings_share_one_key_scope() {
    assert_ne!(
        KeyScope::of(&()).unwrap(),
        KeyScope::of(&Tenant(TenantId::from_uuid([1; 16]))).unwrap()
    );
}

#[test]
fn tenants_have_their_own_key_scopes() {
    let acme = Tenant(TenantId::new("acme").unwrap());

    assert_eq!(
        KeyScope::of(&acme).unwrap(),
        KeyScope::of_keys::<Tenant>(&[PartValue::Bytes(b"acme")]).unwrap()
    );
    assert_ne!(
        KeyScope::of(&acme).unwrap(),
        KeyScope::of(&Tenant(TenantId::new("globex").unwrap())).unwrap()
    );
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

#[test]
fn key_scope_rejects_invalid_values() {
    let org = || SuppliedValue::Bytes(b"acme".to_vec());
    let workspace = || SuppliedValue::Uuid([1; 16]);
    let valid = Supplied(vec![org(), SuppliedValue::I64(1), workspace()]);
    assert!(KeyScope::of(&valid).is_ok(), "control");

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
        (
            "empty keys value",
            Supplied(vec![
                SuppliedValue::Bytes(Vec::new()),
                SuppliedValue::I64(1),
                workspace(),
            ]),
        ),
    ];

    for (case, values) in cases {
        assert_eq!(KeyScope::of(&values), Err(Error::InvalidBinding), "{case}");
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

#[test]
fn key_scope_of_keys_matches_the_binding() {
    assert_eq!(
        KeyScope::of_keys::<OrgProject>(&[PartValue::Bytes(b"acme")]),
        Ok(key_scope(b"acme", 1, 1))
    );
    assert_eq!(KeyScope::of_keys::<()>(&[]), KeyScope::of(&()));
}

#[test]
fn key_scope_of_keys_rejects_invalid_values() {
    let cases: [(&str, &[PartValue<'_>]); 4] = [
        ("missing part", &[]),
        (
            "index part supplied",
            &[PartValue::Bytes(b"acme"), PartValue::I64(1)],
        ),
        ("wrong kind", &[PartValue::I64(1)]),
        ("empty keys value", &[PartValue::Bytes(b"")]),
    ];

    for (case, values) in cases {
        assert_eq!(
            KeyScope::of_keys::<OrgProject>(values),
            Err(Error::InvalidBinding),
            "{case}"
        );
    }
}
