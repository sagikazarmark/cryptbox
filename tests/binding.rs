//! Public-boundary tests for declared binding scopes and their key scopes.

use cryptbox::{
    Binding, Error, FieldOnly, KeyScope, PartKind, PartSpec, PartValue, PartValues, Tenant,
    TenantId, part_id,
};

/// An org scopes keys, a project scopes blind indexes, and a workspace is only bound.
#[derive(Clone, Hash, PartialEq, Eq)]
struct OrgProject {
    org: Vec<u8>,
    project: i64,
    workspace: [u8; 16],
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct OrgProjectSearch {
    org: Vec<u8>,
    project: i64,
}

impl Binding for OrgProject {
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
    type IndexArgs = OrgProjectSearch;

    fn values(&self) -> PartValues<'_> {
        PartValues::from([
            PartValue::Bytes(&self.org),
            PartValue::I64(self.project),
            PartValue::Uuid(self.workspace),
        ])
    }

    fn index_values(args: &OrgProjectSearch) -> PartValues<'_> {
        PartValues::from([PartValue::Bytes(&args.org), PartValue::I64(args.project)])
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
    assert_eq!(key_scope(b"acme", 2, 1), scope, "index-only project");
    assert_ne!(key_scope(b"globex", 1, 1), scope, "keys org");
}

#[test]
fn key_scope_of_index_args_matches_the_binding() {
    let search = OrgProjectSearch {
        org: b"acme".to_vec(),
        project: 9,
    };

    assert_eq!(
        KeyScope::of_index::<OrgProject>(&search).unwrap(),
        key_scope(b"acme", 1, 1)
    );
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
fn field_only_bindings_share_one_key_scope() {
    assert_eq!(
        KeyScope::of(&FieldOnly).unwrap(),
        KeyScope::of_index::<FieldOnly>(&()).unwrap()
    );
    assert_ne!(
        KeyScope::of(&FieldOnly).unwrap(),
        KeyScope::of(&Tenant(TenantId::from_uuid([1; 16]))).unwrap()
    );
}

#[test]
fn tenants_have_their_own_key_scopes() {
    let acme = Tenant(TenantId::new("acme").unwrap());

    assert_eq!(
        KeyScope::of(&acme).unwrap(),
        KeyScope::of_index::<Tenant>(&acme).unwrap()
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

impl Binding for Supplied {
    const PARTS: &'static [PartSpec] = OrgProject::PARTS;
    type IndexArgs = Self;

    fn values(&self) -> PartValues<'_> {
        self.0.iter().map(SuppliedValue::part).collect()
    }

    fn index_values(args: &Self) -> PartValues<'_> {
        args.values()
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
fn key_scope_of_index_rejects_invalid_values() {
    let valid = Supplied(vec![
        SuppliedValue::Bytes(b"acme".to_vec()),
        SuppliedValue::I64(1),
    ]);
    assert!(KeyScope::of_index::<Supplied>(&valid).is_ok(), "control");

    let cases = [
        (
            "missing part",
            Supplied(vec![SuppliedValue::Bytes(b"acme".to_vec())]),
        ),
        (
            "bound-only part supplied",
            Supplied(vec![
                SuppliedValue::Bytes(b"acme".to_vec()),
                SuppliedValue::I64(1),
                SuppliedValue::Uuid([1; 16]),
            ]),
        ),
        (
            "empty keys value",
            Supplied(vec![
                SuppliedValue::Bytes(Vec::new()),
                SuppliedValue::I64(1),
            ]),
        ),
    ];

    for (case, values) in cases {
        assert_eq!(
            KeyScope::of_index::<Supplied>(&values),
            Err(Error::InvalidBinding),
            "{case}"
        );
    }
}
