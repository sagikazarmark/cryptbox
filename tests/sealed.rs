//! Public-boundary tests for sealing and opening values under their runtime binding.

use cryptbox::{
    BoundId, EncryptionKey, EncryptionKeyring, Error, Padding, PartId, PartKind, PartType,
    PartValue, Seal, SealId, Sealed, TenantId, Utf8, key_id, part_id,
};

/// An org's ID.
struct OrgId([u8; 16]);

impl PartType for OrgId {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Uuid(self.0)
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, Error> {
        <[u8; 16]>::from_part_value(value).map(Self)
    }
}

impl BoundId for OrgId {
    const KIND_ID: PartId = part_id!("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90");
}

/// A workspace's ID.
struct WorkspaceId(Vec<u8>);

impl PartType for WorkspaceId {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(&self.0)
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, Error> {
        Vec::<u8>::from_part_value(value).map(Self)
    }
}

impl BoundId for WorkspaceId {
    const KIND_ID: PartId = part_id!("c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48");
}

macro_rules! seal {
    ($name:ident, $id:literal, $bound:ty, $record:ty) => {
        struct $name;

        impl Seal for $name {
            const ID: SealId = cryptbox::seal_id!($id);
            const PADDING: Padding = Padding::NONE;
            type Value = String;
            type Codec = Utf8;
            type Bound = $bound;
            type Record = $record;
            type Indexes = ();
        }
    };
}

seal!(Nickname, "5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01", (), ());
seal!(RowNote, "9e2d4b71-3c8a-4f05-b6e1-7a0c5d3f8b24", (), i64);
seal!(
    CustomerEmail,
    "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    (OrgId, WorkspaceId),
    i64
);
// Same binding as `CustomerEmail`, another seal ID.
seal!(
    BillingEmail,
    "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38",
    (OrgId, WorkspaceId),
    i64
);
// Same seal ID as `CustomerEmail`, another binding declaration.
seal!(
    TenantEmail,
    "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    (TenantId,),
    ()
);

fn first_key() -> EncryptionKey {
    EncryptionKey::new(key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50"), [0x42; 32])
}

fn keys() -> EncryptionKeyring {
    EncryptionKeyring::new(first_key(), []).unwrap()
}

fn org(org: u8) -> OrgId {
    OrgId([org; 16])
}

fn ws(workspace: &[u8]) -> WorkspaceId {
    WorkspaceId(workspace.to_vec())
}

fn email() -> String {
    "ada@example.com".to_owned()
}

#[test]
fn every_argument_form_round_trips() {
    let keys = keys();
    let scope = (org(1), ws(b"ws-1"));
    let record = &7_i64;

    let unscoped = Sealed::<Nickname>::seal(&email(), (), &keys).unwrap();
    assert_eq!(unscoped.open((), &keys).unwrap(), email());

    let row_note = Sealed::<RowNote>::seal(&email(), record, &keys).unwrap();
    assert_eq!(row_note.open(record, &keys).unwrap(), email());

    let scoped =
        Sealed::<CustomerEmail>::seal(&email(), (&scope.0, &scope.1, record), &keys).unwrap();
    assert_eq!(
        scoped.open((&scope.0, &scope.1, record), &keys).unwrap(),
        email()
    );

    let tenant = TenantId::new(b"acme".to_vec()).unwrap();
    let tenant_email = Sealed::<TenantEmail>::seal(&email(), &tenant, &keys).unwrap();
    assert_eq!(tenant_email.open(&tenant, &keys).unwrap(), email());
}

#[test]
fn unscoped_values_carry_the_empty_declaration_fingerprint() {
    let keys = keys();
    let sealed = Sealed::<Nickname>::seal(&email(), (), &keys).unwrap();

    let info = cryptbox::inspect_ciphertext(sealed.as_bytes()).unwrap();
    // docs/wire-format.md#binding-fingerprint
    assert_eq!(hex::encode(info.context_fingerprint()), "65640fc8333534b9");
}

#[test]
fn opening_under_other_binding_values_fails_authentication() {
    let keys = keys();
    let record = &7_i64;
    let sealed =
        Sealed::<CustomerEmail>::seal(&email(), (&org(1), &ws(b"ws-1"), record), &keys).unwrap();

    for (case, result) in [
        ("org", sealed.open((&org(2), &ws(b"ws-1"), record), &keys)),
        (
            "workspace",
            sealed.open((&org(1), &ws(b"ws-2"), record), &keys),
        ),
        (
            "record",
            sealed.open((&org(1), &ws(b"ws-1"), &8_i64), &keys),
        ),
    ] {
        assert_eq!(result.unwrap_err(), Error::AuthenticationFailed, "{case}");
    }
}

#[test]
fn opening_as_another_seal_fails() {
    let keys = keys();
    let scope = (org(1), ws(b"ws-1"));
    let record = &7_i64;
    let sealed =
        Sealed::<CustomerEmail>::seal(&email(), (&scope.0, &scope.1, record), &keys).unwrap();

    let billing = Sealed::<BillingEmail>::from_bytes(sealed.as_bytes()).unwrap();
    assert_eq!(
        billing
            .open((&scope.0, &scope.1, record), &keys)
            .unwrap_err(),
        Error::AuthenticationFailed
    );

    let tenant = TenantId::new(b"acme".to_vec()).unwrap();
    let tenant_email = Sealed::<TenantEmail>::from_bytes(sealed.as_bytes()).unwrap();
    assert_eq!(
        tenant_email.open(&tenant, &keys).unwrap_err(),
        Error::BindingMismatch
    );

    let row_note = Sealed::<RowNote>::seal(&email(), record, &keys).unwrap();
    let nickname = Sealed::<Nickname>::from_bytes(row_note.as_bytes()).unwrap();
    assert_eq!(
        nickname.open((), &keys).unwrap_err(),
        Error::BindingMismatch
    );
}

#[test]
fn key_id_names_the_sealing_key() {
    let keys = keys();
    let sealed = Sealed::<Nickname>::seal(&email(), (), &keys).unwrap();

    assert_eq!(
        sealed.key_id(),
        key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50")
    );
}

#[test]
fn reseal_rewrites_a_value_under_the_current_key() {
    let first = keys();
    let sealed_scope = (org(1), ws(b"ws-1"));
    let args = (&sealed_scope.0, &sealed_scope.1, &7_i64);
    let sealed = Sealed::<CustomerEmail>::seal(&email(), args, &first).unwrap();
    assert!(!sealed.needs_reseal(args, &first).unwrap());

    let current = EncryptionKey::generate().unwrap();
    let rotated = EncryptionKeyring::new(current.clone(), [first_key()]).unwrap();
    assert!(sealed.needs_reseal(args, &rotated).unwrap());

    let resealed = sealed.reseal(args, &rotated).unwrap();
    assert_eq!(resealed.key_id(), current.id());
    assert!(!resealed.needs_reseal(args, &rotated).unwrap());
    assert_eq!(resealed.open(args, &rotated).unwrap(), email());
}

#[test]
fn needs_reseal_reports_another_declaration() {
    let keys = keys();
    let tenant = TenantId::new(b"acme".to_vec()).unwrap();
    let sealed = Sealed::<TenantEmail>::seal(&email(), &tenant, &keys).unwrap();
    let other = Sealed::<CustomerEmail>::from_bytes(sealed.as_bytes()).unwrap();

    assert_eq!(
        other
            .needs_reseal((&org(1), &ws(b"ws-1"), &7_i64), &keys)
            .unwrap_err(),
        Error::BindingMismatch
    );
}

#[test]
fn reseal_across_moves_a_value_to_other_binding_values_and_keys() {
    let from_keys = keys();
    let to_keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let (from_scope, to_scope) = ((org(1), ws(b"ws-1")), (org(1), ws(b"ws-2")));
    let record = &7_i64;
    let sealed =
        Sealed::<CustomerEmail>::seal(&email(), (&from_scope.0, &from_scope.1, record), &from_keys)
            .unwrap();

    let moved = sealed
        .reseal_across(
            (&from_scope.0, &from_scope.1, record),
            &from_keys,
            (&to_scope.0, &to_scope.1, record),
            &to_keys,
        )
        .unwrap();

    assert_eq!(
        moved
            .open((&to_scope.0, &to_scope.1, record), &to_keys)
            .unwrap(),
        email()
    );
    assert!(matches!(
        moved
            .open((&from_scope.0, &from_scope.1, record), &to_keys)
            .unwrap_err(),
        Error::AuthenticationFailed
    ));
    assert!(matches!(
        moved
            .open((&to_scope.0, &to_scope.1, record), &from_keys)
            .unwrap_err(),
        Error::UnknownEncryptionKey(_)
    ));
}
