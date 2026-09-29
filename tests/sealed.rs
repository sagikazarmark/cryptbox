//! Public-boundary tests for sealing and opening values under their runtime binding.

use cryptbox::{
    Binding, EncryptionKey, EncryptionKeyring, Error, Field, FieldId, FieldOnly, Padding, PartKind,
    PartSpec, PartValue, PartValues, RecordId, Sealed, Tenant, TenantId, Utf8, key_id, part_id,
};

/// An org scopes keys; a workspace is only bound.
#[derive(Clone, Hash, PartialEq, Eq)]
struct OrgWorkspace {
    org: [u8; 16],
    workspace: Vec<u8>,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct OrgSearch {
    org: [u8; 16],
}

impl Binding for OrgWorkspace {
    const PARTS: &'static [PartSpec] = &[
        PartSpec::keys(
            part_id!("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90"),
            PartKind::Uuid,
        ),
        PartSpec::bound(
            part_id!("c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48"),
            PartKind::Bytes,
        ),
    ];
    type IndexArgs = OrgSearch;

    fn values(&self) -> PartValues<'_> {
        PartValues::from([PartValue::Uuid(self.org), PartValue::Bytes(&self.workspace)])
    }

    fn index_values(args: &OrgSearch) -> PartValues<'_> {
        PartValues::from([PartValue::Uuid(args.org)])
    }
}

macro_rules! field {
    ($name:ident, $id:literal, $binding:ty, $record:literal) => {
        struct $name;

        impl Field for $name {
            const ID: FieldId = cryptbox::field_id!($id);
            const PADDING: Padding = Padding::NONE;
            const RECORD: bool = $record;
            type Value = String;
            type Codec = Utf8;
            type Binding = $binding;
            type Indexes = ();
        }
    };
}

field!(
    Nickname,
    "5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01",
    FieldOnly,
    false
);
field!(
    RowNote,
    "9e2d4b71-3c8a-4f05-b6e1-7a0c5d3f8b24",
    FieldOnly,
    true
);
field!(
    CustomerEmail,
    "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    OrgWorkspace,
    true
);
// Same binding as `CustomerEmail`, another field ID.
field!(
    BillingEmail,
    "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38",
    OrgWorkspace,
    true
);
// Same field ID as `CustomerEmail`, another binding shape.
field!(
    TenantEmail,
    "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    Tenant,
    false
);

fn first_key() -> EncryptionKey {
    EncryptionKey::new(key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50"), [0x42; 32])
}

fn keys() -> EncryptionKeyring {
    EncryptionKeyring::new(first_key(), []).unwrap()
}

fn scope(org: u8, workspace: &[u8]) -> OrgWorkspace {
    OrgWorkspace {
        org: [org; 16],
        workspace: workspace.to_vec(),
    }
}

fn email() -> String {
    "ada@example.com".to_owned()
}

#[test]
fn every_argument_form_round_trips() {
    let keys = keys();
    let scope = scope(1, b"ws-1");
    let record = RecordId::from(7_i64);

    let field_only = Sealed::<Nickname>::seal(&email(), (), &keys).unwrap();
    assert_eq!(field_only.open((), &keys).unwrap(), email());

    let row_note = Sealed::<RowNote>::seal(&email(), record, &keys).unwrap();
    assert_eq!(row_note.open(record, &keys).unwrap(), email());

    let scoped = Sealed::<CustomerEmail>::seal(&email(), (&scope, record), &keys).unwrap();
    assert_eq!(scoped.open((&scope, record), &keys).unwrap(), email());

    let tenant = Tenant(TenantId::new(b"acme".to_vec()).unwrap());
    let tenant_email = Sealed::<TenantEmail>::seal(&email(), &tenant, &keys).unwrap();
    assert_eq!(tenant_email.open(&tenant, &keys).unwrap(), email());
}

#[test]
fn field_only_values_carry_the_empty_shape_fingerprint() {
    let keys = keys();
    let sealed = Sealed::<Nickname>::seal(&email(), (), &keys).unwrap();

    let info = cryptbox::inspect_ciphertext(sealed.as_bytes()).unwrap();
    // docs/wire-format.md#shape-fingerprint
    assert_eq!(info.shape_fingerprint().to_string(), "ff670aba047d77fa");
}

#[test]
fn opening_under_other_binding_values_fails_authentication() {
    let keys = keys();
    let record = RecordId::from(7_i64);
    let sealed =
        Sealed::<CustomerEmail>::seal(&email(), (&scope(1, b"ws-1"), record), &keys).unwrap();

    for (case, result) in [
        (
            "keys part",
            sealed.open((&scope(2, b"ws-1"), record), &keys),
        ),
        (
            "bound part",
            sealed.open((&scope(1, b"ws-2"), record), &keys),
        ),
        (
            "record",
            sealed.open((&scope(1, b"ws-1"), RecordId::from(8_i64)), &keys),
        ),
        (
            "record kind",
            sealed.open((&scope(1, b"ws-1"), RecordId::from([7; 16])), &keys),
        ),
    ] {
        assert_eq!(result.unwrap_err(), Error::AuthenticationFailed, "{case}");
    }
}

#[test]
fn opening_as_another_field_fails() {
    let keys = keys();
    let scope = scope(1, b"ws-1");
    let record = RecordId::from(7_i64);
    let sealed = Sealed::<CustomerEmail>::seal(&email(), (&scope, record), &keys).unwrap();

    let billing = Sealed::<BillingEmail>::from_bytes(sealed.as_bytes()).unwrap();
    assert_eq!(
        billing.open((&scope, record), &keys).unwrap_err(),
        Error::AuthenticationFailed
    );

    let tenant = Tenant(TenantId::new(b"acme".to_vec()).unwrap());
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
fn invalid_binding_values_are_rejected() {
    #[derive(Clone, Hash, PartialEq, Eq)]
    struct Unchecked(Vec<u8>);

    impl Binding for Unchecked {
        const PARTS: &'static [PartSpec] = &[PartSpec::keys(
            part_id!("1d6f0a3c-7e25-4b98-a4c1-5f8e2b0d3a76"),
            PartKind::Bytes,
        )];
        type IndexArgs = Self;

        fn values(&self) -> PartValues<'_> {
            PartValues::from([PartValue::Bytes(&self.0)])
        }

        fn index_values(args: &Self) -> PartValues<'_> {
            args.values()
        }
    }

    field!(
        Scoped,
        "4f8a2c6e-1b3d-4a57-9e0c-8d2f6b4a1c95",
        Unchecked,
        false
    );

    assert_eq!(
        Sealed::<Scoped>::seal(&email(), &Unchecked(Vec::new()), &keys()).unwrap_err(),
        Error::InvalidBinding
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
    let sealed_scope = scope(1, b"ws-1");
    let args = (&sealed_scope, RecordId::from(7_i64));
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
fn needs_reseal_reports_another_shape() {
    let keys = keys();
    let tenant = Tenant(TenantId::new(b"acme".to_vec()).unwrap());
    let sealed = Sealed::<TenantEmail>::seal(&email(), &tenant, &keys).unwrap();
    let other = Sealed::<CustomerEmail>::from_bytes(sealed.as_bytes()).unwrap();

    assert_eq!(
        other
            .needs_reseal((&scope(1, b"ws-1"), RecordId::from(7_i64)), &keys)
            .unwrap_err(),
        Error::BindingMismatch
    );
}

#[test]
fn reseal_across_moves_a_value_to_other_binding_values_and_keys() {
    let from_keys = keys();
    let to_keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let (from_scope, to_scope) = (scope(1, b"ws-1"), scope(1, b"ws-2"));
    let record = RecordId::from(7_i64);
    let sealed =
        Sealed::<CustomerEmail>::seal(&email(), (&from_scope, record), &from_keys).unwrap();

    let moved = sealed
        .reseal_across(
            (&from_scope, record),
            &from_keys,
            (&to_scope, record),
            &to_keys,
        )
        .unwrap();

    assert_eq!(moved.open((&to_scope, record), &to_keys).unwrap(), email());
    assert!(matches!(
        moved.open((&from_scope, record), &to_keys).unwrap_err(),
        Error::AuthenticationFailed
    ));
    assert!(matches!(
        moved.open((&to_scope, record), &from_keys).unwrap_err(),
        Error::UnknownEncryptionKey(_)
    ));
}
