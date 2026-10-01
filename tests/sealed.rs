//! Public-boundary tests for sealing and opening values under their runtime binding.

use cryptbox::{
    EncryptionKey, EncryptionKeyring, Error, Padding, PartKind, PartType, PartValue, Seal, SealId,
    Sealed, Utf8, key_id,
};

/// A customer's ID, an application-owned record ID type.
struct CustomerId([u8; 16]);

impl PartType for CustomerId {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Uuid(self.0)
    }
}

macro_rules! seal {
    ($name:ident, $id:literal, $record:ty) => {
        struct $name;

        impl Seal for $name {
            const ID: SealId = cryptbox::seal_id!($id);
            const PADDING: Padding = Padding::NONE;
            type Value = String;
            type Codec = Utf8;
            type Record = $record;
            type Indexes = ();
        }
    };
}

seal!(Nickname, "5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01", ());
seal!(RowNote, "9e2d4b71-3c8a-4f05-b6e1-7a0c5d3f8b24", i64);
seal!(
    CustomerEmail,
    "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    CustomerId
);
// Same binding declaration as `CustomerEmail`, another seal ID.
seal!(
    BillingEmail,
    "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38",
    CustomerId
);
// Same seal ID as `CustomerEmail`, another binding declaration.
seal!(UnboundEmail, "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13", ());

fn first_key() -> EncryptionKey {
    EncryptionKey::new(key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50"), [0x42; 32])
}

fn keys() -> EncryptionKeyring {
    EncryptionKeyring::new(first_key(), []).unwrap()
}

fn customer(id: u8) -> CustomerId {
    CustomerId([id; 16])
}

fn email() -> String {
    "ada@example.com".to_owned()
}

#[test]
fn every_argument_form_round_trips() {
    let keys = keys();

    let nickname = Sealed::<Nickname>::seal(&email(), (), &keys).unwrap();
    assert_eq!(nickname.open((), &keys).unwrap(), email());

    let row_note = Sealed::<RowNote>::seal(&email(), &7_i64, &keys).unwrap();
    assert_eq!(row_note.open(&7_i64, &keys).unwrap(), email());

    let customer_email = Sealed::<CustomerEmail>::seal(&email(), &customer(1), &keys).unwrap();
    assert_eq!(customer_email.open(&customer(1), &keys).unwrap(), email());
}

#[test]
fn values_without_a_record_carry_the_empty_declaration_fingerprint() {
    let keys = keys();
    let sealed = Sealed::<Nickname>::seal(&email(), (), &keys).unwrap();

    let info = cryptbox::inspect_ciphertext(sealed.as_bytes()).unwrap();
    // docs/wire-format.md#binding-fingerprint
    assert_eq!(hex::encode(info.context_fingerprint()), "65640fc8333534b9");
}

#[test]
fn opening_under_another_record_fails_authentication() {
    let keys = keys();
    let sealed = Sealed::<CustomerEmail>::seal(&email(), &customer(1), &keys).unwrap();

    assert_eq!(
        sealed.open(&customer(2), &keys).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn opening_as_another_seal_fails() {
    let keys = keys();
    let sealed = Sealed::<CustomerEmail>::seal(&email(), &customer(1), &keys).unwrap();

    let billing = Sealed::<BillingEmail>::from_bytes(sealed.as_bytes()).unwrap();
    assert_eq!(
        billing.open(&customer(1), &keys).unwrap_err(),
        Error::AuthenticationFailed
    );

    let unbound = Sealed::<UnboundEmail>::from_bytes(sealed.as_bytes()).unwrap();
    assert_eq!(unbound.open((), &keys).unwrap_err(), Error::BindingMismatch);

    // A record ID of another kind is another declaration.
    let row_note = Sealed::<RowNote>::seal(&email(), &7_i64, &keys).unwrap();
    let customer_email = Sealed::<CustomerEmail>::from_bytes(row_note.as_bytes()).unwrap();
    assert_eq!(
        customer_email.open(&customer(1), &keys).unwrap_err(),
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
    let id = customer(1);
    let sealed = Sealed::<CustomerEmail>::seal(&email(), &id, &first).unwrap();
    assert!(!sealed.needs_reseal(&id, &first).unwrap());

    let current = EncryptionKey::generate().unwrap();
    let rotated = EncryptionKeyring::new(current.clone(), [first_key()]).unwrap();
    assert!(sealed.needs_reseal(&id, &rotated).unwrap());

    let resealed = sealed.reseal(&id, &rotated).unwrap();
    assert_eq!(resealed.key_id(), current.id());
    assert!(!resealed.needs_reseal(&id, &rotated).unwrap());
    assert_eq!(resealed.open(&id, &rotated).unwrap(), email());
}

#[test]
fn needs_reseal_reports_another_declaration() {
    let keys = keys();
    let sealed = Sealed::<UnboundEmail>::seal(&email(), (), &keys).unwrap();
    let other = Sealed::<CustomerEmail>::from_bytes(sealed.as_bytes()).unwrap();

    assert_eq!(
        other.needs_reseal(&customer(1), &keys).unwrap_err(),
        Error::BindingMismatch
    );
}

#[test]
fn reseal_across_moves_a_value_to_another_record_and_keys() {
    let from_keys = keys();
    let to_keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let sealed = Sealed::<CustomerEmail>::seal(&email(), &customer(1), &from_keys).unwrap();

    let moved = sealed
        .reseal_across(&customer(1), &from_keys, &customer(2), &to_keys)
        .unwrap();

    assert_eq!(moved.open(&customer(2), &to_keys).unwrap(), email());
    assert!(matches!(
        moved.open(&customer(1), &to_keys).unwrap_err(),
        Error::AuthenticationFailed
    ));
    assert!(matches!(
        moved.open(&customer(2), &from_keys).unwrap_err(),
        Error::UnknownEncryptionKey(_)
    ));
}
