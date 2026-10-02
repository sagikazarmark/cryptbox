//! Public-boundary tests for sealing and opening values bound to their seal.

use cryptbox::{
    EncryptionKey, EncryptionKeyring, Error, Padding, Seal, SealId, Sealed, Utf8, key_id,
};

macro_rules! seal {
    ($name:ident, $id:literal) => {
        struct $name;

        impl Seal for $name {
            const ID: SealId = cryptbox::seal_id!($id);
            const PADDING: Padding = Padding::NONE;
            type Value = String;
            type Codec = Utf8;
            type Indexes = ();
        }
    };
}

seal!(CustomerEmail, "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
seal!(BillingEmail, "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38");

fn first_key() -> EncryptionKey {
    EncryptionKey::new(key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50"), [0x42; 32])
}

fn keys() -> EncryptionKeyring {
    EncryptionKeyring::new(first_key(), []).unwrap()
}

fn email() -> String {
    "ada@example.com".to_owned()
}

#[test]
fn a_value_round_trips() {
    let keys = keys();
    let sealed = Sealed::<CustomerEmail>::seal(&email(), &keys).unwrap();

    assert_eq!(sealed.open(&keys).unwrap(), email());
}

#[test]
fn values_carry_the_empty_declaration_fingerprint() {
    let keys = keys();
    let sealed = Sealed::<CustomerEmail>::seal(&email(), &keys).unwrap();

    let info = cryptbox::inspect_ciphertext(sealed.as_bytes()).unwrap();
    // docs/wire-format.md#binding-fingerprint
    assert_eq!(hex::encode(info.context_fingerprint()), "65640fc8333534b9");
}

#[test]
fn opening_as_another_seal_fails_authentication() {
    let keys = keys();
    let sealed = Sealed::<CustomerEmail>::seal(&email(), &keys).unwrap();

    let billing = Sealed::<BillingEmail>::from_bytes(sealed.as_bytes()).unwrap();
    assert_eq!(
        billing.open(&keys).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn key_id_names_the_sealing_key() {
    let keys = keys();
    let sealed = Sealed::<CustomerEmail>::seal(&email(), &keys).unwrap();

    assert_eq!(
        sealed.key_id(),
        key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50")
    );
}

#[test]
fn reseal_rewrites_a_value_under_the_current_key() {
    let first = keys();
    let sealed = Sealed::<CustomerEmail>::seal(&email(), &first).unwrap();
    assert!(!sealed.needs_reseal(&first).unwrap());

    let current = EncryptionKey::generate().unwrap();
    let rotated = EncryptionKeyring::new(current.clone(), [first_key()]).unwrap();
    assert!(sealed.needs_reseal(&rotated).unwrap());

    let resealed = sealed.reseal(&rotated).unwrap();
    assert_eq!(resealed.key_id(), current.id());
    assert!(!resealed.needs_reseal(&rotated).unwrap());
    assert_eq!(resealed.open(&rotated).unwrap(), email());
}

#[test]
fn reseal_across_moves_a_value_to_other_keys() {
    let from_keys = keys();
    let to_keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let sealed = Sealed::<CustomerEmail>::seal(&email(), &from_keys).unwrap();

    let moved = sealed.reseal_across(&from_keys, &to_keys).unwrap();

    assert_eq!(moved.open(&to_keys).unwrap(), email());
    assert!(matches!(
        moved.open(&from_keys).unwrap_err(),
        Error::UnknownEncryptionKey(_)
    ));
}
