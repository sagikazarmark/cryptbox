//! Public-boundary tests for the context record fields and standalone values are sealed under.
#![cfg(feature = "derive")]

use cryptbox::{EncryptionKey, EncryptionKeyring, Error, Record, Sealed};

/// A note whose record ID is an `i64`.
#[derive(Debug, PartialEq, Record)]
struct NumberNote {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "2ad30df3-8b86-47cf-9115-b0c78c14aae1")]
    body: String,
}

/// The same seal ID, in a record whose ID is a UUID.
#[derive(Debug, PartialEq, Record)]
struct UuidNote {
    #[cryptbox(record_id)]
    id: [u8; 16],
    #[cryptbox(seal = "2ad30df3-8b86-47cf-9115-b0c78c14aae1")]
    body: String,
}

/// The same seal ID, not a record's field.
#[derive(cryptbox::Seal)]
#[cryptbox(id = "2ad30df3-8b86-47cf-9115-b0c78c14aae1", value = String)]
struct LooseNote;

fn keys() -> EncryptionKeyring {
    EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap()
}

fn note(keys: &EncryptionKeyring) -> StoredNumberNote {
    NumberNote {
        id: 7,
        body: "ship it".to_owned(),
    }
    .seal(keys)
    .unwrap()
}

#[test]
fn a_record_id_of_another_kind_is_another_declaration() {
    let keys = keys();
    let stored = note(&keys);

    let as_uuid = StoredUuidNote {
        id: [7; 16],
        body: Sealed::from_bytes(stored.body.into_bytes()).unwrap(),
    };
    assert_eq!(
        UuidNote::open(as_uuid, &keys).unwrap_err(),
        Error::ContextMismatch
    );
}

#[test]
fn a_record_fields_value_does_not_open_outside_its_record() {
    let keys = keys();
    let stored = note(&keys);

    let loose = Sealed::<LooseNote>::from_bytes(stored.body.into_bytes()).unwrap();
    assert_eq!(loose.open(&keys).unwrap_err(), Error::ContextMismatch);
}

#[test]
fn a_loose_value_does_not_open_as_a_record_field() {
    let keys = keys();
    let loose = Sealed::<LooseNote>::seal(&"ship it".to_owned(), &keys).unwrap();

    let row = StoredNumberNote {
        id: 7,
        body: Sealed::from_bytes(loose.into_bytes()).unwrap(),
    };
    assert_eq!(
        NumberNote::open(row, &keys).unwrap_err(),
        Error::ContextMismatch
    );
}
