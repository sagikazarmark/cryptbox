//! Public-boundary tests for records: rows whose sealed fields are bound to
//! their seals and record ID.
#![cfg(feature = "derive")]

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, EncryptionKey, EncryptionKeyring, Error,
    InRecord, Keys, Padding, Record, Seal, SealId, Sealed, Utf8,
};
use zeroize::Zeroizing;

/// An org's ID.
#[derive(Clone, Copy, Debug, PartialEq)]
struct OrgId([u8; 16]);

/// A workspace's ID.
#[derive(Clone, Copy, Debug, PartialEq)]
struct WorkspaceId([u8; 16]);

#[allow(clippy::unnecessary_wraps)] // Normalizers are fallible by contract.
fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(
        email.trim().to_ascii_lowercase().into_bytes(),
    ))
}

/// A customer of one workspace of an org.
#[derive(Clone, Debug, PartialEq, Record)]
#[cryptbox(stored(derive(Clone, Debug)))]
struct Customer {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(plaintext)]
    org: OrgId,
    #[cryptbox(plaintext)]
    workspace: WorkspaceId,
    /// The primary contact address, searchable.
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        bits = 1,
        normalize = normalize_email,
        normalizer = "email/1",
    ))]
    email: String,
    /// A note, searchable too.
    #[cryptbox(seal = "5d1f0c3a-8f6e-4b1d-9a7c-2e4b6d8f0a13", padding = block(16))]
    #[cryptbox(blind_index(
        id = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0",
        bits = 32,
        normalize = normalize_email,
        normalizer = "note/1",
    ))]
    note: Option<String>,
    #[cryptbox(plaintext)]
    created_at: i64,
}

const ACME: OrgId = OrgId([1; 16]);
const GLOBEX: OrgId = OrgId([2; 16]);
const SALES: WorkspaceId = WorkspaceId([10; 16]);
const SUPPORT: WorkspaceId = WorkspaceId([11; 16]);

// Fixed index keys keep the false candidates of the one-bit index deterministic.
fn keys() -> Keys {
    let encryption = EncryptionKey::new(
        cryptbox::key_id!("50000000-0000-4000-8000-000000000005"),
        [0x42; 32],
    );
    let blind_indexes = BlindIndexKey::new(
        cryptbox::index_key_id!("70000000-0000-4000-8000-000000000007"),
        [0x24; 32],
    );

    Keys::new(EncryptionKeyring::new(encryption, []).unwrap())
        .with_blind_indexes(BlindIndexKeyring::new(blind_indexes, []).unwrap())
}

/// Another org's keys: a keyring per org keeps orgs apart.
fn other_keys() -> Keys {
    Keys::new(EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap())
        .with_blind_indexes(BlindIndexKeyring::new(BlindIndexKey::generate().unwrap(), []).unwrap())
}

fn customer(id: i64, workspace: WorkspaceId, email: &str) -> Customer {
    Customer {
        id,
        org: ACME,
        workspace,
        email: email.to_owned(),
        note: Some(format!("note {id}")),
        created_at: 1_700_000_000,
    }
}

#[test]
fn a_record_round_trips() {
    let keys = keys();
    let ada = customer(7, SALES, "ada@example.com");

    let stored = ada.seal(&keys).unwrap();

    assert_eq!(
        (stored.id, stored.org, stored.created_at),
        (7, ACME, ada.created_at)
    );
    assert_eq!(Customer::open(stored, &keys).unwrap(), ada);
}

#[test]
fn an_absent_optional_field_is_stored_absent() {
    let keys = keys();
    let ada = Customer {
        note: None,
        ..customer(7, SALES, "ada@example.com")
    };

    let stored = ada.seal(&keys).unwrap();

    assert!(stored.note.is_none() && stored.note_index.is_none());
    assert_eq!(Customer::open(stored, &keys).unwrap(), ada);
}

#[test]
fn a_row_under_another_record_id_fails_to_open() {
    let keys = keys();
    let stored = customer(7, SALES, "ada@example.com").seal(&keys).unwrap();

    assert_eq!(
        Customer::open(StoredCustomer { id: 8, ..stored }, &keys).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn plaintext_columns_are_not_authenticated() {
    let keys = keys();
    let stored = customer(7, SALES, "ada@example.com").seal(&keys).unwrap();

    // Under shared keys, an edited org column opens: authorize on it, or keep a
    // keyring per org.
    let edited = Customer::open(
        StoredCustomer {
            org: GLOBEX,
            ..stored
        },
        &keys,
    )
    .unwrap();
    assert_eq!(edited.org, GLOBEX);
}

#[test]
fn a_value_copied_from_another_row_fails_to_open() {
    let keys = keys();
    let ada = customer(7, SALES, "ada@example.com").seal(&keys).unwrap();
    let bob = customer(8, SALES, "bob@example.com").seal(&keys).unwrap();

    assert_eq!(
        Customer::open(
            StoredCustomer {
                email: ada.email,
                ..bob
            },
            &keys
        )
        .unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn another_orgs_keys_do_not_open_a_row() {
    let stored = customer(7, SALES, "ada@example.com").seal(&keys()).unwrap();

    assert!(matches!(
        Customer::open(stored, &other_keys()).unwrap_err(),
        Error::UnknownEncryptionKey(_)
    ));
}

#[test]
fn open_expecting_rejects_a_row_before_decrypting_it() {
    let stored = customer(7, SALES, "ada@example.com").seal(&keys()).unwrap();

    // Keys that could not open it: the rejection comes first.
    assert_eq!(
        Customer::open_expecting(stored.clone(), &other_keys(), |row| row.org == GLOBEX)
            .unwrap_err(),
        Error::UnexpectedRecord
    );
    assert_eq!(
        Customer::open_expecting(stored, &keys(), |row| row.org == ACME).unwrap(),
        customer(7, SALES, "ada@example.com")
    );
}

#[test]
fn a_record_with_blind_indexes_needs_blind_index_keys() {
    let keys = keys();

    assert_eq!(
        customer(7, SALES, "ada@example.com")
            .seal(keys.encryption())
            .unwrap_err(),
        Error::BlindIndexKeysNotConfigured
    );
}

/// Seals customers of `org`, in several workspaces.
fn rows(keys: &Keys, org: OrgId) -> Vec<StoredCustomer> {
    [
        (1, SALES, "ada@example.com"),
        (2, SUPPORT, " Ada@Example.com"),
        (3, SUPPORT, "grace@example.com"),
        (4, SALES, "hedy@example.com"),
        (5, SALES, "joan@example.com"),
    ]
    .into_iter()
    .map(|(id, workspace, email)| Customer {
        org,
        ..customer(id, workspace, email)
    })
    .map(|customer| customer.seal(keys).unwrap())
    .collect()
}

#[test]
fn a_lookup_opens_its_candidates_and_keeps_the_matches() {
    let keys = keys();
    let probes = Customer::EMAIL_INDEX
        .probes("ada@example.com", &keys)
        .unwrap();
    let candidates: Vec<_> = rows(&keys, ACME)
        .into_iter()
        .filter(|row| probes.contains(&row.email_index))
        .collect();
    assert!(
        candidates.len() > 2,
        "the one-bit index selects false candidates"
    );

    let hits = Customer::EMAIL_INDEX
        .open_matching("ada@example.com", candidates, &keys)
        .unwrap();

    let found: Vec<_> = hits
        .into_iter()
        .map(|hit| hit.map(|customer| (customer.id, customer.workspace)))
        .collect();
    assert_eq!(found, [Ok((1, SALES)), Ok((2, SUPPORT))]);
}

#[test]
fn separate_index_keys_keep_orgs_lookups_apart() {
    let keys = keys();
    let ada = customer(7, SALES, "ada@example.com").seal(&keys).unwrap();
    let probes = |keys: &Keys| Customer::NOTE_INDEX.probes("note 7", keys).unwrap();

    assert_eq!(probes(&keys).first(), ada.note_index.as_ref());
    assert!(!probes(&other_keys()).contains(ada.note_index.as_ref().unwrap()));
}

#[test]
fn a_candidate_that_fails_to_open_is_reported_not_dropped() {
    let hits = Customer::EMAIL_INDEX
        .open_matching("ada@example.com", rows(&other_keys(), GLOBEX), &keys())
        .unwrap();

    assert_eq!(hits.len(), 5);
    assert!(
        hits.iter()
            .all(|hit| matches!(hit, Err(Error::UnknownEncryptionKey(_))))
    );
}

/// A row without blind indexes, with a renamed seal and stored form.
#[derive(Debug, PartialEq, Record)]
#[cryptbox(stored(name = NoteRow))]
struct Note {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(plaintext)]
    org: OrgId,
    #[cryptbox(seal = "6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51", name = NoteBody)]
    body: String,
}

#[test]
fn a_record_without_blind_indexes_takes_an_encryption_keyring() {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let note = Note {
        id: 1,
        org: ACME,
        body: "ship it".to_owned(),
    };

    let row: NoteRow = note.seal(&keys).unwrap();
    let _: &Sealed<NoteBody, InRecord<i64>> = &row.body;

    assert_eq!(Note::open(row, &keys).unwrap(), note);
}

/// The seal a record declares for `Note::body`, written by hand: a seal knows
/// nothing of the record its values are stored in.
struct ManualNoteBody;

impl Seal for ManualNoteBody {
    const ID: SealId = cryptbox::seal_id!("6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

#[test]
fn a_record_field_is_bound_to_its_seal_and_record_id() {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let body =
        Sealed::<ManualNoteBody, InRecord<i64>>::seal_in(&"ship it".to_owned(), &1, &keys).unwrap();
    let row = NoteRow {
        id: 1,
        org: ACME,
        body: Sealed::from_bytes(body.into_bytes()).unwrap(),
    };

    assert_eq!(Note::open(row, &keys).unwrap().body, "ship it");
}

#[test]
fn a_record_field_opens_with_its_record_id_alone() {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let row: NoteRow = Note {
        id: 1,
        org: ACME,
        body: "ship it".to_owned(),
    }
    .seal(&keys)
    .unwrap();

    assert_eq!(row.body.open_in(&row.id, &keys).unwrap(), "ship it");
    assert!(matches!(
        row.body.open_in(&2, &keys),
        Err(Error::AuthenticationFailed)
    ));
}

#[test]
fn a_record_field_sealed_standalone_does_not_open_as_the_record_s() {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    // Nothing stops sealing a record field's seal standalone: the seal knows
    // nothing of the record. The value is bound to the seal ID alone.
    let standalone = Sealed::<NoteBody>::seal(&"ship it".to_owned(), &keys).unwrap();
    let row = NoteRow {
        id: 1,
        org: ACME,
        body: Sealed::from_bytes(standalone.as_bytes()).unwrap(),
    };

    assert!(matches!(
        Note::open(row, &keys),
        Err(Error::ContextMismatch)
    ));
    assert_eq!(standalone.open(&keys).unwrap(), "ship it");
}

#[cfg(feature = "json")]
mod serde_forms {
    use cryptbox::{EncryptionKey, EncryptionKeyring, Record};
    use serde::{Deserialize, Serialize};

    /// A tenant, carried in messages.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
    #[serde(transparent)]
    struct TenantKey(i64);

    /// A record carried as a message, its stored form serialized by Serde.
    #[derive(Debug, PartialEq, Record)]
    #[cryptbox(stored(derive(Serialize, Deserialize)))]
    struct Event {
        #[cryptbox(record_id)]
        #[cryptbox(stored(serde(rename = "eventId")))]
        id: i64,
        #[cryptbox(plaintext)]
        tenant: TenantKey,
        #[cryptbox(seal = "3a9d4e21-7b6c-4f58-9e0a-1c2b3d4e5f60")]
        detail: String,
    }

    #[test]
    fn stored_attributes_are_forwarded_to_the_stored_form() {
        let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
        let event = Event {
            id: 3,
            tenant: TenantKey(9),
            detail: "created".to_owned(),
        };

        let json = serde_json::to_value(event.seal(&keys).unwrap()).unwrap();
        assert_eq!(json["eventId"], 3);
        assert_eq!(json["tenant"], 9);

        let stored: StoredEvent = serde_json::from_value(json).unwrap();
        assert_eq!(Event::open(stored, &keys).unwrap(), event);
    }
}

#[cfg(feature = "sqlx-sqlite")]
mod sqlite {
    use cryptbox::{EncryptionKey, EncryptionKeyring, Record};
    use sqlx::{Connection, sqlite::SqliteConnection};

    /// A tenant, stored as its integer.
    #[derive(Clone, Copy, Debug, PartialEq, sqlx::Type)]
    #[sqlx(transparent)]
    struct TenantKey(i64);

    /// A record whose stored form is read with `sqlx::FromRow`.
    #[derive(Debug, PartialEq, Record)]
    #[cryptbox(stored(derive(sqlx::FromRow), sqlx(rename_all = "UPPERCASE")))]
    struct Customer {
        #[cryptbox(record_id)]
        id: i64,
        #[cryptbox(plaintext)]
        tenant: TenantKey,
        #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
        #[cryptbox(stored(sqlx(rename = "EMAIL_CIPHERTEXT")))]
        email: String,
    }

    #[test]
    fn a_stored_form_reads_rows_with_forwarded_sqlx_attributes() {
        let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
        let ada = Customer {
            id: 7,
            tenant: TenantKey(3),
            email: "ada@example.com".to_owned(),
        };
        let stored = ada.seal(&keys).unwrap();

        let read = futures_executor::block_on(async {
            let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
            sqlx::query(
                "CREATE TABLE customers (ID INTEGER, TENANT INTEGER, EMAIL_CIPHERTEXT BLOB)",
            )
            .execute(&mut connection)
            .await
            .unwrap();
            sqlx::query("INSERT INTO customers VALUES (?, ?, ?)")
                .bind(stored.id)
                .bind(stored.tenant)
                .bind(&stored.email)
                .execute(&mut connection)
                .await
                .unwrap();

            sqlx::query_as::<_, StoredCustomer>("SELECT * FROM customers WHERE TENANT = ?")
                .bind(TenantKey(3))
                .fetch_one(&mut connection)
                .await
                .unwrap()
        });

        assert_eq!(
            Customer::open_expecting(read, &keys, |row| row.id == 7).unwrap(),
            ada
        );
    }
}
