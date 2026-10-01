//! Public-boundary tests for records: rows that carry their bound values.
#![cfg(feature = "derive")]

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BoundId, EncryptionKey, EncryptionKeyring,
    Error, Keys, Padding, Record, Seal, SealId, Sealed, Utf8,
};
use zeroize::Zeroizing;

/// An org's ID.
#[derive(BoundId, Clone, Copy, Debug, PartialEq)]
#[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
struct OrgId([u8; 16]);

/// A workspace's ID.
#[derive(BoundId, Clone, Copy, Debug, PartialEq)]
#[cryptbox(kind = "78f0169a-f024-402b-9cdf-f436864fa17f")]
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
    #[cryptbox(bound)]
    org: OrgId,
    #[cryptbox(bound)]
    workspace: WorkspaceId,
    /// The primary contact address, searchable across the org's workspaces.
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        across(workspace),
        bits = 1,
        normalize = normalize_email,
        normalizer = "email/1",
    ))]
    email: String,
    /// A note, searchable within one workspace.
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
fn a_moved_row_fails_to_open() {
    let keys = keys();
    let stored = customer(7, SALES, "ada@example.com").seal(&keys).unwrap();
    let moved = [
        (
            "org",
            StoredCustomer {
                org: GLOBEX,
                ..stored.clone()
            },
        ),
        (
            "workspace",
            StoredCustomer {
                workspace: SUPPORT,
                ..stored.clone()
            },
        ),
        ("record", StoredCustomer { id: 8, ..stored }),
    ];

    for (case, row) in moved {
        assert_eq!(
            Customer::open(row, &keys).unwrap_err(),
            Error::AuthenticationFailed,
            "{case}"
        );
    }
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
    let other = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();

    assert!(matches!(
        Customer::open(stored, &other).unwrap_err(),
        Error::UnknownEncryptionKey(_)
    ));
}

#[test]
fn open_expecting_rejects_a_row_before_decrypting_it() {
    let stored = customer(7, SALES, "ada@example.com").seal(&keys()).unwrap();
    // Keys that could not open it: the rejection comes first.
    let other = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();

    assert_eq!(
        Customer::open_expecting(stored.clone(), &other, |row| row.org == GLOBEX).unwrap_err(),
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
            .seal(&keys.encryption)
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
fn an_index_across_workspaces_finds_matches_in_every_workspace_of_the_org() {
    let keys = keys();
    let probes = Customer::EMAIL_INDEX
        .probes("ada@example.com", &ACME, &keys)
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
        .open_matching("ada@example.com", &ACME, candidates, &keys)
        .unwrap();

    let found: Vec<_> = hits
        .into_iter()
        .map(|hit| hit.map(|customer| (customer.id, customer.workspace)))
        .collect();
    assert_eq!(found, [Ok((1, SALES)), Ok((2, SUPPORT))]);
}

#[test]
fn an_index_partitions_by_the_bound_values_it_does_not_span() {
    let keys = keys();
    let ada = customer(7, SALES, "ada@example.com").seal(&keys).unwrap();
    let probe = |org| {
        Customer::EMAIL_INDEX
            .probes("ada@example.com", &org, &keys)
            .unwrap()
    };

    assert_eq!(probe(ACME), std::slice::from_ref(&ada.email_index));
    assert_ne!(probe(GLOBEX), [ada.email_index]);
}

#[test]
fn rows_outside_the_partition_are_refused_without_decrypting() {
    let keys = keys();
    let other = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();

    let hits = Customer::EMAIL_INDEX
        .open_matching("ada@example.com", &ACME, rows(&keys, GLOBEX), &other)
        .unwrap();

    assert_eq!(hits.len(), 5);
    assert!(hits.iter().all(|hit| hit == &Err(Error::OutsidePartition)));
}

#[test]
fn an_index_partitioned_by_two_bound_values_takes_a_partition_struct() {
    let keys = keys();
    let stored = customer(7, SALES, "ada@example.com").seal(&keys).unwrap();
    let sales = CustomerNoteIndexPartition {
        org: ACME,
        workspace: SALES,
    };

    let probes = Customer::NOTE_INDEX
        .probes("note 7", &sales, &keys)
        .unwrap();
    assert_eq!(Some(&probes[0]), stored.note_index.as_ref());
    assert_eq!(
        Customer::NOTE_INDEX
            .open_matching("note 7", &sales, [stored.clone()], &keys)
            .unwrap(),
        [Ok(customer(7, SALES, "ada@example.com"))]
    );

    let support = CustomerNoteIndexPartition {
        org: ACME,
        workspace: SUPPORT,
    };
    assert_eq!(
        Customer::NOTE_INDEX
            .open_matching("note 7", &support, [stored], &keys)
            .unwrap(),
        [Err(Error::OutsidePartition)]
    );
}

/// A row bound to its org alone, without blind indexes, with a renamed seal and
/// stored form.
#[derive(Debug, PartialEq, Record)]
#[cryptbox(stored(name = NoteRow))]
struct Note {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(bound)]
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
    let body: &Sealed<NoteBody> = &row.body;

    assert_eq!(body.open((&ACME, &1), &keys).unwrap(), "ship it");
    assert_eq!(Note::open(row, &keys).unwrap(), note);
}

/// The seal a record declares for `Note::body`, written by hand.
struct ManualNoteBody;

impl Seal for ManualNoteBody {
    const ID: SealId = cryptbox::seal_id!("6e2d9a4c-1b7f-4c38-a5e0-3d9b8c7a6f51");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Bound = (OrgId,);
    type Record = i64;
    type Indexes = ();
}

#[test]
fn a_record_field_is_bound_to_its_seal_bound_values_and_record_id() {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let body = Sealed::<ManualNoteBody>::seal(&"ship it".to_owned(), (&ACME, &1), &keys).unwrap();
    let row = NoteRow {
        id: 1,
        org: ACME,
        body: Sealed::from_bytes(body.into_bytes()).unwrap(),
    };

    assert_eq!(Note::open(row, &keys).unwrap().body, "ship it");
}

#[cfg(feature = "json")]
mod serde_forms {
    use cryptbox::{BoundId, EncryptionKey, EncryptionKeyring, Record};
    use serde::{Deserialize, Serialize};

    /// A tenant, carried in messages.
    #[derive(BoundId, Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
    #[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
    #[serde(transparent)]
    struct TenantKey(i64);

    /// A record carried as a message, its stored form serialized by Serde.
    #[derive(Debug, PartialEq, Record)]
    #[cryptbox(stored(derive(Serialize, Deserialize)))]
    struct Event {
        #[cryptbox(record_id)]
        #[cryptbox(stored(serde(rename = "eventId")))]
        id: i64,
        #[cryptbox(bound)]
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
    use cryptbox::{BoundId, EncryptionKey, EncryptionKeyring, Record};
    use sqlx::{Connection, sqlite::SqliteConnection};

    /// A tenant, stored as its integer.
    #[derive(BoundId, Clone, Copy, Debug, PartialEq, sqlx::Type)]
    #[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
    #[sqlx(transparent)]
    struct TenantKey(i64);

    /// A record whose stored form is read with `sqlx::FromRow`.
    #[derive(Debug, PartialEq, Record)]
    #[cryptbox(stored(derive(sqlx::FromRow), sqlx(rename_all = "UPPERCASE")))]
    struct Customer {
        #[cryptbox(record_id)]
        id: i64,
        #[cryptbox(bound)]
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

/// A contact's email, as it was sealed before it moved into its record:
/// unbound.
struct UnboundEmail;

impl Seal for UnboundEmail {
    const ID: SealId = cryptbox::seal_id!("9e2d4b71-3c8a-4f05-b6e1-7a0c5d3f8b24");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Bound = ();
    type Record = ();
    type Indexes = ();
}

/// A contact whose email is now bound to its org and record, and whose note
/// moved from another seal ID.
#[derive(Debug, PartialEq, Record)]
#[cryptbox(stored(derive(Clone)))]
struct Contact {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(bound)]
    org: OrgId,
    #[cryptbox(seal = "9e2d4b71-3c8a-4f05-b6e1-7a0c5d3f8b24")]
    #[cryptbox(legacy(record = false))]
    email: String,
    #[cryptbox(seal = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38")]
    #[cryptbox(legacy(seal = "4f8a2c6e-1b3d-4a57-9e0c-8d2f6b4a1c95", bound(org)))]
    note: String,
}

/// The seal `Contact::note` had before: another ID, the same binding.
struct OldNote;

impl Seal for OldNote {
    const ID: SealId = cryptbox::seal_id!("4f8a2c6e-1b3d-4a57-9e0c-8d2f6b4a1c95");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Bound = (OrgId,);
    type Record = i64;
    type Indexes = ();
}

fn legacy_contact(keys: &EncryptionKeyring) -> StoredContact {
    let email = Sealed::<UnboundEmail>::seal(&"ada@example.com".to_owned(), (), keys).unwrap();
    let note = Sealed::<OldNote>::seal(&"VIP".to_owned(), (&ACME, &7), keys).unwrap();

    StoredContact {
        id: 7,
        org: ACME,
        email: Sealed::from_bytes(email.into_bytes()).unwrap(),
        note: Sealed::from_bytes(note.into_bytes()).unwrap(),
    }
}

#[test]
fn a_legacy_window_opens_rows_sealed_with_the_old_declaration() {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let contact = Contact {
        id: 7,
        org: ACME,
        email: "ada@example.com".to_owned(),
        note: "VIP".to_owned(),
    };

    assert_eq!(
        Contact::open(legacy_contact(&keys), &keys).unwrap(),
        contact
    );
    // New rows are written with the current declaration, and read back.
    assert_eq!(
        Contact::open(contact.seal(&keys).unwrap(), &keys).unwrap(),
        contact
    );
}

#[test]
fn a_legacy_window_still_authenticates_the_row() {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let moved = StoredContact {
        org: GLOBEX,
        ..legacy_contact(&keys)
    };

    assert_eq!(
        Contact::open(moved, &keys).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn the_manifest_lists_open_legacy_windows() {
    let manifest = cryptbox::schema::Manifest::new()
        .record::<Contact>()
        .to_string();

    assert!(manifest.ends_with("  legacy: email, note\n"), "{manifest}");
}

#[cfg(feature = "migrate")]
mod sweep {
    use cryptbox::{
        EncryptionKey, EncryptionKeyring, Record,
        migrate::{RowArgs, RowPlanner, RowState},
    };

    use super::{ACME, Contact, ContactEmail, ContactEmailLegacy, StoredContact, legacy_contact};

    #[test]
    fn a_planner_reseals_rows_of_a_legacy_seal() {
        let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
        let row = legacy_contact(&keys);
        let planner = RowPlanner::<ContactEmail, StoredContact>::for_rows(&keys, |row| {
            Ok(RowArgs::new(&row.org).with_record(row.id.into()))
        })
        .legacy_seal::<ContactEmailLegacy>(&keys);

        let outcome = planner.plan_row(&row, row.email.as_bytes(), &[]).unwrap();

        assert_eq!(outcome.state(), RowState::LegacyBinding);
        let resealed = StoredContact {
            email: cryptbox::Sealed::from_bytes(outcome.write().unwrap().ciphertext()).unwrap(),
            ..row
        };
        assert_eq!(
            resealed.email.open((&ACME, &7), &keys).unwrap(),
            "ada@example.com"
        );
        assert_eq!(
            Contact::open(resealed, &keys).unwrap().email,
            "ada@example.com"
        );
    }
}
