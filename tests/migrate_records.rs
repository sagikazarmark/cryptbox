//! Public-boundary tests for sweeping a record's sealed fields.

#![cfg(all(feature = "migrate", feature = "derive"))]

use std::{
    convert::Infallible,
    future::{Future, ready},
};

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyring, EncryptionKey,
    EncryptionKeyring, Error, Keys, Padding, Record, Seal, Sealed, Utf8, index_key_id, key_id,
    migrate::{RowPlanner, RowState, RowWrite, Sweep, SweepRow, SweepStore},
};
use futures_executor::block_on;
use zeroize::Zeroizing;

#[allow(clippy::unnecessary_wraps)] // Normalizers are fallible by contract.
fn normalize(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(
        input.trim().to_ascii_lowercase().into_bytes(),
    ))
}

/// A customer whose email is bound to its record.
#[derive(Debug, PartialEq, Record)]
struct Customer {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "8a000000-0000-4000-8000-00000000000a")]
    #[cryptbox(blind_index(
        id = "8b000000-0000-4000-8000-00000000000b",
        bits = 128,
        normalize = normalize,
        normalizer = "email/1",
    ))]
    email: String,
}

/// The same seal ID, for standalone values.
struct UnboundEmail;

impl Seal for UnboundEmail {
    const ID: cryptbox::SealId = CustomerEmail::ID;
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Indexes = ();
}

/// The columns a row's record ID is read from.
#[derive(Clone, Debug)]
struct Columns {
    id: i64,
}

fn row(id: i64) -> Columns {
    Columns { id }
}

#[allow(clippy::unnecessary_wraps)] // A row closure is fallible by contract.
fn record_id(row: &Columns) -> Result<&i64, Error> {
    Ok(&row.id)
}

fn old_key() -> EncryptionKey {
    EncryptionKey::new(key_id!("81000000-0000-4000-8000-000000000001"), [0x11; 32])
}

fn new_key() -> EncryptionKey {
    EncryptionKey::new(key_id!("82000000-0000-4000-8000-000000000002"), [0x22; 32])
}

/// The keys before the rotation.
fn old_keys() -> EncryptionKeyring {
    EncryptionKeyring::new(old_key(), []).unwrap()
}

/// The keys after the rotation: the new key, and the old one still readable.
fn rotated_keys() -> EncryptionKeyring {
    EncryptionKeyring::new(new_key(), [old_key()]).unwrap()
}

fn index_keys() -> BlindIndexKeyring {
    BlindIndexKeyring::new(
        BlindIndexKey::new(
            index_key_id!("84000000-0000-4000-8000-000000000004"),
            [0x44; 32],
        ),
        [],
    )
    .unwrap()
}

/// Seals `email` for `row` with `keys`, as the application writes it.
fn seal(row: &Columns, email: &str, keys: &EncryptionKeyring) -> (Vec<u8>, Vec<u8>) {
    let keys = Keys::new(keys.clone()).with_blind_indexes(index_keys());
    let stored = Customer {
        id: row.id,
        email: email.to_owned(),
    }
    .seal(&keys)
    .unwrap();

    (stored.email.into_bytes(), stored.email_index.into_bytes())
}

/// Opens a row as the application reads it.
fn open(
    id: i64,
    ciphertext: &[u8],
    index: &[u8],
    keys: &EncryptionKeyring,
) -> Result<Customer, Error> {
    let stored = StoredCustomer {
        id,
        email: Sealed::from_bytes(ciphertext.to_vec())?,
        email_index: BlindIndex::from_bytes(index.to_vec())?,
    };

    Customer::open(stored, keys)
}

fn planner<'a>(
    keys: &'a EncryptionKeyring,
    index_keys: &'a BlindIndexKeyring,
) -> RowPlanner<'a, CustomerEmail, Columns> {
    RowPlanner::for_rows(keys, record_id).with_index::<CustomerEmailIndex>(index_keys)
}

#[test]
fn planner_skips_a_current_row_bound_to_its_record() {
    let (keys, index_keys) = (rotated_keys(), index_keys());
    let row = row(7);
    let (ciphertext, index) = seal(&row, "ada@example.com", &keys);
    let planner = planner(&keys, &index_keys);

    assert_eq!(
        planner.classify_row(&row, &ciphertext, &[&index]).unwrap(),
        RowState::Current
    );
    let outcome = planner.plan_row(&row, &ciphertext, &[&index]).unwrap();
    assert_eq!(outcome.state(), RowState::Current);
    assert!(outcome.write().is_none());
}

#[test]
fn planner_reseals_a_stale_row_under_its_record() {
    let (keys, index_keys) = (rotated_keys(), index_keys());
    let row = row(7);
    let (ciphertext, index) = seal(&row, "ada@example.com", &old_keys());
    let planner = planner(&keys, &index_keys);

    let outcome = planner.plan_row(&row, &ciphertext, &[&index]).unwrap();
    assert_eq!(outcome.state(), RowState::Stale);
    let write = outcome.into_write().unwrap();

    let resealed = Sealed::<CustomerEmail>::from_bytes(write.ciphertext()).unwrap();
    assert_eq!(resealed.key_id(), new_key().id());
    assert_eq!(
        open(7, write.ciphertext(), &write.indexes()[0], &keys)
            .unwrap()
            .email,
        "ada@example.com"
    );
    assert_eq!(
        open(8, write.ciphertext(), &write.indexes()[0], &keys).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn a_standalone_value_in_a_record_column_is_a_binding_mismatch() {
    let (keys, index_keys) = (rotated_keys(), index_keys());
    let row = row(7);
    let ciphertext = Sealed::<UnboundEmail>::seal(&"ada@example.com".into(), &keys)
        .unwrap()
        .into_bytes();
    let index = seal(&row, "ada@example.com", &keys).1;
    let planner = planner(&keys, &index_keys);

    assert_eq!(
        planner
            .classify_row(&row, &ciphertext, &[&index])
            .unwrap_err(),
        Error::ContextMismatch
    );
}

/// An in-memory [`SweepStore`] over one keyring's rows, with their columns.
struct MemoryStore {
    rows: Vec<StoredRow>,
    checkpoint: Option<i64>,
}

#[derive(Clone)]
struct StoredRow {
    columns: Columns,
    ciphertext: Vec<u8>,
    indexes: Vec<Vec<u8>>,
}

impl SweepStore for MemoryStore {
    type Cursor = i64;
    type Columns = Columns;
    type Error = Infallible;

    fn load_checkpoint(&mut self) -> impl Future<Output = Result<Option<i64>, Infallible>> + Send {
        ready(Ok(self.checkpoint))
    }

    fn save_checkpoint(
        &mut self,
        cursor: &i64,
    ) -> impl Future<Output = Result<(), Infallible>> + Send {
        self.checkpoint = Some(*cursor);
        ready(Ok(()))
    }

    fn load_batch(
        &mut self,
        after: Option<&i64>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<SweepRow<i64, Columns>>, Infallible>> + Send {
        let after = after.copied().unwrap_or(i64::MIN);
        ready(Ok(self
            .rows
            .iter()
            .filter(|row| row.columns.id > after)
            .take(limit)
            .map(|row| SweepRow {
                cursor: row.columns.id,
                columns: row.columns.clone(),
                ciphertext: row.ciphertext.clone(),
                indexes: row.indexes.clone(),
            })
            .collect()))
    }

    fn update(
        &mut self,
        row: &SweepRow<i64, Columns>,
        replacement: &RowWrite,
    ) -> impl Future<Output = Result<bool, Infallible>> + Send {
        let stored = self
            .rows
            .iter_mut()
            .find(|stored| stored.columns.id == row.cursor)
            .unwrap();
        if stored.ciphertext != row.ciphertext || stored.indexes != row.indexes {
            return ready(Ok(false));
        }

        stored.ciphertext = replacement.ciphertext().to_vec();
        stored.indexes = replacement.indexes().to_vec();
        ready(Ok(true))
    }
}

const EMAILS: [&str; 4] = [
    "ada@example.com",
    "grace@example.com",
    "alan@example.com",
    "edsger@example.com",
];

/// Three rows sealed before a key rotation and one after it.
fn half_rotated_store() -> MemoryStore {
    let rows = EMAILS
        .iter()
        .zip(1..)
        .map(|(email, id)| {
            let columns = row(id);
            let keys = if id == 4 { rotated_keys() } else { old_keys() };
            let (ciphertext, index) = seal(&columns, email, &keys);
            StoredRow {
                columns,
                ciphertext,
                indexes: vec![index],
            }
        })
        .collect();

    MemoryStore {
        rows,
        checkpoint: None,
    }
}

#[test]
fn a_sweep_reseals_a_records_fields_under_the_new_key() {
    let (keys, index_keys) = (rotated_keys(), index_keys());
    let sweep = Sweep::new(planner(&keys, &index_keys)).with_batch_size(2);
    let mut store = half_rotated_store();

    let before = block_on(sweep.verify(&mut store)).unwrap();
    assert_eq!((before.stale, before.current), (3, 1));
    assert!(!before.is_terminal());

    block_on(sweep.run(&mut store)).unwrap();

    let after = block_on(sweep.verify(&mut store)).unwrap();
    assert_eq!((after.stale, after.current), (0, 4));
    assert!(after.is_terminal());
    for (row, email) in store.rows.iter().zip(EMAILS) {
        let new_only = EncryptionKeyring::new(new_key(), []).unwrap();
        let opened = open(row.columns.id, &row.ciphertext, &row.indexes[0], &new_only).unwrap();
        assert_eq!(opened.email, email);
    }
}
