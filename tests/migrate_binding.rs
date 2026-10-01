//! Public-boundary tests for migrating a seal's binding declaration.

#![cfg(feature = "migrate")]

use std::{
    convert::Infallible,
    future::{Future, ready},
};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, IndexId, Padding, RecordId, Seal, Sealed, Utf8, index_id,
    index_key_id, key_id,
    migrate::{RowPlanner, RowState, RowWrite, Sweep, SweepRow, SweepStore, open_across},
    seal_id,
};
use futures_executor::block_on;
use zeroize::Zeroizing;

/// The seal after the migration: bound to its record.
struct CustomerEmail;

impl Seal for CustomerEmail {
    const ID: cryptbox::SealId = seal_id!("8a000000-0000-4000-8000-00000000000a");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Record = i64;
    type Indexes = (EmailLookup,);
}

/// The same seal as it was declared before the migration: bound to its seal ID
/// alone.
struct UnboundEmail;

impl Seal for UnboundEmail {
    const ID: cryptbox::SealId = CustomerEmail::ID;
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Record = ();
    type Indexes = (UnboundEmailLookup,);
}

const LOOKUP_ID: IndexId = index_id!("8b000000-0000-4000-8000-00000000000b");

fn normalize(input: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(input.trim().to_ascii_lowercase().into_bytes())
}

struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Seal = CustomerEmail;
    const ID: IndexId = LOOKUP_ID;
    const BITS: u16 = 128;
    const NORMALIZER: &'static str = "email/1";
    type Query = str;

    fn normalize_query(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(normalize(input))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(normalize(value))
    }
}

/// The lookup as it was declared before the migration.
struct UnboundEmailLookup;

impl BlindIndexSpec for UnboundEmailLookup {
    type Seal = UnboundEmail;
    const ID: IndexId = LOOKUP_ID;
    const BITS: u16 = 128;
    const NORMALIZER: &'static str = "email/1";
    type Query = str;

    fn normalize_query(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(normalize(input))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(normalize(value))
    }
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
fn record_id(row: &Columns) -> Result<RecordId<'_>, Error> {
    Ok(RecordId::from(row.id))
}

/// The keys the application used before the migration.
fn old_keys() -> EncryptionKeyring {
    EncryptionKeyring::new(
        EncryptionKey::new(key_id!("81000000-0000-4000-8000-000000000001"), [0x11; 32]),
        [],
    )
    .unwrap()
}

fn old_index_keys() -> BlindIndexKeyring {
    BlindIndexKeyring::new(
        BlindIndexKey::new(
            index_key_id!("83000000-0000-4000-8000-000000000003"),
            [0x33; 32],
        ),
        [],
    )
    .unwrap()
}

/// The keys of tenant `acme`.
fn acme_keys() -> EncryptionKeyring {
    EncryptionKeyring::new(
        EncryptionKey::new(key_id!("82000000-0000-4000-8000-000000000002"), [0x22; 32]),
        [],
    )
    .unwrap()
}

fn acme_index_keys() -> BlindIndexKeyring {
    BlindIndexKeyring::new(
        BlindIndexKey::new(
            index_key_id!("84000000-0000-4000-8000-000000000004"),
            [0x44; 32],
        ),
        [],
    )
    .unwrap()
}

/// Seals `email` for `row` the way the application writes it after the migration.
fn seal_current(row: &Columns, email: &str) -> (Vec<u8>, Vec<u8>) {
    let email = email.to_owned();
    let prepared = Sealed::<CustomerEmail>::prepare(&email, &row.id, &acme_keys())
        .unwrap()
        .with_index_with::<EmailLookup>(&acme_index_keys())
        .unwrap();
    let index = prepared.index::<EmailLookup>().unwrap().as_bytes().to_vec();

    (prepared.into_sealed().into_bytes(), index)
}

fn planner<'a>(
    keys: &'a EncryptionKeyring,
    index_keys: &'a BlindIndexKeyring,
) -> RowPlanner<'a, CustomerEmail, Columns> {
    RowPlanner::for_rows(keys, record_id).with_index_with::<EmailLookup>(index_keys)
}

#[test]
fn planner_skips_a_current_row_bound_to_its_record() {
    let (keys, index_keys) = (acme_keys(), acme_index_keys());
    let row = row(7);
    let (ciphertext, index) = seal_current(&row, "ada@example.com");
    let planner = planner(&keys, &index_keys);

    assert_eq!(
        planner.classify_row(&row, &ciphertext, &[&index]).unwrap(),
        RowState::Current
    );
    let outcome = planner.plan_row(&row, &ciphertext, &[&index]).unwrap();
    assert_eq!(outcome.state(), RowState::Current);
    assert!(outcome.write().is_none());
}

/// Seals `email` the way the application wrote it before the migration.
fn seal_unbound(email: &str) -> (Vec<u8>, Vec<u8>) {
    let email = email.to_owned();
    let prepared = Sealed::<UnboundEmail>::prepare(&email, (), &old_keys())
        .unwrap()
        .with_index_with::<UnboundEmailLookup>(&old_index_keys())
        .unwrap();
    let index = prepared
        .index::<UnboundEmailLookup>()
        .unwrap()
        .as_bytes()
        .to_vec();

    (prepared.into_sealed().into_bytes(), index)
}

fn migrating_planner<'a>(
    keys: &'a EncryptionKeyring,
    old_keys: &'a EncryptionKeyring,
    index_keys: &'a BlindIndexKeyring,
) -> RowPlanner<'a, CustomerEmail, Columns> {
    planner(keys, index_keys).legacy_binding::<()>(old_keys)
}

#[test]
fn planner_reseals_an_unbound_row_under_its_record_and_new_keys() {
    let (keys, old_keys, index_keys) = (acme_keys(), old_keys(), acme_index_keys());
    let row = row(7);
    let (ciphertext, index) = seal_unbound("Ada@Example.com");
    let planner = migrating_planner(&keys, &old_keys, &index_keys);

    assert_eq!(
        planner.classify_row(&row, &ciphertext, &[&index]).unwrap(),
        RowState::LegacyBinding
    );
    let outcome = planner.plan_row(&row, &ciphertext, &[&index]).unwrap();
    assert_eq!(outcome.state(), RowState::LegacyBinding);
    let write = outcome.into_write().unwrap();

    let sealed = Sealed::<CustomerEmail>::from_bytes(write.ciphertext()).unwrap();
    assert_eq!(sealed.open(&7_i64, &keys).unwrap(), "Ada@Example.com");
    assert_eq!(
        sealed.open(&8_i64, &keys).unwrap_err(),
        Error::AuthenticationFailed
    );
    // The index is derived again under the new index keys.
    assert_eq!(write.indexes(), [seal_current(&row, "ada@example.com").1]);
    assert_eq!(
        planner
            .classify_row(&row, write.ciphertext(), &[&write.indexes()[0]])
            .unwrap(),
        RowState::Current
    );
}

#[test]
fn an_unbound_row_without_a_legacy_binding_window_is_a_binding_mismatch() {
    let (keys, index_keys) = (acme_keys(), acme_index_keys());
    let row = row(7);
    let (ciphertext, index) = seal_unbound("ada@example.com");
    let planner = planner(&keys, &index_keys);

    assert_eq!(
        planner
            .classify_row(&row, &ciphertext, &[&index])
            .unwrap_err(),
        Error::BindingMismatch
    );
    assert_eq!(
        planner.plan_row(&row, &ciphertext, &[&index]).unwrap_err(),
        Error::BindingMismatch
    );
}

#[test]
fn a_legacy_binding_moves_rows_out_of_their_record() {
    let keys = acme_keys();
    let row = row(7);
    // Sealed while the seal bound its record.
    let (ciphertext, _) = seal_current(&row, "ada@example.com");
    let planner = RowPlanner::<UnboundEmail, Columns>::for_rows(&keys, record_id)
        .legacy_binding::<i64>(&keys);

    assert_eq!(
        planner.classify_row(&row, &ciphertext, &[]).unwrap(),
        RowState::LegacyBinding
    );
    let write = planner
        .plan_row(&row, &ciphertext, &[])
        .unwrap()
        .into_write()
        .unwrap();
    assert_eq!(
        Sealed::<UnboundEmail>::from_bytes(write.ciphertext())
            .unwrap()
            .open((), &keys)
            .unwrap(),
        "ada@example.com"
    );
}

#[test]
fn a_record_for_a_seal_that_binds_none_is_invalid_without_a_window_that_does() {
    let keys = old_keys();
    let row = row(7);
    let (ciphertext, _) = seal_unbound("ada@example.com");
    let planner = RowPlanner::<UnboundEmail, Columns>::for_rows(&keys, record_id);

    assert_eq!(
        planner.classify_row(&row, &ciphertext, &[]).unwrap_err(),
        Error::InvalidBinding
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

/// Three rows written before the migration and one written after it.
fn half_written_store() -> MemoryStore {
    let rows = EMAILS
        .iter()
        .zip(1..)
        .map(|(email, id)| {
            let columns = row(id);
            let (ciphertext, index) = if id == 4 {
                seal_current(&columns, email)
            } else {
                seal_unbound(email)
            };
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
fn a_sweep_migrates_an_unbound_seal_into_its_record() {
    let (keys, old_keys, index_keys) = (acme_keys(), old_keys(), acme_index_keys());
    let sweep = Sweep::new(migrating_planner(&keys, &old_keys, &index_keys)).with_batch_size(2);
    let mut store = half_written_store();

    let before = block_on(sweep.verify(&mut store)).unwrap();
    assert_eq!((before.legacy_binding, before.current), (3, 1));
    assert!(!before.is_terminal());

    let report = block_on(sweep.run(&mut store)).unwrap();
    assert_eq!((report.legacy_binding, report.current), (3, 1));

    let after = block_on(sweep.verify(&mut store)).unwrap();
    assert_eq!((after.legacy_binding, after.current), (0, 4));
    assert!(after.is_terminal());
    for (row, email) in store.rows.iter().zip(EMAILS) {
        let sealed = Sealed::<CustomerEmail>::from_bytes(row.ciphertext.clone()).unwrap();
        assert_eq!(sealed.open(&row.columns.id, &keys).unwrap(), email);
        assert_eq!(row.indexes, [seal_current(&row.columns, email).1]);
    }
}

/// Looks `email` up the way the application does during the window: probes
/// under both index keyrings, then opening each candidate under either
/// declaration.
fn look_up(store: &MemoryStore, email: &str) -> Vec<(i64, String)> {
    let mut probes = EmailLookup::probes_with(email, &acme_index_keys()).unwrap();
    probes.extend(EmailLookup::probes_with(email, &old_index_keys()).unwrap());

    store
        .rows
        .iter()
        .filter(|row| {
            probes
                .iter()
                .any(|probe| probe.as_bytes() == row.indexes[0])
        })
        .map(|row| {
            let sealed = Sealed::<CustomerEmail>::from_bytes(row.ciphertext.clone()).unwrap();
            let value =
                open_across::<(), _>(&sealed, &row.columns.id, &acme_keys(), &old_keys()).unwrap();
            assert!(EmailLookup::verify_candidate(email, &value).unwrap());
            (row.columns.id, value)
        })
        .collect()
}

fn assert_every_email_is_found(store: &MemoryStore) {
    for (email, id) in EMAILS.iter().zip(1..) {
        assert_eq!(
            look_up(store, email),
            [(id, (*email).to_owned())],
            "{email}"
        );
    }
}

#[test]
fn lookups_keep_working_throughout_the_window() {
    let (keys, old_keys, index_keys) = (acme_keys(), old_keys(), acme_index_keys());
    let sweep = Sweep::new(migrating_planner(&keys, &old_keys, &index_keys)).with_batch_size(2);
    let mut store = half_written_store();
    assert_every_email_is_found(&store);

    let first = block_on(sweep.run_batch(&mut store)).unwrap();
    assert_eq!(first.report.legacy_binding, 2);
    assert_every_email_is_found(&store);

    block_on(sweep.run(&mut store)).unwrap();
    assert!(block_on(sweep.verify(&mut store)).unwrap().is_terminal());
    assert_every_email_is_found(&store);
}

#[test]
fn moving_into_a_record_keeps_the_index_binding() {
    // The record never takes part in an index, so the old declaration's indexes
    // are found by probing with the old keys.
    assert_eq!(
        EmailLookup::probes_with("ada@example.com", &old_index_keys())
            .unwrap()
            .iter()
            .map(|probe| probe.as_bytes().to_vec())
            .collect::<Vec<_>>(),
        UnboundEmailLookup::probes_with("ada@example.com", &old_index_keys())
            .unwrap()
            .iter()
            .map(|probe| probe.as_bytes().to_vec())
            .collect::<Vec<_>>()
    );
}

/// The same seal, bound to a record ID of another kind.
struct KeyedEmail;

impl Seal for KeyedEmail {
    const ID: cryptbox::SealId = CustomerEmail::ID;
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Record = Vec<u8>;
    type Indexes = ();
}

#[test]
fn open_across_reports_a_value_of_neither_declaration_as_a_binding_mismatch() {
    let keys = acme_keys();
    let sealed =
        Sealed::<KeyedEmail>::seal(&"ada@example.com".into(), &b"row-7".to_vec(), &keys).unwrap();
    let sealed = Sealed::<CustomerEmail>::from_bytes(sealed.into_bytes()).unwrap();

    assert_eq!(
        open_across::<(), _>(&sealed, &7_i64, &keys, &old_keys()).unwrap_err(),
        Error::BindingMismatch
    );
}
