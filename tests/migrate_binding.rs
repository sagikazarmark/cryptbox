//! Public-boundary tests for migrating a seal's binding declaration.

#![cfg(feature = "migrate")]

use std::{
    convert::Infallible,
    future::{Future, ready},
};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, IndexId, Padding, RecordId, Recorded, Seal, Sealed, Tenant, TenantId,
    Utf8, index_id, index_key_id, key_id,
    migrate::{
        RowArgs, RowPlanner, RowState, RowWrite, Sweep, SweepRow, SweepStore, open_across,
        probes_across,
    },
    seal_id,
};
use futures_executor::block_on;
use zeroize::Zeroizing;

/// The seal after the migration: bound to its tenant and its record.
struct CustomerEmail;

impl Seal for CustomerEmail {
    const ID: cryptbox::SealId = seal_id!("8a000000-0000-4000-8000-00000000000a");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Scope = Recorded<Tenant, i64>;
    type Indexes = (EmailLookup,);
}

/// The same seal as it was declared before the migration.
struct UnscopedEmail;

impl Seal for UnscopedEmail {
    const ID: cryptbox::SealId = CustomerEmail::ID;
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Scope = ();
    type Indexes = (UnscopedEmailLookup,);
}

const LOOKUP_ID: IndexId = index_id!("8b000000-0000-4000-8000-00000000000b");

fn normalize(input: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(input.trim().to_ascii_lowercase().into_bytes())
}

struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Seal = CustomerEmail;
    type Scope = Tenant;
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
struct UnscopedEmailLookup;

impl BlindIndexSpec for UnscopedEmailLookup {
    type Seal = UnscopedEmail;
    type Scope = ();
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

/// The columns a row's binding arguments are built from.
#[derive(Clone, Debug)]
struct Columns {
    tenant: Vec<u8>,
    id: i64,
}

fn row(tenant: &[u8], id: i64) -> Columns {
    Columns {
        tenant: tenant.to_vec(),
        id,
    }
}

fn tenant(name: &[u8]) -> Tenant {
    Tenant(TenantId::new(name.to_vec()).unwrap())
}

fn row_args(row: &Columns) -> Result<RowArgs<'_, Tenant>, Error> {
    Ok(
        RowArgs::new(Tenant(TenantId::new(row.tenant.clone())?))
            .with_record(RecordId::from(row.id)),
    )
}

/// The keys the application used before the migration.
fn unscoped_keys() -> EncryptionKeyring {
    EncryptionKeyring::new(
        EncryptionKey::new(key_id!("81000000-0000-4000-8000-000000000001"), [0x11; 32]),
        [],
    )
    .unwrap()
}

fn unscoped_index_keys() -> BlindIndexKeyring {
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
    let prepared =
        Sealed::<CustomerEmail>::prepare(&email, (&tenant(&row.tenant), &row.id), &acme_keys())
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
    RowPlanner::for_rows(keys, row_args).with_index_with::<EmailLookup>(index_keys)
}

#[test]
fn planner_skips_a_current_row_bound_to_its_scope_and_record() {
    let (keys, index_keys) = (acme_keys(), acme_index_keys());
    let row = row(b"acme", 7);
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

#[test]
fn planner_rejects_row_args_without_the_seals_record() {
    let (keys, index_keys) = (acme_keys(), acme_index_keys());
    let planner = RowPlanner::<CustomerEmail, Columns>::for_rows(&keys, |row| {
        Ok(RowArgs::new(Tenant(TenantId::new(row.tenant.clone())?)))
    })
    .with_index_with::<EmailLookup>(&index_keys);
    let row = row(b"acme", 7);
    let (ciphertext, index) = seal_current(&row, "ada@example.com");

    assert_eq!(
        planner
            .classify_row(&row, &ciphertext, &[&index])
            .unwrap_err(),
        Error::InvalidBinding
    );
}

/// Seals `email` the way the application wrote it before the migration.
fn seal_unscoped(email: &str) -> (Vec<u8>, Vec<u8>) {
    let email = email.to_owned();
    let prepared = Sealed::<UnscopedEmail>::prepare(&email, (), &unscoped_keys())
        .unwrap()
        .with_index_with::<UnscopedEmailLookup>(&unscoped_index_keys())
        .unwrap();
    let index = prepared
        .index::<UnscopedEmailLookup>()
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
fn planner_reseals_an_unscoped_row_under_its_scope_and_record() {
    let (keys, old_keys, index_keys) = (acme_keys(), unscoped_keys(), acme_index_keys());
    let row = row(b"acme", 7);
    let (ciphertext, index) = seal_unscoped("Ada@Example.com");
    let planner = migrating_planner(&keys, &old_keys, &index_keys);

    assert_eq!(
        planner.classify_row(&row, &ciphertext, &[&index]).unwrap(),
        RowState::LegacyBinding
    );
    let outcome = planner.plan_row(&row, &ciphertext, &[&index]).unwrap();
    assert_eq!(outcome.state(), RowState::LegacyBinding);
    let write = outcome.into_write().unwrap();

    let sealed = Sealed::<CustomerEmail>::from_bytes(write.ciphertext()).unwrap();
    assert_eq!(
        sealed.open((&tenant(b"acme"), &7_i64), &keys).unwrap(),
        "Ada@Example.com"
    );
    assert_eq!(
        sealed.open((&tenant(b"acme"), &8_i64), &keys).unwrap_err(),
        Error::AuthenticationFailed
    );
    // The index is derived again under the tenant's index binding.
    assert_eq!(write.indexes(), [seal_current(&row, "ada@example.com").1]);
    assert_eq!(
        planner
            .classify_row(&row, write.ciphertext(), &[&write.indexes()[0]])
            .unwrap(),
        RowState::Current
    );
}

#[test]
fn an_unscoped_row_without_a_legacy_binding_window_is_a_binding_mismatch() {
    let (keys, index_keys) = (acme_keys(), acme_index_keys());
    let row = row(b"acme", 7);
    let (ciphertext, index) = seal_unscoped("ada@example.com");
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

/// The same seal when it was bound to its tenant but not yet to its record.
struct TenantEmail;

impl Seal for TenantEmail {
    const ID: cryptbox::SealId = CustomerEmail::ID;
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Scope = Tenant;
    type Indexes = ();
}

#[test]
fn a_legacy_binding_takes_its_parts_from_the_rows_binding() {
    let (keys, index_keys) = (acme_keys(), acme_index_keys());
    let row = row(b"acme", 7);
    let ciphertext =
        Sealed::<TenantEmail>::seal(&"ada@example.com".into(), &tenant(b"acme"), &keys)
            .unwrap()
            .into_bytes();
    // Adding a record leaves the index binding, and so the index, unchanged.
    let index = seal_current(&row, "ada@example.com").1;
    let planner = planner(&keys, &index_keys).legacy_binding::<Tenant>(&keys);

    let write = planner
        .plan_row(&row, &ciphertext, &[&index])
        .unwrap()
        .into_write()
        .unwrap();

    assert_eq!(
        Sealed::<CustomerEmail>::from_bytes(write.ciphertext())
            .unwrap()
            .open((&tenant(b"acme"), &7_i64), &keys)
            .unwrap(),
        "ada@example.com"
    );
    assert_eq!(write.indexes(), [index]);
}

#[test]
fn a_legacy_binding_moves_rows_out_of_their_record() {
    let keys = acme_keys();
    let row = row(b"acme", 7);
    // Sealed while the seal bound its record.
    let (ciphertext, _) = seal_current(&row, "ada@example.com");
    let planner = RowPlanner::<TenantEmail, Columns>::for_rows(&keys, row_args)
        .legacy_binding::<Recorded<Tenant, i64>>(&keys);

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
        Sealed::<TenantEmail>::from_bytes(write.ciphertext())
            .unwrap()
            .open(&tenant(b"acme"), &keys)
            .unwrap(),
        "ada@example.com"
    );

    // The old declaration binds the record, so its rows must still pass it.
    let without_record = RowPlanner::<TenantEmail, Columns>::for_rows(&keys, |row| {
        Ok(RowArgs::new(tenant(&row.tenant)))
    })
    .legacy_binding::<Recorded<Tenant, i64>>(&keys);
    assert_eq!(
        without_record.plan_row(&row, &ciphertext, &[]).unwrap_err(),
        Error::InvalidBinding
    );
}

#[test]
fn a_record_for_a_seal_that_binds_none_is_invalid_without_a_window_that_does() {
    let keys = acme_keys();
    let row = row(b"acme", 7);
    let ciphertext =
        Sealed::<TenantEmail>::seal(&"ada@example.com".into(), &tenant(b"acme"), &keys)
            .unwrap()
            .into_bytes();
    let planner = RowPlanner::<TenantEmail, Columns>::for_rows(&keys, row_args);

    assert_eq!(
        planner.classify_row(&row, &ciphertext, &[]).unwrap_err(),
        Error::InvalidBinding
    );
}

/// A binding whose one part the current binding does not have.
#[derive(Clone, Hash, PartialEq, Eq)]
struct Region;

impl cryptbox::Scope for Region {
    const PARTS: &'static [cryptbox::PartSpec] = &[cryptbox::PartSpec::new(
        cryptbox::part_id!("8c000000-0000-4000-8000-00000000000c"),
        cryptbox::PartKind::Bytes,
    )];
    fn values(&self) -> cryptbox::PartValues<'_> {
        cryptbox::PartValues::from([cryptbox::PartValue::Bytes(b"eu")])
    }
}

#[test]
fn a_legacy_binding_with_a_part_the_current_binding_lacks_is_invalid() {
    let (keys, index_keys) = (acme_keys(), acme_index_keys());
    let row = row(b"acme", 7);
    let ciphertext = Sealed::<RegionEmail>::seal(&"ada@example.com".into(), &Region, &keys)
        .unwrap()
        .into_bytes();
    let planner = planner(&keys, &index_keys).legacy_binding::<Region>(&keys);

    assert_eq!(
        planner.classify_row(&row, &ciphertext, &[b""]).unwrap(),
        RowState::LegacyBinding
    );
    assert_eq!(
        planner.plan_row(&row, &ciphertext, &[b""]).unwrap_err(),
        Error::InvalidBinding
    );
}

struct RegionEmail;

impl Seal for RegionEmail {
    const ID: cryptbox::SealId = CustomerEmail::ID;
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Scope = Region;
    type Indexes = ();
}

/// An in-memory [`SweepStore`] over one partition's rows, with their columns.
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
            let columns = row(b"acme", id);
            let (ciphertext, index) = if id == 4 {
                seal_current(&columns, email)
            } else {
                seal_unscoped(email)
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
fn a_sweep_migrates_an_unscoped_seal_to_its_scope_and_record() {
    let (keys, old_keys, index_keys) = (acme_keys(), unscoped_keys(), acme_index_keys());
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
        let args = (&tenant(b"acme"), &row.columns.id);
        let sealed = Sealed::<CustomerEmail>::from_bytes(row.ciphertext.clone()).unwrap();
        assert_eq!(sealed.open(args, &keys).unwrap(), email);
        assert_eq!(row.indexes, [seal_current(&row.columns, email).1]);
    }
}

/// Looks `email` up the way the application does during the window: probes
/// over both index declarations, then opening each candidate under either declaration.
fn look_up(store: &MemoryStore, email: &str) -> Vec<(i64, String)> {
    let acme = tenant(b"acme");
    let probes =
        probes_across::<(), EmailLookup>(email, &acme, &acme_index_keys(), &unscoped_index_keys())
            .unwrap();

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
            let args = (&acme, &row.columns.id);
            let value =
                open_across::<(), _>(&sealed, args, &acme_keys(), &unscoped_keys()).unwrap();
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
    let (keys, old_keys, index_keys) = (acme_keys(), unscoped_keys(), acme_index_keys());
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
fn probes_across_cover_the_old_and_the_new_index_declarations() {
    let acme = tenant(b"acme");
    let probes = probes_across::<(), EmailLookup>(
        "ada@example.com",
        &acme,
        &acme_index_keys(),
        &unscoped_index_keys(),
    )
    .unwrap();
    let new = EmailLookup::probes_with("ada@example.com", &acme, &acme_index_keys()).unwrap();
    let old =
        UnscopedEmailLookup::probes_with("ada@example.com", &(), &unscoped_index_keys()).unwrap();

    let probes: Vec<_> = probes
        .iter()
        .map(|probe| probe.as_bytes().to_vec())
        .collect();
    let expected: Vec<_> = new
        .iter()
        .map(|probe| probe.as_bytes().to_vec())
        .chain(old.iter().map(|probe| probe.as_bytes().to_vec()))
        .collect();
    assert_eq!(probes, expected);
}

#[test]
fn a_probe_both_index_declarations_share_is_returned_once() {
    // Adding a record leaves the index binding unchanged.
    let acme = tenant(b"acme");
    let probes = probes_across::<Tenant, EmailLookup>(
        "ada@example.com",
        &acme,
        &acme_index_keys(),
        &acme_index_keys(),
    )
    .unwrap();

    assert_eq!(
        probes,
        EmailLookup::probes_with("ada@example.com", &acme, &acme_index_keys()).unwrap()
    );
}

#[test]
fn open_across_reports_a_value_of_neither_declaration_as_a_binding_mismatch() {
    let keys = acme_keys();
    let sealed =
        Sealed::<TenantEmail>::seal(&"ada@example.com".into(), &tenant(b"acme"), &keys).unwrap();
    let sealed = Sealed::<CustomerEmail>::from_bytes(sealed.into_bytes()).unwrap();

    assert_eq!(
        open_across::<(), _>(&sealed, (&tenant(b"acme"), &7_i64), &keys, &unscoped_keys(),)
            .unwrap_err(),
        Error::BindingMismatch
    );
}

/// A tenant plus a bound-only workspace: [`Tenant`]'s part, and one more.
#[derive(Clone, Hash, PartialEq, Eq)]
struct TenantWorkspace {
    tenant: Vec<u8>,
    workspace: i64,
}

impl cryptbox::Scope for TenantWorkspace {
    const PARTS: &'static [cryptbox::PartSpec] = &[
        // The part ID of `Tenant`.
        cryptbox::PartSpec::new(
            cryptbox::part_id!("1e8306bf-3135-4570-831c-6732f92550e9"),
            cryptbox::PartKind::Bytes,
        ),
        cryptbox::PartSpec::new(
            cryptbox::part_id!("8d000000-0000-4000-8000-00000000000d"),
            cryptbox::PartKind::I64,
        ),
    ];
    fn values(&self) -> cryptbox::PartValues<'_> {
        cryptbox::PartValues::from([
            cryptbox::PartValue::Bytes(&self.tenant),
            cryptbox::PartValue::I64(self.workspace),
        ])
    }
}

/// The seal after a workspace part is added to a binding that already binds a record.
struct WorkspaceEmail;

impl Seal for WorkspaceEmail {
    const ID: cryptbox::SealId = CustomerEmail::ID;
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Scope = Recorded<TenantWorkspace, i64>;
    type Indexes = ();
}

#[test]
fn a_legacy_binding_keeps_the_record_its_rows_were_sealed_with() {
    let keys = acme_keys();
    let row = row(b"acme", 7);
    let (ciphertext, _) = seal_current(&row, "ada@example.com");
    let planner = RowPlanner::<WorkspaceEmail, Columns>::for_rows(&keys, |row| {
        let binding = TenantWorkspace {
            tenant: row.tenant.clone(),
            workspace: 3,
        };
        Ok(RowArgs::new(binding).with_record(RecordId::from(row.id)))
    })
    .legacy_binding::<Recorded<Tenant, i64>>(&keys);

    assert_eq!(
        planner.classify_row(&row, &ciphertext, &[]).unwrap(),
        RowState::LegacyBinding
    );
    let write = planner
        .plan_row(&row, &ciphertext, &[])
        .unwrap()
        .into_write()
        .unwrap();
    let binding = TenantWorkspace {
        tenant: b"acme".to_vec(),
        workspace: 3,
    };
    let sealed = Sealed::<WorkspaceEmail>::from_bytes(write.ciphertext()).unwrap();
    assert_eq!(
        sealed.open((&binding, &7_i64), &keys).unwrap(),
        "ada@example.com"
    );

    let old = Sealed::<WorkspaceEmail>::from_bytes(ciphertext).unwrap();
    assert_eq!(
        open_across::<Recorded<Tenant, i64>, _>(&old, (&binding, &7_i64), &keys, &keys).unwrap(),
        "ada@example.com"
    );
    assert_eq!(
        open_across::<Recorded<Tenant, i64>, _>(&old, (&binding, &8_i64), &keys, &keys)
            .unwrap_err(),
        Error::AuthenticationFailed
    );
}
