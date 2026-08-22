//! Public-boundary tests for the explicit migration facility.

#![cfg(feature = "migrate")]

use std::{
    convert::Infallible,
    future::{Future, ready},
};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Ciphertext, Encrypted,
    EncryptionKey, EncryptionProfile, Error, Field, FieldBound, GlobalKeyContext, IndexId,
    IndexKeyId, KeyId, LocalBlindIndexKeyring, LocalEncryptionKeyring, Utf8, derive_blind_index,
    field_id, index_id, index_key_id, inspect_blind_index, inspect_ciphertext, key_id,
    migrate::{
        MaybeEncrypted, RowPlanner, RowState, Sweep, SweepError, SweepReport, SweepRow, SweepStore,
    },
};
use zeroize::Zeroizing;

const OLD_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const CURRENT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");
const OLD_INDEX_KEY_ID: IndexKeyId = index_key_id!("30000000-0000-4000-8000-000000000003");
const CURRENT_INDEX_KEY_ID: IndexKeyId = index_key_id!("40000000-0000-4000-8000-000000000004");

struct UserEmail;

impl Field for UserEmail {
    const ID: cryptbox::FieldId = field_id!("50000000-0000-4000-8000-000000000005");
    const NAME: &'static str = "user-email";
}

impl EncryptionProfile<String> for UserEmail {
    type Binding = FieldBound<Self>;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
}

struct EmailLookup;

impl BlindIndexMetadata for EmailLookup {
    const ID: IndexId = index_id!("60000000-0000-4000-8000-000000000006");
    const BITS: usize = 128;
}

impl BlindIndexSpec<String> for EmailLookup {
    fn normalize(input: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(
            input.trim().to_ascii_lowercase().into_bytes(),
        ))
    }
}

fn old_keys() -> LocalEncryptionKeyring {
    LocalEncryptionKeyring::new(EncryptionKey::new(OLD_KEY_ID, [0x11; 32]), []).unwrap()
}

fn rotated_keys() -> LocalEncryptionKeyring {
    LocalEncryptionKeyring::new(
        EncryptionKey::new(CURRENT_KEY_ID, [0x22; 32]),
        [EncryptionKey::new(OLD_KEY_ID, [0x11; 32])],
    )
    .unwrap()
}

fn old_index_keys() -> LocalBlindIndexKeyring {
    LocalBlindIndexKeyring::new(BlindIndexKey::new(OLD_INDEX_KEY_ID, [0x33; 32]), []).unwrap()
}

fn rotated_index_keys() -> LocalBlindIndexKeyring {
    LocalBlindIndexKeyring::new(
        BlindIndexKey::new(CURRENT_INDEX_KEY_ID, [0x44; 32]),
        [BlindIndexKey::new(OLD_INDEX_KEY_ID, [0x33; 32])],
    )
    .unwrap()
}

fn encrypt_email(email: &str, keys: &LocalEncryptionKeyring) -> Vec<u8> {
    Encrypted::<_, UserEmail>::new(email.to_owned())
        .encrypt_with(&(), keys)
        .unwrap()
        .into_bytes()
}

fn derive_email_index(email: &str, index_keys: &LocalBlindIndexKeyring) -> Vec<u8> {
    derive_blind_index::<EmailLookup, String, FieldBound<UserEmail>>(
        &email.to_owned(),
        &(),
        index_keys,
    )
    .unwrap()
    .into_bytes()
}

#[test]
fn classification_accepts_valid_envelopes() {
    let keys = rotated_keys();
    let bytes = encrypt_email("mark@example.com", &keys);

    let read = MaybeEncrypted::<String, UserEmail>::from_bytes(bytes).unwrap();
    assert!(!read.is_plaintext());
    assert!(read.as_ciphertext().is_some());
    assert_eq!(
        read.decrypt_with(&(), &keys).unwrap().expose_secret(),
        "mark@example.com"
    );
}

#[test]
fn classification_treats_bytes_without_magic_as_legacy_plaintext() {
    let read =
        MaybeEncrypted::<String, UserEmail>::from_bytes(b"mark@example.com".to_vec()).unwrap();
    assert!(read.is_plaintext());
    assert!(read.as_ciphertext().is_none());

    // A legacy plaintext read never touches key providers, including the
    // uninstalled process-global context selected by the profile.
    assert_eq!(read.decrypt().unwrap().expose_secret(), "mark@example.com");
}

#[test]
fn classification_treats_empty_bytes_as_legacy_plaintext() {
    let read = MaybeEncrypted::<String, UserEmail>::from_bytes(Vec::new()).unwrap();
    assert!(read.is_plaintext());
    assert_eq!(read.decrypt().unwrap().expose_secret(), "");
}

#[test]
fn classification_fails_on_plaintext_the_codec_rejects() {
    assert_eq!(
        MaybeEncrypted::<String, UserEmail>::from_bytes(vec![0xFF, 0xFE]).unwrap_err(),
        Error::CodecFailed(cryptbox::CodecError::new(
            cryptbox::CodecErrorKind::InvalidUtf8
        )),
    );
}

#[test]
fn magic_prefixed_garbage_is_a_hard_error_not_plaintext() {
    assert_eq!(
        MaybeEncrypted::<String, UserEmail>::from_bytes(b"CBX\0garbage".to_vec()).unwrap_err(),
        Error::InvalidEnvelope,
    );
}

#[test]
fn unsupported_format_version_is_a_hard_error_not_plaintext() {
    let mut bytes = encrypt_email("mark@example.com", &rotated_keys());
    bytes[4] = 9;

    assert_eq!(
        MaybeEncrypted::<String, UserEmail>::from_bytes(bytes).unwrap_err(),
        Error::UnsupportedFormatVersion(9),
    );
}

#[test]
fn out_of_band_constructors_bypass_byte_classification() {
    let keys = rotated_keys();
    let read = MaybeEncrypted::from_plaintext(Encrypted::<String, UserEmail>::new(
        "CBX\0-prefixed legacy value".to_owned(),
    ));
    assert!(read.is_plaintext());

    let ciphertext =
        Ciphertext::<String, UserEmail>::from_bytes(encrypt_email("mark@example.com", &keys))
            .unwrap();
    let read = MaybeEncrypted::from(ciphertext);
    assert!(!read.is_plaintext());
}

#[test]
fn planner_skips_current_rows_without_writes() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let ciphertext = encrypt_email("mark@example.com", &keys);
    let index = derive_email_index("mark@example.com", &index_keys);
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);

    assert_eq!(
        planner.classify_row(&ciphertext, &[&index]).unwrap(),
        RowState::Current
    );
    let outcome = planner.plan_row(&ciphertext, &[&index]).unwrap();
    assert_eq!(outcome.state(), RowState::Current);
    assert!(outcome.into_write().is_none());
}

#[test]
fn planner_reencrypts_stale_envelopes_and_keeps_current_index_bytes() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let ciphertext = encrypt_email("mark@example.com", &old_keys());
    let index = derive_email_index("mark@example.com", &index_keys);
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);

    assert_eq!(
        planner.classify_row(&ciphertext, &[&index]).unwrap(),
        RowState::Stale
    );
    let outcome = planner.plan_row(&ciphertext, &[&index]).unwrap();
    assert_eq!(outcome.state(), RowState::Stale);
    let write = outcome.into_write().unwrap();
    assert_eq!(
        inspect_ciphertext(write.ciphertext()).unwrap().key_id(),
        CURRENT_KEY_ID
    );
    assert_eq!(
        Ciphertext::<String, UserEmail>::from_bytes(write.ciphertext().to_vec())
            .unwrap()
            .decrypt_with(&(), &keys)
            .unwrap()
            .expose_secret(),
        "mark@example.com"
    );
    assert_eq!(write.indexes(), &[index]);
}

#[test]
fn planner_rederives_stale_indexes_from_the_authoritative_ciphertext() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let ciphertext = encrypt_email("mark@example.com", &keys);
    let index = derive_email_index("mark@example.com", &old_index_keys());
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);

    let outcome = planner.plan_row(&ciphertext, &[&index]).unwrap();
    assert_eq!(outcome.state(), RowState::Stale);
    let write = outcome.into_write().unwrap();
    // A current envelope is kept byte-identical: no fresh nonce is consumed.
    assert_eq!(write.ciphertext(), ciphertext.as_slice());
    assert_eq!(
        write.indexes(),
        &[derive_email_index("mark@example.com", &index_keys)]
    );
    assert_eq!(
        inspect_blind_index(&write.indexes()[0])
            .unwrap()
            .index_key_id(),
        CURRENT_INDEX_KEY_ID
    );
}

#[test]
fn planner_encrypts_legacy_plaintext_and_derives_every_index() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);

    let placeholder: &[u8] = &[];
    let outcome = planner
        .plan_row(b"mark@example.com", &[placeholder])
        .unwrap();
    assert_eq!(outcome.state(), RowState::Plaintext);
    let write = outcome.into_write().unwrap();
    assert_eq!(
        Ciphertext::<String, UserEmail>::from_bytes(write.ciphertext().to_vec())
            .unwrap()
            .decrypt_with(&(), &keys)
            .unwrap()
            .expose_secret(),
        "mark@example.com"
    );
    assert_eq!(
        write.indexes(),
        &[derive_email_index("mark@example.com", &index_keys)]
    );
}

#[test]
fn planner_propagates_malformed_index_bytes() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let ciphertext = encrypt_email("mark@example.com", &keys);
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);

    let malformed: &[u8] = b"not an index";
    assert_eq!(
        planner.classify_row(&ciphertext, &[malformed]).unwrap_err(),
        Error::InvalidBlindIndex
    );
    assert_eq!(
        planner.plan_row(&ciphertext, &[malformed]).unwrap_err(),
        Error::InvalidBlindIndex
    );
}

#[test]
fn planner_rejects_index_column_arity_mismatch() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let ciphertext = encrypt_email("mark@example.com", &keys);
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);

    assert_eq!(
        planner.classify_row(&ciphertext, &[]).unwrap_err(),
        Error::IndexColumnMismatch {
            expected: 1,
            actual: 0
        },
    );
}

/// An in-memory [`SweepStore`] upholding the batch, compare-and-swap, and
/// durable-checkpoint contract.
struct MemoryStore {
    rows: Vec<(i64, Vec<u8>, Vec<Vec<u8>>)>,
    checkpoint: Option<i64>,
    update_calls: u64,
    checkpoint_saves: u64,
    /// Simulates a concurrent writer that rewrites this row (with a current
    /// envelope) between the sweep's read and its compare-and-swap update.
    concurrent_writer_on: Option<(i64, Vec<u8>, Vec<Vec<u8>>)>,
}

impl MemoryStore {
    fn new(rows: Vec<(i64, Vec<u8>, Vec<Vec<u8>>)>) -> Self {
        Self {
            rows,
            checkpoint: None,
            update_calls: 0,
            checkpoint_saves: 0,
            concurrent_writer_on: None,
        }
    }
}

impl SweepStore for MemoryStore {
    type Cursor = i64;
    type Error = Infallible;

    fn load_checkpoint(&mut self) -> impl Future<Output = Result<Option<i64>, Infallible>> + Send {
        ready(Ok(self.checkpoint))
    }

    fn save_checkpoint(
        &mut self,
        cursor: &i64,
    ) -> impl Future<Output = Result<(), Infallible>> + Send {
        self.checkpoint = Some(*cursor);
        self.checkpoint_saves += 1;
        ready(Ok(()))
    }

    fn load_batch(
        &mut self,
        after: Option<&i64>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<SweepRow<i64>>, Infallible>> + Send {
        let after = after.copied().unwrap_or(i64::MIN);
        ready(Ok(self
            .rows
            .iter()
            .filter(|(cursor, _, _)| *cursor > after)
            .take(limit)
            .map(|(cursor, ciphertext, indexes)| SweepRow {
                cursor: *cursor,
                ciphertext: ciphertext.clone(),
                indexes: indexes.clone(),
            })
            .collect()))
    }

    fn update(
        &mut self,
        row: &SweepRow<i64>,
        replacement: &cryptbox::migrate::RowWrite,
    ) -> impl Future<Output = Result<bool, Infallible>> + Send {
        self.update_calls += 1;

        if let Some((cursor, ciphertext, indexes)) = self.concurrent_writer_on.take() {
            let stored = self
                .rows
                .iter_mut()
                .find(|(stored, _, _)| *stored == cursor)
                .unwrap();
            stored.1 = ciphertext;
            stored.2 = indexes;
        }

        let stored = self
            .rows
            .iter_mut()
            .find(|(cursor, _, _)| *cursor == row.cursor)
            .unwrap();
        if stored.1 != row.ciphertext || stored.2 != row.indexes {
            return ready(Ok(false));
        }

        stored.1 = replacement.ciphertext().to_vec();
        stored.2 = replacement.indexes().to_vec();
        ready(Ok(true))
    }
}

fn mixed_rows() -> Vec<(i64, Vec<u8>, Vec<Vec<u8>>)> {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    vec![
        (1, b"first@example.com".to_vec(), vec![Vec::new()]),
        (2, b"second@example.com".to_vec(), vec![Vec::new()]),
        (
            3,
            encrypt_email("third@example.com", &old_keys()),
            vec![derive_email_index("third@example.com", &old_index_keys())],
        ),
        (
            4,
            encrypt_email("fourth@example.com", &keys),
            vec![derive_email_index("fourth@example.com", &index_keys)],
        ),
    ]
}

#[test]
fn sweep_migrates_plaintext_and_stale_rows_to_a_terminal_state() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);
    let sweep = Sweep::new(planner).with_batch_size(2);
    let mut store = MemoryStore::new(mixed_rows());

    let report = futures_executor::block_on(sweep.run(&mut store)).unwrap();
    assert_eq!(report.plaintext, 2);
    assert_eq!(report.stale, 1);
    assert_eq!(report.current, 1);
    assert_eq!(report.conflicts, 0);
    // One checkpoint per non-empty batch, saved only after the whole batch.
    assert_eq!(store.checkpoint_saves, 2);
    assert_eq!(store.checkpoint, Some(4));

    let report = futures_executor::block_on(sweep.verify(&mut store)).unwrap();
    assert!(report.is_terminal());
    assert_eq!(report.current, 4);
}

#[test]
fn sweep_replay_after_a_lost_checkpoint_is_idempotent() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);
    let sweep = Sweep::new(planner).with_batch_size(2);
    let mut store = MemoryStore::new(mixed_rows());

    futures_executor::block_on(sweep.run(&mut store)).unwrap();
    let migrated: Vec<_> = store.rows.clone();

    // A crashed worker replays from an older durable checkpoint. Every row is
    // already current, so replay rewrites nothing.
    store.checkpoint = None;
    let report = futures_executor::block_on(sweep.run(&mut store)).unwrap();
    assert_eq!(report.current, 4);
    assert_eq!(report.plaintext + report.stale + report.conflicts, 0);
    assert_eq!(store.rows, migrated);
}

#[test]
fn sweep_never_overwrites_a_concurrent_writer() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);
    let sweep = Sweep::new(planner).with_batch_size(2);
    let mut store = MemoryStore::new(mixed_rows());

    // While the sweep processes row 1, a writer stores a fresh current value.
    let newer_ciphertext = encrypt_email("renamed@example.com", &keys);
    let newer_index = derive_email_index("renamed@example.com", &index_keys);
    store.concurrent_writer_on = Some((1, newer_ciphertext.clone(), vec![newer_index.clone()]));

    let report = futures_executor::block_on(sweep.run(&mut store)).unwrap();
    assert_eq!(report.conflicts, 1);
    assert_eq!(report.plaintext, 1);
    assert_eq!(store.rows[0].1, newer_ciphertext);
    assert_eq!(store.rows[0].2, vec![newer_index]);
}

#[test]
fn sweep_run_stops_at_a_malformed_row_and_keeps_the_last_checkpoint() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);
    let sweep = Sweep::new(planner).with_batch_size(2);

    let mut rows = mixed_rows();
    rows[2].1 = b"CBX\0garbage".to_vec();
    let mut store = MemoryStore::new(rows);

    let error = futures_executor::block_on(sweep.run(&mut store)).unwrap_err();
    assert!(matches!(error, SweepError::Row(Error::InvalidEnvelope)));
    // The offending row lies within one batch after the durable checkpoint.
    assert_eq!(store.checkpoint, Some(2));

    let report = futures_executor::block_on(sweep.verify(&mut store)).unwrap();
    assert_eq!(report.malformed, 1);
    assert!(!report.is_terminal());
}

#[test]
fn verification_is_read_only_and_ignores_the_checkpoint() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);
    let sweep = Sweep::new(planner).with_batch_size(3);
    let mut store = MemoryStore::new(mixed_rows());
    store.checkpoint = Some(3);

    let report = futures_executor::block_on(sweep.verify(&mut store)).unwrap();
    // The pass covered every row despite the checkpoint and wrote nothing.
    assert_eq!(report.plaintext, 2);
    assert_eq!(report.stale, 1);
    assert_eq!(report.current, 1);
    assert_eq!(store.update_calls, 0);
    assert_eq!(store.checkpoint_saves, 0);
    assert_eq!(store.checkpoint, Some(3));
}

#[test]
fn stepped_run_batches_match_a_full_run() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);
    let sweep = Sweep::new(planner).with_batch_size(2);
    let mut store = MemoryStore::new(mixed_rows());

    // Each externally scheduled step processes exactly one batch and saves
    // the durable checkpoint; the None checkpoint signals exhaustion.
    let mut report = SweepReport::default();
    let mut steps = 0;
    loop {
        let outcome = futures_executor::block_on(sweep.run_batch(&mut store)).unwrap();
        report.merge(outcome.report);
        steps += 1;
        if outcome.checkpoint.is_none() {
            break;
        }
        assert_eq!(store.checkpoint, outcome.checkpoint);
    }

    assert_eq!(steps, 3);
    assert_eq!(store.checkpoint_saves, 2);
    assert_eq!(report.plaintext, 2);
    assert_eq!(report.stale, 1);
    assert_eq!(report.current, 1);
    assert_eq!(report.conflicts, 0);

    let verified = futures_executor::block_on(sweep.verify(&mut store)).unwrap();
    assert!(verified.is_terminal());
}

#[test]
fn orchestrator_owned_cursor_never_touches_store_checkpoints() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);
    let sweep = Sweep::new(planner).with_batch_size(2);
    let mut store = MemoryStore::new(mixed_rows());

    // A durable-execution runtime journals the cursor itself and passes it
    // back on the next step; the store's checkpoint stays untouched.
    let mut journaled_cursor: Option<i64> = None;
    let mut report = SweepReport::default();
    loop {
        let outcome =
            futures_executor::block_on(sweep.process_batch(&mut store, journaled_cursor.as_ref()))
                .unwrap();
        report.merge(outcome.report);
        match outcome.checkpoint {
            Some(next) => journaled_cursor = Some(next),
            None => break,
        }
    }

    assert_eq!(store.checkpoint_saves, 0);
    assert_eq!(store.checkpoint, None);
    assert_eq!(journaled_cursor, Some(4));
    assert_eq!(report.plaintext, 2);
    assert_eq!(report.stale, 1);
    assert_eq!(report.current, 1);

    let verified = futures_executor::block_on(sweep.verify(&mut store)).unwrap();
    assert!(verified.is_terminal());
}

#[test]
fn replaying_a_processed_batch_is_idempotent() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);
    let sweep = Sweep::new(planner).with_batch_size(2);
    let mut store = MemoryStore::new(mixed_rows());

    // An at-least-once runtime applied the side effect but crashed before
    // journaling the cursor, so the same step fires again.
    let first = futures_executor::block_on(sweep.process_batch(&mut store, None)).unwrap();
    assert_eq!(first.report.plaintext, 2);
    assert_eq!(first.checkpoint, Some(2));
    let rows_after_first: Vec<_> = store.rows.clone();

    let replay = futures_executor::block_on(sweep.process_batch(&mut store, None)).unwrap();
    assert_eq!(replay.checkpoint, Some(2));
    assert_eq!(replay.report.current, 2);
    assert_eq!(
        replay.report.plaintext + replay.report.stale + replay.report.conflicts,
        0
    );
    assert_eq!(store.rows, rows_after_first);
}

#[test]
fn stepped_verification_matches_a_full_pass() {
    let keys = rotated_keys();
    let index_keys = rotated_index_keys();
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);
    let sweep = Sweep::new(planner).with_batch_size(3);
    let mut store = MemoryStore::new(mixed_rows());

    let full = futures_executor::block_on(sweep.verify(&mut store)).unwrap();

    let mut cursor: Option<i64> = None;
    let mut stepped = SweepReport::default();
    loop {
        let outcome =
            futures_executor::block_on(sweep.verify_batch(&mut store, cursor.as_ref())).unwrap();
        stepped.merge(outcome.report);
        match outcome.checkpoint {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    assert_eq!(stepped, full);
    assert_eq!(store.update_calls, 0);
    assert_eq!(store.checkpoint_saves, 0);
}

#[test]
fn report_terminal_state_requires_zero_plaintext_stale_and_malformed() {
    let mut clean = SweepReport::default();
    clean.current = 10;
    clean.conflicts = 3;
    assert!(clean.is_terminal());

    let mut with_plaintext = clean;
    with_plaintext.plaintext = 1;
    let mut with_stale = clean;
    with_stale.stale = 1;
    let mut with_malformed = clean;
    with_malformed.malformed = 1;

    for dirty in [with_plaintext, with_stale, with_malformed] {
        assert!(!dirty.is_terminal());
    }
}
