use std::{fmt, future::Future};

use zeroize::Zeroize;

use crate::{Error, Seal};

use super::{RowPlanner, RowWrite, SweepReport};

/// One loaded row: its cursor plus the exact bytes read from every migrated
/// column.
///
/// The stored bytes may be legacy data, including plaintext, so the buffers are
/// zeroized on drop and `Debug` prints lengths only.
#[non_exhaustive]
pub struct SweepRow<C, R = ()> {
    /// The row's unique, immutable cursor value.
    pub cursor: C,
    /// The columns the planner reads the row's record ID from; see
    /// [`RowPlanner::for_rows`].
    pub columns: R,
    /// The encrypted column's bytes exactly as read.
    pub ciphertext: Vec<u8>,
    /// Each blind-index column's bytes exactly as read, in the order the
    /// columns were registered with [`RowPlanner::with_index`].
    pub indexes: Vec<Vec<u8>>,
}

impl<C, R> SweepRow<C, R> {
    /// A row loaded from storage: its cursor, the columns its context is read
    /// from, and the bytes read from the encrypted column and from each
    /// blind-index column.
    #[must_use]
    pub const fn new(cursor: C, columns: R, ciphertext: Vec<u8>, indexes: Vec<Vec<u8>>) -> Self {
        Self {
            cursor,
            columns,
            ciphertext,
            indexes,
        }
    }
}

impl<C, R> Drop for SweepRow<C, R> {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
        for bytes in &mut self.indexes {
            bytes.zeroize();
        }
    }
}

impl<C: fmt::Debug, R> fmt::Debug for SweepRow<C, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SweepRow")
            .field("cursor", &self.cursor)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("indexes", &self.indexes.len())
            .finish_non_exhaustive()
    }
}

/// Storage operations the sweep driver requires.
///
/// Implementations must uphold the sweep guide's contract:
///
/// - [`Self::load_batch`] returns rows strictly after `after`, ordered
///   ascending by a unique, immutable, indexed cursor. Uniqueness is
///   load-bearing: paging resumes strictly after the checkpoint, so rows
///   sharing a cursor value with a batch boundary would be silently skipped
///   by both the sweep and verification.
/// - [`Self::update`] compares every byte in `row` in its predicate and
///   reports whether the row was written; zero matched rows means a
///   concurrent writer won.
/// - Checkpoints are durable outside the worker's memory.
pub trait SweepStore {
    /// The unique, immutable, indexed cursor rows are totally ordered by.
    type Cursor: Clone + Send + Sync;
    /// The columns each row carries for its context, such as its record ID;
    /// `()` for standalone values.
    type Columns: Send + Sync;
    /// The storage backend's error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Loads the durable checkpoint, absent when the sweep has not started.
    fn load_checkpoint(
        &mut self,
    ) -> impl Future<Output = Result<Option<Self::Cursor>, Self::Error>> + Send;

    /// Durably stores the checkpoint after a fully processed batch.
    fn save_checkpoint(
        &mut self,
        cursor: &Self::Cursor,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Loads up to `limit` rows strictly after `after` in cursor order.
    #[expect(
        clippy::type_complexity,
        reason = "a batch is a plain list of rows of this store"
    )]
    fn load_batch(
        &mut self,
        after: Option<&Self::Cursor>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<SweepRow<Self::Cursor, Self::Columns>>, Self::Error>> + Send;

    /// Applies one replacement with a compare-and-swap on every read byte.
    ///
    /// Returns `false` when zero rows matched because a concurrent writer
    /// changed the row first.
    fn update(
        &mut self,
        row: &SweepRow<Self::Cursor, Self::Columns>,
        replacement: &RowWrite,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}

/// An error that interrupted a sweep or verification pass.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SweepError<E>
where
    E: std::error::Error + 'static,
{
    /// A storage operation failed.
    #[error("sweep storage operation failed")]
    Store(#[source] E),
    /// A row could not be classified or rewritten. The durable checkpoint
    /// still names the last fully processed batch, so the offending row lies
    /// within one batch after it.
    #[error("sweep row rewrite failed")]
    Row(#[source] Error),
}

/// Drives a batched, resumable migration sweep over one column family.
///
/// [`Self::run`] resumes from the durable checkpoint and rewrites legacy and
/// stale rows; [`Self::verify`] is the read-only migration-state check, not an
/// authenticated-read or index-consistency check.
/// Both operate through a [`SweepStore`], keeping the driver independent of
/// any storage backend.
///
/// Rerunning is idempotent: current rows are skipped and every update compares
/// the originally read bytes. A rewrite replayed after a crash loses its
/// compare-and-swap and counts as a conflict, so run reports are advisory;
/// [`Self::verify`] remains the authoritative terminal-state check.
#[derive(Debug)]
pub struct Sweep<'a, F, R = ()>
where
    F: Seal,
{
    planner: RowPlanner<'a, F, R>,
    batch_size: usize,
}

impl<'a, F, R> Sweep<'a, F, R>
where
    F: Seal,
{
    /// Creates a driver over a configured row planner.
    #[must_use]
    pub const fn new(planner: RowPlanner<'a, F, R>) -> Self {
        Self {
            planner,
            batch_size: 100,
        }
    }

    /// Sets the batch size; values below one are treated as one.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.max(1);

        self
    }

    /// Resumes from the durable checkpoint and rewrites until exhausted,
    /// saving the checkpoint after every batch.
    ///
    /// Rows that lose their compare-and-swap to a concurrent writer are
    /// counted as conflicts and deliberately not retried: once every writer
    /// uses current keys, the newer value is already current, and
    /// [`Self::verify`] detects legacy or stale generations left behind.
    ///
    /// # Errors
    ///
    /// Returns a storage error, or stops at the first row that cannot be
    /// classified or rewritten so the operator can investigate; the durable
    /// checkpoint still names the last fully processed batch.
    pub async fn run<S: SweepStore<Columns = R>>(
        &self,
        store: &mut S,
    ) -> Result<SweepReport, SweepError<S::Error>> {
        let mut report = SweepReport::default();
        let mut cursor = store.load_checkpoint().await.map_err(SweepError::Store)?;

        while let Some(checkpoint) = self
            .process_batch(store, cursor.as_ref(), &mut report)
            .await?
        {
            store
                .save_checkpoint(&checkpoint)
                .await
                .map_err(SweepError::Store)?;
            cursor = Some(checkpoint);
        }

        Ok(report)
    }

    /// Performs a fresh, full, read-only pass from the start.
    ///
    /// The pass ignores the durable checkpoint, never writes, and counts
    /// unclassifiable rows as malformed instead of stopping, so the returned
    /// report is complete. Check [`SweepReport::is_terminal`] on the result.
    /// A storage or configuration error aborts the pass; no complete report is
    /// returned in that case.
    ///
    /// This uses [`RowPlanner::classify_row`]: ciphertext and index metadata
    /// remain unauthenticated. It does not decrypt, validate decoded values,
    /// recompute indexes, or establish ciphertext/index consistency. Even a
    /// terminal report can contain ciphertext that fails authentication. For
    /// additional assurance, separately decrypt every value with its intended
    /// seal and recompute each index from that plaintext under the
    /// intended specification and allowed generation, comparing complete bytes.
    ///
    /// The pass observes rows as loaded, not a library-provided snapshot. Ensure
    /// all writers use the target generations and repeat a full pass as needed.
    /// Its scope is this store; retained backups and other stores may still need
    /// historical keys after live-data convergence.
    ///
    /// # Errors
    ///
    /// Returns a storage error or a configuration or environment failure, such
    /// as an index column arity mismatch or unavailable keys. Malformed rows are
    /// counted, not errors.
    pub async fn verify<S: SweepStore<Columns = R>>(
        &self,
        store: &mut S,
    ) -> Result<SweepReport, SweepError<S::Error>> {
        let mut report = SweepReport::default();
        let mut cursor: Option<S::Cursor> = None;

        while let Some(checkpoint) = self
            .verify_batch(store, cursor.as_ref(), &mut report)
            .await?
        {
            cursor = Some(checkpoint);
        }

        Ok(report)
    }

    /// Rewrites one batch strictly after `after` into `report`, and returns the
    /// cursor after it, or `None` when the scan is exhausted.
    async fn process_batch<S: SweepStore<Columns = R>>(
        &self,
        store: &mut S,
        after: Option<&S::Cursor>,
        report: &mut SweepReport,
    ) -> Result<Option<S::Cursor>, SweepError<S::Error>> {
        let rows = store
            .load_batch(after, self.batch_size)
            .await
            .map_err(SweepError::Store)?;

        for row in &rows {
            let indexes: Vec<&[u8]> = row.indexes.iter().map(Vec::as_slice).collect();
            let outcome = self
                .planner
                .plan_row(&row.columns, &row.ciphertext, &indexes)
                .map_err(SweepError::Row)?;

            match outcome.write() {
                None => report.record(outcome.state()),
                Some(replacement) => {
                    if store
                        .update(row, replacement)
                        .await
                        .map_err(SweepError::Store)?
                    {
                        report.record(outcome.state());
                    } else {
                        report.conflicts += 1;
                    }
                }
            }
        }

        Ok(rows.last().map(|row| row.cursor.clone()))
    }

    /// Classifies one batch strictly after `after` into `report`, without
    /// writing, and returns the cursor after it, or `None` when the scan is
    /// exhausted.
    async fn verify_batch<S: SweepStore<Columns = R>>(
        &self,
        store: &mut S,
        after: Option<&S::Cursor>,
        report: &mut SweepReport,
    ) -> Result<Option<S::Cursor>, SweepError<S::Error>> {
        let rows = store
            .load_batch(after, self.batch_size)
            .await
            .map_err(SweepError::Store)?;

        for row in &rows {
            let indexes: Vec<&[u8]> = row.indexes.iter().map(Vec::as_slice).collect();
            match self
                .planner
                .classify_row(&row.columns, &row.ciphertext, &indexes)
            {
                Ok(state) => report.record(state),
                Err(error) if is_row_data_failure(&error) => report.malformed += 1,
                Err(error) => return Err(SweepError::Row(error)),
            }
        }

        Ok(rows.last().map(|row| row.cursor.clone()))
    }
}

/// Reports whether `error` describes one row's stored bytes, rather than the
/// configuration or environment.
///
/// Verification counts row data failures as malformed and aborts on everything
/// else, since a misconfigured pass would misreport every row. The match is
/// exhaustive so that a new error variant must be classified here.
const fn is_row_data_failure(error: &Error) -> bool {
    match error {
        Error::NotCiphertext
        | Error::InvalidEnvelope
        | Error::UnsupportedFormatVersion(_)
        | Error::UnsupportedSuite(_)
        | Error::UnsupportedFlags(_)
        | Error::UnknownEncryptionKey(_)
        | Error::UnknownBlindIndexKey(_)
        | Error::AuthenticationFailed
        | Error::ContextMismatch
        | Error::CodecFailed(_)
        | Error::BlindIndexNormalizationFailed(_)
        | Error::MessageTooLong
        | Error::PaddingOverflow
        | Error::InvalidPadding
        | Error::InvalidBlindIndex
        | Error::UnsupportedBlindIndexVersion(_)
        | Error::UnexpectedRecord
        | Error::LegacyRecoveryFailed(_) => true,
        Error::BlindIndexKeysNotConfigured
        | Error::DuplicateEncryptionKey(_)
        | Error::DuplicateBlindIndexKey(_)
        | Error::RandomnessUnavailable
        | Error::InvalidKeyEncoding
        | Error::Internal
        | Error::IndexColumnMismatch { .. } => false,
    }
}
