use std::{fmt, future::Future};

use zeroize::Zeroize;

use crate::{EncryptionProfile, Error};

use super::{RowPlanner, RowState, RowWrite, SweepReport};

/// One loaded row: its cursor plus the exact bytes read from every migrated
/// column.
///
/// The stored bytes may be legacy plaintext, so the buffers are zeroized on
/// drop and `Debug` prints lengths only.
pub struct SweepRow<C> {
    /// The row's unique, immutable cursor value.
    pub cursor: C,
    /// The encrypted column's bytes exactly as read.
    pub ciphertext: Vec<u8>,
    /// Each blind-index column's bytes exactly as read, in the order the
    /// columns were registered with [`RowPlanner::with_index_with`].
    pub indexes: Vec<Vec<u8>>,
}

impl<C> Drop for SweepRow<C> {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
        for bytes in &mut self.indexes {
            bytes.zeroize();
        }
    }
}

impl<C: fmt::Debug> fmt::Debug for SweepRow<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SweepRow")
            .field("cursor", &self.cursor)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("indexes", &self.indexes.len())
            .finish()
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
    fn load_batch(
        &mut self,
        after: Option<&Self::Cursor>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<SweepRow<Self::Cursor>>, Self::Error>> + Send;

    /// Applies one replacement with a compare-and-swap on every read byte.
    ///
    /// Returns `false` when zero rows matched because a concurrent writer
    /// changed the row first.
    fn update(
        &mut self,
        row: &SweepRow<Self::Cursor>,
        replacement: &RowWrite,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}

/// An error that interrupted a sweep or verification pass.
#[derive(Debug, thiserror::Error)]
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
/// [`Self::run`] resumes from the durable checkpoint and rewrites plaintext
/// and stale rows; [`Self::verify`] is the read-only terminal-state check.
/// Both operate through a [`SweepStore`], keeping the driver independent of
/// any storage backend.
///
/// Both are thin loops over single-batch primitives, so external
/// orchestrators — a scheduler tick, a queue consumer, or a durable-execution
/// runtime — can drive the sweep one batch at a time instead:
///
/// - [`Self::run_batch`] and [`Self::verify_batch`] page with the store's
///   durable checkpoint (run) or a caller-held cursor (verify);
/// - [`Self::process_batch`] performs no checkpoint IO at all, taking and
///   returning the cursor so the orchestrator owns progress durability.
///
/// Batch replay is idempotent: current rows are skipped and every update
/// compares the originally read bytes, so stepped execution composes with
/// at-least-once runtimes. Replayed rewrites lose their compare-and-swap and
/// surface as conflicts, which makes summed per-batch reports advisory;
/// [`Self::verify`] remains the authoritative terminal-state check.
#[derive(Debug)]
pub struct Sweep<'a, T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    planner: RowPlanner<'a, T, Profile>,
    batch_size: usize,
}

impl<'a, T, Profile> Sweep<'a, T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    /// Creates a driver over a configured row planner.
    #[must_use]
    pub const fn new(planner: RowPlanner<'a, T, Profile>) -> Self {
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

    /// Rewrites one batch strictly after `after`, without checkpoint IO.
    ///
    /// The caller owns progress durability: a durable-execution runtime or
    /// scheduler journals the returned checkpoint itself and passes it back
    /// as `after` for the next step. Replaying a batch is safe.
    ///
    /// Rows that lose their compare-and-swap to a concurrent writer are
    /// counted as conflicts and deliberately not retried: once every writer
    /// uses current keys, the newer value is already current, and
    /// [`Self::verify`] catches anything a misconfigured writer left behind.
    ///
    /// # Errors
    ///
    /// Returns a storage error, or stops at the first row that cannot be
    /// classified or rewritten so the operator can investigate; the batch is
    /// then not checkpointed, so the row lies within one batch after `after`.
    pub async fn process_batch<S: SweepStore>(
        &self,
        store: &mut S,
        after: Option<&S::Cursor>,
    ) -> Result<BatchOutcome<S::Cursor>, SweepError<S::Error>> {
        let mut report = SweepReport::default();
        let rows = store
            .load_batch(after, self.batch_size)
            .await
            .map_err(SweepError::Store)?;
        let Some(last) = rows.last() else {
            return Ok(BatchOutcome {
                report,
                checkpoint: None,
            });
        };
        let checkpoint = last.cursor.clone();

        for row in &rows {
            let indexes: Vec<&[u8]> = row.indexes.iter().map(Vec::as_slice).collect();
            let outcome = self
                .planner
                .plan_row(&row.ciphertext, &indexes)
                .map_err(SweepError::Row)?;

            match outcome.write() {
                None => report.record(RowState::Current),
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

        Ok(BatchOutcome {
            report,
            checkpoint: Some(checkpoint),
        })
    }

    /// Rewrites one batch using the store's durable checkpoint.
    ///
    /// Loads the checkpoint, processes the next batch, and saves the new
    /// checkpoint when the batch was non-empty. Suited to externally
    /// scheduled steps — a cron tick or queue consumer — that rely on the
    /// store for progress durability. A returned checkpoint of `None` means
    /// the scan is exhausted.
    ///
    /// # Errors
    ///
    /// Fails under the same conditions as [`Self::process_batch`], plus
    /// checkpoint load and save failures.
    pub async fn run_batch<S: SweepStore>(
        &self,
        store: &mut S,
    ) -> Result<BatchOutcome<S::Cursor>, SweepError<S::Error>> {
        let after = store.load_checkpoint().await.map_err(SweepError::Store)?;
        let outcome = self.process_batch(store, after.as_ref()).await?;

        if let Some(checkpoint) = &outcome.checkpoint {
            store
                .save_checkpoint(checkpoint)
                .await
                .map_err(SweepError::Store)?;
        }

        Ok(outcome)
    }

    /// Resumes from the durable checkpoint and rewrites until exhausted.
    ///
    /// Equivalent to looping [`Self::process_batch`] with per-batch
    /// checkpoint saves until the scan is exhausted.
    ///
    /// # Errors
    ///
    /// Returns a storage error, or stops at the first row that cannot be
    /// classified or rewritten so the operator can investigate; the durable
    /// checkpoint still names the last fully processed batch.
    pub async fn run<S: SweepStore>(
        &self,
        store: &mut S,
    ) -> Result<SweepReport, SweepError<S::Error>> {
        let mut report = SweepReport::default();
        let mut cursor = store.load_checkpoint().await.map_err(SweepError::Store)?;

        loop {
            let outcome = self.process_batch(store, cursor.as_ref()).await?;
            report.merge(outcome.report);
            let Some(checkpoint) = outcome.checkpoint else {
                return Ok(report);
            };

            store
                .save_checkpoint(&checkpoint)
                .await
                .map_err(SweepError::Store)?;
            cursor = Some(checkpoint);
        }
    }

    /// Classifies one batch strictly after `after`, without writing.
    ///
    /// The read-only counterpart of [`Self::process_batch`] for stepped
    /// verification: the caller holds the cursor between steps and sums the
    /// per-batch reports with [`SweepReport::merge`].
    ///
    /// # Errors
    ///
    /// Returns a storage error, an index column arity mismatch, or an
    /// unavailable key provider. Malformed rows are counted, not errors.
    pub async fn verify_batch<S: SweepStore>(
        &self,
        store: &mut S,
        after: Option<&S::Cursor>,
    ) -> Result<BatchOutcome<S::Cursor>, SweepError<S::Error>> {
        let mut report = SweepReport::default();
        let rows = store
            .load_batch(after, self.batch_size)
            .await
            .map_err(SweepError::Store)?;
        let Some(last) = rows.last() else {
            return Ok(BatchOutcome {
                report,
                checkpoint: None,
            });
        };
        let checkpoint = last.cursor.clone();

        for row in &rows {
            let indexes: Vec<&[u8]> = row.indexes.iter().map(Vec::as_slice).collect();
            match self.planner.classify_row(&row.ciphertext, &indexes) {
                Ok(state) => report.record(state),
                // Configuration and environment failures abort the pass;
                // only per-row data failures count as malformed.
                Err(
                    error @ (Error::IndexColumnMismatch { .. }
                    | Error::KeyProviderUnavailable
                    | Error::KeyProviderNotInitialized),
                ) => return Err(SweepError::Row(error)),
                Err(_) => report.malformed += 1,
            }
        }

        Ok(BatchOutcome {
            report,
            checkpoint: Some(checkpoint),
        })
    }

    /// Performs a fresh, full, read-only pass from the start.
    ///
    /// The pass ignores the durable checkpoint, never writes, and counts
    /// unclassifiable rows as malformed instead of stopping, so the returned
    /// report is complete. Check [`SweepReport::is_terminal`] on the result.
    ///
    /// # Errors
    ///
    /// Fails under the same conditions as [`Self::verify_batch`].
    pub async fn verify<S: SweepStore>(
        &self,
        store: &mut S,
    ) -> Result<SweepReport, SweepError<S::Error>> {
        let mut report = SweepReport::default();
        let mut cursor: Option<S::Cursor> = None;

        loop {
            let outcome = self.verify_batch(store, cursor.as_ref()).await?;
            report.merge(outcome.report);
            match outcome.checkpoint {
                Some(next) => cursor = Some(next),
                None => return Ok(report),
            }
        }
    }
}

/// The result of processing or verifying one batch.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BatchOutcome<C> {
    /// Tallies for this batch only; sum across batches with
    /// [`SweepReport::merge`].
    pub report: SweepReport,
    /// The cursor after this batch, to pass as `after` for the next step.
    /// `None` means the scan is exhausted.
    pub checkpoint: Option<C>,
}
