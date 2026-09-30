//! Explicit migration facility for adopting encryption over existing data.
//!
//! Available with the `migrate` feature. Packaged `SQLx` stores additionally
//! require their backend feature; see each store's availability documentation.
//!
//! Everything in this module is intended for a bounded migration window and
//! deliberately kept out of the crate root. The steady-state decoding path
//! stays strict: legacy data or invalid envelopes fail to decode. During the
//! window, [`MaybeEncrypted`] reads columns that may still hold plaintext or
//! data encrypted by a previous solution. [`LegacyFormat`] recovers that data,
//! and [`Sweep`] drives the batched rewrite documented in the [legacy migration
//! guide] until a verification pass reports a terminal state through
//! [`SweepReport::is_terminal`].
//! A successful full pass checks structure and generation convergence only, not
//! authenticated readability, decoded-value validity, or index consistency.
//! Obtain those assurances with separate decryption and index recomputation.
//!
//! The same sweep changes a seal's binding declaration. [`RowPlanner::for_key_scope`]
//! builds each row's binding arguments from its columns for one key scope, and
//! [`RowPlanner::legacy_binding`] opens a legacy-binding window in which rows
//! sealed with the older declaration are resealed. Until verification counts none of
//! them, readers use [`probes_across`] and [`open_across`] to find and open
//! values of either declaration.
//!
//! Reads are permissive; writes never are. [`MaybeEncrypted`] implements no
//! storage `Encode`, and its only forward path is the opened value, which
//! must be sealed again with [`Sealed::seal`]. Once verification passes, remove
//! `MaybeEncrypted` usages, delete the legacy handler, and disable the `migrate`
//! feature. Only then consider online historical-key removal following the
//! [maintenance sweep guide]. A clean live-data pass says nothing about keys
//! needed by backups or other stores. Retain historical and legacy recovery keys
//! separately; destroy them only when all dependent artifacts and retention
//! requirements permit it.
//!
#![doc = concat!(
    "[maintenance sweep guide]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/reencryption-sweep.md\n",
    "[legacy migration guide]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/legacy-migration.md",
)]
//! [`Sealed::seal`]: crate::Sealed::seal

mod legacy;
mod read;
mod report;
mod row;
#[cfg(feature = "sqlx-postgres")]
mod sqlx_postgres;
#[cfg(feature = "sqlx-sqlite")]
mod sqlx_sqlite;
mod sweep;
#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
mod table;
mod window;

pub use legacy::{LegacyError, LegacyErrorKind, LegacyFormat};
pub use read::MaybeEncrypted;
pub use report::SweepReport;
pub use row::{RowArgs, RowOutcome, RowPlanner, RowState, RowWrite};
#[cfg(feature = "sqlx-postgres")]
pub use sqlx_postgres::PostgresSweepStore;
#[cfg(feature = "sqlx-sqlite")]
pub use sqlx_sqlite::SqliteSweepStore;
pub use sweep::{BatchOutcome, Sweep, SweepError, SweepRow, SweepStore};
#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
pub use table::SweepTable;
pub use window::{open_across, probes_across};
