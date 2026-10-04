//! Rewriting stored values: adopting encryption over existing data, and
//! maintenance sweeps.
//!
//! Available with the `migrate` feature. Packaged `SQLx` stores additionally
//! require their backend feature; see each store's availability documentation.
//!
//! [`Sweep`] rewrites stored values in bounded, resumable batches, for two jobs:
//!
//! - **Maintenance** moves values to the current key generation, format, and
//!   padding policy, for as long as keys rotate; see the [maintenance sweep
//!   guide].
//! - **Adoption** is a bounded migration window over columns that may still
//!   hold plaintext or data encrypted by a previous solution. [`MaybeSealed`]
//!   reads them, [`LegacyFormat`] recovers that data, and the sweep drives the
//!   rewrite documented in the [legacy migration guide] until a verification
//!   pass reports a terminal state through [`SweepReport::is_terminal`].
//!
//! The module is deliberately kept out of the crate root. The steady-state
//! decoding path stays strict: legacy data or invalid envelopes fail to decode.
//! A successful full pass checks structure and generation convergence only, not
//! authenticated readability, decoded-value validity, or index consistency.
//! Obtain those assurances with separate decryption and index recomputation.
//!
//! A record's fields are sealed under each row's record ID, which
//! [`RowPlanner::for_rows`] reads from the row's columns.
//!
//! Reads are permissive; writes never are. [`MaybeSealed`] implements no
//! storage `Encode`, and its only forward path is the opened value, which
//! must be sealed again with [`Sealed::seal`]. Once verification passes, remove
//! `MaybeSealed` usages and delete the legacy handler; keep the `migrate`
//! feature only if you run maintenance sweeps. Only then consider online
//! historical-key removal following the [maintenance sweep guide]. A clean
//! live-data pass says nothing about keys needed by backups or other stores.
//! Retain historical and legacy recovery keys
//! separately; destroy them only when all dependent artifacts and retention
//! requirements permit it.
//!
#![doc = concat!(
    "[maintenance sweep guide]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/docs/operations.md#maintenance-sweeps\n",
    "[legacy migration guide]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/docs/operations.md#legacy-migration",
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

pub use legacy::{LegacyError, LegacyErrorKind, LegacyFormat};
pub use read::MaybeSealed;
pub use report::SweepReport;
pub use row::{RowOutcome, RowPlanner, RowState, RowWrite};
#[cfg(feature = "sqlx-postgres")]
pub use sqlx_postgres::PostgresSweepStore;
#[cfg(feature = "sqlx-sqlite")]
pub use sqlx_sqlite::SqliteSweepStore;
pub use sweep::{Sweep, SweepError, SweepRow, SweepStore};
#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
pub use table::SweepTable;
