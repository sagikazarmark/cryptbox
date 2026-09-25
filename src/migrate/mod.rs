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
//! Reads are permissive; writes never are. [`MaybeEncrypted`] implements no
//! storage `Encode`, and its only forward path is an [`Encrypted`] value,
//! which always encrypts. Once verification passes, remove `MaybeEncrypted`
//! usages, delete the legacy handler, and disable the `migrate` feature. Only
//! then consider online historical-key removal following the [maintenance sweep
//! guide]. A clean live-data pass says nothing about keys needed by backups or
//! other stores. Retain historical and legacy recovery keys separately; destroy
//! them only when all dependent artifacts and retention requirements permit it.
//!
//! These guide links describe the 0.5.0 release archive. Later documentation
//! improvements are available through the crate's development task index.
//!
//! [maintenance sweep guide]: https://docs.rs/crate/cryptbox/0.5.0/source/docs/reencryption-sweep.md
//! [legacy migration guide]: https://docs.rs/crate/cryptbox/0.5.0/source/docs/legacy-migration.md
//! [`Encrypted`]: crate::Encrypted

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
pub use read::MaybeEncrypted;
pub use report::SweepReport;
pub use row::{RowOutcome, RowPlanner, RowState, RowWrite};
#[cfg(feature = "sqlx-postgres")]
pub use sqlx_postgres::PostgresSweepStore;
#[cfg(feature = "sqlx-sqlite")]
pub use sqlx_sqlite::SqliteSweepStore;
pub use sweep::{BatchOutcome, Sweep, SweepError, SweepRow, SweepStore};
#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
pub use table::SweepTable;
