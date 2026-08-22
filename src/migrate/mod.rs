//! Explicit migration facility for adopting encryption over existing data.
//!
//! Everything in this module is intended for a bounded migration window and
//! deliberately kept out of the crate root. The steady-state decoding path
//! stays strict: plaintext or invalid envelopes fail to decode. During the
//! window, [`MaybeEncrypted`] reads columns that may still hold legacy
//! plaintext, and [`Sweep`] drives the batched rewrite documented in the
//! [maintenance sweep guide] until a verification pass reports a terminal
//! state through [`SweepReport::is_terminal`].
//!
//! Reads are permissive; writes never are. [`MaybeEncrypted`] implements no
//! storage `Encode`, and its only forward path is an [`Encrypted`] value,
//! which always encrypts. Once verification passes, remove `MaybeEncrypted`
//! usages and disable the `migrate` feature; only then retire historical keys
//! following the sweep guide.
//!
//! [maintenance sweep guide]: https://docs.rs/crate/cryptbox/latest/source/docs/reencryption-sweep.md
//! [`Encrypted`]: crate::Encrypted

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
