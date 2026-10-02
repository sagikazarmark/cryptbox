use super::RowState;

/// Row tallies from one sweep or verification pass.
///
/// Counts are metadata only and never contain plaintext or key material.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct SweepReport {
    /// Rows whose envelope and blind indexes structurally parse and name current generations.
    /// This does not establish authenticity or index consistency.
    pub current: u64,
    /// Rows rewritten from (or, during verification, still naming) a
    /// historical generation.
    pub stale: u64,
    /// Rows encrypted from (or still holding) legacy data.
    #[doc(alias = "plaintext")]
    pub legacy: u64,
    /// Rows that could not be classified during verification.
    pub malformed: u64,
    /// Rewrites lost to a concurrent writer; always zero for verification.
    pub conflicts: u64,
}

impl SweepReport {
    pub(crate) const fn record(&mut self, state: RowState) {
        match state {
            RowState::Current => self.current += 1,
            RowState::Stale => self.stale += 1,
            RowState::Legacy => self.legacy += 1,
        }
    }

    /// Accumulates another batch's or pass's tallies into this report.
    ///
    /// Orchestrators driving single-batch execution sum per-batch reports
    /// with this. Under replay by an at-least-once runtime, summed tallies
    /// may overcount (a replayed rewrite loses its compare-and-swap and
    /// counts as a conflict); reports are advisory and a verification pass
    /// remains the authoritative terminal-state check.
    pub const fn merge(&mut self, other: Self) {
        self.current += other.current;
        self.stale += other.stale;
        self.legacy += other.legacy;
        self.malformed += other.malformed;
        self.conflicts += other.conflicts;
    }

    /// Returns whether the legacy, stale, and malformed counts are all zero.
    ///
    /// This predicate does not know whether a pass is complete: even an empty
    /// default report returns `true`, and conflicts are not considered. Use the
    /// result of a successful full [`super::Sweep::verify`] pass, or merge every
    /// verification batch from the start through exhaustion. A run report or
    /// partial verification report is insufficient to close permissive reads.
    /// Ensure every writer uses the target generations; if writes continue,
    /// repeat until one complete pass is clean.
    ///
    /// A terminal report establishes migration-state convergence for the rows
    /// observed, not authenticated readability, codec validity, or ciphertext/index
    /// consistency. Those require separate decryption and index recomputation.
    /// It says nothing about historical keys needed by backups or other stores.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.legacy == 0 && self.stale == 0 && self.malformed == 0
    }
}
