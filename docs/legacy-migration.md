# Migrating Legacy Data To CryptBox

**How-to · CryptBox 0.5.0.** Adopt encryption over plaintext, previous-solution
ciphertext or mixed storage. [All tasks](README.md) · [Sweep operations](reencryption-sweep.md).

The `migrate` feature supplies explicit permissive reads, an application-owned
legacy handler and a resumable driver for a bounded migration window. Normal
`Encrypted`/`Ciphertext` decoding remains strict throughout. Plaintext migration
is the identity-recovery case; it follows the same rollout and closure gates.

## Preconditions

1. Inventory readers, writers, jobs, imports, replicas, rollback binaries and
   restore paths. Inventory legacy formats, trusted discriminators and provenance
   evidence. Add index columns and agree a missing-projection marker before writes change.
2. Provision stable, independently generated CryptBox encryption/index roots and
   required legacy access. Deploy compatible readers **before any encrypted write**:
   every instance must recover legacy formats, decrypt all relevant generations
   and support [transitional search](#transitional-search).
3. Promote every writer to atomic prepared ciphertext/index writes. During rollout,
   readers still handle new legacy writes. Fence old binaries/credentials and drain
   in-flight transactions before assuming a bounded legacy population.
4. Sweep with fixed targets, durable progress and one owner under the
   [sweep contract](reencryption-sweep.md#run-identity-and-progress-ownership).
   Retain compatible readers and required keys until closure.

This recipe uses non-NULL byte columns and an **empty byte string**, not SQL NULL,
for missing indexes. Nullable/filtered stores need an explicit custom policy;
see [packaged-store limits](reencryption-sweep.md#prepare-the-consumer).

### Coordinated maintenance cutover

Use a maintenance window if readers cannot coexist, old writers cannot be fenced,
fallback search is too expensive, provenance cannot be validated online, or read
consistency is insufficient. Stop traffic/readers and write/import/restore jobs,
drain transactions and capture a recoverable backup with schema and key dependencies.
Install the compatible build, repair and sweep, and complete all closure gates
before installing strict readers and reopening traffic. Any unresolved row blocks
cutover. Rollback requires a migrated-format-compatible build or a coordinated
full data restore while traffic remains stopped; a plaintext-only binary is no
longer compatible after encrypted writes.

## Recovering Legacy Values

Implement and explicitly inject `LegacyFormat`; its synchronous
`recover(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, LegacyError>` returns
plaintext bytes for the profile codec. Keep network recovery in a custom store
or prefetch stage. The handler owns zeroization of its keys/intermediates and
sanitized errors; CryptBox zeroizes the legacy/recovered buffers it owns, not
SQLx buffers, application clones, storage or backups. Protect quarantine copies
and log only approved row/run IDs and error categories.

CryptBox only distinguishes its envelopes from non-envelope bytes. Route foreign
formats using trusted inventory/discriminators and authenticated format headers;
allow identity recovery only for data authorized as plaintext. Never interpret
failed legacy authentication as plaintext. A permissive fallback can accept an
attacker's plausible replacement of an envelope, and syntax checks cannot prove
that replacement legitimate. Previous-solution AEAD also authenticates only its
own key/AAD policy; it may permit same-domain replay or substitution.

For unauthenticated legacy formats (including plaintext or CBC without a MAC),
require application validation and trusted out-of-band evidence for **every**
accepted value, or an explicitly approved disposition. Codec success is insufficient
(`Raw` rejects no bytes), and sampling cannot establish unsampled provenance.
Re-encryption protects recovered bytes going forward, not their historical origin.

## The Bounded Window

Read as `cryptbox::migrate::MaybeEncrypted<T, Profile>` only where legacy values
may still occur. `from_bytes` and SQLx `Decode` classify without accessing keys:

- Valid envelopes are retained structurally; explicit decryption authenticates
  them and ignores the legacy handler.
- Bytes without envelope magic are retained in a zeroizing buffer. `decrypt_with`
  uses plaintext identity recovery; `decrypt_with_legacy` invokes the handler
  before codec decoding. Codec errors are deferred until the decrypt call.
- Magic-bearing malformed/unsupported envelopes are hard errors, **never legacy
  fallback**. A structurally valid envelope's authentication failure is also final.

`MaybeEncrypted` has no storage `Encode` or Serde. Use `Encrypted`/`Prepared` for
new writes; other database clients still need fencing.

For legacy bytes colliding with `CBX\0`, a **trusted out-of-band discriminator**
may authorize `MaybeEncrypted::from_legacy_bytes`, which bypasses classification.
`from_plaintext` takes an already decoded `Encrypted<T, Profile>`;
`From<Ciphertext>` wraps known ciphertext. The packaged stores load no discriminator
and `RowPlanner` uses ordinary classification: use a custom/manual guarded repair
for collisions, never a general malformed-envelope fallback.

## Transitional search

Before enabling probe lookup, establish that every populated index is a valid
projection under a readable generation and every unfilled/untrusted projection
has the agreed empty marker, set with a guarded write. Wrong nonempty indexes can
hide matches. If this invariant cannot be established, scan/verify **all** rows
under suitable consistency or use the maintenance cutover.

Select **all readable-generation probes OR the missing-index marker** in one
statement, joining trusted format metadata one-to-one. A row should appear once.
Separate fallback/probe queries can miss a row that moves from unindexed to
indexed between queries. The consumer's `migration-search` uses one candidate
statement and a read transaction sharing its snapshot with the quarantine gate
(PostgreSQL `REPEATABLE READ`, SQLite read snapshot). A separate read-committed
gate could miss a quarantine that removes a row before selection.

Authenticate/decrypt CryptBox candidates; recover and validate legacy candidates;
then compare normalized plaintext. False candidates are discarded, while recovery
or decoding failures fail the **whole lookup**, with no partial results. Unresolved
quarantine blocks lookup: removing a row from the live table cannot silently make
search complete. The result is relative to its snapshot, not later commits.

Use the same validation and normalization policy across writes, recovery, reads
and closure. The consumer validates trimmed ASCII email-like syntax, preserves
original whitespace/case, and trims/lowercases for lookup; this is not general email
validation or provenance evidence. Its candidate set is materialized, including
all unindexed rows. Larger deployments need bounded streaming under a consistent
snapshot and a complete-result contract, not independently paged moving populations.
Switch to blind-index-only lookup only after the [closure gates](#verification-and-closing-the-window).

## Running The Sweep

Configure `RowPlanner::<T, Profile>::new(context, encryption_provider)`, add the
explicit handler with `with_legacy`, and register indexes in stored order with
`with_index_with::<Spec>(index_provider)`. Omit `with_legacy` only for authorized
plaintext-only data. Recovery decodes through the profile codec, encrypts and
derives every registered index. Stale CryptBox components are rewritten; current
ones are retained under the [sweep rules](reencryption-sweep.md#sweep-loop).

The packaged planner repairs missing indexes on **legacy** bytes by deriving them,
but rejects empty/malformed indexes on existing CryptBox ciphertext. It also
rejects magic collisions. Handle these exceptional rows explicitly below.

### Stepped Execution And Durable Runtimes

Use `Sweep::run` to exhaust the store, `run_batch` for durable checkpointed steps,
or `process_batch` when an orchestrator journals its own cursor. Follow the
[failure/replay procedure](reencryption-sweep.md#failures-replay-and-load-bounds):
partial row commits can precede failure, and rewrite counts are advisory.
An unrecoverable row stops the run; investigate after saved progress rather than
jumping the checkpoint. Full verification always starts separately from the beginning.

### Fail, investigate, quarantine and resume

Confirm the legacy key/format against authoritative records using restricted
recovery tooling. Quarantine transactionally: copy sensitive evidence and remove
the live row with a guard on every original ciphertext/index byte, rolling back
on conflict. Record an unresolved case and include it in the recovery inventory.

Quarantine is not successful migration. Lookup and closure remain blocked until
approved replacement data or an explicitly authorized business deletion resolves
the case. Restore without overwriting a concurrent recreation and resolve the case
in the same transaction; retain evidence under its separate retention policy.
Resume the saved run after resolution. Repairs behind completed progress require
a fresh run or targeted guarded repair, followed by fresh verification.

### Repair exceptional rows without relaxing classification

Load the exact ciphertext/index tuple and trusted discriminator. Use ordinary
classification for CryptBox rows with missing indexes; use `from_legacy_bytes`
**only** for discriminator-known legacy collisions. Authenticate/recover, validate,
prepare target ciphertext/indexes, and atomically CAS against the full old tuple.
Clear the discriminator in that transaction with its own guard; any conflict
requires rollback, reload and investigation.

All writers must coordinate format metadata with value changes transactionally,
or exceptional rows must be fenced. The fixture's ordinary `put` does not manage
legacy metadata, so its collision row stays under exclusive maintenance ownership
until repaired. See `repair` in [migration.rs](snippets/migration.rs).

## Verification And Closing The Window

Fence old writers, imports and restores. Pause/drain writes through verification
and strict-reader cutover, or supply equivalent application-owned consistency.

1. Resolve every quarantine case and trusted legacy discriminator under the
   recovery/disposition policy; row removal alone does not resolve a case.
2. Complete the [canonical verification and audit procedure](reencryption-sweep.md#verification-and-retirement):
   a fresh full pass with zero legacy/stale/malformed rows, followed by strict
   authenticated reads, application validation and complete index recomputation.
   A wrong current-generation index can pass generation verification while hiding
   matches. Any failure blocks closure; guarded repair must be followed by fresh gates.
3. Reconcile expected rows/searches against the inventory and retain provenance
   evidence for unauthenticated legacy values. Successful encryption cannot supply it.
4. Replace `MaybeEncrypted` with strict reads. Remove online handler references,
   migration commands/configuration and the `migrate` feature. In the consumer,
   remove `src/migration.rs`, its module/dispatch/planner-injection blocks, the
   `legacy-migration` feature/dependencies, and `maintenance` if no longer needed.
5. Rebuild/restart strict readers; verify historical converted reads, complete
   searches and a prepared write/read/search round trip before reopening traffic.

The consumer's `migration-close` rejects unresolved quarantine/discriminators,
runs full generation verification and the paginated strict authenticated/index
audit without a legacy handler. The operator supplies the consistency boundary,
inventory and provenance evidence.

Remove online legacy access after preserving required recovery copies. Retain
historical encryption/index keys, legacy handlers/keys and schema for pre-migration
backups, rollback artifacts and quarantine. Test restore with historical probes or
verified re-indexing. Follow [retirement and recovery](key-rotation.md#retirement-and-recovery)
for online key removal and eventual destruction; live closure alone permits neither.

## Durable mixed-format walkthrough

The [consumer module](snippets/migration.rs) and [migration scenario](../scripts/check-migration-consumer.mjs)
exercise plaintext, authenticated illustrative legacy ciphertext, historical/current
CryptBox rows, missing indexes and a trusted magic collision. The scenario drives
failure/quarantine/recovery, replay and manual repairs, then verifies closure.
The [runner](../scripts/check-searchable-consumer.mjs) additionally removes the
online module/key and rebuilds without migration features for strict smoke checks.

With Rust/Cargo 1.85+, Node.js 18+, a native C compiler for bundled SQLite, and
dependency access, run from the repository root:

```sh
node scripts/check-searchable-consumer.mjs checkout sqlite migration
```

Use `published` for crates.io 0.5.0, or `postgres` with a disposable `DATABASE_URL`.
The runner creates independent keys and fresh persistent fixtures; damage/repair
commands are for those fixtures only. For manual setup, use the [SQLx tutorial](searchable-sqlx.md),
copy `migration.rs` to `src/migration.rs`, enable `legacy-migration`, and provision
`legacy.hex` once without replacing material needed by stored legacy ciphertext.
The illustrative previous protocol is not a recommended format for new storage.
The smaller [legacy](../examples/legacy_migration.rs) and
[plaintext](../examples/plaintext_migration.rs) examples are in-memory API introductions.
