# Re-encryption Maintenance Sweeps

**How-to · current 0.5.0 API.** Run bounded maintenance over stored values.
[All tasks](README.md) · [Rotation concepts](concepts.md#generations-and-lookup).

Key rotation makes a new encryption key current while retaining historical keys
for reads. It does not require an immediate table rewrite. A maintenance sweep
is useful when an application later wants to retire historical keys or migrate
an encryption suite.
Live-data convergence does not show that backups or other stores no longer need
historical keys: online removal, recovery retention, and destruction are separate
decisions, as described under [verification and retirement](#verification-and-retirement).

The runnable [SQLite sweep example] shows the complete pattern with SQLx. The
same control flow applies to PostgreSQL and other stores.

The manual loop below remains the reference semantics. The `migrate` Cargo
feature packages the same invariants as library code in
`cryptbox::migrate::{RowPlanner, Sweep, SweepStore}` and additionally
handles migration from plaintext or a previous encryption solution; see the
[legacy migration guide](legacy-migration.md).

## Preconditions

Before starting a sweep, deploy the current-plus-historical keyring to every
application instance. Confirm that every writer uses the current encryption and
blind-index keys. Keep all historical keys available during the sweep and final
verification; retain recovery copies separately for older backups and other stores.

Choose a unique, immutable, indexed cursor such as a monotonically increasing
primary key. Uniqueness is required, not just recommended: paging resumes
strictly after the last cursor value, so rows sharing a value with a batch
boundary would be skipped by the sweep and its verification alike. Size
batches to limit database load and plaintext residence time. A sweep
decrypts sensitive data in the maintenance process, so give that process the
same logging, memory, and access controls as an application writer.

## Sweep Loop

For each batch:

1. Select rows after the last durable cursor, ordered by that cursor.
2. Parse each `Ciphertext` and call `needs_reencryption_with`.
3. Skip current envelopes rather than generating fresh nonces and unnecessary writes.
4. Re-encrypt stale envelopes with `reencrypt_with`.
5. Update with optimistic concurrency and advance the cursor only after the batch succeeds.

The compare-and-swap update must include the value that was read:

```sql
UPDATE users
SET email_ciphertext = $new
WHERE id = $id AND email_ciphertext = $old
```

If the affected-row count is zero, a concurrent writer changed the row. Do not
overwrite it. Once all writers use current keys, that newer value is already
current. A final verification pass detects stale writes from a misconfigured
instance. Applications that prefer row locks can instead select each bounded
batch with the database's locking facilities and keep the read and update in
one short transaction.

Persist the last fully processed cursor outside the worker's memory. A crash
before checkpointing may replay part of a batch, but replay is safe because
current rows are skipped and every update compares against the bytes originally
read. New rows receive larger cursors and are encountered by the running scan.

## Blind Indexes

Blind-index key rotation is independent from encryption-key rotation. During
migration, continue querying with every value from `blind_index_probes`.

For a row whose `inspect_blind_index` metadata names a historical index key:

1. Decrypt the authoritative ciphertext.
2. Derive a replacement with `derive_blind_index` and the current index key.
3. Update the ciphertext and index columns atomically.
4. Compare both old columns in the update predicate so a concurrent writer cannot be partially overwritten.

The SQLite example combines both migrations in one compare-and-swap update. A
deployment may run them separately, but it must preserve the same concurrency
guard and candidate-verification rules.

## Verification And Retirement

**A clean live-data pass does not establish that retained backups or other stores
no longer need historical keys.** Separate online provider removal from recovery
retention and eventual destruction.

After the keyset scan completes, perform a fresh full verification pass from the
start. Every ciphertext must return `false` from `needs_reencryption_with`, and
every blind index must name the current `IndexKeyId`. Treat malformed values as
errors rather than skipping them.

This is **migration-state verification**: it checks parsed structure and generation
metadata, which remain unauthenticated. It does not establish authenticated
readability, decoded-value validity, or ciphertext/index consistency. Current
rows are skipped without decryption; current index bytes are preserved without
recomputation even when another component is rewritten. Re-encryption authenticates
and checks padding, but does not by itself decode with the profile's codec.

With `migrate`, `Sweep::verify` performs this fresh full pass, ignoring the rewrite
checkpoint. `SweepReport::is_terminal()` only checks zero legacy, stale, and
malformed counts; it cannot tell whether a pass is complete. For `verify_batch`,
start with no cursor, merge each report, and follow returned checkpoints until
`None` before checking the aggregate. A clean batch, default report, or rewrite
report is insufficient. Classification may stop on a stale component before
inspecting later columns; fix the reported state and verify again.

For **authenticated readability**, separately parse and `decrypt_with` every
ciphertext using the intended profile/context, validate the decoded application
value, and account for every failure. For **index consistency**, recompute each
index from that authenticated plaintext using the intended specification,
normalization, binding, precision, and allowed generation, then compare complete
stored bytes. Use the [step-by-step assurance procedure](stored-values.md#obtain-additional-assurance)
for current or mixed-generation stores and concurrency-safe repair. Candidate
plaintext comparison alone does not check stored index metadata.

Ensure every writer uses the target generations. Verification observes loaded
rows, not a library-provided snapshot. If writes continue, repeat verification
until a complete pass is clean; use your store's consistency guarantees for any
stronger point-in-time claim. Revisit stale rows behind the rewrite checkpoint
with a fresh sweep or targeted repair before another fresh verification pass.

After convergence, make three distinct decisions:

1. **Online removal:** once all relevant live stores and readers have converged,
   remove historical encryption keys from online providers and stop historical
   blind-index probes for those stores. A clean pass over one table is not an
   inventory of other tables, caches, queues, replicas, or offline stores.
2. **Recovery retention:** keep securely managed historical encryption keys,
   index keys, and the required profile/index schema for retained backups,
   archives, snapshots, and rollback data. Test restoration with that recovery
   keyset. Restored historical indexes require historical probes or an explicit
   re-indexing pass before current-only lookup is complete.
3. **Destruction:** destroy key material only when every artifact that needs it
   has expired, been migrated, or been deliberately made unrecoverable under the
   application's retention policy. Removing a key from an online provider does
   not destroy recovery copies, and live convergence alone is not this condition.

[SQLite sweep example]: ../examples/reencryption_sweep.rs
