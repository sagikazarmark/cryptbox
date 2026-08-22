# Re-encryption Maintenance Sweeps

Key rotation makes a new encryption key current while retaining historical keys
for reads. It does not require an immediate table rewrite. A maintenance sweep
is useful when an application later wants to retire historical keys or migrate
an encryption suite.

The runnable [SQLite sweep example] shows the complete pattern with SQLx. The
same control flow applies to PostgreSQL and other stores.

The manual loop below remains the reference semantics. The `migrate` Cargo
feature packages the same invariants as library code —
`cryptbox::migrate::{RowPlanner, Sweep, SweepStore}` — and additionally
handles plaintext-to-ciphertext adoption; see the
[plaintext migration guide](plaintext-migration.md).

## Preconditions

Before starting a sweep, deploy the current-plus-historical keyring to every
application instance. Confirm that every writer uses the current encryption and
blind-index keys. Keep all historical keys available until final verification
passes.

Choose an immutable, indexed cursor such as a monotonically increasing primary
key. Size batches to limit database load and plaintext residence time. A sweep
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

After the keyset scan completes, perform a fresh full verification pass from the
start. Every ciphertext must return `false` from `needs_reencryption_with`, and
every blind index must name the current `IndexKeyId`. Treat malformed values as
errors rather than skipping them.

Only after verification succeeds may the application remove historical
encryption keys from its providers and stop generating historical blind-index
probes. If writes continue during verification, repeat verification until a
complete pass observes no historical generations.

[SQLite sweep example]: ../examples/reencryption_sweep.rs
