# Re-encryption Maintenance Sweeps

**How-to · current 0.5.0 API.** Run bounded maintenance over stored values.
[All tasks](README.md) · [Fleet rotation procedure](key-rotation.md) ·
[Rotation concepts](concepts.md#generations-and-lookup).

Key rotation makes a new encryption key current while retaining historical keys
for reads. It does not require an immediate table rewrite. A maintenance sweep
is useful when an application later wants to retire historical keys or migrate
an encryption suite.
Live-data convergence does not show that backups or other stores no longer need
historical keys: online removal, recovery retention, and destruction are separate
decisions, as described under [verification and retirement](#verification-and-retirement).

The [durable walkthrough](#durable-postgresql-and-sqlite-walkthrough) below uses
the searchable consumer and packaged SQLx stores, with real process exits. The
runnable [SQLite sweep example] preserves a small manual reference loop; its
in-memory database is **not** evidence of cross-process durability.

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

## Run identity and progress ownership

Record a run manifest in your deployment/job configuration before starting:

- Database/schema, table, ciphertext/index columns (in planner registration order),
  profile/index schema revision, and unique immutable cursor column.
- Fixed target encryption and index generation IDs, readable keyset revision,
  and sweep policy. Do not change a provider's current selection during a run.
- Stable run name, e.g. `users-email-e2-i2-attempt-1`, and progress table.
- One owner responsible for serialized batch execution, handover after process
  exit, and final verification. Stop/join the old worker before handing over.

`SweepTable::with_progress("cryptbox_migration_progress", run_name)` selects the
durable `(name, last_id)` row. The packaged stores persist **only** these two
fields, not targets, completion, counters, leases, or an execution lock. The
default name `table.ciphertext_column` does not distinguish rotations. Enforce
ownership with your scheduler or database coordination; two overlapping workers
can overwrite progress even though guarded row updates preserve application writes.

**Resume:** use the same manifest and name, reload its cursor, and continue after
it. `run_batch` does this automatically. **New rotation or recovery from the
beginning:** first quiesce the prior worker, create a new name with no progress
row, and keep the old record for audit. An operator can alternatively delete the
exact old progress row using application-owned SQL while its workers are stopped;
there is no packaged reset method. Never treat `save_checkpoint(0)` as a general
reset: valid cursors may be negative or zero.

## Durable PostgreSQL and SQLite walkthrough

### Prepare the consumer

Start with the [searchable consumer prerequisites, service, and key files](searchable-sqlx.md).
Copy its **current** manifest and [complete source](snippets/searchable.rs), which
include the optional `maintenance` feature. Use a fresh disposable database:
these commands deliberately rehearse a misconfigured writer and an interleaved
application update. With the tutorial's PostgreSQL service:

```sh
docker exec cryptbox-searchable-postgres createdb -U cryptbox cryptbox_sweep
export DATABASE_URL='postgres://cryptbox:cryptbox@127.0.0.1:55432/cryptbox_sweep?sslmode=disable'
cargo check --features maintenance
cargo build --features maintenance
```

Or preserve the SQLite route by choosing a new file and building:

```sh
export DATABASE_URL="sqlite://$PWD/sweep.db?mode=rwc"
cargo check --no-default-features --features sqlite,maintenance
cargo build --no-default-features --features sqlite,maintenance
```

The tutorial supplies runtime/TLS dependencies and four independent persistent
key files. Do not regenerate those files between commands. In Bash or Zsh:

```sh
export CRYPTBOX_KEY_DIR="$PWD/keys"
unset CRYPTBOX_GENERATION
consumer() { ./target/debug/searchable-consumer "$@"; }
old() { CRYPTBOX_ENCRYPTION=staged CRYPTBOX_INDEX=staged consumer "$@"; }
current() { CRYPTBOX_ENCRYPTION=2 CRYPTBOX_INDEX=2 consumer "$@"; }
current init
old put 10 sweep@example.com
old put 20 sweep@example.com
old put 30 sweep@example.com
current put 40 sweep@example.com
current search SWEEP@example.com
```

Adjust the binary path if `CARGO_TARGET_DIR` is set. Each invocation is a separate
OS process opening the same persistent database and loading the same ID/material
pairs. Search returns `[10, 20, 30, 40]`. Before a real sweep, complete the
[fleet compatibility and writer-promotion gates](key-rotation.md); `old` here is
only a fixture for historical data and the deliberate stale-write rehearsal.

The packaged route here requires **non-NULL byte columns for every swept row**,
unlike the introductory nullable CRUD route. Do not run `put-null` in this
rehearsal. For nullable tables, use an application-owned `SweepStore`/manual loop
with an explicit NULL policy and appropriate atomic predicates. The packaged
store cannot be configured with a `WHERE` filter or upper cursor bound. Do not
assume backend NULL decoding supplies that policy.

### Interrupt, resume, and replay

Record `rotation-2` as targeting E2 `20000000-0000-4000-8000-000000000002` and
I2 `40000000-0000-4000-8000-000000000004`, with both generations retained.
Commands process at most **two rows** per batch:

```sh
current sweep-status rotation-2
current sweep-batch rotation-2
# The first worker has exited. A new process reads its saved progress:
current sweep-status rotation-2
current sweep-uncheckpointed rotation-2
current sweep-status rotation-2
current sweep-batch rotation-2
current sweep-batch rotation-2
current sweep-verify rotation-2
```

Expected sequence:

| Command | Observation |
| --- | --- |
| Initial status | `Checkpoint: None.` |
| First batch | checkpoint `Some(20)`, stale 2 |
| Restarted status | `Checkpoint: Some(20).` |
| Uncheckpointed batch | returned checkpoint `Some(40)`, stale 1, current 1 |
| Status after process exit | still `Some(20)` |
| Replayed batch | checkpoint `Some(40)`, stale 0, current 2 |
| Next batch | checkpoint `None`, all counters zero (scan exhausted) |
| Fresh verification | `Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.` |

`sweep-uncheckpointed` is a rehearsal of the interruption window: it calls
`process_batch` and exits without saving its returned checkpoint. It does not
send a kill signal; it deliberately leaves the same durable state as a worker
lost after writes and before checkpointing. Normal scheduling uses `sweep-batch`
(`run_batch`), which saves progress after a successful batch. The final empty
batch returns `None` but leaves the stored cursor at 40; it does not erase progress.

### Detect and recover stale rows behind progress

Rehearse a stale write behind the completed cursor:

```sh
old put 10 sweep@example.com
current sweep-batch rotation-2
current sweep-verify rotation-2
```

Resume still returns an empty batch; fresh verification reports current 3,
stale 1 and `Complete: false`. Repeating verification only detects the problem.
In production, first fix the writer/restore path producing stale data. Stop any
old sweep worker, then record a **fresh recovery identity with the same targets**:

```sh
current sweep-status rotation-2-repair-1
current sweep-batch rotation-2-repair-1
current sweep-batch rotation-2-repair-1
current sweep-batch rotation-2-repair-1
current sweep-verify rotation-2-repair-1
```

The first batch revisits row 10 (stale 1, current 1); the final verification is
clean for all four rows. A targeted guarded repair is another supported manual
route, but it must be followed by the same fresh complete verification.

### Repeat for a second rotation and preserve a competing write

Provision E3 and I3 independently **once**, without replacing files 1 or 2:

```sh
(umask 077; openssl rand -hex 32 > "$CRYPTBOX_KEY_DIR/encryption-3.hex")
(umask 077; openssl rand -hex 32 > "$CRYPTBOX_KEY_DIR/index-3.hex")
staged3() { CRYPTBOX_ENCRYPTION=staged-3 CRYPTBOX_INDEX=staged-3 consumer "$@"; }
third() { CRYPTBOX_ENCRYPTION=3 CRYPTBOX_INDEX=3 consumer "$@"; }
third rotation-canary third.canary
staged3 rotation-ready third.canary
staged3 search SWEEP@example.com
```

The loader assigns E3 `70000000-0000-4000-8000-000000000007` and I3
`90000000-0000-4000-8000-000000000009`. `staged-3` writes generation 2 and reads/
probes 1, 2, 3; `3` writes generation 3 with all three retained. Distribute that
staged configuration to **every** reader and pass the fleet readiness gate before
promoting writers to `3`. Keep the existing binding, normalization, and index IDs.

Use `rotation-3`, not either completed E2/I2 identity:

```sh
third sweep-status rotation-3
third sweep-conflict rotation-3
staged3 get 10
staged3 search CONCURRENT@example.com
third sweep-batch rotation-3
staged3 search SWEEP@example.com
third sweep-batch rotation-3
third sweep-batch rotation-3
third sweep-verify rotation-3
staged3 search SWEEP@example.com
```

Initial progress is absent. The fixture-only `sweep-conflict` loads and plans
row 10, then commits `concurrent@example.com` through a **second connection**
using prepared storage. Applying the old plan with `SweepStore::update` returns
false: it prints `Stored 10.` and `Conflicts: 1.`. Neither the new ciphertext nor
its index is overwritten. The command saves no progress. `get` reads the new
value, and its candidate-verified search finds `[10]`.

The normal batches now report `(current 1, stale 1)` then `(current 0, stale 2)`,
then exhaustion. Verification reports all four current. Throughout this retained-
key window, both staged and promoted readers can decrypt all rows and search
every readable index generation; `SWEEP@example.com` returns `[20, 30, 40]` even
mid-sweep. No historical keys are retired by these commands.

For a failure rehearsal, `current sweep-batch missing-key-rehearsal` after the
E3 write fails because that provider lacks E3. Its checkpoint remains absent.
Restore the run's correct provider configuration before retrying; do not advance
progress around the failure. Keep this deliberately wrong-target rehearsal
separate from `rotation-3`.

### Check the walkthrough

From the repository root (Node.js 18+, Rust/Cargo 1.85+, and for PostgreSQL the
established disposable service with `DATABASE_URL` exported):

```sh
node scripts/check-searchable-consumer.mjs checkout sqlite sweep
node scripts/check-searchable-consumer.mjs checkout postgres sweep
node scripts/check-searchable-consumer.mjs published postgres sweep
```

The harness generates independent temporary key files, runs each command as a
new process, and isolates PostgreSQL data/progress in a random schema which it
drops afterward. It asserts restart, replay, stale recovery, failed-batch progress,
guarded conflict preservation, mixed-generation search and the second rotation.
SQLite uses a real temporary file. The existing Dagger PostgreSQL check executes
both checkout and published scenarios; the consumer documentation checks execute
both SQLite variants. See [database check entry points](testing.md#live-postgresql-sweep-checks).

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
read. Under a monotonic allocation/visibility policy, new visible rows ahead of
the cursor can be encountered by the running scan. A unique immutable cursor
alone does not guarantee this: explicit lower-ID inserts and late commits can
appear behind it, even with database-generated sequences. Fresh verification
and the recovery procedure above account for that case.

### Failures, replay, and load bounds

A batch is not one transaction in the packaged stores: individual guarded row
updates may already have committed when a later rewrite, storage operation, or
checkpoint save fails. Stop on the error and investigate within the next batch
after the saved cursor. On uncertain checkpoint-save outcomes, reload durable
progress. Retry after resolving the cause; do not manually jump over a failed row.
Replay loads current rows and skips them; replaying an old in-memory write loses
its compare-and-swap. Concurrent-write conflicts are counted and skipped, and
the batch may advance past them. Fresh verification determines whether recovery
is needed, including for writes behind the cursor.

Per-batch reports describe that invocation, not a durable inventory: restart,
partial success and replay make summed run counters **advisory**. They cannot
replace a fresh complete migration-state verification pass.

The two-row limit in the walkthrough bounds row count, **not bytes**, plaintext
size, database I/O, locks, or wall time. Loaded ciphertext/index buffers and
per-row decoding/rewriting add memory beyond the row count; a single large value
can dominate. Set application value limits, measure batch bytes/latency and DB
load, tune batch size, and throttle between `run_batch` calls. `verify_batch`
uses the same pagination; even `verify` loops over bounded batches, not a
whole-table `fetch_all`. The manual reference also verifies with keyset pages.

A bounded batch does not bound the whole run. Inserts ahead of the cursor can
extend a scan indefinitely, and late inserts/updates behind it require another
pass. For a finite, point-in-time completion claim, coordinate a write pause or
implement the necessary snapshot/high-water policy in your own store and
verification procedure. The packaged store does not provide it. A high-water
mark alone still needs a plan for late commits behind that mark.

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
