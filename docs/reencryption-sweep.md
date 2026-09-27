# Re-encryption maintenance sweeps

Rewrite stored values in bounded, resumable batches.
[Documentation](README.md) · [Key lifecycle](key-rotation.md) · [Legacy adoption](legacy-migration.md).

Rotation selects keys for future writes; a later sweep converges existing
ciphertext and indexes. The same sweep rewrites ciphertext in an older format or
whose padding flag disagrees with the field's current policy, so it also upgrades
format 1 values and applies a padding change. The `migrate` feature supplies
`RowPlanner`, `Sweep` and `SweepStore`, which also reseal values after a
[binding-shape change](#binding-shape-changes); the
[manual SQLite example](../examples/reencryption_sweep.rs) demonstrates the same
concurrency rules without the driver.

## Preconditions

Finish [fleet promotion](key-rotation.md#key-states-and-the-promotion-gate), confirm
every writer uses the target generations, and settle rollback policy. Retain
historical keys during rewriting and verification, with recovery copies for backups.

Choose a **unique, immutable, indexed cursor** providing a total order. Pagination
resumes strictly after a cursor; duplicates at a boundary silently skip rows in
both rewriting and verification. Protect the maintenance process like a writer:
it handles plaintext. Log sanitized metadata, not values, tokens or key material.

## Run identity and progress ownership

Record the database/schema/table, ciphertext and index columns in planner order,
cursor, field/index schema revision, fixed target encryption/index IDs, readable
keyset revision, policy, run name and progress table. **Do not change the keyrings'
current keys during a run.** Assign one owner to serialize batches and
stop/join the old worker before handover.

Configure `SweepTable::new(...).with_progress(progress_table, run_name)`.
Packaged stores persist only `(name, last_id)`: no targets, completion flag,
counters, lease or execution lock. The default `table.ciphertext_column` name
does not distinguish rotations. Concurrent workers can overwrite progress despite
safe row-level compare-and-swap (CAS); coordinate ownership externally.

Resume with the same name and manifest. For a new rotation or repair from the
beginning, stop the prior worker and use a fresh name with no progress row.
Alternatively, delete that exact progress row with application-owned SQL while
workers are stopped; there is no packaged reset method. Saving cursor zero is
not a reset because valid cursors may be zero or negative.

## Run the automated scenario

This section runs an automated rehearsal. It is separate from the nullable
dataset created by the [searchable example](../examples/searchable/README.md): the runner
provisions a fresh non-NULL population. To operate your own nullable application,
use the explicit NULL policy and custom-store/manual-loop boundary described below.

### Prepare the consumer

Use the [example setup](../examples/searchable/README.md), [complete source](../examples/searchable/main.rs)
and its `maintenance` feature. The [runnable sweep scenario](../tests/e2e/sweep.rs)
contains the interruption, replay, stale-write recovery, second rotation and
competing-write rehearsal. Use Rust/Cargo 1.85+, a native C compiler
for bundled SQLite, and dependency access. Run from the repository root:

```sh
cargo test --locked --test e2e --all-features sqlite_sweep
```

For live PostgreSQL, see the [test instructions](documentation.md#live-postgresql).
The runner provisions persistent temporary keys and storage, and each consumer
command runs in a new process. The manual in-memory example is not evidence of
cross-process durability.

`SqliteSweepStore` and `PostgresSweepStore` use an `i64` cursor and require
**non-NULL bytes in every swept column** for this recipe. Packaged stores offer
no NULL policy, `WHERE` filter, discriminator or upper cursor bound. Nullable or
filtered populations, other cursor shapes and snapshot/high-water policies need
an application-owned `SweepStore` or manual loop with appropriate atomic predicates.
Do not infer a NULL policy from backend decoding behavior.

## Sweep loop

Register each index in the same order in `RowPlanner::with_index_with` and
`SweepTable::with_index_column`; create the store's progress table with
`ensure_progress_table`. For each batch:

1. Load rows strictly after the saved cursor in ascending order.
2. Classify stored bytes. Skip current rows without new nonces or writes; rewrite
   stale ciphertext with the target encryption generation, current format, and
   the field's padding policy, and stale indexes from
   authenticated, decoded authoritative ciphertext. Legacy recovery is covered in
   the [adoption recipe](legacy-migration.md#running-the-sweep).
3. Atomically write the replacement tuple with a predicate matching **every
   original ciphertext and index byte**, including components retained unchanged.
4. A zero-row update is a concurrent-write conflict: count it and skip it, never
   overwrite or retry the stale plan. Save progress only after the batch succeeds.

For a single indexed value, the SQL shape is:

```sql
UPDATE users SET email = $1, email_lookup = $2
WHERE id = $3 AND email = $4 AND email_lookup = $5
```

The last two parameters are the exact old pair. Include every additional swept
index column too. A manual implementation may instead lock the bounded batch and
keep its read/update in one short transaction.

`Sweep::run_batch` loads and saves durable progress; `Sweep::run` loops to
exhaustion. `Sweep::process_batch` takes/returns a cursor without checkpoint I/O
for an orchestrator that journals progress itself. Returned checkpoint `None`
means exhaustion; an empty batch leaves the saved cursor intact.

### Failures, replay, and load bounds

A packaged batch is **not one transaction**. Earlier row updates may commit before
a later rewrite, storage operation or checkpoint save fails. Stop, investigate the
next batch after saved progress, resolve the cause and resume. Reload durable
progress after an uncertain save. Never jump over a failed row. Replay loads and
skips already-current rows; an old in-memory plan loses its full-tuple CAS.

Conflicts may be checkpointed past. Old writers, explicit lower-ID inserts and
late commits can also put stale rows behind progress, even with database sequences.
Fresh verification detects these; fix the producing writer/restore path, then use
a fresh run identity or targeted guarded repair and verify again. Resuming an
exhausted checkpoint cannot revisit those rows. Per-batch and summed rewrite
counters are advisory under partial success, restart and replay.

Batch size bounds rows, not bytes, plaintext size, memory, I/O, locks or elapsed
time. Apply value limits, measure load/latency and throttle. Verification also
uses bounded pages. Inserts ahead can extend the whole run indefinitely; for a
finite point-in-time claim, coordinate a write pause or implement a snapshot/
high-water policy for rewriting **and** verification. A high-water mark alone
does not solve late commits behind it; packaged stores provide neither mechanism.

## Blind indexes

Encryption and index roots rotate independently. Continue lookup with every
readable-generation probe and authenticated, normalized candidate comparison.
An index-only rewrite derives from decrypted authoritative plaintext, never index
metadata; ciphertext may remain unchanged. Preserve atomic tuple writes and the
full original-tuple guard whether both roles are swept together or separately.

Current rows are skipped without decryption. Current index bytes are retained
without recomputation even when another component changes. Re-encryption alone
authenticates and checks padding but does not decode through the field codec.
These behaviors make the following separate audit necessary.

## Binding-shape changes

A field's binding shape (its parts, their roles and whether it binds a record) is
persistent schema, so changing it is a migration: an explicit legacy-binding
window, a reseal sweep, and lookups over both index shapes until the window
closes ([ADR-0005](adr/0005-runtime-binding-is-the-core.md)).

A bound field's sweep is **partitioned by key scope**, because its keys are.
Configure one planner per key scope with
`RowPlanner::for_key_scope(key_scope, keys, row_args)`. The key scope comes from
the job, never from the rows; `row_args` builds each row's `RowArgs` (its
binding and record ID) from the columns the store loads into
`SweepRow::columns`. The store selects only that key scope's rows. A row whose
arguments name another key scope is left alone and counted as `out_of_scope`:
an anomaly to investigate, not a row to rewrite. Packaged stores load no
columns, so a bound field needs an application-owned `SweepStore`.

Open the window with `RowPlanner::legacy_binding::<Old>(old_keys)`, where `Old`
is the binding the field had before, such as `FieldOnly`. Its parts take their
values from each row's current binding by part ID, and a row whose header
names `Old` with a record keeps the row's record. The window covers adding parts
or a record and changing a role, not removing a part or changing its kind. Rows
are classified by the shape fingerprint in their header: a row of the old shape is
opened under it with `old_keys`, resealed under the current binding, and every
index derived again, since the index binding may have changed. Rows of any
other shape still fail with `Error::BindingMismatch`.

While the window is open, readers use `migrate::probes_across::<Old, S>` for
probes over both [index bindings](wire-format.md#index-binding) and
`migrate::open_across::<Old, _>` to open a candidate of either shape. Close the
window, and drop the old keys from the readers,
only after a complete verification pass counts zero `legacy_binding` rows.

To move a value to other binding values or keys under the same shape, such as a
record moving between workspaces or data changing residency, use
`Sealed::reseal_across`.

## Verification and retirement

This is the canonical whole-store audit procedure. The
[assurance reference](security.md#what-each-check-establishes) explains what each
check establishes. Fix the intended field ID, binding shape, value type,
codec, index specifications, normalization, precision and allowed generations
from trusted application schema, not stored metadata.

1. **Establish scope and consistency.** Inventory expected rows/stores and confirm
   all writers use target generations. Hold a write/import/restore pause across
   final checks and cutover, or provide equivalent application-owned consistency.
   Library pagination observes loaded rows, not a shared snapshot. If writes
   continue, repeat complete passes until clean under your storage guarantees.
2. **Verify migration state from the beginning.** `Sweep::verify` ignores rewrite
   progress and performs a fresh read-only pass. Require zero legacy,
   legacy-binding, out-of-scope, stale and malformed rows. For `verify_batch`,
   start with no cursor, merge every report using `SweepReport::merge`, and
   follow checkpoints to `None` before evaluating `is_terminal()`. That method
   checks counts, not completion: a clean partial,
   default or rewrite report is insufficient. Malformed rows are counted;
   storage/configuration failures abort the pass. Classification can stop at a
   stale component before inspecting later columns; repair and verify again.
3. **Authenticate and validate every value.** Read ciphertext and indexes together,
   parse typed `Sealed`, and call `open` with the intended binding arguments and
   keyring. Authentication, padding, codec and key-availability failures all fail
   the audit. Validate decoded application constraints; account for every row.
4. **Recompute every index.** Parse as `BlindIndex<ExpectedSpec>` and call
   `ExpectedSpec::is_consistent_with` with the authenticated plaintext and a
   blind-index keyring holding exactly the allowed generations; it compares
   **complete stored bytes**, not just IDs, under the generation the index names.
   `Ok(false)` is an inconsistent index. `Error::UnknownBlindIndexKey` means an
   unknown or disallowed generation: it also fails the check, but report it
   distinctly as unverifiable. After convergence, also require that the stored
   bytes equal `ExpectedSpec::derive_with` under the current generation.
5. **Resolve failures and reconcile coverage.** Record sanitized row/run metadata
   and compare coverage with the inventory and expected searches. Repair only
   from authoritative values with atomic full-tuple CAS, then repeat the complete
   gates. Revisit stale rows behind progress using a fresh run or guarded repair.

Generation verification reads unauthenticated metadata; it proves neither
readability nor stored-index consistency. A wrong current-generation token can
pass it. Candidate plaintext comparison does not inspect index metadata, and
complete-byte agreement establishes consistency only at the configured precision.
These checks do not establish provenance, freshness, row binding or that a
database returned every matching row.

The consumer's `sweep-verify` covers step 2; `audit-current` separately pages strict
authenticated reads, application validation and current-index recomputation.
`migration-close` additionally gates unresolved legacy cases. The operator supplies
scope, consistency and provenance evidence.

After inventory-wide success, follow [retirement and recovery](key-rotation.md#retirement-and-recovery)
for online removal, isolated restore and recovery retention. A clean live-table
pass says nothing about older backups or other stores and never authorizes key
destruction by itself.
