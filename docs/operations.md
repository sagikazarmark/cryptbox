# Operations

Rotate keys, rewrite stored values, adopt legacy data, and shred a tenant.
CryptBox supplies the primitives; the deployment owns inventory, coordination,
custody, and evidence. The [searchable example](../examples/searchable/README.md)
implements the commands named below, and `tests/e2e` rehearses each procedure
(`sqlite_rotation`, `sqlite_recovery`, `sqlite_sweep`, `sqlite_migration`).

## Key rotation

A key generation is an immutable ID/root-material pair. Generate encryption and
blind-index roots independently, rotate them independently, and never replace
material under an existing ID. The current generation writes; every readable
encryption generation decrypts by exact ID, and every readable index generation
supplies a probe.

Rotation changes future writes only. Reads never rewrite storage; a later
[sweep](#maintenance-sweeps) converges existing rows. Neither rotation nor online
key removal revokes leaked keys or ciphertext, or erases copies.

### The promotion gate

Before **any writer** promotes a role, **every participating reader** must load
the new pair, retain the existing pairs, and prove compatibility. Include workers,
scheduled jobs, read-only services, autoscaling, and rollback deployments. A
secret on disk is not readiness: record acknowledgments against a configuration
revision from each serving instance. Missing, failed, or outdated instances
block promotion. The deployment owns this gate and who can change write
selection.

Prove compatibility with a canary: generate one synthetic envelope and index
from the trusted target configuration, distribute that same fixture to every
reader, and on each reader authenticate, decrypt, compare the known plaintext,
and check the complete index against all local probes. Regenerating fixtures per
reader would miss mismatched material under the same ID; writing
future-generation rows into live storage would expose incompatible readers before
the gate passes. Keep baseline canaries too. Run the check on the snapshot
actually serving traffic, including after a restart. A canary proves material
compatibility, not fleet membership or the state of the store. The example's
`rotation-canary` and `rotation-ready` commands implement this.

### Procedure

1. **Encryption.** Distribute the new encryption pair to all readers, keeping the
   old pair current. Refresh or restart, and collect readiness for the baseline
   and target canaries. Then promote writers incrementally: during overlap, old
   and new ciphertext must both decrypt and search. Finish every writer before
   planning a sweep. This rotates no index keys and rewrites no rows.
2. **Blind index.** Repeat the gate for the new index pair, retaining every
   historical probe. Use a target-encryption, target-index canary: a reader can
   decrypt it and still fail its probe check. Missing index material silently
   omits matches. Promote index writers incrementally; each write seals and
   derives the indexes from the same value and persists them in one statement.

A keyring is a snapshot. Keyrings the application passes to operations come
from its own snapshot, which owns refresh, consistency, and readiness: CryptBox
calls do not distribute secrets or refresh KMS state. See the
[custom-seal obligations](../examples/custom_seal/README.md#implementor-obligations).

### Rollback

To roll back write selection, keep the union of the generations used before and
after promotion readable: select the old generation as current, never drop the
new one. Dropping the newer encryption pair breaks reads; dropping the newer
index pair hides matches even when decryption succeeds. A rolled-back binary must
also support the stored formats, persistent schema, and all-probe candidate
verification. Settle rollback policy before sweeping, because old-generation
writers reintroduce stale rows behind sweep progress.

### New suites and formats

A later cipher suite or format version, if one is ever added, must be opt-in
for writers, and passes the same gate as a key: upgrade **every** reader,
including rollback deployments, to a release that reads it before **any**
writer produces it. `Sealed::from_bytes` rejects an unknown suite or format
version (`UnsupportedSuite`, `UnsupportedFormatVersion`) when a column is
decoded, before any key is consulted, so an old reader fails on the whole row,
not just the value.

### Retirement and recovery

Stopping old writes, removing online access, retaining recovery material, and
destroying material are separate decisions. Keep historical pairs readable
throughout rewriting and verification.

**Inventory first.** For every live store and retained artifact, record its owner,
location, both roles' generation dependencies, schema and software revisions, and
retention: tables and tenants, replicas, caches, queues, projections, backups and
PITR logs, snapshots, exports, offline copies, rollback deployments, secret
versions, and migration quarantine, including other teams' copies. A recovery
manifest ties each backup's identity and capture boundary to key IDs, compatible
binary and configuration revisions, and the [persistent schema](guide.md#persistent-schema).
Keep secret material in separate custody, never in the manifest or the backup.

**Remove historical keys from online keyrings:**

1. Prove an isolated restore with the retained historical pairs **before**
   changing online access. Use consistent backup tooling: never raw-copy an
   active SQLite database without its WAL (the example's `recovery-copy` uses
   `VACUUM INTO`).
2. Complete writer promotion, then sweep and [verify](#verification) the whole
   inventory. Fence stale writers, rollback configurations, and restores; hold a
   write and restore pause through final checks and cutover, or supply equivalent
   consistency.
3. Distribute reduced keyrings and drain or restart every process. Verify
   current-only reads, audits, and searches, and that historical canaries now fail.
4. Retain the exact historical pairs separately for recovery and rehearse
   restores. Removing an online file is custody separation, not erasure.

**Restore in isolation.** Restore to a new destination, with recovery-only keys,
isolated credentials and network, and serving traffic, schedulers, imports, and
outbound effects disabled. Keep the original backup unchanged. Verify historical
canaries, authenticated reads, the full audit, the expected row set, and
historical searches. Historical searches need historical probes independently of
encryption keys: successful decryption can accompany an incomplete search.
Authentication establishes neither freshness nor row binding; the backup's
provenance and capture boundary supply the recovery point.

**Return recovered data to service.** Keep traffic fenced. Load the union of
restored and target generations into every recovery process, check readiness,
select target writes, and sweep under a **fresh run name**, never restored
progress. Repeat the audit and expected searches, accounting for loss since
capture, before routing traffic. Pre-migration backups also need the retained
legacy handler, keys, schema, and provenance evidence.

**Destroy only with evidence.** The retention owner must establish that every
dependent artifact has expired and been disposed of, been migrated with validated
recovery, or been approved as unrecoverable, including secret-store backups,
escrow, replicas, rollback copies, historical indexes, and legacy material.
Destroy through the secret store and verify across cached snapshots, running
processes, and retained copies. A clean live scan or dropped keyring proves
neither. CryptBox supplies no inventory, escrow, or erasure service.

## Maintenance sweeps

The `migrate` feature's `RowPlanner`, `Sweep`, and `SweepStore` rewrite stored
values in bounded, resumable batches: stale ciphertext to the target encryption
generation, current format, and the seal's padding policy, and stale indexes
from authenticated plaintext. A sweep therefore applies enabling or disabling
padding, but **not a resized policy** such as `Padding::block(16)` to
`Padding::block(64)`: the envelope records only whether a value is padded, so
those values count as current. The [manual SQLite example](../examples/reencryption_sweep.rs)
shows the same rules without the driver.

### Before a run

- Finish [writer promotion](#procedure), settle rollback policy, and keep
  historical keys readable, with recovery copies for backups.
- Choose a **unique, immutable, indexed cursor** with a total order. Pagination
  resumes strictly after a cursor; duplicates at a boundary silently skip rows.
- Protect the sweep like a writer: it handles plaintext. Log sanitized metadata
  only.
- Fix the run's identity: table, columns in planner order, cursor, schema
  revision, target generation IDs, readable keyset, and run name. **Do not change
  the keyrings' current keys during a run.**
- Assign one owner. Packaged stores persist only `(name, last_id)`, with no
  targets, completion flag, lease, or lock; concurrent workers can overwrite
  progress despite row-level compare-and-swap. Stop and join the old worker before
  handover.
- Resume with the same name. For a new rotation or a repair from the beginning,
  stop workers and use a fresh name, or delete that exact progress row. Saving
  cursor zero is not a reset: valid cursors may be zero or negative.

Configure `SweepTable::new(...).with_progress(table, run_name)`, register indexes
in the same order in `RowPlanner::with_index` and `SweepTable::with_index_column`,
and create the progress table with `ensure_progress_table`.

`SqliteSweepStore` and `PostgresSweepStore` use an `i64` cursor and require
**non-NULL bytes in every swept column**: a NULL stops the sweep with a decode
error. The SQLite store reads TEXT values as bytes. Packaged stores offer no NULL
policy, filter, discriminator, or upper bound; other populations need an
application-owned `SweepStore` or manual loop.

### Each batch

1. Load rows strictly after the saved cursor, in ascending order.
2. Classify. Skip current rows without writing. Rewrite stale components;
   current index bytes are retained without recomputation.
3. Write the replacement tuple atomically, guarded by **every original ciphertext
   and index byte**, including unchanged ones:

   ```sql
   UPDATE users SET email = $1, email_lookup = $2
   WHERE id = $3 AND email = $4 AND email_lookup = $5
   ```

4. A zero-row update is a concurrent write: count and skip it, never retry the
   stale plan. Save progress only after the batch succeeds.

`Sweep::run` loops to exhaustion, saving progress after each batch. An
orchestrator that journals its own progress steps through `SweepStore` itself:
`load_batch`, `RowPlanner::plan_row` and `update` for each row, then
`save_checkpoint` with the last row's cursor; an empty batch means exhaustion.
The searchable example's `sweep-batch` command does this.

**Failures.** A packaged batch is not one transaction: earlier rows may commit
before a later failure. Stop, investigate after the saved progress, fix the
cause, and resume; never jump a failed row. Reload progress after an uncertain
save. Replay skips current rows. Rewrite counters are advisory.

**Rows behind progress.** Skipped conflicts, old writers, lower-ID inserts, and
late commits can leave stale rows behind the cursor; an exhausted run cannot
revisit them. Verification finds them: fix the producer, then use a fresh run or
a guarded repair and verify again.

**Load.** Batch size bounds rows, not bytes, memory, locks, or time; throttle. For
a point-in-time claim, pause writes or implement a snapshot policy for both
rewriting and verification. Packaged stores provide neither.

**Records.** A record's fields are sealed under each row's record ID, and a
planner seals with one keyring, so partition the sweep by keys: one
`RowPlanner::for_rows(keys, |row| Ok(&row.id))` per tenant, with a store that
selects only that tenant's rows and loads the record ID into `SweepRow::columns`.
Packaged stores load no columns, so records need an application-owned
`SweepStore`. A sweep never changes a value's context; a row under another
context fails with `Error::ContextMismatch` (see
[records and tenants](guide.md#records-and-tenants)). To move a value to other
keys, open and seal the record again, or use `Sealed::reseal_across`.

### Verification

Sweep classification skips current rows without decrypting them, and
re-encryption does not decode through the codec, so a separate audit is required.
Take the expected seal, record ID type, codec, index specifications,
normalization, precision, and allowed generations from trusted application
schema, never stored metadata. [Security](security.md#what-each-check-establishes)
explains what each check establishes.

1. **Scope and consistency.** Inventory expected rows and stores and confirm every
   writer uses the target generations. Pause writes, imports, and restores
   through final checks and cutover, or repeat complete passes until clean.
2. **Migration state.** `Sweep::verify` runs a fresh read-only pass from the
   beginning, ignoring rewrite progress. Require zero legacy, stale, and malformed
   rows: check `is_terminal()` on the report of a complete pass. A clean partial
   pass proves nothing.
3. **Authenticate every value.** Parse and open each value or record with the
   intended keyring, and validate decoded application constraints. Account for
   every row.
4. **Recompute every index.** Call `BlindIndex::<Spec>::is_consistent_with` with
   the authenticated plaintext and a keyring holding exactly the allowed
   generations; it compares complete bytes. `Ok(false)` is inconsistent;
   `Error::UnknownBlindIndexKey` fails too, reported as unverifiable. After
   convergence, require bytes equal to `BlindIndex::<Spec>::derive` under the
   current generation.
5. **Reconcile.** Compare coverage with the inventory and expected searches.
   Repair only from authoritative values with full-tuple guards, then repeat the
   gates.

Generation checks read unauthenticated metadata: a wrong current-generation index
passes them. None of these checks establish provenance, freshness, row binding,
or that the database returned every row. The example's `sweep-verify` covers
step 2 and `audit-current` steps 3 and 4. A clean live pass says nothing about
backups and never authorizes key destruction: continue with
[retirement and recovery](#retirement-and-recovery).

## Legacy migration

The `migrate` feature adopts encryption over plaintext, previous-solution
ciphertext, or mixed storage during a bounded window. Plaintext is the
identity-recovery case and follows the same gates. Normal `Sealed` decoding stays
strict throughout. The [legacy](../examples/legacy_migration.rs)
and [plaintext](../examples/plaintext_migration.rs) examples introduce the API.

### Rollout

1. Inventory readers, writers, jobs, imports, replicas, rollback binaries,
   restore paths, legacy formats, trusted discriminators, and provenance evidence.
   Add index columns and agree a missing-index marker (these stores use an
   **empty byte string**, not NULL).
2. Provision CryptBox roots and legacy access. Deploy compatible readers **before
   any encrypted write**: every instance must recover legacy values, decrypt all
   generations, and run [transitional search](#transitional-search).
3. Promote every writer to atomic writes that seal and derive indexes from the
   same value. Fence old binaries and credentials and drain transactions before
   assuming the legacy population is bounded.
4. [Sweep](#maintenance-sweeps) with fixed targets, durable progress, and one
   owner. Keep compatible readers and keys until the window closes.

Use a maintenance window instead if readers cannot coexist, old writers cannot be
fenced, fallback search is too expensive, or provenance cannot be validated
online: stop traffic and jobs, back up with schema and key dependencies, sweep,
pass every closure gate, then reopen with strict readers. A plaintext-only binary
cannot roll back past encrypted writes.

### Recovering legacy values

Inject a `LegacyFormat`; its synchronous `recover` returns plaintext bytes for the
seal's codec. It owns zeroization of its own keys and intermediates and sanitized
errors. Do network recovery in a custom store or prefetch stage.

CryptBox distinguishes only its envelopes from other bytes. Route foreign formats
by trusted discriminators and authenticated headers, and allow identity recovery
only for data authorized as plaintext. **Never treat failed legacy
authentication as plaintext**: a permissive fallback accepts an attacker's
replacement of an envelope. Previous-solution AEAD authenticates only its own
policy and may allow replay or substitution. For unauthenticated formats,
including plaintext and CBC without a MAC, require validation and trusted
evidence for **every** accepted value; codec success (`Raw` rejects nothing) and
sampling prove nothing. Re-encryption protects bytes going forward, not their
origin.

Values CryptBox 0.5.0 stored are not legacy values: they carry the CryptBox
magic, so reads report `UnsupportedFormatVersion(1)` and never reach a
`LegacyFormat`, and no sweep can upgrade them. Rewrite them with a program that
depends on both versions; see
[upgrading stored values from 0.5](../CHANGELOG.md#upgrading-stored-values-from-05).

`cryptbox::migrate::MaybeSealed<F>` reads columns that may still hold legacy
values. Classification needs no keys:

- A valid envelope opens with authentication, ignoring the handler.
- Bytes without envelope magic are kept zeroized; `open` recovers them as
  plaintext, `open_legacy` through the handler.
- A malformed or unsupported envelope, or an envelope that fails authentication,
  is a hard error, **never a legacy fallback**.

`MaybeSealed` cannot be written; new writes use `Sealed::seal` (with
`BlindIndex::derive` for indexes). For legacy bytes that collide with
the `CBX\0` magic, only a trusted out-of-band discriminator may authorize
`MaybeSealed::from_legacy_bytes`.

### Transitional search

Before probe lookup, establish that every populated index is valid under a
readable generation and every missing one holds the agreed marker; a wrong
nonempty index hides matches. Otherwise scan every row, or use a maintenance
window. Select **all readable probes OR the marker** in one statement, under a
snapshot shared with the quarantine check; separate queries miss rows that move
between them. Authenticate or recover each candidate, then compare normalized
plaintext. A recovery or decoding failure fails the whole lookup, and unresolved
quarantine blocks it. Use one validation and normalization policy across writes,
recovery, reads, and closure. Switch to index-only lookup only after the window
closes.

### Running the sweep

Configure `RowPlanner::<F>::new(keys).with_legacy(handler)`, omitting
`with_legacy` only for authorized plaintext, and register indexes in stored
order. Recovered values are decoded, sealed, and indexed. For records, use
`RowPlanner::for_rows` as [above](#each-batch), and migrate only over record ID
columns whose provenance is established like legacy bytes. The planner derives
missing indexes for legacy rows but rejects empty or malformed indexes on CryptBox
ciphertext and magic collisions; repair those explicitly.

An unrecoverable row stops the run. Confirm the format against authoritative
records with restricted tooling, then **quarantine** in one transaction: copy the
evidence and remove the live row, guarded by every original byte. Quarantine is
not migration: it blocks lookup and closure until approved replacement data or an
authorized deletion resolves it. Resume after resolution; repairs behind progress
need a fresh run and fresh verification.

To repair an exceptional row, load the exact tuple and discriminator, classify it
normally (or with `from_legacy_bytes` **only** for a known collision), recover,
validate, seal and derive indexes, and write with a full-tuple guard, clearing
the discriminator in the same transaction. Writers must update format metadata
transactionally, or exceptional rows must stay fenced. See `repair` in
[migration.rs](../examples/searchable/migration.rs).

### Closing the window

Fence old writers, imports, and restores, and pause writes through verification
and the strict-reader cutover, or supply equivalent consistency.

1. Resolve every quarantine case and discriminator; removing a row resolves
   nothing.
2. Pass the full [verification](#verification): zero legacy, stale, and
   malformed rows, then strict authenticated reads, validation, and complete
   index recomputation.
3. Reconcile expected rows and searches with the inventory, and retain
   provenance evidence for unauthenticated values.
4. Replace `MaybeSealed` with strict reads; remove the handler, migration
   commands, and the `migrate` feature.
5. Restart strict readers and verify converted reads, complete searches, and a
   write, read, and search round trip before reopening traffic.

The example's `migration-close` runs gates 1 and 2. Retain historical keys, the
legacy handler and keys, and schema for pre-migration backups, rollbacks, and
quarantine, and follow [retirement and recovery](#retirement-and-recovery);
closing the window authorizes neither online removal nor destruction.

## Shredding

Destroying a tenant's root keys makes every value sealed under them unreadable,
wherever a copy of those bytes is: the copies you cannot reach, such as
snapshots, archives, and remote replicas.

| After destroying a tenant's roots | Effect |
| --- | --- |
| Sealed values, in live tables, replicas, exports, and backups | Unreadable |
| Blind-index columns | Not queryable |
| Plaintext columns, queue keys, row counts, sizes, timestamps | Untouched |
| Equal index bytes for equal values | Still correlatable |
| Leaked keys, or plaintext already copied out | Unaffected |
| The bytes themselves | On disk until storage and backups expire them |

Shredding is not erasure, revocation, or row deletion.

### Prerequisites

None of these can be established afterwards:

1. **The tenant has roots of its own**, for both roles, in its own keyring, never
   shared, destroyable independently. A tenant shares its keys' scope: workspaces
   under an org's keys cannot be shredded alone, and values under one
   process-wide keyring cannot be shredded per tenant.
2. **Custody is tested.** Sealing with the wrong keyring succeeds silently, and
   that value survives shredding unreported. See
   [choosing keyrings](guide.md#choosing-keyrings) and [testing](guide.md#testing).
3. **The inventory is complete**, as for [retirement](#retirement-and-recovery),
   including the plaintext around the sealed values.
4. **Nothing else depends on the roots**: no shared recovery keyset, rollback
   deployment, or open migration window.

Treat a tenant with undocumented or untested custody as not shreddable.

### Procedure

1. **Stop new work.** Revoke the tenant's access and disable its jobs, imports,
   and schedules.
2. **Drain in-flight work.** An operation already holding a keyring keeps it, and
   a retry after destruction fails with unavailable keys, which queues often retry
   forever. Complete or cancel work and run compensations while the keys exist.
3. **Clear in-memory copies.** Evict the tenant from key-resolution snapshots
   and keyring caches (a clone keeps keys alive until its last handle drops),
   from plaintext caches and sessions, and from precomputed probes, which stay
   valid without the key. Restart processes that loaded the roots at startup.
4. **Dispose of the plaintext around the values**: identifiers, queue and
   workflow keys and journals, unencrypted columns, search and analytics
   projections, payloads, exports, and logs.
5. **Destroy both roots** through the secret store, including its replicas,
   escrow, and backups. Until every copy is gone, the destruction is pending.
6. **Verify.** Key resolution reports both roles unavailable; a canary read and a
   lookup fail rather than return plaintext or an empty result; a neighbouring
   tenant still reads and searches; plaintext items are disposed of.
7. **Record evidence**: key IDs destroyed, when, who approved, and which
   artifacts are accepted as unreadable.

A shared recovery keyset makes a backup restore every tenant or none: keep
recovery keys per tenant where shredding is required. A restore after shredding
succeeds structurally and fails to open the tenant's values; rehearse it in
isolation beforehand to know what it still yields. Copies held by other teams are
reachable only through the inventory, and whatever they decrypted earlier stays
readable.
