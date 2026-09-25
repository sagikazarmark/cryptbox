# Retire online keys while preserving backup recovery

**How-to · published CryptBox 0.5.0 API.** Continue the
[compatible fleet rollout](key-rotation.md) and [durable sweep](reencryption-sweep.md)
through online removal and an isolated restore. [All tasks](README.md).
CryptBox remains [experimental](security.md).

## Five separate decisions

| Step | Preconditions and effect |
| --- | --- |
| Stop new writes with a generation | Stage compatible readers first, then promote **all** writers, including workers, importers and rollback deployments. Old data still requires historical reads/probes. |
| Retain readable generations | Keep exact historical encryption ID/material pairs for decryption and index ID/material pairs for probes while any accessible data needs them. This includes the sweep and verification window. |
| Remove historical online access | Inventory every affected live store, converge it, validate authenticated readability and index consistency, and prevent stale writers/restores from reintroducing dependencies. Restart/drain all relevant processes with the reduced provider snapshot. |
| Retain recovery-only material | Preserve the historical pairs, schema and compatible software in an application-controlled recovery environment for retained artifacts. Prove a restore works before releasing online access. Recovery retention can overlap the earlier steps. |
| Destroy material | Make a separate, evidenced retention decision covering **all** dependent artifacts and key copies; see [destruction evidence](#evidence-before-eventual-destruction). Online removal alone never authorizes it. |

Rotation and online removal are **neither revocation nor crypto-shredding
guarantees**. Someone retaining keys and ciphertext can still decrypt them;
removing providers cannot invalidate leaked copies or revoke previously exposed
plaintext. CryptBox supplies no backup inventory, secret escrow or erasure service.

## Inventory before retirement

Record an owner, location, generation dependencies (encryption **and** index),
schema/software revision, retention disposition, and last successful restore
evidence for each relevant item:

- Every table/column, database, tenant store, replica, cache, queue, object store
  and downstream projection that retains encrypted bytes or index tokens.
- Database backups, point-in-time recovery logs, snapshots, archives, exports,
  offline copies, and copies held by another team or environment.
- Rollback databases, deployment manifests/images, secret versions, migration
  quarantine, and legacy recovery handlers/keys where applicable.

Keep the backup identifier, capture time, consistency boundary, schema revision,
stable key IDs and required binary/configuration revision together in a recovery
manifest. Keep secret material under separately controlled access, not embedded
in that manifest or the database backup. Retain field/index IDs, binding, codec,
padding, normalization and precision; retaining root bytes alone is insufficient.

**A clean live-table scan cannot justify destruction:** it says nothing about
an earlier backup, a replica outside the scan, an exported index, a legacy
quarantine row, or a rollback artifact. Even a live generation scan is structural,
not an authenticated-read or index-consistency audit.

## 1. Capture a pre-rotation copy

This bounded rehearsal uses **SQLite** and the same public consumer as the
PostgreSQL rotation/sweep guides. It exercises a complete database copy, not a
general backup platform. For PostgreSQL, use your established consistent
backup/restore tooling and isolated database with the same gates below; this
fixture does not validate that tooling.

Follow the [searchable consumer setup](searchable-sqlx.md) for its manifest,
complete [current source](snippets/searchable.rs), two SQL schema files, and four
independently provisioned persistent key files. Use a fresh consumer working
directory/database for this rehearsal; never substitute an existing application
database. The source adds `2-only`, `audit-current`, and `recovery-copy`.
From the consumer directory, in Bash or Zsh:

```sh
cargo check --no-default-features --features sqlite,maintenance
cargo build --no-default-features --features sqlite,maintenance
export CRYPTBOX_KEY_DIR="$PWD/keys"
unset CRYPTBOX_GENERATION
export DATABASE_URL="sqlite://$PWD/retirement-live.db?mode=rwc"
consumer() { ./target/debug/searchable-consumer "$@"; }
old() { CRYPTBOX_ENCRYPTION=1 CRYPTBOX_INDEX=1 consumer "$@"; }
staged() { CRYPTBOX_ENCRYPTION=staged CRYPTBOX_INDEX=staged consumer "$@"; }
current() { CRYPTBOX_ENCRYPTION=2 CRYPTBOX_INDEX=2 consumer "$@"; }
online() { CRYPTBOX_ENCRYPTION=2-only CRYPTBOX_INDEX=2-only consumer "$@"; }
old init
old put 10 recovery@example.com
old put 20 recovery@example.com
old rotation-canary baseline.canary
(umask 077; old recovery-copy "$PWD/before-rotation.db")
```

Adjust the binary path if `CARGO_TARGET_DIR` is set. Every call exits its OS
process. `recovery-copy NEW_FILE` uses SQLite `VACUUM INTO` to capture a consistent
standalone database including committed WAL data, and refuses an existing
destination. It prints `Database copy saved.`. Quiesce/drain all writers for this
rehearsal; no process keeps this database open between commands. Do not raw-copy
an active SQLite database and ignore its WAL. Preserve the completed backup
unchanged and restrict access: other columns/metadata remain unencrypted.

Record this backup's dependency mapping:

| Role/file | Stable ID | Used in backup |
| --- | --- | --- |
| E1 / `encryption-1.hex` | `10000000-0000-4000-8000-000000000001` | Envelopes |
| I1 / `index-1.hex` | `30000000-0000-4000-8000-000000000003` | Search tokens |
| E2 / `encryption-2.hex` | `20000000-0000-4000-8000-000000000002` | Not yet; subsequent live writes |
| I2 / `index-2.hex` | `40000000-0000-4000-8000-000000000004` | Not yet; subsequent live tokens |

Never generate replacement material under these IDs. Retain the original E1/I1
pairs, profile `ca274e85-63c4-4f7d-a255-2dfecbfe5e25`, index
`80000000-0000-4000-8000-000000000008`, and the consumer's unchanged schema policy.
Before an actual online removal, rehearse section 4 on an isolated copy using
your retained recovery material while online history is still available. Repeat
it after removal as demonstrated here to verify separation.

## 2. Complete compatible promotion and live convergence

Apply the [fleet readiness gate](key-rotation.md#key-states-and-the-promotion-gate)
to every participating reader/writer. This shortened rehearsal starts two staged
processes with the same controlled configuration; the rotation guide exercises
staggered and independent role promotion in detail:

```sh
current rotation-canary target.canary
staged rotation-ready baseline.canary
staged rotation-ready target.canary  # instance A
staged rotation-ready baseline.canary
staged rotation-ready target.canary  # instance B
current put 30 recovery@example.com
current put 40 different@example.com
current search RECOVERY@example.com
current sweep-batch retire-2
current sweep-batch retire-2
current sweep-batch retire-2
current sweep-verify retire-2
current audit-current
```

Canary checks print `Ready.`; search returns `[10, 20, 30]` with zero rejections.
The sweep's two-row batches report stale 2, then current 2, then exhaustion.
Record `retire-2` as a fresh run targeting E2/I2 with one progress owner.
Every writer must now use E2/I2; stop old-generation write-selection rollback.
Hold the write/restore pause across final checks and provider cutover. This gives
the small fixture a finite, stable population; CryptBox does not create a fleet
barrier or snapshot across paginated commands.

Expect:

```text
Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.
Audited: 4 authenticated, current-index rows.
```

The first is a fresh structural/generation pass. `audit-current` separately
pages from the beginning (two rows at a time), authenticates/decrypts and UTF-8
decodes each value, and recomputes/compares the **complete** stored token under
the current index key. This demo accepts any UTF-8 `String`; add application
domain validation where your profile requires it. Neither command tolerates
NULL maintenance rows; this is the [sweep fixture's policy](reencryption-sweep.md#prepare-the-consumer).
Count expected rows against your inventory as well as checking command success.

To see why both checks matter on this disposable fixture:

```sh
current demo-false-candidate 40 30
current sweep-verify retire-2
current audit-current
```

Verification still reports all four current, but the audit **must fail** with
`index consistency check failed`. Stop retirement until repaired. Restore the
known synthetic value through an atomic application write and repeat both gates:

```sh
current put 40 different@example.com
current sweep-verify retire-2
current audit-current
```

## 3. Remove historical online providers, retain recovery material

Only after the inventory-wide gates and recovery rehearsal pass, distribute the
reduced online snapshot to every relevant application, worker, job and rollback
configuration. Explicit providers here load once at startup: drain/restart to
replace them. Global installation is also one-time; see
[provider lifecycle](key-rotation.md#provider-lifecycle). Do not count a file edit
as proof that a running process dropped its historical provider.

Both selectors now support `2-only`: current/readable E2 or I2, loading only that
role's generation-2 file. Ordinary `2` still loads 1 and 2 for compatible rollout.
This demo models separate recovery custody by moving files out of the online
directory after every CLI process has exited:

```sh
(umask 077; mkdir recovery-keys)
mv keys/encryption-1.hex recovery-keys/
mv keys/index-1.hex recovery-keys/
online audit-current
online search RECOVERY@example.com
online rotation-ready baseline.canary
```

The audit reports four rows and search still returns `[10, 20, 30]`. The final
baseline readiness command **must fail**: the online provider cannot decrypt E1.
Starting the old `current` helper also fails key loading because files 1 are
absent. Use `online` for normal service from here onward. Moving files is a
fixture for custody separation, **not** secure erasure or a secret-storage
recommendation. The application owns recovery storage, credentials, access and
retention durations. This rehearsal deliberately retains the historical material.

## 4. Restore and search in isolation

Use a new recovery database path, separate processes and recovery-only key
directory. For a deployment, isolate credentials/network routing and disable
serving traffic, schedulers, imports and outbound side effects before startup.
Do not restore over the live database or install historical configuration in
normal service. Copy the closed standalone backup while keeping it intact:

```sh
test ! -e isolated-recovery.db && cp before-rotation.db isolated-recovery.db
recovery() {
  DATABASE_URL="sqlite://$PWD/isolated-recovery.db?mode=rw" \
    CRYPTBOX_KEY_DIR="$PWD/recovery-keys" \
    CRYPTBOX_ENCRYPTION=1 CRYPTBOX_INDEX=1 consumer "$@"
}
recovery rotation-ready baseline.canary
recovery get 10
recovery get 20
recovery audit-current
recovery search ' RECOVERY@EXAMPLE.COM '
```

Stop if the copy command fails; never reuse an existing restore destination.
The canary prints `Ready.`; rows 10 and 20 decrypt to `recovery@example.com`;
the audit reports **two** authenticated/current-index rows and search returns
`Matches: [10, 20]; rejected: 0.`. Row 30 is absent because it was inserted after
capture. Here “current” means E1/I1 in the isolated historical configuration,
not convergence to the live E2/I2 target. Authentication establishes readability,
not freshness or row binding; trusted backup provenance and the recorded capture
boundary supply the recovery point.

This path uses **retained historical probes** during recovery; no index rewrite
is necessary for this isolated read-only task. I1 is essential independently of
E1. To demonstrate the omission failure on the restored copy:

```sh
cp keys/index-2.hex recovery-keys/
DATABASE_URL="sqlite://$PWD/isolated-recovery.db?mode=rw" \
  CRYPTBOX_KEY_DIR="$PWD/recovery-keys" \
  CRYPTBOX_ENCRYPTION=1 CRYPTBOX_INDEX=2-only consumer get 10
DATABASE_URL="sqlite://$PWD/isolated-recovery.db?mode=rw" \
  CRYPTBOX_KEY_DIR="$PWD/recovery-keys" \
  CRYPTBOX_ENCRYPTION=1 CRYPTBOX_INDEX=2-only consumer search recovery@example.com
```

The read succeeds but search incorrectly returns `Matches: []; rejected: 0.`.
A successful decrypt is not evidence of complete lookup. Resume the `recovery`
helper's historical I1 configuration; do not treat the negative search as absence.
The automated test also confirms the audit rejects this index configuration.
Finally, `online get 30` and `online search RECOVERY@example.com` still succeed
against live storage with E2/I2 only.

### Returning recovered data to service

This rehearsal ends with isolated historical reads. If recovered data must serve
normal traffic, select an explicit, coordinated cutover:

1. Load the union of all generations needed by the restored data and intended
   target writes into **every recovery reader/writer** before any target write.
   Preserve stable IDs/schema and query every readable index probe. Validate
   readiness on the configuration actually serving, including restarted jobs.
2. Keep normal traffic fenced. Select the intended current pair, sweep with a
   **fresh recovery run identity** (never blindly resume restored progress), and
   repeat full convergence, authenticated reads, domain validation, index checks
   and expected-result searches. Account for data lost since the recovery point.
3. Only after those gates pass, route traffic to that verified environment with
   compatible application/rollback configuration. If returning to E2-only service,
   first rewrite all E1/I1 dependencies there. An alternative historical-key
   serving cutover requires fleet-wide compatibility and an explicit policy
   decision; never silently reintroduce E1/I1 writers into E2-only service.

Recovering legacy pre-migration backups additionally requires the recorded
legacy handler/keys and provenance checks from the
[migration closure procedure](legacy-migration.md#verification-and-closing-the-window).
Strict live closure does not erase those recovery dependencies.

## Evidence before eventual destruction

The retention owner needs evidence that every dependent store/artifact from the
inventory has expired and been disposed of, been migrated with separately
validated recovery, or been explicitly approved to become unrecoverable. Include
backups of secret stores, escrow/replicas, archives/exports, deployment rollback
copies, historical index dependencies, and legacy material. Verify the surviving
recovery set with restore tests and document the accepted loss of access to any
remaining artifact. Preserve audit metadata without retaining secrets in logs.

Then execute and verify destruction through the application's secret/storage
mechanisms, accounting for running processes, cached key snapshots and retained
copies. Removing a file or dropping an online keyring is not evidence of physical
erasure or destruction of all copies. Retention durations, authorization and
secret-storage mechanisms remain application-owned. This walkthrough destroys
no key material and makes no claim of revoking access held by others.

## Check the walkthrough

From the repository root with Rust/Cargo, Node.js 18+ and dependency access:

```sh
node scripts/check-searchable-consumer.mjs checkout sqlite recovery
node scripts/check-searchable-consumer.mjs published sqlite recovery
```

The [consumer-level database test](../scripts/check-recovery-consumer.mjs)
checks the same commands with independent temporary keys and separate OS
processes. It captures a SQLite database, converges live data, detects a
generation-current inconsistent token, physically removes historical files from
the online directory, and restores into a separate database. It asserts
authenticated values, the pre-rotation row set, correct historical search,
missing-probe omissions, and continued live availability. Both modes run in the
existing GitHub Actions and Dagger consumer checks. This verifies the example's
lifecycle, not a deployment's backup system or retention policy.

For a docs-only operator trial, use this page and its linked public consumer
sources/prerequisites. Record backup/configuration identities, gate outcomes,
expected failures, restored row/search results and any undocumented inference.
This is a repeatable task, not a claim that an independent reader trial ran.

Next: preserve the recovery manifest and schedule restore rehearsals under your
application's retention policy; see [security boundaries](security.md).
