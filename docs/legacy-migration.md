# Migrating Legacy Data To CryptBox

**How-to · current 0.5.0 API.** Adopt encryption over existing stored data.
[All tasks](README.md) · [Concepts](concepts.md).

Deployments may adopt CryptBox over columns that contain plaintext, ciphertext
from a previous application encryption solution, or a mixture of both. The
`migrate` Cargo feature provides an explicit facility for this bounded window: a
permissive read type, an application-supplied legacy recovery handler, and a
resumable sweep driver. The steady-state decoding path stays strict throughout:
legacy data and invalid CryptBox envelopes always fail normal
`Encrypted`/`Ciphertext` decoding.

The [durable PostgreSQL/SQLite walkthrough](#durable-mixed-format-walkthrough)
extends the searchable consumer through transitional lookup, failed recovery,
manual exceptional-row repair, and a strict rebuild. The smaller [SQLite legacy
migration example] and [plaintext-only example] are in-memory API introductions.

## Preconditions

Use this compatibility-first deployment order:

1. Inventory every reader and writer: services, batch jobs, imports, replicas,
   rollback binaries and restore paths. Add the index column and agree a single
   missing-projection marker before changing writes. Inventory legacy formats,
   trusted discriminators and the source of truth for validation.
2. Provision stable CryptBox encryption and independent index keys, plus legacy
   recovery access, to the processes that need them. Deploy **compatible readers
   first**: they must recover each legacy format, decrypt all relevant CryptBox
   generations and perform the [transitional search](#transitional-search).
   Confirm readiness on every instance before any encrypted write can reach it.
3. Promote writers to atomic prepared ciphertext/index writes. During the rollout,
   readers must still handle new legacy writes. Confirm **every writer** has
   switched, fence old binaries/credentials and drain old in-flight transactions
   before relying on a bounded legacy population or starting closure gates.
   `MaybeEncrypted` has no write adapter but cannot constrain other DB clients.
4. Run the guarded sweep with fixed targets and durable progress. Keep compatible
   readers and historical keys until [closure](#verification-and-closing-the-window).

For this recipe all swept rows have non-NULL bytes. The missing index marker is
an empty byte string, **not SQL NULL**. Nullable applications need an explicit
NULL policy and a custom/manual store as described in the [sweep prerequisites](reencryption-sweep.md#durable-postgresql-and-sqlite-walkthrough).
The packaged planner derives indexes for legacy bytes, but rejects empty/malformed
indexes on existing CryptBox ciphertext. Use the demonstrated manual repair for
those rows. Give maintenance processes the same access and memory/logging controls
as application writers.

### Coordinated maintenance cutover

Use a maintenance window when old readers cannot coexist with encrypted writes,
legacy writers cannot be fenced, the fallback scan is too costly, provenance
cannot be validated online, or the required read consistency is unavailable:

1. Disable traffic and all write/import/restore jobs; drain transactions and stop
   old readers. Capture a recoverable backup with its schema and required keys.
2. Install the compatible reader/writer and maintenance build while traffic stays
   stopped. Run the walkthrough's repairs, sweep and failure recovery on storage.
   Any unresolved row keeps the cutover blocked.
3. Run fresh migration-state **and** authenticated/application/index verification.
   Install the strict build, run the final read/search/write smoke checks, then
   reopen traffic only to the new writers/readers.
4. Roll back only to a build able to read the migrated formats, or coordinate a
   full data restore with its keyset while traffic remains stopped. An old
   plaintext-only binary is not a compatible rollback after encrypted writes.

The same executable commands below work under that pause; online mode additionally
requires the readiness, writer fencing, and transitional-search gates above.

## Recovering Legacy Values

Implement `LegacyFormat` on an application-owned handler. The handler closes
over the previous solution's keys and returns plaintext bytes in a
`Zeroizing<Vec<u8>>`; CryptBox then decodes those bytes with the profile's
codec. Keep the handler explicit rather than process-global so its uses can be
found and removed when the window closes.

```rust,ignore
struct PreviousEncryption {
    key: Zeroizing<[u8; 32]>,
}

impl LegacyFormat for PreviousEncryption {
    fn recover(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, LegacyError> {
        // Parse, authenticate, and decrypt with the previous solution.
        // Return only sanitized errors; never retain bytes or key material.
        previous_decrypt(&self.key, bytes)
    }
}
```

The trait is synchronous and intended for local, CPU-bound recovery. A legacy
system that requires a network call for every value should recover values in a
custom `SweepStore` or pre-fetch step rather than block inside the handler.

When plaintext and foreign ciphertext coexist, the handler must distinguish
the previous solution's representation, normally by an authenticated header,
and use identity recovery for plaintext:

```rust,ignore
if bytes.starts_with(PREVIOUS_FORMAT_HEADER) {
    previous_decrypt(&self.key, bytes)
} else {
    Ok(Zeroizing::new(bytes.to_vec()))
}
```

CryptBox only distinguishes valid CryptBox envelopes from non-envelope legacy
bytes. It does not detect which legacy format a non-envelope value uses, and it
never writes the legacy format.

**Unauthenticated legacy formats require extra verification.** A wrong key or
corrupt value in an authenticated format fails recovery. CBC without a MAC and
other unauthenticated formats can instead produce plausible garbage that the
sweep would encrypt as authoritative data. A structured codec may reject some
garbage, but `Raw` rejects none. Require application validation and trusted
out-of-band evidence for every unauthenticated value accepted (or an explicitly
approved disposition). Sampling can help investigation but cannot establish the
provenance of unsampled rows.

Non-envelope acceptance is not authentication. An attacker able to replace a
CryptBox envelope with plausible plaintext can exploit a permissive identity
fallback. Syntax checks do not detect that replacement. Likewise, previous-solution
AEAD authenticates under its own key/AAD policy, not necessarily a row identity:
valid ciphertext can still be replayed or substituted where that policy permits.
Use trusted inventory/discriminators, access controls, business validation and
authoritative records; never reinterpret a failed AEAD tag as plaintext. Keep the
window short. Re-encryption protects the recovered bytes going forward; it cannot
retroactively authenticate their origin.

Handler implementations are responsible for zeroizing their own key material
and intermediate buffers. CryptBox zeroizes the legacy and recovered plaintext
buffers that it owns.
SQLx row buffers, database storage/backups, arguments and application clones are
outside that erasure guarantee. Treat them and quarantine copies as sensitive.
Return sanitized error categories; log access-controlled row IDs/run IDs when
needed, never bytes, plaintext, tokens, secrets or unreviewed error payloads.

## The Bounded Window

Read the column as `cryptbox::migrate::MaybeEncrypted<T, Profile>` wherever
legacy rows may still appear. `MaybeEncrypted::from_bytes` and its SQLx
`Decode` implementations classify bytes without accessing either CryptBox or
legacy keys:

- Structurally valid CryptBox envelopes are retained without authentication;
  explicit decryption later authenticates them and ignores the legacy handler.
- Bytes without the envelope magic are retained in a zeroizing legacy buffer.
  `decrypt_with` treats them as plaintext; `decrypt_with_legacy` first invokes
  the handler and then the profile codec.
- Bytes carrying the magic must be structurally valid CryptBox envelopes.
  Malformed or unsupported envelopes are hard errors and never fall back to a
  legacy handler.

Because legacy decoding is deferred, codec-invalid non-envelope bytes now
construct and SQLx-decode successfully; the codec error is returned by
`decrypt`, `decrypt_with`, `decrypt_legacy`, or `decrypt_with_legacy` instead.

`MaybeEncrypted` implements no storage `Encode` and no Serde. Once every writer
has switched to `Encrypted` or `Prepared`, new writes cannot add legacy rows;
replacing a legacy row shrinks the legacy population.

**Envelope-magic collision.** Arbitrary legacy data that begins with the 4-byte
CryptBox envelope magic is classified as CryptBox ciphertext and then fails, a
hard error rather than silently wrong data. If a discriminator column tracks
the storage format, use `MaybeEncrypted::from_legacy_bytes` for rows known to be
legacy; it bypasses envelope classification entirely. Use `from_plaintext` for
an already decoded value and `From<Ciphertext>` for known CryptBox ciphertext.
The packaged SQLx stores load bytes without discriminator columns and `RowPlanner`
uses ordinary classification. They have **no discriminator option**. Use a custom
store/manual procedure with guarded atomic writes, as exercised below; never add
a general malformed-envelope fallback.

## Transitional search

The consumer's `migration-search` uses a **single SQL statement** selecting rows
whose index matches **any readable-generation probe OR the empty marker**. Its
primary-key join to trusted format metadata is one-to-one. A row is selected once
even if multiple predicates/probes match; there is no concatenated-list duplicate.
One statement snapshot avoids an omission when a sweep moves a row from unindexed
to indexed between separate queries. The consistency claim is relative to that
statement's snapshot, not writes committed afterward.
The quarantine gate shares that snapshot: the implementation uses a read
transaction (PostgreSQL `REPEATABLE READ`, SQLite's read snapshot). A separate
read-committed gate could miss a quarantine that removes a row before selection.

Every selected row is decrypted/authenticated when applicable, recovered and
application-validated when legacy, then compared using `EmailLookup` normalization.
False candidates are rejected. Recovery failures fail the **whole** lookup with
no partial success response. Unresolved quarantine also blocks lookup so taking a
row out of the live table cannot silently make search incomplete.

Normal writes, legacy recovery, transitional reads, and closure all use the same
`validate_email` policy: after trimming surrounding whitespace, the value must be
at most 254 bytes, contain `@`, and contain only ASCII graphic bytes. Storage
preserves the original whitespace/case, and lookup trims and lowercases it. This
is illustrative application syntax, not general email validation or proof of
legacy provenance. In particular, a successful `put` of ` MiXeD@example.com `
must remain readable and searchable during migration and pass the closing audit.

Prerequisite: each populated index is a valid projection under a readable key;
every unfilled/untrusted projection is marked empty under a guarded write. Audit
that invariant before enabling this strategy. Arbitrary wrong nonempty indexes
can hide matching rows from a probe query. If you cannot establish the invariant,
scan and verify **all** rows under an appropriate snapshot, or use the maintenance
cutover. Equality/frequency leakage and candidate checks still apply.

The illustrative query materializes its candidate set, including every unindexed
row, so it suits this small rehearsal only. Measure fallback cost before an online
rollout; larger installations need bounded streaming/pagination under a consistent
snapshot and a complete-result contract. Do not simply split fallback and probe
queries or independently page a changing table without addressing movement.

**Blind-index-only gate:** all writers atomically maintain the projection, all
exceptional/quarantined rows are resolved, a fresh complete pass finds no legacy,
stale or malformed state, and a separate complete authenticated read, application
validation and index-recomputation pass succeeds. Establish those observations
under a coordinated final write pause (used here) or application-owned equivalent
consistency controls. Only then switch from `migration-search` to strict `search`.

## Durable mixed-format walkthrough

### Prepare and read the fixture

Follow the [searchable consumer](searchable-sqlx.md) for Rust/Node, runtime/TLS,
PostgreSQL service, schema and four independent persistent CryptBox key files.
Copy the current [manifest](snippets/searchable.toml), [main source](snippets/searchable.rs)
and both schemas as instructed there. Additionally copy [migration.rs](snippets/migration.rs)
to `src/migration.rs`. It is a complete consumer-owned module using public APIs.
Its optional `chacha20poly1305` and `getrandom` dependencies belong to the
**illustrative previous solution**, not to a recommended new legacy protocol.
It authenticates its header as AAD and uses random 24-byte nonces. The collision
variant deliberately starts with `CBX\0` and is identified by trusted fixture metadata.

Use a fresh disposable database, never an existing application table:

```sh
docker exec cryptbox-searchable-postgres createdb -U cryptbox cryptbox_legacy
export DATABASE_URL='postgres://cryptbox:cryptbox@127.0.0.1:55432/cryptbox_legacy?sslmode=disable'
export CRYPTBOX_KEY_DIR="$PWD/keys"
# Provision ONCE; do not replace a key needed by already stored legacy ciphertext.
(umask 077; openssl rand -hex 32 > "$CRYPTBOX_KEY_DIR/legacy.hex")
unset CRYPTBOX_GENERATION
export CRYPTBOX_ENCRYPTION=2 CRYPTBOX_INDEX=2
cargo check --features legacy-migration
cargo build --features legacy-migration
consumer() { ./target/debug/searchable-consumer "$@"; }
consumer init
consumer migration-seed
consumer migration-search ' MIXED@example.com '
consumer migration-get 60
```

For SQLite choose `DATABASE_URL="sqlite://$PWD/legacy.db?mode=rwc"` and replace
both Cargo feature selections with `--no-default-features --features sqlite,legacy-migration`.
Adjust the executable path if `CARGO_TARGET_DIR` is set. Every invocation is a new
process using the same persisted key/ID pairs and data. Do not rerun `migration-seed`.
`migration-get`/`get` print synthetic plaintext for the tutorial; do not log actual
customer values or pass them via shell history in a production tool.

| ID | Initial authoritative value | Index |
| --- | --- | --- |
| 10 | Plaintext `mixed@example.com` | empty |
| 20 | Authenticated previous-solution ciphertext of the same value | empty |
| 30 | Historical CryptBox E1 ciphertext | I1 |
| 40 | Current CryptBox E2 ciphertext | I2 |
| 50 | Current CryptBox E2 ciphertext | empty (manual backfill needed) |
| 60 | Authenticated legacy magic collision, trusted discriminator | empty |
| 70 | Plaintext `other@example.com` | empty |

Initial search returns `Matches: [10, 20, 30, 40, 50, 60]; rejected: 1.`;
row 70 is recovered but rejected by normalized comparison. `migration-get 60`
returns `60: mixed@example.com`. Every format can also be read using
`migration-get ID`. Ordinary strict reads of legacy rows remain errors.

### Fail, investigate, quarantine and resume

Record a run manifest and serialize one worker following [durable sweep ownership](reencryption-sweep.md#run-identity-and-progress-ownership).
Use identity `legacy-2`, fixed E2/I2 targets, the existing profile/index IDs, and
two-row batches. Freeze old writers before this point. The commands deliberately
corrupt only disposable fixture data:

```sh
consumer migration-damage
consumer sweep-batch legacy-2         # expected authentication failure
consumer sweep-status legacy-2        # Checkpoint: None.
consumer migration-search mixed@example.com  # expected failure, no partial results
consumer migration-quarantine
consumer migration-close              # expected unresolved-quarantine failure
consumer migration-restore
consumer sweep-batch legacy-2
consumer sweep-uncheckpointed legacy-2
consumer sweep-status legacy-2
consumer sweep-batch legacy-2
```

The failed batch may have committed row 10 before row 20 failed; its checkpoint
has not advanced. Investigate the next batch after the saved cursor using
sanitized row/error metadata and restricted recovery tooling. Confirm the legacy
key/format, compare authoritative records and preserve evidence. Never log raw
data or jump the checkpoint around the row.

`migration-quarantine` transactionally copies row 20 and removes it with a guard
on **both original columns**, rolling back on conflict. The quarantine includes
an unresolved case marker; it is sensitive retained evidence, not successful
migration. Restrict access and include it in retention/recovery inventory. Both
transitional lookup and closure stay blocked until disposition. In production,
investigation must supply approved replacement data or an explicitly authorized
business deletion. The fixture's `migration-restore` uses the known synthetic
source, inserts a prepared E2/I2 pair without overwriting a concurrent recreation,
and resolves the case in the same transaction. It retains the damaged evidence.
The CLI maps SQLx errors (including nested sweep-store errors) to the static
`database operation failed` category. The acceptance check attempts a duplicate
restore and asserts that no database detail reaches stderr.

The resumed batch reports checkpoint 20/current 2. The uncheckpointed batch
rewrites row 30, observes row 40 current, and exits with returned checkpoint 40
but saved checkpoint still 20. Replay reports checkpoint 40/current 2. As in the
[sweep recovery procedure](reencryption-sweep.md#failures-replay-and-load-bounds),
save progress only after a whole batch succeeds, reload after uncertainty, and
use fresh run identities for repairs behind completed progress. Aggregate rewrite
counters are advisory, not an inventory or closure proof.

### Repair exceptional rows without relaxing classification

```sh
consumer migration-classify 60        # expected malformed/unsupported envelope error
consumer sweep-batch legacy-2         # expected empty-index error on row 50
consumer sweep-status legacy-2        # still Some(40)
consumer migration-repair-missing
consumer sweep-batch legacy-2         # expected envelope error on row 60
consumer sweep-status legacy-2        # still Some(40)
consumer migration-repair-collision
consumer sweep-batch legacy-2         # Some(60), current 2
consumer sweep-batch legacy-2         # Some(70), legacy row rewritten
consumer sweep-batch legacy-2         # None: exhausted
consumer migration-search mixed@example.com
```

The supported manual procedure is in `repair` in [migration.rs](snippets/migration.rs):
load the exact bytes/index and trusted discriminator; use ordinary classification
for row 50, and **only for discriminator-known row 60** use
`MaybeEncrypted::from_legacy_bytes`; authenticate the previous format, validate
the recovered value, prepare current ciphertext and its index, then atomically
compare-and-swap both original columns. Clear the collision discriminator in the
same transaction and roll back if it changed. A conflict requires reloading and
investigating, never overwriting. The ordinary classifier and packaged store
continue to reject magic-bearing malformed envelopes throughout.

Application writers must coordinate discriminator metadata with the value in
the same transaction. This fixture's ordinary `put` does not manage legacy
metadata: keep row 60 under exclusive maintenance ownership until its manual
repair commits, then ordinary writers may handle it. A real online deployment
must implement that coordination or fence writes to exceptional rows.

Search now returns all six matching IDs with zero rejected candidates; there
are no unindexed rows left. Guarded writes preserve competing application updates;
the [separate executable conflict rehearsal](reencryption-sweep.md#repeat-for-a-second-rotation-and-preserve-a-competing-write)
tests that packaged updates lose rather than overwrite a newly prepared pair.

### Verify and close the rehearsal

Pause and drain writers/imports/restores for a finite final gate. Keep them paused
until strict readers are installed; these commands do not acquire a fleet lock:

```sh
consumer sweep-verify legacy-2
consumer migration-close
```

Expected: `Complete: true; current: 7; stale: 0; legacy: 0; malformed: 0.` and
`Closure verified: 7 authenticated, validated, indexed rows.` The first command
is only migration-state verification. The second rejects unresolved quarantine
or discriminators, performs another fresh full state pass, then keyset-pages
every row through strict authenticated decryption, application validation, and
complete current-index recomputation/comparison. No legacy handler is used in
that audit. It does not prove historical plaintext provenance.

The acceptance check deliberately gives row 70 a wrong **current** index: state
verification stays clean and candidate filtering rejects it, but `migration-close`
fails the independent index-consistency check. Repair through an approved guarded
write and repeat fresh verification; a clean generation report is insufficient.

Remove `src/migration.rs` from the online application and remove the guarded
`mod migration`, planner-handler injection, and command dispatch blocks in
`main.rs`. Remove the `legacy-migration` feature and its optional AEAD/entropy
dependencies from the online manifest; remove `maintenance` if no longer used.
Disable migration configuration/commands and remove online access to `legacy.hex`
after securely retaining any required recovery copy. Keep damaged quarantine
evidence and its recovery material under the separate approved retention policy.

Build the strict application with **neither** migration feature and restart it:

```sh
cargo check --no-default-features --features postgres
cargo build --no-default-features --features postgres
consumer get 10
consumer get 20
consumer get 60
consumer search MIXED@example.com
consumer search OTHER@example.com
consumer put 80 strict@example.com
consumer get 80
consumer search STRICT@example.com
```

Use `--features sqlite` for SQLite. The two original searches return
`[10, 20, 30, 40, 50, 60]` and `[70]`; the new strict write reads back and searches
as `[80]`. There is no migration fallback. Reopen traffic after these checks and
fleet strict-read readiness. Recovery-only schemas/handlers/keys remain separately
retained for older artifacts; live closure is not permission to destroy them.

### Execute the acceptance check

From the repository root (Node.js 18+, Rust/Cargo 1.85+, and a disposable
PostgreSQL `DATABASE_URL` for PostgreSQL):

```sh
node scripts/check-searchable-consumer.mjs checkout sqlite migration
node scripts/check-searchable-consumer.mjs published sqlite migration
node scripts/check-searchable-consumer.mjs checkout postgres migration
node scripts/check-searchable-consumer.mjs published postgres migration
```

The harness creates independent key files, uses a persistent SQLite file or an
isolated PostgreSQL schema, and runs each command in a new process. It asserts
all results/failures above, checks and lints the consumer's declared dependencies,
then physically removes the legacy module and online key and rebuilds without
either migration feature before strict read/search/write checks. The feature-gated
references are inactive in that check; the production cleanup above removes them
entirely. SQLite runs in consumer documentation checks; PostgreSQL runs in the
[existing Dagger database check](testing.md#live-postgresql-sweep-checks).

## Running The Sweep

Configure a `RowPlanner` with the profile context, CryptBox key provider,
legacy handler, and each blind-index column in stored order:

```rust,ignore
let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
    .with_legacy(&previous_encryption)
    .with_index_with::<EmailLookup>(&index_keys);
```

Omit `with_legacy` for a plaintext-only migration; non-envelope bytes then use
identity recovery and decode directly through the profile's codec.

Drive the planner with `Sweep` over a `SweepStore`:

- `SqliteSweepStore` and `PostgresSweepStore` cover tables with an integer
  cursor column. A `SweepTable` names the table, cursor, ciphertext, and index
  columns. The cursor must contain unique, immutable values: pagination resumes
  strictly after the checkpoint, so a non-unique cursor silently skips rows at
  a batch boundary during both sweeping and verification.
- Any other store or cursor shape can implement `SweepStore` directly under
  the same unique total-order cursor contract.

`Sweep::run` resumes from the durable checkpoint and, per row, recovers and
encrypts legacy data (deriving every registered index), re-encrypts stale
envelopes, re-derives stale indexes from authoritative decrypted ciphertext,
and skips current rows without consuming nonces. Updates are compare-and-swap
against all originally read bytes. A row lost to a concurrent writer is counted
as a conflict and deliberately not retried. The checkpoint advances only after
a whole batch succeeds, so replay after a crash is safe.

An unrecoverable legacy row stops the run for investigation just like a
malformed envelope. The durable checkpoint bounds the search to one batch. Fix
or quarantine the row, then resume.

## Stepped Execution And Durable Runtimes

`Sweep::run` loops to exhaustion, but external orchestrators can drive one
batch at a time:

- `Sweep::run_batch` processes one batch using the store's durable checkpoint.
- `Sweep::process_batch` takes and returns a cursor without checkpoint IO, so a
  durable-execution runtime can journal progress itself.
- `Sweep::verify_batch` steps the read-only verification pass. Sum batch
  reports with `SweepReport::merge`.

Batch replay is idempotent: current rows are skipped and updates compare the
originally read bytes. Under replay, summed reports may overcount conflicts, so
treat run reports as advisory and a full terminal verification pass as authoritative
only for migration-state convergence.

## Verification And Closing The Window

Use the complete [closing rehearsal](#verify-and-close-the-rehearsal), including
all the gates below. A terminal generation report is necessary but insufficient.
Confirm every writer uses the target generations, fence old binaries/imports/
restore paths, and pause and drain writes through validation and strict-reader
cutover (or provide an equivalent application-owned consistency boundary).

`Sweep::verify` checks **structure and generation state only**. It does not decrypt current
rows, establish authenticated readability or decoded-value validity, or recompute
indexes to check consistency. Its metadata remains unauthenticated. For stepped
verification, start without a cursor, merge every batch, and continue until the
returned checkpoint is `None`; a clean partial or default report is insufficient.
Before removing permissive reads or switching to blind-index-only lookup:

1. Resolve every quarantine case and trusted legacy discriminator under the
   documented recovery/disposition policy. Removing a row from the live table
   does not resolve its case or establish complete lookup.
2. Run a fresh **complete** migration-state pass with zero legacy, stale, and
   malformed rows. Do not reuse rewrite progress as verification progress.
3. Complete the [authenticated-read, application-validation, and index-recomputation procedure](stored-values.md#obtain-additional-assurance)
   over every row. A wrong current-generation token can pass step 2 while hiding
   a matching row from searches. Any failure blocks closure; repair through an
   approved guarded write and repeat the full gates.
4. Account for expected row/search coverage against the migration inventory.
   Preserve the provenance evidence required for unauthenticated legacy values;
   successful re-encryption cannot retroactively authenticate their origin.

The consumer's `migration-close` checks quarantine/discriminators, full generation
convergence, and the shared paginated authenticated/application/index audit.
The operator supplies the write pause, inventory, and provenance evidence.

Only after **all** these gates pass:

**A clean live-data pass does not establish that backups or other stores no longer
need historical or legacy keys.** Online removal, recovery retention, and key
destruction are distinct decisions.
Follow the [tested backup-aware retirement and isolated restore](key-retirement.md)
for historical CryptBox ciphertext and indexes; retain legacy handlers/material
as well when a pre-migration artifact needs them.

1. Replace `MaybeEncrypted` reads with strict `Encrypted`/`Ciphertext` reads.
2. Delete the legacy handler and confirm no references to its type remain.
3. Disable the `migrate` feature.
4. Rebuild/restart strict readers and verify authenticated reads, complete searches,
   and a prepared write/read/search round trip before reopening traffic.
5. Remove historical CryptBox keys and probes from converged online stores following the
    [re-encryption sweep guide](reencryption-sweep.md).
6. Retain historical CryptBox and previous-solution keys, index keys, and recovery
   schema/handlers for backups and rollback artifacts that still require them.
   Test restoration, including historical probes or re-indexing for lookup.
7. Destroy key material only after all dependent artifacts expire, are migrated,
   or are deliberately made unrecoverable under the retention policy.

[SQLite legacy migration example]: ../examples/legacy_migration.rs
[plaintext-only example]: ../examples/plaintext_migration.rs
