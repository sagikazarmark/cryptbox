# Rotate keys across staggered application instances

**How-to · published CryptBox 0.5.0 API.** Continue the
[durable searchable consumer](searchable-sqlx.md) through independent encryption
and index promotion, process restarts, and compatible rollback. [All tasks](README.md).
CryptBox remains [experimental](security.md).

## Key states and the promotion gate

A generation is an immutable **ID/root-material pair**, not a deployment version.
Provision encryption and index roots independently and preserve the
[consumer's file/ID mapping](searchable-sqlx.md#2-provision-durable-key-generations-once).
Never regenerate bytes under an existing ID. The current encryption generation
encrypts new values; the current index generation creates new stored tokens.
Readable encryption generations decrypt envelopes by their exact ID. Readable
index generations each produce a lookup probe. A readable generation can be
**staged before its first application write**, as well as retained after promotion.

The consumer accepts two independent startup selectors, `CRYPTBOX_ENCRYPTION`
and `CRYPTBOX_INDEX`. Set **both**; a partial pair or invalid value fails startup.
Each has these states:

| Selector | Current for writes | Readable/probeable | Files loaded for this role |
| --- | --- | --- | --- |
| `1` | 1 | 1 | `role-1.hex` only |
| `staged` | 1 | 1 and 2 | `role-1.hex`, `role-2.hex` |
| `2` | 2 | 1 and 2 | `role-1.hex`, `role-2.hex` |

When neither is set, the introductory `CRYPTBOX_GENERATION=1` means **both roles
staged**, and `=2` means both promoted. The explicit pair takes precedence; unset
the shorthand for this procedure to avoid ambiguity. Staging and rollback here
use `staged`, not `1`: the latter removes generation 2 from the provider.

**Before any writer promotes a role**, every participating reader must have
loaded the same new ID/material pair for that role, retained existing readable
pairs, and proved compatibility. This includes background workers, scheduled
jobs, read-only applications, and instances restarted by autoscaling or rollback.
They must use the same persistent profile/index schema, query **every** readable
index probe, and authenticate/decrypt and normalize-compare candidates. Finish
distributing the compatible configuration and validate it on every serving
instance; a secret existing on disk or a rollout merely starting is not readiness.

Inventory the participating instances and record acknowledgments for a specific
configuration revision and canary set. Hold promotion if any instance is missing,
fails, or restarts with an older snapshot. Restrict who can select the new current
generation until the gate passes. CryptBox does not coordinate this fleet gate;
the deployment/operator owns it.

## 1. Prepare two instance configurations and shared storage

Use the tutorial's manifest, **complete current source**, schemas,
and four provisioned key files. If you copied an earlier tutorial, replace
`src/main.rs` from [the shared application](searchable-sqlx.md#4-copy-the-application)
first; it includes `rotation-canary`, `rotation-ready`, and `generations`.
No new dependency or schema design is needed. Keep the same field and index
IDs as the tutorial. **Use a fresh empty database for this rehearsal.** The
completed tutorial already has E2/I2 rows; starting its existing database with
generation-1-only providers would break reads and silently omit search matches.
For an actual next rotation of that database, provision new independent E3/I3
pairs with new IDs, extend the loader, and retain E1/E2 and I1/I2 throughout the
same compatibility-first sequence.

With the tutorial's disposable PostgreSQL service still running, create a new
database once (choose another name if this one already exists):

```sh
docker exec cryptbox-searchable-postgres createdb -U cryptbox cryptbox_rotation
export DATABASE_URL='postgres://cryptbox:cryptbox@127.0.0.1:55432/cryptbox_rotation?sslmode=disable'
```

SQLite instead: choose a path that does not yet exist, then:

```sh
export DATABASE_URL="sqlite://$PWD/rotation.db?mode=rwc"
```

Keep the original tutorial database intact. Use the new URL for both instances
for the entire rehearsal.

From the consumer directory, for PostgreSQL:

```sh
cargo check
cargo build
consumer() { ./target/debug/searchable-consumer "$@"; }
```

For SQLite instead:

```sh
cargo check --no-default-features --features sqlite
cargo build --no-default-features --features sqlite
consumer() { ./target/debug/searchable-consumer "$@"; }
```

If you set `CARGO_TARGET_DIR`, use its `debug/searchable-consumer` path. With the
fresh database URL exported above, run:

```sh
export CRYPTBOX_KEY_DIR="$PWD/keys"
unset CRYPTBOX_GENERATION
A_E=1; A_I=1
B_E=1; B_I=1
a() { CRYPTBOX_ENCRYPTION="$A_E" CRYPTBOX_INDEX="$A_I" consumer "$@"; }
b() { CRYPTBOX_ENCRYPTION="$B_E" CRYPTBOX_INDEX="$B_I" consumer "$@"; }
target_keys() { CRYPTBOX_ENCRYPTION="$1" CRYPTBOX_INDEX="$2" consumer "${@:3}"; }
a init
a put 101 rollout@example.com
b get 101
b search ROLLOUT@example.com
a rotation-canary baseline.canary
```

These helpers require Bash or Zsh. A and B are two independently configured
application instances sharing storage. Each invocation is a **new OS process**
loading that instance's selected snapshot; interleaving their requests exercises
staggered deployment. The fixture does not simulate a long-lived server hot reload.
In a real deployment, execute the corresponding operations through the serving
instances, and restart each instance with its new configuration before requesting
its readiness acknowledgment. Generation 2 files are already provisioned in this
demo, but state `1` does not load them.

Expect `Schema ready.`, `Stored 101.`, `101: rollout@example.com`,
`Matches: [101]; rejected: 0.`, and `Canary saved.`.

### What the readiness command proves

`rotation-canary FILE` uses the selected **current** encryption/index pair to
prepare a synthetic known email and stores the complete envelope/token in a
two-line hex file. It does **not** connect to the database. Generate these files
once from the trusted provisioned configuration and distribute the same files
through your controlled deployment channel. Do not regenerate them separately
on each reader: that would fail to detect mismatched material under the same ID.
Do not substitute real user data in these fixtures.

`rotation-ready FILE` authenticates/decrypts that envelope, compares the known
plaintext, and checks that the stored token appears among **all** local index
probes. It prints `Ready.` only on success and otherwise exits nonzero. This
checks actual material, not just a list of IDs or structurally valid bytes.
Keep the trusted baseline canary to verify retained generation-1 access too.
The readiness tool itself does not prove fleet membership, the active
configuration of a different process, or every stored row's validity.

## 2. Stage encryption everywhere, then promote its writers

Make an out-of-band E2/I1 canary; do not write future-generation application rows
into shared storage to test readiness while B is incompatible:

```sh
target_keys 2 1 rotation-canary encryption.canary
b rotation-ready encryption.canary
```

The second command **must fail** (nonzero, unknown encryption generation). This
is the stop condition if an actual reader has not received E2. Stage A first:

```sh
A_E=staged
a rotation-ready baseline.canary
a rotation-ready encryption.canary
a put 102 rollout@example.com
b get 102
b search ROLLOUT@example.com
```

Both readiness calls print `Ready.`. A still writes E1/I1; B can read row 102 and
find `[101, 102]` with `rejected: 0`. Now stage B and finish the readiness gate:

```sh
B_E=staged
b rotation-ready baseline.canary
b rotation-ready encryption.canary
```

Only after **both** readers acknowledge compatibility, promote A, leaving B as
an old-generation writer temporarily:

```sh
A_E=2
a put 103 rollout@example.com
b put 104 rollout@example.com
b get 103
a get 101
a search ROLLOUT@example.com
b search ROLLOUT@example.com
a generations 103
b generations 104
B_E=2
b search ROLLOUT@example.com
```

Reads succeed; all searches return `[101, 102, 103, 104]` with `rejected: 0`.
Row 103 uses E2/I1, row 104 E1/I1. **Encryption promotion did not rotate the
index key** or rewrite existing rows. The `generations` command prints full
stable IDs from stored metadata, e.g. row 103:

```text
Encryption: 20000000-0000-4000-8000-000000000002; index: 30000000-0000-4000-8000-000000000003.
```

Inspection is structural only; it does not authenticate or establish index
consistency. The `get` and verified `search` calls are separate behavioral checks.

## 3. Stage index probes everywhere, then promote index writers

Keep encryption current at E2 on both instances. Stage I2 independently:

```sh
target_keys 2 2 rotation-canary index.canary
b rotation-ready index.canary
```

B can decrypt this canary but **must fail** its index check: I2 is not yet
probeable. Missing index material can otherwise cause silent search omissions.
Proceed with compatibility distribution, retaining I1 as current:

```sh
A_I=staged
a rotation-ready index.canary
a put 105 rollout@example.com
b search ROLLOUT@example.com
B_I=staged
b rotation-ready index.canary
```

Expect `Ready.` on A and B; B's intervening search returns `[101, 102, 103, 104,
105]` with `rejected: 0`. With the I2 readiness gate complete, promote A first:

```sh
A_I=2
a put 106 rollout@example.com
b put 107 rollout@example.com
a put 108 different@example.com
a demo-false-candidate 108 106
a search ' ROLLOUT@EXAMPLE.COM '
b search ' ROLLOUT@EXAMPLE.COM '
a generations 106
b generations 107
B_I=2
b search ROLLOUT@example.com
```

Every search returns `Matches: [101, 102, 103, 104, 105, 106, 107]; rejected: 1.`.
Row 106 uses E2/I2; row 107 uses E2/I1. B finds I2 tokens **before** it selects
I2 for writes because lookup uses every readable probe, not just the current one.
The deliberately corrupted row 108 tests normal false-candidate filtering: it
is decrypted but rejected by the same normalization policy used to index values.
This fixture is for a disposable database only; authentication/decoding failures
are errors, not collisions. Leave row 108 as a false candidate through the
rollback checks in section 4; cleanup is explicitly placed after those checks.

The ordinary upsert prepares ciphertext and index together and atomically writes
both. Such a write may replace a row's ciphertext too; that is not a requirement
of index rotation. A later **index-only rewrite** derives a new token from
authenticated plaintext and guards against concurrent changes; it need not
change ciphertext. See [independent index maintenance](reencryption-sweep.md#blind-indexes).

## 4. Restart and roll back compatibly

At this point both selectors are `2` on A and B. Re-run readiness against all
three canaries on both instances, then exercise retained historical reads:

```sh
for file in baseline.canary encryption.canary index.canary; do
  a rotation-ready "$file"
  b rotation-ready "$file"
done
a get 101
b get 106
```

All six checks print `Ready.`; both rows decrypt. Every CLI invocation has already
exited and reloaded the same durable ID/material pairs, providing real restart
coverage. For a long-lived deployment, readiness must run with the snapshot the
restarted service actually serves; a separate helper launched with different
configuration cannot attest to that service.

To roll back **write selection**, retain E2/I2 in both readable sets:

```sh
A_E=staged; A_I=staged
B_E=staged; B_I=staged
a get 106
b get 106
a search ROLLOUT@example.com
b search ROLLOUT@example.com
a put 109 rollout@example.com
b search ROLLOUT@example.com
a generations 109
```

The reads succeed. Before row 109, search still returns IDs 101–107 with one
rejection; afterward it returns `[101, 102, 103, 104, 105, 106, 107, 109]` with
one rejection. Row 109 is E1/I1, and both historical and newer data remain
accessible. To resume promotion after validating the fleet gate, set
`A_E=2; A_I=2; B_E=2; B_I=2` and repeat search and canary checks. Restore row 108
now; subsequent searches have zero rejections.

**Do not roll back to generation-1-only providers after any E2/I2 write.** Losing
E2 makes new ciphertext unreadable; losing I2 can silently hide matches even if
all ciphertext remains decryptable. A binary rollback must support the stored
formats, unchanged profile/index schema, all-probe lookup, and the **union of
generations used before and after promotion**. Roll back with that compatible
keyset; if an older binary cannot load it, keep compatible readers serving while
repairing the rollout. Restoring an old deployment manifest alone is insufficient.

### Provider lifecycle

This application uses explicit local providers loaded once at startup. Files or
environment changes do not mutate a running `LocalEncryptionKeyring` or
`LocalBlindIndexKeyring`; restart/drain the process to install a new snapshot.
There is no global installation in this consumer.

For applications using automatic adapters, `GlobalKeyContext::install` is
**immutable and one-time per process**. Do not call it again to replace the
providers. Restart the process, or design the originally installed custom
provider to refresh its own synchronized internal snapshot. That provider owns
refresh, consistency, error handling, and readiness: synchronous CryptBox calls
do not implement secret distribution or asynchronous KMS refresh for you. See
[provider obligations](custom-profile.md#implementor-obligations).

## Sequence and later maintenance

<!-- BEGIN SHARED: rotation -->

```mermaid
sequenceDiagram
    actor O as Operator
    participant A as Instance A
    participant PA as A provider snapshot
    participant B as Instance B
    participant PB as B provider snapshot
    participant DB as Shared storage
    participant M as Later maintenance / recovery
    Note over O,PB: Repeat independently for encryption E and index I
    O->>PA: Distribute generation 2, restart A, keep 1 current
    A->>PA: Check baseline and target canaries
    PA-->>A: 1 and 2 readable/probeable
    A-->>O: Ready for this configuration revision
    B->>DB: Continue writes with generation 1
    O->>PB: Distribute generation 2, restart B, keep 1 current
    B->>PB: Check baseline and target canaries
    PB-->>B: 1 and 2 readable/probeable
    B-->>O: Ready for this configuration revision
    Note over O,DB: Gate: ALL participating readers ready before ANY writer promotes
    O->>PA: Select 2 current, restart A
    A->>DB: Write generation 2
    B->>DB: Write generation 1, read/search both generations
    DB-->>B: Candidates require decryption and normalized comparison
    O->>PB: Select 2 current, restart B
    Note over A,PB: Compatible rollback selects 1 current but retains readable 1 and 2
    O->>M: Later, all writers promoted and rollback policy settled
    M->>DB: Guarded sweep and separate convergence / readability / index checks
    M-->>O: Inventory backups and stores, validate recovery before online retirement
```

<!-- END SHARED: rotation -->

In words: the operator provisions independent roots and distributes a compatible
snapshot to A's provider, then B's, while both still write generation 1 to shared
storage. Both instances prove they can consume the trusted target canary and
retain baseline access. Only then does the operator promote A's writer, followed
by B's. During overlap, old and new ciphertext decrypt and all readable index
generations are queried with candidate verification. Repeat these stages
independently for the other key role. Rollback changes current selection while
retaining the union of readable generations. Later, a maintenance worker can
sweep storage, verify convergence and readability, and plan online retirement
with recovery retention.

**Rotation is neither revocation nor crypto-shredding.** It changes the key for
future writes, does not invalidate existing ciphertext or leaked copies, does
not erase material, and does not itself require immediate rewriting. Keep
historical encryption keys and index probes available as long as accessible data
uses them. No online key is removed by this procedure.

Before a later [maintenance sweep](reencryption-sweep.md), finish writer promotion
everywhere, settle rollback policy (old writers can reintroduce old generations),
retain readable historical material, and choose durable run identity/checkpoints
and guarded atomic updates. Encryption convergence and index convergence are
separate. Verify structural generation state, authenticated readability, and
index/plaintext consistency separately; a generation-only scan is not all three.
Before removing online keys, inventory every store and retained artifact, preserve
the historical ID/material pairs for backups/archives/rollback data, and validate
restoration and historical lookup. Live-table convergence alone is not permission
to destroy keys. The [recovery continuation (#60)](https://github.com/sagikazarmark/cryptbox/issues/60)
owns the complete retirement/restore exercise.

## Verification and operator task

The [existing consumer checks](testing.md#durable-searchable-consumer) execute
this rollout on SQLite and live PostgreSQL, against both the checkout and
published 0.5.0, through independent CLI processes. They assert readiness failures
before staging, detection of mismatched root bytes under stable IDs, interleaved
old/new writes, independent stored generations, all-probe verified searches,
restart, and compatible rollback. They also check that dropping I2 actually omits
a match, so a successful decryption cannot masquerade as complete search coverage.

For a docs-only operator trial, start with just this page, the linked consumer
tutorial/source, the published API, and the declared Rust/database prerequisites.
Complete sections 1–4 on an isolated database, recording every command, result,
and undocumented inference. Success means both instances acknowledge readiness
before each promotion, every listed match remains visible, the false candidate
is rejected, and rollback reads/searches newer rows while writing generation 1.
This is a repeatable task, not a claim that an independent fresh-agent trial ran.

Next: [bounded maintenance and retirement prerequisites](reencryption-sweep.md).
