# Testing and diagnostics

**How-to · current 0.5.0 API.** Run independent application tests, exercise
automatic SQLx adapters, and report failures without exposing values or keys.
These recipes run against both published 0.5.0 and this checkout using their
own manifests. [All tasks](README.md).

Prerequisites: Rust/Cargo **1.85 or newer** and dependency network access, as in
the [first-field tutorial](first-field.md). SQLite needs no server or Tokio
runtime here: SQLx's SQLite feature bundles SQLite and the example selects
`futures-executor`. No environment variables or external keys are needed.
All predictable keys below are **public test fixtures**, never durable keys;
real encryption and blind-index roots must be generated independently and
[loaded durably](searchable-sqlx.md#2-provision-durable-key-generations-once).

## Local providers

Use explicit providers for ordinary application tests. `&()` supplies the unit
**binding context**, while `&keys` supplies a local provider; field binding still
applies. The profile's default `GlobalKeyContext` is never consulted by these
explicit operations.

1. Run `cargo new --lib testing-local-consumer` and enter that directory.
2. Replace `Cargo.toml` with this complete manifest (no CryptBox features needed):

<!-- BEGIN SHARED: testing-local-manifest -->

```toml
[package]
name = "testing-local-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
cryptbox = "=0.5.0"
zeroize = { version = "1.8.1", features = ["alloc"], default-features = false }
```

<!-- END SHARED: testing-local-manifest -->

3. Replace `src/lib.rs` with the complete [local test source](snippets/testing-local.rs).
4. Run:

```sh
cargo check --all-targets
cargo test --lib -- --test-threads=2
```

Expected: **two passing tests**. One test explicitly launches two simultaneous
threaded cases, while the second is independent test-runner work. Each owns its
encryption and blind-index keyrings; none installs a context or mutates shared
environment. The cases deliberately reuse generation IDs with different fixture
keys to expose accidental dependence on shared provider state. This ID reuse is
only for isolated fixtures, not a durable generation-management pattern.

Each case exercises `encrypt_with`, `decrypt_with`, `prepare_with`, and
`with_index_with`, derives probes with the local index provider, and decrypts
and compares a candidate. A different query is rejected by candidate comparison.
The fixture normalizer uses exact UTF-8 bytes and 128-bit indexes; choose your
application's equality and leakage policy deliberately, as explained in
[lookup guidance](searchable-sqlx.md#why-lookup-needs-verification).
Prepared storage borrows its plaintext source. The recipe checks storage
representations in memory; use the [durable consumer](#durable-searchable-consumer)
to test database writes and restart behavior.

The explicit `needs_reencryption_with` and `reencrypt_with` methods use the same
local-provider approach when testing rotation.

## Automatic adapters

Automatic SQLx encoding/decoding cannot take a provider argument. Instead, the
profile's `Keys` associated type selects a statically reachable `KeyContext`.
This recipe defines `TestKeys`, selects it with `keys: TestKeys` in `profile!`,
and stores **both** providers in an application-owned `OnceLock`. It installs
one immutable fixture per process and uses a separate in-memory SQLite database
per invocation.

1. Run `cargo new testing-automatic-consumer` and enter that directory.
2. Replace `Cargo.toml` with:

<!-- BEGIN SHARED: testing-automatic-manifest -->

```toml
[package]
name = "testing-automatic-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
cryptbox = { version = "=0.5.0", features = ["sqlx-sqlite"] }
sqlx = { version = "0.8.6", default-features = false, features = ["sqlite"] }
futures-executor = "0.3.34"
zeroize = { version = "1.8.1", features = ["alloc"], default-features = false }
```

<!-- END SHARED: testing-automatic-manifest -->

3. Replace `src/main.rs` with the complete [automatic-adapter source](snippets/testing-automatic.rs).
4. Build once, then run each fixture in its own process. On a POSIX shell:

```sh
cargo check --all-targets
cargo build
./target/debug/testing-automatic-consumer first &
first_pid=$!
./target/debug/testing-automatic-consumer second &
second_pid=$!
wait "$first_pid"
wait "$second_pid"
```

These binary paths assume Cargo's default target directory; if you set
`CARGO_TARGET_DIR`, use its `debug/` directory instead. Expected: each process
prints `Automatic adapter round trip succeeded.` and exits successfully.

Binding `Encrypted` exercises automatic encryption; decoding it exercises
authenticated decryption. The first insert deliberately leaves the separate
index column null: **automatic encryption does not maintain index columns**.
Next, context-less `prepare().with_index::<EmailLookup>()` resolves both
providers through `TestKeys`, and one SQL update writes the ciphertext/index
pair atomically. The recipe reads back the plaintext and stored index. Full
candidate lookup is covered by the local recipe and the durable tutorial.

### Why the isolation boundary differs

`GlobalKeyContext::install` accepts providers once for the **remainder of the
process**. Installation cannot be replaced or reset; a second installation
returns `KeyProviderAlreadyInitialized`. For profiles using that default context,
install at the application binary entry point before context-less operations.
Reusable library code must let its host own installation, and ordinary test
setup must not compete to install different fixtures. The custom context above
avoids installation into `GlobalKeyContext`, but its own static still lives for
the whole process: a new process is what isolates each fixture.

An application-defined context can instead delegate through synchronized,
swappable providers. **An `RwLock` around individual provider calls does not make
fixture replacement parallel-safe**: another case can replace keys between
encryption and decryption, or between ciphertext and index preparation. If you
choose shared mutable replacement, serialize every participating case across
its entire setup/operation/cleanup lifetime (including background work), or
run the cases in isolated processes. Merely using separate database connections
or serializing the replacement call is insufficient. Multiple cases can share
an immutable provider only when they intentionally share the same fixture.

### Run the checked consumer recipes

From the repository root, with Node.js **18+** in addition to Rust/Cargo:

```sh
node scripts/check-testing-consumers.mjs checkout
node scripts/check-testing-consumers.mjs published
```

Each mode creates fresh Cargo projects from the manifests and complete sources,
checks all targets, runs the local test file with two test threads, launches
the automatic cases in separate concurrent processes, checks the diagnostic
process's output, and runs Clippy with warnings denied. Add `local`, `automatic`,
or `diagnostics` as the final argument for a focused check. `checkout` patches
only CryptBox; `published` resolves crates.io 0.5.0. The shared
`check-consumers.mjs` runner includes all three in GitHub Actions and Dagger.

## Durable searchable consumer

The [SQLx tutorial](searchable-sqlx.md) is checked at its public CLI seam. Run from
the repository root with Rust/Cargo, Node.js 18+, and dependency network access:

```sh
node scripts/check-searchable-consumer.mjs checkout sqlite
node scripts/check-searchable-consumer.mjs published sqlite
```

For PostgreSQL, use the disposable PostgreSQL 18 setup in the tutorial, export
its `DATABASE_URL`, and run:

```sh
node scripts/check-searchable-consumer.mjs checkout postgres
node scripts/check-searchable-consumer.mjs published postgres
```

The database role must be able to create/drop schemas. Each run owns an isolated
`cryptbox_consumer_*` schema and drops it in cleanup; a killed process may leave
its schema behind. SQLite uses a temporary on-disk database. Both routes create
isolated Cargo projects with the exact tutorial manifest, patching only CryptBox
in `checkout` mode. `published` resolves crates.io 0.5.0. They typecheck, build,
execute the commands, and check macro-enabled builds with Clippy. They do not
inherit the library's dev-dependencies.

Assertions observe separate CLI processes: fail-closed key loading, inserts,
updates removing stale lookup tokens, null-to-value and value-to-null transitions,
deferred reads, both encryption/index generations after restart, normalized
lookup, and deterministic rejection of a false candidate. SQLx `query!` compiles
against the live schema and executes both nullable and non-null reads, plus a
prepared macro write with a custom ciphertext input override followed by lookup. Errors
from authentication are not classified as ordinary false candidates.

The same runner includes `scripts/check-rotation-consumer.mjs`, exercising the
[fleet rotation procedure](key-rotation.md) on both backends: two independently
configured instances stage and promote encryption and index keys separately,
acknowledge trusted canaries, retain all-generation lookup with candidate
filtering, and roll back current selection without losing historical access.
Every request restarts the CLI. Checks cover mismatched material under stable
IDs, premature readiness failure, independent stored generations without a sweep,
and the read failures/search omissions caused by an incompatible rollback.

`check-consumers.mjs` includes the SQLite route in the existing GitHub Actions and
Dagger docs checks. `dagger check cryptbox:test:postgres` runs both consumer modes
against its existing PostgreSQL service before the round-trip/sweep tests below.
This is actual database execution, including process exit/reload, not a
compile-only guarantee. The [docs-only reader trial](searchable-sqlx-walk.md)
separately evaluates whether the instructions supply enough information.

Append `sweep` to the focused runner to execute the
[durable maintenance walkthrough](reencryption-sweep.md#durable-postgresql-and-sqlite-walkthrough):

```sh
node scripts/check-searchable-consumer.mjs checkout sqlite sweep
node scripts/check-searchable-consumer.mjs checkout postgres sweep
node scripts/check-searchable-consumer.mjs published postgres sweep
```

This scenario selects the consumer's `maintenance` feature, checks and lints its
public-API CLI, and uses non-NULL encrypted rows. Each operation starts a fresh
process: it checks checkpoint survival, uncheckpointed writes and replay,
paginated verification, stale data behind completed progress, fresh-run recovery,
a failed batch with no checkpoint advance, competing application writes, and a
second rotation with retained-key reads/searches. SQLite uses a persistent file;
PostgreSQL uses the same isolated-schema infrastructure. Both published/checkout
SQLite variants run in the consumer checks, and both PostgreSQL variants run in
the existing Dagger service check. This supplements the connection-level cases below.

Append `recovery` with SQLite to exercise the
[backup-aware retirement walkthrough](key-retirement.md):

```sh
node scripts/check-searchable-consumer.mjs checkout sqlite recovery
node scripts/check-searchable-consumer.mjs published sqlite recovery
```

The consumer creates a pre-rotation SQLite database copy with `VACUUM INTO`,
promotes compatible writers, sweeps and audits live data, then continues online
with only E2/I2 after E1/I1 files move into a separate recovery directory. A
separate restored database and processes prove historical authenticated reads
and verified lookup. Assertions also detect an inconsistent current-generation
index, missing historical probes, and changes to the captured row set. Both
modes run through `check-consumers.mjs` in GitHub Actions and Dagger. This tests
the example's SQLite backup lifecycle, not PostgreSQL backup tooling.

Append `migration` instead for the [mixed-format migration journey](legacy-migration.md#durable-mixed-format-walkthrough):

```sh
node scripts/check-searchable-consumer.mjs checkout sqlite migration
node scripts/check-searchable-consumer.mjs published sqlite migration
node scripts/check-searchable-consumer.mjs checkout postgres migration
node scripts/check-searchable-consumer.mjs published postgres migration
```

This selects `legacy-migration`, checks candidate-verified lookup across plaintext,
authenticated illustrative legacy formats, historical/current CryptBox ciphertext
and missing projections, then exercises authentication failure, quarantine,
resume/replay, manual discriminator/missing-index repairs and separate closure
assurance. Finally it removes the online legacy module/key and builds without
migration features, checking strict reads, searches and new writes. Both SQLite
modes run in documentation consumer checks; both PostgreSQL modes reuse the
Dagger service below. These are public-consumer acceptance checks, not proof of
an application's legacy provenance or fleet coordination.

## Live PostgreSQL sweep checks

**Development checkout tooling.** From the repository root, run:

```sh
dagger check cryptbox:test:postgres
dagger check cryptbox:test:sqlx-features
```

Prerequisites: the Dagger version pinned by the repository's generated
[GitHub Actions workflow](../.github/workflows/dagger.yaml), a working Dagger
container engine (for example Docker), and network access to pull the configured
Rust and PostgreSQL images and Cargo dependencies. No host Rust installation or
existing database is required for these Dagger checks.

The PostgreSQL check reuses the service in [dagger.dang](../dagger.dang), by
default `postgres:18-trixie`. Dagger binds it as `postgres:5432`, sets
`DATABASE_URL=postgres://cryptbox:cryptbox@postgres:5432/cryptbox`, and runs:

```sh
cargo test --locked --test sqlx_postgres --test migrate_sqlx_postgres \
  --no-default-features --features migrate,sqlx-postgres -- --include-ignored
```

The expected result is **six passing tests and zero ignored tests**: four SQLx
adapter tests (including the existing live round trip) and two packaged-sweep
scenarios. The live cases are ignored in ordinary `cargo test` because they need
a server. `--include-ignored` explicitly executes them in this check. The
GitHub Actions Dagger workflow runs `dagger check` on PRs and pushes to `main`,
so this live check is part of the effective CI gate, not compilation-only coverage.

### Use an existing local test server

Alternatively, install Rust **1.85 or newer** and provide a reachable PostgreSQL
test database. Version 18 is the configured Dagger baseline. Set `DATABASE_URL`
to your test connection and run the same Cargo command above, for example:

```sh
export DATABASE_URL='postgres://cryptbox:cryptbox@127.0.0.1:5432/cryptbox'
cargo test --locked --test sqlx_postgres --test migrate_sqlx_postgres \
  --no-default-features --features migrate,sqlx-postgres -- --include-ignored
```

The example credentials are disposable development credentials. These repository
tests select Tokio through **dev-dependencies**, with no TLS feature selected.
Use a local non-TLS test connection for this command. Consumers still choose
their own runtime, TLS, credentials, and trust configuration as described in the
[feature reference](features.md); enabling a CryptBox backend does not choose them.

Use a dedicated test database, never application data. The test role needs
`CONNECT`, `CREATE` (schemas) and `TEMPORARY` privileges on that database. Each
sweep case creates a randomly named `cryptbox_sweep_*` schema with its own
`users` and `cryptbox_migration_progress` tables. This permits parallel runs,
independent connections, and reconnecting to stored progress. It drops its schema
after success or an assertion panic. A killed process can leave a schema behind;
remove that test-owned schema or recreate the disposable database before reusing
it. The adapter round trip uses a connection-local temporary table. Dagger owns
the service lifecycle and does not use an application database or a persistent
database volume.

### What the scenarios establish

[`tests/migrate_sqlx_postgres.rs`](../tests/migrate_sqlx_postgres.rs) exercises
public `RowPlanner`, `Sweep`, `SweepStore`, and `PostgresSweepStore` APIs and
observes SQLx-decoded values and database results:

- Plaintext, a toy `legacy:` representation, historical ciphertext/indexes,
  current ciphertext with a historical index, and fully current rows.
- Strict rejection of legacy bytes, permissive recovery, and authenticated
  strict reads of the converted values.
- All-readable-generation lookup before and after migration, with normalized
  candidate comparison rejecting a deliberately injected false index hit.
  Unindexed legacy rows are absent from probe lookup until backfilled; this is
  not a transitional full-search strategy.
- One-row batches over a non-contiguous `BIGINT` primary-key cursor, stored
  checkpoints, resume after closing/reopening the connection, exhaustion, and
  a fresh full generation-verification pass.
- Independent-connection writes to either ciphertext or the index causing a
  guarded-update conflict while preserving both stored columns. A successful
  update replaces both columns; replay of a stale snapshot conflicts.
  PostgreSQL counts a matching update even if assigned bytes are unchanged,
  and the store reports that case as success.

The terminal report checks **migration-state convergence**, not authentication
or stored-index consistency. Separate authenticated reads and candidate
comparisons are asserted explicitly; the injected current-generation false
index survives the sweep and is still rejected by candidate comparison. The toy
legacy handler supplies no authenticity. Connection restart checks persisted
progress, not cross-process key provisioning or backup recovery.

### Backend feature matrix and future stores

Both GitHub Actions and Dagger run the shared feature check:

```sh
sh scripts/check-sqlx-features.sh
cargo test --locked --test migrate_sqlx_sqlite --features migrate,sqlx-sqlite
```

The script checks all targets with each of `sqlx-postgres`, `sqlx-sqlite`,
`migrate,sqlx-postgres`, and `migrate,sqlx-sqlite` independently and without default
features, in addition to the existing default/all-feature checks. The second
command is the focused SQLite regression check; it needs no database service.

Every future packaged sweep store must have live-backend public-boundary tests
in the effective CI run, including pagination, checkpoints, and its backend's
guarded-update/affected-row behavior. Shared SQL construction and SQLite tests
alone cannot establish another backend's correctness. MySQL integration remains
separately tracked in [#33](https://github.com/sagikazarmark/cryptbox/issues/33).

## Diagnostics

`Field::ID` is the stable machine identifier; `Field::NAME` is a human-readable
display label that may change without migrating encrypted data. Include both
when attaching field context to application-owned errors, logs, traces, or
metrics, when your destination is allowed to see schema metadata.

Field names must not contain plaintext, record-specific data, or key material.
They may still reveal application schema, so applications decide where to emit
them. CryptBox does not emit logs or require an observability framework.

Use an allowlist: stable field ID, static diagnostic name, static operation,
and sanitized error category. Do not emit `expose_secret()` values, encoded or
normalized plaintext, keys (including hex/base64 forms), ciphertext/index dumps,
query parameters, or arbitrary upstream error chains. Ciphertext and index
tokens are sensitive stored artifacts even though they are not plaintext.
Redacted library `Debug` output does not sanitize surrounding application data.
Custom codecs, normalizers, and providers must preserve their sanitized error
contracts; application-level SQLx errors can carry additional context, so map
them to approved categories before emitting them too.

Configuration errors also need sanitization at their read boundary. In particular,
`std::env::VarError::NotUnicode` retains the original environment bytes: printing
it for `DATABASE_URL` can expose credentials. The searchable consumer maps missing
or non-UTF-8 database configuration to a static category before connecting, and
its process-level checks assert empty stdout and exact sanitized stderr for both
cases, including a synthetic secret in a non-UTF-8 environment value.

To run a complete example:

1. Run `cargo new testing-diagnostics-consumer` and enter that directory.
2. Replace `Cargo.toml` with this manifest. Only CryptBox is a direct dependency;
   output uses the standard library, with no logging dependency:

<!-- BEGIN SHARED: testing-diagnostics-manifest -->

```toml
[package]
name = "testing-diagnostics-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
cryptbox = "=0.5.0"
```

<!-- END SHARED: testing-diagnostics-manifest -->

3. Replace `src/main.rs` with the following [canonical source](snippets/testing-diagnostics.rs):

<!-- BEGIN SHARED: testing-diagnostics -->

```rust
//! Application-owned diagnostics with an allowlist of observable fields.

use cryptbox::{Ciphertext, Encrypted, EncryptionKey, Error, Field, LocalEncryptionKeyring};

cryptbox::profile! {
    UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
    }
}

fn error_category(error: &Error) -> &'static str {
    // Allowlisted categories, not arbitrary Display/Debug or error-chain content.
    match error {
        Error::AuthenticationFailed => "authentication_failed",
        Error::UnknownEncryptionKey(_) => "unknown_encryption_key",
        Error::KeyProviderUnavailable => "key_provider_unavailable",
        Error::KeyProviderNotInitialized => "key_provider_not_initialized",
        Error::NotCiphertext | Error::InvalidEnvelope => "invalid_ciphertext",
        _ => "cryptbox_error", // Error is non-exhaustive; new variants stay sanitized.
    }
}

fn main() -> Result<(), Error> {
    // Public test key only; never use this fixture for real data.
    let keys = LocalEncryptionKeyring::new(
        EncryptionKey::new(
            cryptbox::key_id!("40000000-0000-4000-8000-000000000004"),
            [0x31; 32],
        ),
        [],
    )?;
    let email = Encrypted::<_, UserEmail>::new("private-fixture@example.test".to_owned());
    let ciphertext = email.encrypt_with(&(), &keys)?;
    let mut damaged = ciphertext.as_bytes().to_vec();
    // Corrupt the authentication tag while leaving a structurally valid envelope.
    *damaged.last_mut().ok_or(Error::Internal)? ^= 1;
    let damaged = Ciphertext::<String, UserEmail>::try_from(damaged)?;
    let error = match damaged.decrypt_with(&(), &keys) {
        Err(error) => error,
        Ok(_) => return Err(Error::Internal),
    };
    assert!(matches!(error, Error::AuthenticationFailed));
    println!(
        "field_id={} field_name={} operation=decrypt error={}",
        UserEmail::ID,
        UserEmail::NAME,
        error_category(&error),
    );
    Ok(())
}
```

<!-- END SHARED: testing-diagnostics -->

4. Run `cargo check --all-targets` and `cargo run`. The program deliberately
   damages a tag and reports the resulting failure; it exits successfully after
   checking that authentication failed. Program stdout is exactly:

```text
field_id=ca274e85-63c4-4f7d-a255-2dfecbfe5e25 field_name=user-email operation=decrypt error=authentication_failed
```

The consumer checker asserts that complete line and empty program stderr,
excluding the fixture plaintext and all key material from observable output.
Cargo's own build status is separate. This is representative failure-path
coverage, not a guarantee about every future application log call. With your
own tracing/logging framework, attach these same allowlisted fields rather
than logging a whole request or error chain.

Next: follow the [stored-value assurance procedure](stored-values.md#obtain-additional-assurance)
or run the [repository checks](documentation.md).
