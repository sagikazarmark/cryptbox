# Testing and diagnostics

**How-to · current 0.5.0 API.** These are the existing local-provider and
automatic-adapter patterns, moved from the project landing page. A complete
consumer testing recipe is tracked in
[#56](https://github.com/sagikazarmark/cryptbox/issues/56). [All tasks](README.md).

## Local providers

Applications that use context-less methods or automatic storage adapters should
install `GlobalKeyContext` once in the binary entry point. Do not install it from
test setup or reusable library code: it is process-global and cannot be replaced
or reset. Most tests should keep their keyring local and use the explicit
`encrypt_with`, `decrypt_with`, `prepare_with`, `with_index_with`,
`needs_reencryption_with`, and `reencrypt_with` methods. This keeps tests
independent and safe to run in parallel.

## Automatic adapters

Tests that exercise automatic storage adapters cannot pass a provider directly.
Such a test binary can select an application-defined `KeyContext` whose provider
delegates through an `RwLock`:

```rust
use std::sync::{OnceLock, RwLock};

use cryptbox::{
    BlindIndexKeyProvider, EncryptionKey, EncryptionKeyProvider, KeyContext,
    KeyId, KeyProviderError, LocalEncryptionKeyring,
};

struct TestKeys(RwLock<LocalEncryptionKeyring>);

static TEST_KEYS: OnceLock<TestKeys> = OnceLock::new();

impl TestKeys {
    fn replace(keys: LocalEncryptionKeyring) -> Result<(), KeyProviderError> {
        let context = TEST_KEYS.get_or_init(|| Self(RwLock::new(keys.clone())));
        *context.0.write().map_err(|_| KeyProviderError::Unavailable)? = keys;
        Ok(())
    }
}

impl EncryptionKeyProvider for TestKeys {
    fn current_key(&self) -> Result<EncryptionKey, KeyProviderError> {
        self.0
            .read()
            .map_err(|_| KeyProviderError::Unavailable)?
            .current_key()
    }

    fn key(&self, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        self.0
            .read()
            .map_err(|_| KeyProviderError::Unavailable)?
            .key(id)
    }
}

impl KeyContext for TestKeys {
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, KeyProviderError> {
        TEST_KEYS
            .get()
            .map(|keys| keys as &dyn EncryptionKeyProvider)
            .ok_or(KeyProviderError::NotInitialized)
    }

    fn blind_index_keys() -> Result<&'static dyn BlindIndexKeyProvider, KeyProviderError> {
        Err(KeyProviderError::Unavailable)
    }
}
```

Set `type Keys = TestKeys` on profiles used by those tests and call
`TestKeys::replace` before each case. The context is still shared across the test
process, so tests that replace it must be serialized. Add a second locked
provider when automatic blind-index operations also need test-specific keys.

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

`check-consumers.mjs` includes the SQLite route in the existing GitHub Actions and
Dagger docs checks. `dagger check cryptbox:test:postgres` runs both consumer modes
against its existing PostgreSQL service before the round-trip/sweep tests below.
This is actual database execution, including process exit/reload, not a
compile-only guarantee. The [docs-only reader trial](searchable-sqlx-walk.md)
separately evaluates whether the instructions supply enough information.

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
metrics. This is an illustrative fragment requiring the application's `tracing`
dependency, field declaration, and sanitized error:

```text
tracing::warn!(
    error = %error,
    field_id = %UserEmail::ID,
    field_name = UserEmail::NAME,
    operation = "decrypt",
    "CryptBox operation failed",
);
```

Field names must not contain plaintext, record-specific data, or key material.
They may still reveal application schema, so applications decide where to emit
them. CryptBox does not emit logs or require an observability framework.

Next: follow the [stored-value assurance procedure](stored-values.md#obtain-additional-assurance)
or run the [repository checks](documentation.md).
