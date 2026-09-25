# Testing and diagnostics

**How-to · published CryptBox 0.5.0 API.** Use local providers for ordinary tests
and process isolation for static key contexts. [All tasks](README.md).

## Local providers

Give each test its own encryption and blind-index keyrings. Explicit
`encrypt_with`, `decrypt_with` and `prepare_with` calls bypass the profile's
global key context. `&()` supplies unit binding context; field binding still applies.

For runnable tests, create a library with `cargo new --lib testing-local-consumer`,
use [testing-local.toml](snippets/testing-local.toml) as `Cargo.toml`, and copy
[testing-local.rs](snippets/testing-local.rs) to `src/lib.rs`. In that project:

```sh
cargo test --lib -- --test-threads=2
```

Expect two passing tests, including concurrent round trips and verified candidate
comparison. Predictable roots and reused IDs are isolated test fixtures, never a
[durable provisioning pattern](searchable-sqlx.md#2-provision-durable-key-generations-once).

## Automatic adapters

Automatic SQLx encryption/decryption resolves providers through the profile's
`Keys: KeyContext`. The [automatic example](snippets/testing-automatic.rs) selects
`keys: TestKeys` and holds both providers in an application-owned `OnceLock`.
Automatic encryption does not maintain index columns; the example also uses
`prepare().with_index()` and writes the pair atomically.

Create a binary with `cargo new testing-automatic-consumer`, use
[testing-automatic.toml](snippets/testing-automatic.toml) as its manifest, and copy
the source to `src/main.rs`. SQLite needs a native C compiler, but no server.
Run each fixture in its own process:

```sh
cargo run -- first
cargo run -- second
```

Each prints `Automatic adapter round trip succeeded.`

### Why the isolation boundary differs

`GlobalKeyContext::install` is once per process: it cannot be reset or replaced.
Install at the binary entry point; reusable libraries let their host own it.
A custom static context also lives for the whole process.

An `RwLock` around individual provider calls does not isolate fixture replacement:
keys can change between encryption and decryption or ciphertext/index preparation.
Use separate processes, or serialize each case's entire setup/operation/cleanup
lifetime, including background work. Separate database connections are insufficient.

## Diagnostics

Allowlist the stable `Field::ID`, static `Field::NAME`, operation and sanitized
error category. Names must not contain record data or secrets; even schema labels
should go only to approved destinations. CryptBox does not emit logs.

Do not log plaintext, normalized/encoded values, keys, ciphertext/index dumps,
query parameters or arbitrary upstream error chains. Redacted library `Debug`
does not sanitize surrounding application data. Sanitize configuration errors at
their read boundary: `VarError::NotUnicode` can retain database credentials.

The [diagnostics example](snippets/testing-diagnostics.rs) damages a tag and emits
only field context plus `error=authentication_failed`. Create a binary with
`cargo new testing-diagnostics-consumer`, use
[testing-diagnostics.toml](snippets/testing-diagnostics.toml) as its manifest,
copy the source to `src/main.rs`, and run `cargo run`.

See [durable SQLx integration](searchable-sqlx.md) for restart and database behavior,
or [documentation checks](documentation.md) to run the repository's consumer checks.
