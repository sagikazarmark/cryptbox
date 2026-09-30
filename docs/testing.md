# Testing and diagnostics

Use local keyrings for ordinary tests, and process isolation for the installed
keys. [Documentation](README.md).

## Local keyrings

Give each test its own encryption and blind-index keyrings. Explicit
`Sealed::seal`, `open` and `Sealed::prepare` calls take their keys and never read
the installed keys; seal binding still applies.

For runnable tests, create a library with `cargo new --lib testing-local-consumer`,
use [testing-local.toml](snippets/testing-local.toml) as `Cargo.toml`, and copy
[testing-local.rs](snippets/testing-local.rs) to `src/lib.rs`. In that project:

```sh
cargo test --lib -- --test-threads=2
```

Expect two passing tests, including concurrent round trips and verified candidate
comparison. Predictable roots and reused IDs are isolated test fixtures, never a
[durable provisioning pattern](integration.md#keyrings).

## Automatic adapters

For the design choice between automatic adapters and explicit ciphertext storage,
see [storage boundaries](integration.md#storage-boundaries). This example shows
how to exercise the automatic path with the installed keys.

An automatic SQLx column `Plain<F>` reads the installed keys; a seal does not
select its own keys. The [automatic example](snippets/testing-automatic.rs)
installs both keyrings with `keys::install` once per process, so each fixture
runs in its own process.
`Plain` serves only seals without blind indexes, since a column cannot write
its index. The example seals its indexed value explicitly with `Sealed::prepare`
and `with_index()`, and writes the pair atomically.

To test automatic columns without the installed keys, implement `ColumnKeys`
over a fixed test keyring in a `static` and use `Plain<F, TestKeys>`, as the
crate's [SQLite adapter tests](../tests/sqlx_sqlite.rs) do. Such tests run
concurrently in one process because nothing is installed or replaced.

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

`keys::install` is once per process: it cannot be reset or replaced. Install at
the binary entry point; reusable libraries let their host own it. Process-wide calls
before installation return `Error::KeysNotInstalled`, so a test binary that
installs must sequence every assertion that depends on installation, such as in
one test function.

An `RwLock` around individual key lookups does not isolate fixture replacement:
keys can change between encryption and decryption or ciphertext/index preparation.
Use separate processes, or serialize each case's entire setup/operation/cleanup
lifetime, including background work. Separate database connections are insufficient.

## Schema guardrails

Stored bytes do not describe codecs, IDs, or normalization, so a schema change
compiles and deploys silently. Pin the schema with golden-bytes fixtures
(`testing::assert_encoding`), a `schema::Manifest` snapshot, and
`assert_unique_ids!`. See [guarding the schema in CI](integration.md#guarding-the-schema-in-ci).

Choosing which keyring protects which values is application code, and a
wrong choice seals and opens without error. Seal a value with the keys the
application resolves and check it with
`testing::assert_sealed_under::<F>(&sealed, &expected_keyring)`, which fails
when the value names a key that the keyring does not hold.

## Diagnostics

Allowlist the stable `Seal::ID`, a caller-owned static label, operation and sanitized
error category. Labels must not contain record data or secrets; even schema labels
should go only to approved destinations. CryptBox does not emit logs.

Do not log plaintext, normalized/encoded values, keys, ciphertext/index dumps,
query parameters or arbitrary upstream error chains. Redacted library `Debug`
does not sanitize surrounding application data. Sanitize configuration errors at
their read boundary: `VarError::NotUnicode` can retain database credentials.

The [diagnostics example](snippets/testing-diagnostics.rs) damages a tag and emits
only the seal's identifiers plus `error=authentication_failed`. Create a binary with
`cargo new testing-diagnostics-consumer`, use
[testing-diagnostics.toml](snippets/testing-diagnostics.toml) as its manifest,
copy the source to `src/main.rs`, and run `cargo run`.

See the [searchable storage example](../examples/searchable/README.md) for restart and database behavior,
or [documentation checks](documentation.md) to run the repository's consumer checks.
