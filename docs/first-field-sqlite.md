# Store your first field in SQLite

**Example · published CryptBox 0.5.0 API.** Continue from
[your first field](first-field.md). [All tasks](README.md).

[`examples/sqlx_sqlite.rs`](../examples/sqlx_sqlite.rs) stores a field-bound email
in an **in-memory database with ephemeral keys**. Run from the repository root:

```sh
cargo run --locked --example sqlx_sqlite --features sqlx-sqlite
```

Expect `Field-bound SQLite round trip succeeded.`

For a standalone project, run `cargo new sqlite-consumer`, replace its
`Cargo.toml` with [sqlite.toml](snippets/sqlite.toml), and copy the example to
`src/main.rs`. Run `cargo run` in that project. The manifest enables CryptBox's
`sqlx-sqlite` adapter, SQLx 0.8's `sqlite` feature, and `futures-executor` to drive
this SQLite-only program. Bundled SQLite needs a native C compiler; no server is needed.

## Storage boundary

The example prepares with a local provider, binds `prepared.ciphertext()` into a
`BLOB`, and reads `Ciphertext<String, UserEmail>` with `row.try_get("email")`.
SQLx decoding checks structure; `decrypt_with(&(), keys)` authenticates and decodes.
Preparation borrows the original plaintext, and no global provider is installed.

When adding indexes, derive them from the same preparation and write them with
ciphertext atomically. Automatic encryption does not maintain an index column.
Continue with [durable keys, updates and verified search](searchable-sqlx.md).
