# Durable SQLite storage

Store one sealed email, let the process exit, then open it in a new process. The
database and one encryption root persist across the restart.

Needs Rust 1.85+, OpenSSL, a POSIX shell, and a C compiler for bundled SQLite.
Run everything from the repository root; data goes in the ignored
`examples/sqlite/demo/` directory.

## Run it

Build, and provision a random 32-byte encryption root once:

```sh
cargo build --locked --example sqlx_sqlite --features derive,sqlx-sqlite
mkdir -p examples/sqlite/demo
(umask 077; set -C; openssl rand -hex 32 > examples/sqlite/demo/encryption-root.hex)
```

The example pairs that root with the fixed generation ID in `ENCRYPTION_KEY_ID`.
Keep the pair together for as long as the data needs it: a new root under the
same ID cannot open the stored value.

Write, then read in a second process:

```sh
cargo run --locked --example sqlx_sqlite --features derive,sqlx-sqlite -- \
  write examples/sqlite/demo/demo.sqlite3 examples/sqlite/demo/encryption-root.hex
cargo run --locked --example sqlx_sqlite --features derive,sqlx-sqlite -- \
  read examples/sqlite/demo/demo.sqlite3 examples/sqlite/demo/encryption-root.hex
```

Expect `Encrypted field stored. Run read in a new process.`, then
`Persistent SQLite read succeeded; demonstration value verified.`

`write` creates the `users` table and inserts row 1 with the ciphertext in an
`email BLOB NOT NULL` column; repeating it fails on the primary key. `read` opens
the database read-only, authenticates and decrypts row 1, and checks it without
printing plaintext or keys. Pointing `read` at a missing key file fails with
`Cannot open encryption key file`; no key is generated.

Remove `examples/sqlite/demo` to start over.

## Adapting it

`write` and `read` in [main.rs](main.rs) are the storage boundary: SQLx decoding
of `Sealed<UserEmail>` checks structure, and `open(&keys)` authenticates. Replace
`load_keys` with loading a stable ID/root pair from your secret store; `hex` and
`zeroize` are choices of this sample's file loader. A standalone value is bound
to its seal, not its row; see [records](../../docs/guide.md#records-and-tenants)
and the [persistent schema](../../docs/guide.md#persistent-schema). For equality
lookup, continue with [searchable storage](../searchable/README.md).
