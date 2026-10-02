# Store your first sealed value in SQLite

Store one sealed email, let the writing process exit, then authenticate and
decrypt it in a new process. You will keep both the SQLite database and one
independently provisioned encryption root across the restart.

Continue from [seal your first value](../../docs/first-field.md).
[Examples](../README.md) · [Documentation](../../docs/README.md).

## 1. Run from the checkout

Use current stable Rust/Cargo (minimum Rust 1.85), OpenSSL, and a POSIX shell on
Linux or macOS. Bundled SQLite needs a native C compiler; no server is needed.
Start with a local checkout of this repository and network access for dependencies.

From the repository root, build the example and create a directory for its data:

```sh
cargo build --locked --example sqlx_sqlite --features derive,sqlx-sqlite
mkdir -p examples/sqlite/demo
```

All commands below run from the repository root. The [complete example](main.rs)
uses SQLx with `futures-executor` for this SQLite-only program. Running it without
arguments prints usage. Generated keys and the database stay in the ignored
`examples/sqlite/demo/` directory.

## 2. Provision the demonstration key once

Generate an independent random 32-byte encryption root as hex in a private file:

```sh
(
    umask 077
    set -C
    openssl rand -hex 32 > examples/sqlite/demo/encryption-root.hex
)
```

Continue only if this succeeds. `umask 077` gives a newly created file private
permissions; shell noclobber (`set -C`) refuses to overwrite an existing file.
Provision once, then reuse the file for every run. Keep it out of version control.

The example pairs this root with the fixed demonstration generation ID
`d2cde2dd-2294-4d2e-a7fa-beb7304a533e` in `ENCRYPTION_KEY_ID`. A **key generation**
is the immutable pairing of that ID and root material: preserve both across
restarts and retain them for as long as the database or its backups need them.
The ID is public metadata, not the secret. Do not generate another root under
the same ID to replace a lost file; it cannot decrypt the stored value.

This file and fixed ID are demonstration provisioning. An application should load
its stable ID/root pairing from its own secret store and access policy; the database
does not supply the secret. See
[keyrings](../../docs/integration.md#keyrings)
for the general design. This example uses one encryption generation only.

## 3. Write the value and exit

```sh
cargo run --locked --example sqlx_sqlite --features derive,sqlx-sqlite -- \
  write examples/sqlite/demo/demo.sqlite3 examples/sqlite/demo/encryption-root.hex
```

Expect exit status 0 and:

```text
Encrypted field stored. Run read in a new process.
```

`write` loads the key before opening storage, creates `demo.sqlite3` if needed,
then creates the `users` table and inserts row 1 in a transaction. It stores the
ciphertext in an `email BLOB NOT NULL` column. The process commits and closes the
connection before reporting success. A repeated `write` fails on the primary key
rather than replacing the existing demonstration row.

## 4. Read after the restart

Run a second command after the first process has exited:

```sh
cargo run --locked --example sqlx_sqlite --features derive,sqlx-sqlite -- \
  read examples/sqlite/demo/demo.sqlite3 examples/sqlite/demo/encryption-root.hex
```

Expect exit status 0 and:

```text
Persistent SQLite read succeeded; demonstration value verified.
```

This new process reloads the same key generation, opens the database **read-only**,
fetches row 1, authenticates and decrypts it, and asserts that it equals the known
demonstration plaintext `mark@example.com`. It prints neither plaintext nor keys,
including on an assertion failure. You can repeat `read` or return to the
repository root in a new terminal and run it again.

`read` never creates a database, table, or demonstration row. A missing database
or row fails instead of seeding new data. To observe missing-key behavior, use a
path that does not exist:

```sh
cargo run --locked --example sqlx_sqlite --features derive,sqlx-sqlite -- \
  read examples/sqlite/demo/demo.sqlite3 examples/sqlite/demo/missing-root.hex
```

Expect a nonzero exit status and `Cannot open encryption key file`. No replacement
key is generated, and the database is not opened. Repeating the successful `read`
with `encryption-root.hex` still works. Invalid key-file input also fails with a
sanitized message; the loader holds both hex input and decoded root in `Zeroizing`
buffers and does not include their contents in errors.

## What crossed the storage boundary?

The example seals with a local encryption keyring, binds the
`Sealed<UserEmail>` into a `BLOB`, and reads it back with
`row.try_get("email")`. SQLx decoding checks structure; `open(keys)`
authenticates and decodes, returning the bare `String`. Sealing borrows the
original plaintext, and no global keys are installed: `keys` supplies the
key explicitly.

A binding without a record identifies a seal alone, not a row or tenant. Preserve the
seal ID, codec compatibility, and binding choices with your stored data; see
[persistent schema](../../docs/integration.md#persistent-schema).

You now have durable encryption-only storage. If you also need equality lookup,
continue with [verified searchable storage](../searchable/README.md).

## Use it in your application

The `write` and `read` functions in [main.rs](main.rs) show the storage boundary.
Adapt the table and seal declaration, and replace `load_keys` with your application's
key loading. Enable `sqlx-sqlite` and add SQLx with your chosen runtime. The example
also uses `hex` and `zeroize` for its file loader; those are choices of this sample,
not requirements for every integration.

## Clean up

Keep the database and its key together for another read. To discard this demo and
start fresh, remove only its generated data directory:

```sh
rm -r examples/sqlite/demo
```
