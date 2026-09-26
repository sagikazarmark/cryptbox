# Store your first field in SQLite

**Tutorial · published CryptBox 0.5.0 API.** Continue from
[your first field](first-field.md). [All tasks](README.md).

Store one field-bound email, let the writing process exit, then authenticate and
decrypt it in a new process. You will keep both the SQLite database and one
independently provisioned encryption root across the restart.

## 1. Create a consumer project

Use current stable Rust/Cargo (minimum Rust 1.85), OpenSSL, and a POSIX shell on
Linux or macOS. Bundled SQLite needs a native C compiler; no server is needed.
Start with a local checkout of this repository and network access for dependencies.

Set `CRYPTBOX_REPO` to the absolute path of that checkout, then run:

```sh
CRYPTBOX_REPO=/absolute/path/to/cryptbox
cargo new sqlite-consumer
cd sqlite-consumer
cp "$CRYPTBOX_REPO/docs/snippets/sqlite.toml" Cargo.toml
cp "$CRYPTBOX_REPO/examples/sqlx_sqlite.rs" src/main.rs
cargo build
```

The [manifest](snippets/sqlite.toml) pins CryptBox to published version 0.5.0,
enables its `sqlx-sqlite` adapter, and uses SQLx 0.8 with `futures-executor` for
this SQLite-only program. The [complete example](../examples/sqlx_sqlite.rs) is
the program you just copied. Running it without arguments only prints usage.

## 2. Provision the demonstration key once

Generate an independent random 32-byte encryption root as hex in a private file:

```sh
(
    umask 077
    set -C
    openssl rand -hex 32 > encryption-root.hex
)
```

Continue only if this succeeds. `umask 077` gives a newly created file private
permissions; shell noclobber (`set -C`) refuses to overwrite an existing file.
Provision once, then reuse the file for every run. Keep it out of version control.

The example pairs this root with the fixed demonstration generation ID
`40000000-0000-4000-8000-000000000004` in `ENCRYPTION_KEY_ID`. A **key generation**
is the immutable pairing of that ID and root material: preserve both across
restarts and retain them for as long as the database or its backups need them.
The ID is public metadata, not the secret. Do not generate another root under
the same ID to replace a lost file; it cannot decrypt the stored field.

This file and fixed ID are demonstration provisioning. An application should load
its stable ID/root pairing from its own key source and access policy; the database
does not supply the secret. See
[key providers and key contexts](integration.md#key-providers-and-key-contexts)
for the general design. This tutorial uses one encryption generation only.

## 3. Write the field and exit

```sh
cargo run --locked -- write demo.sqlite3 encryption-root.hex
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
cargo run --locked -- read demo.sqlite3 encryption-root.hex
```

Expect exit status 0 and:

```text
Persistent SQLite read succeeded; demonstration value verified.
```

This new process reloads the same key generation, opens the database **read-only**,
fetches row 1, authenticates and decrypts it, and asserts that it equals the known
demonstration plaintext `mark@example.com`. It prints neither plaintext nor keys,
including on an assertion failure. You can repeat `read` or return to this directory
in a new terminal and run it again.

`read` never creates a database, table, or demonstration row. A missing database
or row fails instead of seeding new data. To observe missing-key behavior, use a
path that does not exist:

```sh
cargo run --locked -- read demo.sqlite3 missing-root.hex
```

Expect a nonzero exit status and `Cannot open encryption key file`. No replacement
key is generated, and the database is not opened. Repeating the successful `read`
with `encryption-root.hex` still works. Invalid key-file input also fails with a
sanitized message; the loader holds both hex input and decoded root in `Zeroizing`
buffers and does not include their contents in errors.

## What crossed the storage boundary?

The example prepares with a local encryption key provider, binds
`prepared.ciphertext()` into a `BLOB`, and reads
`Ciphertext<String, UserEmail>` with `row.try_get("email")`. SQLx decoding checks
structure; `decrypt_with(&(), keys)` authenticates and decodes. Preparation borrows
the original plaintext, and no global provider is installed. `&()` is the unit
binding context; `keys` supplies the key separately.

Field binding identifies a logical field, not a row or tenant. Preserve the field
ID, codec compatibility, binding, and padding choices with your stored data; see
[persistent schema](integration.md#persistent-schema).

You now have durable encryption-only storage. If you also need equality lookup,
continue with [verified searchable storage](searchable-sqlx.md).
