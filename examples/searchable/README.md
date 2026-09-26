# Build a durable, searchable SQLx application

Build a sample application with prepared writes, nullable/deferred reads,
verified lookup, and process restarts.
[Examples](../README.md) · [Security](../../docs/security.md).

Run the sample, then read the storage operations below to adapt it to your own
application. SQLite is the default backend; PostgreSQL is also supported. Query
macros and operations are optional follow-ups. For encryption without search,
start with [durable SQLite storage](../sqlite/README.md). For design choices,
read [integration design](../../docs/integration.md).

This sample has its own keys and database, separate from the encryption-only
SQLite example. Its [manifest](Cargo.toml), [source](main.rs), and SQL schemas
live in this directory. The same package is used by the end-to-end tests.

## Run the example

Use current stable Rust/Cargo, a native C compiler/linker, OpenSSL's command-line
tool and network access for dependencies. PostgreSQL also needs Docker or a test
server; SQLite needs no service.

```sh
cd examples/searchable
cargo build --locked
```

Run the remaining commands from this directory. Select exactly one backend. The
manifest defaults to SQLite and explicitly selects Tokio and Rustls/native-root
TLS; a CryptBox backend feature alone selects
neither runtime nor TLS. SQL schemas are embedded from the adjacent files.

### Provision durable key generations once

Run **once in this directory**; never overwrite existing key files:

```sh
(
    umask 077
    set -C
    mkdir keys &&
    openssl rand -hex 32 > keys/encryption-1.hex &&
    openssl rand -hex 32 > keys/encryption-2.hex &&
    openssl rand -hex 32 > keys/index-1.hex &&
    openssl rand -hex 32 > keys/index-2.hex
)
export CRYPTBOX_KEY_DIR="$PWD/keys"
unset CRYPTBOX_ENCRYPTION CRYPTBOX_INDEX
export CRYPTBOX_GENERATION=1
```

Continue only if provisioning succeeds. The key directory and SQLite database
are ignored by Git. The loader pairs the independent roots with demonstration IDs:

| File | Generation ID |
| --- | --- |
| `encryption-1.hex` | `10000000-0000-4000-8000-000000000001` |
| `encryption-2.hex` | `20000000-0000-4000-8000-000000000002` |
| `index-1.hex` | `30000000-0000-4000-8000-000000000003` |
| `index-2.hex` | `40000000-0000-4000-8000-000000000004` |

In an application, provision unique IDs with your secure secret source and retain
each immutable **ID/material pair** across restarts and recovery. Never reuse
encryption roots for indexes. Missing, malformed or wrong-length files fail startup
before database access; valid-length wrong material can fail decryption or silently
omit search results. Never repair a load failure by generating replacement material.

`CRYPTBOX_GENERATION=1` makes generation 1 current and both generations readable;
`2` promotes both roles while retaining generation 1. Leave the independent
`CRYPTBOX_ENCRYPTION`/`CRYPTBOX_INDEX` selectors unset for this exercise.

### Choose a database

For SQLite, no service is needed:

```sh
export DATABASE_URL="sqlite://$PWD/users.db?mode=rwc"
consumer() { cargo run --locked -- "$@"; }
```

For PostgreSQL, start a disposable local service instead:

```sh
docker run --detach --rm --name cryptbox-searchable-postgres \
  -e POSTGRES_USER=cryptbox -e POSTGRES_PASSWORD=cryptbox \
  -e POSTGRES_DB=cryptbox -p 127.0.0.1:55432:5432 postgres:18-trixie
docker exec cryptbox-searchable-postgres pg_isready -U cryptbox -d cryptbox
export DATABASE_URL='postgres://cryptbox:cryptbox@127.0.0.1:55432/cryptbox?sslmode=disable'
consumer() { cargo run --locked --no-default-features --features postgres -- "$@"; }
```

Repeat `pg_isready` until it reports `accepting connections`. The credentials and
disabled TLS are for loopback testing. Deployment needs its own credentials and
TLS trust policy (for example `sslmode=verify-full` with the appropriate CA).

Both schemas store complete ciphertext envelopes and index tokens in `BYTEA`/`BLOB`
columns. The lookup index is **non-unique**. A check constraint pairs `NULL` email
with `NULL` lookup; it does not establish cryptographic consistency. Preserve
field/index IDs, codec, binding, padding, normalization and precision as
[persistent schema](../../docs/integration.md#persistent-schema).

This example supports nullable fields. The packaged maintenance rehearsal linked
at the end uses a separate non-NULL population; it cannot sweep this example's
nullable dataset unchanged.

### Write, update, exit and search

Using the selected backend's `consumer` helper:

```sh
consumer init
consumer put 1 ' Alice@Example.com '
consumer put-null 2
consumer get 2
consumer put 2 before@example.com
consumer put 2 after@example.com
consumer search before@example.com
consumer search AFTER@example.com
consumer put-null 2
```

`get 2` prints `2: NULL`; the searches report `Matches: []; rejected: 0.` then
`Matches: [2]; rejected: 0.`. Each command runs in a separate process. The final
write clears both columns. `init` applies the schema without resetting data.

To demonstrate a generation change across restarts:

```sh
export CRYPTBOX_GENERATION=2
consumer get 1
consumer put 3 alice@example.com
consumer search ALICE@example.com
```

Row 1 retains its original spelling and generation-1 storage; row 3 uses generation
2. Search reports `Matches: [1, 3]; rejected: 0.` because both remain readable.
In a new terminal, return to this directory and restore `CRYPTBOX_KEY_DIR`,
`CRYPTBOX_GENERATION`, `DATABASE_URL`, and the backend helper before continuing.

### Reject a controlled false candidate

In this disposable database only:

```sh
consumer put 4 bob@example.com
consumer demo-false-candidate 4 3
consumer search ' ALICE@EXAMPLE.COM '
consumer put 4 bob@example.com
```

The fixture copies row 3's index onto row 4. Search reports
`Matches: [1, 3]; rejected: 1.`; the final write restores consistency.
You have now run the complete demonstration. Writes upsert the named rows, so the
commands can be repeated with the same keys. The displayed results assume the
fresh dataset above; additional rows from earlier runs may also be returned.

## How the storage operations work

These excerpts come from the [complete application](main.rs).
Its `UserEmail` profile uses `String`, `Utf8`, field binding and `NoPadding`.
`EmailLookup` retains 128 bits and trims/ASCII-lowercases for equality—an illustrative
policy, not general email canonicalization. Application validation requires a
trimmed ASCII graphic value containing `@`, at most 254 bytes. Stored text retains
its original case and whitespace.

### Atomic insert/update

`put` derives both representations from one source and upserts them in one SQL
statement, including value-to-NULL transitions:

<!-- BEGIN SHARED: searchable-put -->

```rust
async fn put(
    connection: &mut DbConnection,
    id: i64,
    email: Option<String>,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    if let Some(email) = &email {
        validate_email(email)?;
    }
    let value = email.map(Encrypted::<_, UserEmail>::new);
    let prepared = value
        .as_ref()
        .map(|value| {
            value
                .prepare_with(&(), encryption)?
                .with_index_with::<EmailLookup>(indexes)
        })
        .transpose()?;
    let ciphertext = prepared.as_ref().map(|p| p.ciphertext());
    let index = prepared
        .as_ref()
        .map(|p| p.index::<EmailLookup>())
        .transpose()?;
    // One statement: insert OR update both representations from the same source.
    sqlx::query("INSERT INTO users (id, email, email_lookup) VALUES ($1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET email = excluded.email, email_lookup = excluded.email_lookup")
        .bind(id).bind(ciphertext).bind(index.map(|i| i.as_bytes()))
        .execute(connection).await?;
    println!("Stored {id}.");
    Ok(())
}
```

<!-- END SHARED: searchable-put -->

Use an application-owned transaction for related multi-statement writes. This
upsert is last-writer-wins; add a version guard if lost updates matter. Automatic
encryption of an `Encrypted` column does **not** maintain a separate index column.
Preparation borrows and retains the plaintext source.

### Nullable and deferred reads

<!-- BEGIN SHARED: searchable-get -->

```rust
async fn get(connection: &mut DbConnection, id: i64, keys: &LocalEncryptionKeyring) -> Result<()> {
    let row = sqlx::query("SELECT email FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(connection)
        .await?;
    // Decode the stored envelope now; choose when to authenticate/decrypt later.
    let stored: Option<EmailCiphertext> = row.try_get("email")?;
    match stored {
        Some(ciphertext) => println!(
            "{id}: {}",
            ciphertext.decrypt_with(&(), keys)?.expose_secret()
        ),
        None => println!("{id}: NULL"),
    }
    Ok(())
}
```

<!-- END SHARED: searchable-get -->

`EmailCiphertext` aliases `Ciphertext<String, UserEmail>`. SQLx decoding checks
structure; only `decrypt_with` authenticates. Explicit local providers need no
global installation; `&()` is unit binding context. Plaintext output and shell
arguments are demonstration conveniences; keep real user values out of logs/history.

### Why lookup needs verification

<!-- BEGIN SHARED: searchable-search -->

```rust
async fn search(
    connection: &mut DbConnection,
    query: &str,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    let probes =
        blind_index_probes::<EmailLookup, str, FieldBound<UserEmail>>(query, &(), indexes)?;
    let mut sql = QueryBuilder::<Db>::new("SELECT id, email FROM users WHERE email_lookup IN (");
    let mut values = sql.separated(", ");
    for probe in &probes {
        values.push_bind(probe.as_bytes());
    }
    values.push_unseparated(") ORDER BY id");
    let rows = sql.build().fetch_all(connection).await?;
    let mut matches = Vec::<i64>::new();
    let mut rejected = 0;
    for row in rows {
        let ciphertext: EmailCiphertext = row.try_get("email")?;
        let candidate = ciphertext.decrypt_with(&(), encryption)?;
        if verify_blind_index_candidate::<EmailLookup, str>(query, candidate.expose_secret())? {
            matches.push(row.try_get("id")?);
        } else {
            rejected += 1; // A collision is an ordinary non-match, not an assertion failure.
        }
    }
    println!("Matches: {matches:?}; rejected: {rejected}.");
    Ok(())
}
```

<!-- END SHARED: searchable-search -->

Probe **every readable index generation**, authenticate/decrypt candidates, then
compare normalized plaintext. False candidates are ordinary non-matches;
authentication/decoding failures fail lookup. Bound or paginate large candidate
sets without skipping verification. Candidate comparison cannot detect omitted
rows or authenticate index metadata; see
[what each check establishes](../../docs/security.md#what-each-check-establishes).

Blind indexes reveal equality/frequency and cannot enforce uniqueness. `NoPadding`
reveals encoded length; field binding does not prevent same-field substitution or replay.

## Use it in your application

Adapt `UserEmail`, `EmailLookup`, and the `put`, `get`, and `search` functions in
[main.rs](main.rs). Keep ciphertext and index writes atomic, and preserve complete
candidate verification. Replace fixture key files and IDs with your application's
providers. The sample validates ASCII email-like input; choose normalization and
validation that match your actual domain.

The [manifest](Cargo.toml) shows backend, runtime, and TLS dependencies. Its
`cryptbox` path dependency points at this checkout. When copying the sample into
another project, supply your project's dependency and keep the SQL files beside
`main.rs`. See [integration design](../../docs/integration.md) and
[testing](../../docs/testing.md) before adapting the optional operational commands.

## Optional: SQLx query macros

**Optional:** use this section if your application uses SQLx compile-time query macros.

Dynamic `query`/`QueryBuilder` needs no build-time database. `query!` needs a
reachable `DATABASE_URL` with the schema already applied (or a matching SQLx
offline cache). The example's macro read forces nullable output and the custom decoder:

<!-- BEGIN SHARED: searchable-macro-get -->

```rust
    let row = sqlx::query!(
        r#"SELECT email AS "email?: EmailCiphertext" FROM users WHERE id = $1"#,
        id
    )
    .fetch_one(connection)
    .await?;
```

<!-- END SHARED: searchable-macro-get -->

Keep `?` for legitimate NULLs. The macro write prepares ciphertext/index together,
then overrides PostgreSQL's `BYTEA` input inference with `ciphertext as _`:

<!-- BEGIN SHARED: searchable-macro-put -->

```rust
    sqlx::query!("INSERT INTO users (id, email, email_lookup) VALUES ($1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET email = excluded.email, email_lookup = excluded.email_lookup",
        id, ciphertext as _, index)
        .execute(connection).await?;
```

<!-- END SHARED: searchable-macro-put -->

For SQLite, after `consumer init`:

```sh
cargo check --locked --features macro-check
cargo run --locked --features macro-check -- macro-get 2
cargo run --locked --features macro-check -- macro-put 5 macro@example.com
consumer search MACRO@example.com
```

For PostgreSQL, replace `--features macro-check` with
`--no-default-features --features postgres,macro-check`. Expect `2: NULL`, `Stored 5.`,
then `Matches: [5]; rejected: 0.`. For offline compilation, generate `.sqlx` metadata
with a compatible SQLx 0.8 CLI's `cargo sqlx prepare -- --features macro-check`
(use the PostgreSQL flags when applicable); regenerate when schema or queries change.
Set `SQLX_OFFLINE=true` when building from the cache, especially if `DATABASE_URL`
is still set but the database is unavailable.

## Optional: operational scenarios

First review [testing and diagnostics](../../docs/testing.md)
when adapting the application to your project.

This application's providers are startup snapshots. Follow [fleet rotation](../../docs/key-rotation.md)
to stage readable generations on every reader before promoting writers. Promotion
does not rewrite old rows; retain keys required by data and recoverable backups.
The [maintenance](../../docs/reencryption-sweep.md#run-the-automated-scenario)
and [legacy migration](../../docs/legacy-migration.md#run-the-automated-scenario)
automated scenarios provision their own data. They are separate rehearsals, not
commands to run unchanged against this example's resulting database: row 2 is
NULL, while the packaged sweep and audit require non-NULL values in every swept
column. Operating a nullable application requires a custom `SweepStore` or manual
loop with an explicit NULL policy and matching audit coverage. See
[packaged-store limits](../../docs/reencryption-sweep.md#prepare-the-consumer).

For adoption over existing plaintext or foreign ciphertext, review the
[migration prerequisites](../../docs/legacy-migration.md#preconditions) before changing
writes. The optional `legacy-migration` feature enables the adjacent
[migration module](migration.rs).

## Clean up

When finished, `docker stop cryptbox-searchable-postgres` removes the disposable
service and its data. SQLite's `users.db` and the key files persist until removed.
For a fresh SQLite demonstration, remove `users.db` and any `users.db-wal` or
`users.db-shm` files while the application is stopped. Keep `keys/` for retained
data; remove it only when discarding this entire demonstration and its data.
