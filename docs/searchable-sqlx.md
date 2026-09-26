# Build a durable, searchable SQLx application

**Guide · published CryptBox 0.5.0 API.** Prepared writes, nullable/deferred reads,
verified lookup and process restarts on PostgreSQL or SQLite.
[All tasks](README.md) · [Security](security.md).

## 1. Create the consumer

Use current stable Rust/Cargo, a native C compiler/linker, OpenSSL's command-line
tool and network access for dependencies. PostgreSQL also needs Docker or a test
server; SQLite needs no service.

```sh
cargo new searchable-consumer
cd searchable-consumer
```

Copy these canonical files into the new project:

| Source | Destination |
| --- | --- |
| [searchable.toml](snippets/searchable.toml) | `Cargo.toml` |
| [searchable.rs](snippets/searchable.rs) — complete application | `src/main.rs` |
| [searchable-postgres.sql](snippets/searchable-postgres.sql) | `src/searchable-postgres.sql` |
| [searchable-sqlite.sql](snippets/searchable-sqlite.sql) | `src/searchable-sqlite.sql` |

Select exactly one backend. The manifest defaults to PostgreSQL and explicitly
selects Tokio and Rustls/native-root TLS; a CryptBox backend feature alone selects
neither runtime nor TLS. Only the selected backend's schema file is required.

## 2. Provision durable key generations once

Run **once in the new consumer directory**; never overwrite existing key files:

```sh
umask 077
mkdir keys
openssl rand -hex 32 > keys/encryption-1.hex
openssl rand -hex 32 > keys/encryption-2.hex
openssl rand -hex 32 > keys/index-1.hex
openssl rand -hex 32 > keys/index-2.hex
printf '\n/keys/\n/users.db*\n' >> .gitignore
export CRYPTBOX_KEY_DIR="$PWD/keys"
unset CRYPTBOX_ENCRYPTION CRYPTBOX_INDEX
export CRYPTBOX_GENERATION=1
```

The loader pairs these independent 32-byte roots with fixed demonstration IDs:

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

## 3. Choose a database and save its schema

### PostgreSQL

Start a disposable local service:

```sh
docker run --detach --rm --name cryptbox-searchable-postgres \
  -e POSTGRES_USER=cryptbox -e POSTGRES_PASSWORD=cryptbox \
  -e POSTGRES_DB=cryptbox -p 127.0.0.1:55432:5432 postgres:18-trixie
docker exec cryptbox-searchable-postgres pg_isready -U cryptbox -d cryptbox
export DATABASE_URL='postgres://cryptbox:cryptbox@127.0.0.1:55432/cryptbox?sslmode=disable'
consumer() { cargo run -- "$@"; }
```

Repeat `pg_isready` until it reports `accepting connections`. The credentials and
disabled TLS are for loopback testing. Deployment needs its own credentials and
TLS trust policy (for example `sslmode=verify-full` with the appropriate CA).

### SQLite

```sh
export DATABASE_URL="sqlite://$PWD/users.db?mode=rwc"
consumer() { cargo run --no-default-features --features sqlite -- "$@"; }
```

Both schemas store complete ciphertext envelopes and index tokens in `BYTEA`/`BLOB`
columns. The lookup index is **non-unique**. A check constraint pairs `NULL` email
with `NULL` lookup; it does not establish cryptographic consistency. Preserve
field/index IDs, codec, binding, padding, normalization and precision as
[persistent schema](https://docs.rs/cryptbox/0.5.0/cryptbox/#persistent-schema).

## 4. Storage operations

These excerpts come from the [complete application](snippets/searchable.rs).
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
rows or authenticate index metadata; see [assurance](concepts.md#assurance).

Blind indexes reveal equality/frequency and cannot enforce uniqueness. `NoPadding`
reveals encoded length; field binding does not prevent same-field substitution or replay.

## 5. Write, update, exit and search

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
`Matches: [2]; rejected: 0.`. The final write clears both columns. `init` applies
the schema without resetting data. Each command is a separate process.

Open a **new terminal** in the same consumer directory. Reload the same key path,
database URL and backend helper from above, then:

```sh
export CRYPTBOX_KEY_DIR="$PWD/keys"
unset CRYPTBOX_ENCRYPTION CRYPTBOX_INDEX
export CRYPTBOX_GENERATION=2
consumer get 1
consumer put 3 alice@example.com
consumer search ALICE@example.com
```

Row 1 retains its original spelling and generation-1 storage; row 3 uses generation
2. Search reports `Matches: [1, 3]; rejected: 0.` because both generations remain readable.

### Reject a controlled false candidate

In this disposable database only:

```sh
consumer put 4 bob@example.com
consumer demo-false-candidate 4 3
consumer search ' ALICE@EXAMPLE.COM '
consumer put 4 bob@example.com
```

The fixture copies row 3's index onto row 4. Search reports
`Matches: [1, 3]; rejected: 1.`; the final normal write restores consistency.

## 6. Verify SQLx query macros and type overrides

Dynamic `query`/`QueryBuilder` needs no build-time database. `query!` needs a
reachable `DATABASE_URL` with the schema already applied (or a matching SQLx
offline cache). The canonical macro read forces nullable output and the custom decoder:

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

For PostgreSQL, after `consumer init`:

```sh
cargo check --features macro-check
cargo run --features macro-check -- macro-get 2
cargo run --features macro-check -- macro-put 5 macro@example.com
consumer search MACRO@example.com
```

For SQLite, replace `--features macro-check` with
`--no-default-features --features sqlite,macro-check`. Expect `2: NULL`, `Stored 5.`,
then `Matches: [5]; rejected: 0.`. For offline compilation, generate `.sqlx` metadata
with a compatible SQLx 0.8 CLI's `cargo sqlx prepare -- --features macro-check`
(use the SQLite flags when applicable); regenerate when schema or queries change.
Set `SQLX_OFFLINE=true` when building from the cache, especially if `DATABASE_URL`
is still set but the database is unavailable.

## 7. Continue rotation and verify the integration

This application's providers are startup snapshots. Follow [fleet rotation](key-rotation.md)
to stage readable generations on every reader before promoting writers. Promotion
does not rewrite old rows; retain keys required by data and recoverable backups.
Continue with [maintenance sweeps](reencryption-sweep.md) or [legacy migration](legacy-migration.md).
The latter's optional feature also needs [migration.rs](snippets/migration.rs) as
`src/migration.rs`.

When finished, `docker stop cryptbox-searchable-postgres` removes the disposable
service and its data. SQLite's `users.db` and the key files persist until removed.
See [testing and diagnostics](testing.md) for application guidance.
