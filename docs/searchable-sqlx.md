# Build a durable, searchable SQLx application

**Tutorial · published CryptBox 0.5.0 API.** Continue from [your first field](first-field.md)
to a PostgreSQL email column, prepared insert/update, verified lookup and real
process restarts. The SQLite route uses the same program and key contract.
[All tasks](README.md). CryptBox remains [experimental](security.md).

## 1. Create the consumer

Use current stable Rust/Cargo on native Linux or macOS, network access for crates,
OpenSSL's command-line tool for one-time random provisioning, and Docker for the
PostgreSQL route. No library checkout or library dev-dependencies are required.
Use a working native C compiler/linker and platform SDK too: on macOS install
Xcode Command Line Tools (`xcode-select --install`); on Debian/Ubuntu install
`build-essential` and `pkg-config`. Retain your toolchain's environment when
opening a new shell; only the application's configuration needs to be reloaded.

```sh
cargo new searchable-consumer
cd searchable-consumer
```

Replace `Cargo.toml` with:

<!-- BEGIN SHARED: searchable-manifest -->

```toml
[package]
name = "searchable-consumer"
version = "0.1.0"
edition = "2024"

[features]
default = ["postgres"]
postgres = ["cryptbox/sqlx-postgres", "sqlx/postgres"]
sqlite = ["cryptbox/sqlx-sqlite", "sqlx/sqlite"]
macro-check = ["sqlx/macros"]
maintenance = ["cryptbox/migrate"]

[dependencies]
cryptbox = "=0.5.0"
hex = "0.4"
sqlx = { version = "0.8.6", default-features = false, features = ["runtime-tokio", "tls-rustls-ring-native-roots"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
zeroize = { version = "1", features = ["alloc"] }
```

<!-- END SHARED: searchable-manifest -->

The consumer explicitly selects Tokio and SQLx's Rustls/native-root TLS support.
Enabling a CryptBox backend alone selects neither. PostgreSQL is the default;
select **exactly one** backend. SQLite commands below disable the default first.

## 2. Provision durable key generations once

Run this **once in a new consumer directory**, before storing data:

```sh
umask 077
mkdir keys
openssl rand -hex 32 > keys/encryption-1.hex
openssl rand -hex 32 > keys/encryption-2.hex
openssl rand -hex 32 > keys/index-1.hex
openssl rand -hex 32 > keys/index-2.hex
printf '\n/keys/\n/users.db*\n' >> .gitignore
export CRYPTBOX_KEY_DIR="$PWD/keys"
export CRYPTBOX_GENERATION=1
```

Each invocation provisions an **independent** 32-byte root: never reuse encryption
material for indexing. Preserve these files securely; **do not rerun the random
commands over existing files**. The program never generates keys at startup.
Missing, unreadable, malformed, or wrong-length files and an absent/invalid
generation selector cause startup failure before database access.

The fixed generation IDs in the program are immutable companions to these files:

| File | Stable generation ID | Role |
| --- | --- | --- |
| `encryption-1.hex` | `10000000-0000-4000-8000-000000000001` | Encryption generation 1 |
| `encryption-2.hex` | `20000000-0000-4000-8000-000000000002` | Encryption generation 2 |
| `index-1.hex` | `30000000-0000-4000-8000-000000000003` | Index generation 1 |
| `index-2.hex` | `40000000-0000-4000-8000-000000000004` | Index generation 2 |

This tutorial uses fixed IDs for reproducibility in an isolated application.
Assign unique generation IDs when provisioning real application generations,
record them alongside the bytes, and load the identical pair on restart. Never
replace material while retaining its ID. Valid-length but incorrect material
cannot be detected by this loader: reading existing ciphertext will fail
authentication, and incorrect index material can silently omit search results.

For deployment, mount files from your application's secret manager with restricted
access instead of checking keys into source control or baking them into images.
Back up the ID/material mapping separately from the database, retaining historical
generations for recovery. The environment carries a path and current-generation
selector, not raw roots. Temporary read/decoded buffers are zeroizing; this does
not erase the filesystem, environment, OS caches, or all compiler copies.

## 3. Choose a database and save its schema

### PostgreSQL

Start a disposable local PostgreSQL 18 service (Docker must be running):

```sh
docker run --detach --rm --name cryptbox-searchable-postgres \
  -e POSTGRES_USER=cryptbox -e POSTGRES_PASSWORD=cryptbox \
  -e POSTGRES_DB=cryptbox -p 127.0.0.1:55432:5432 postgres:18-trixie
docker exec cryptbox-searchable-postgres pg_isready -U cryptbox -d cryptbox
export DATABASE_URL='postgres://cryptbox:cryptbox@127.0.0.1:55432/cryptbox?sslmode=disable'
```

Repeat `pg_isready` until it reports `accepting connections`. These are local,
disposable credentials with TLS disabled on loopback. In deployment, use your
database role/secret distribution and a TLS URL such as `sslmode=verify-full`;
configure server-name verification and the trusted CA (for example SQLx's
`sslrootcert` connection option) for your service. Merely enabling a TLS feature
does not define your trust policy. Never use the tutorial's role or password in
deployment. Schema creation needs DDL privileges; separate migration and runtime
roles there.

Save as `src/postgres.sql`:

<!-- BEGIN SHARED: searchable-postgres-schema -->

```sql
CREATE TABLE IF NOT EXISTS users (
    id BIGINT PRIMARY KEY,
    email BYTEA,
    email_lookup BYTEA,
    CHECK ((email IS NULL) = (email_lookup IS NULL))
);
CREATE INDEX IF NOT EXISTS users_email_lookup ON users (email_lookup);
```

<!-- END SHARED: searchable-postgres-schema -->

### SQLite

SQLite requires no service. Save this as `src/sqlite.sql`:

<!-- BEGIN SHARED: searchable-sqlite-schema -->

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email BLOB,
    email_lookup BLOB,
    CHECK ((email IS NULL) = (email_lookup IS NULL))
);
CREATE INDEX IF NOT EXISTS users_email_lookup ON users (email_lookup);
```

<!-- END SHARED: searchable-sqlite-schema -->

Then use:

```sh
export DATABASE_URL="sqlite://$PWD/users.db?mode=rwc"
```

For **every** Cargo invocation below add `--no-default-features --features sqlite`
before `--` (for macro commands use `--features sqlite,macro-check`). For example:

```sh
cargo run --no-default-features --features sqlite -- init
```

Both schemas store the **complete** `Ciphertext` envelope and complete blind-index
token, including their generation metadata. Do not store only the digest or strip
the ciphertext header. The lookup index is deliberately **non-unique**. `NULL`
means no email and no token; the check constraint enforces paired nullability,
not cryptographic consistency. Keep the field/index IDs, codec, binding, padding,
normalization and precision stable as [persistent schema](first-field.md#4-freeze-schema-decisions-before-durable-storage).

## 4. Copy the application

Replace `src/main.rs` with the complete program below. Only the selected backend's
schema file is required. `init` applies that schema; it does not reset existing data.

<!-- BEGIN SHARED: searchable -->

```rust
use std::{env, error::Error, path::Path};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Ciphertext, Encrypted,
    EncryptionKey, FieldBound, IndexId, LocalBlindIndexKeyring, LocalEncryptionKeyring,
    blind_index_probes, index_id, index_key_id, inspect_blind_index, inspect_ciphertext, key_id,
    verify_blind_index_candidate,
};
use sqlx::{Connection, QueryBuilder, Row};
use zeroize::Zeroizing;

#[cfg(any(
    all(feature = "postgres", feature = "sqlite"),
    not(any(feature = "postgres", feature = "sqlite"))
))]
compile_error!("select exactly one of postgres or sqlite");

#[cfg(feature = "postgres")]
type Db = sqlx::Postgres;
#[cfg(feature = "sqlite")]
type Db = sqlx::Sqlite;
type DbConnection = <Db as sqlx::Database>::Connection;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
type EmailCiphertext = Ciphertext<String, UserEmail>;

cryptbox::profile! {
    UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
    }
}

struct EmailLookup;
impl BlindIndexMetadata for EmailLookup {
    const ID: IndexId = index_id!("80000000-0000-4000-8000-000000000008");
    const BITS: usize = 128;
}
impl BlindIndexSpec<str> for EmailLookup {
    fn normalize(input: &str) -> std::result::Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        // Illustrative ASCII equality policy, not general email canonicalization.
        let mut bytes = Zeroizing::new(input.trim().as_bytes().to_vec());
        bytes.make_ascii_lowercase();
        Ok(bytes)
    }
}
impl BlindIndexSpec<String> for EmailLookup {
    fn normalize(input: &String) -> std::result::Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        <Self as BlindIndexSpec<str>>::normalize(input)
    }
}

fn load_root_key(directory: &Path, name: &str) -> Result<Zeroizing<[u8; 32]>> {
    let text = Zeroizing::new(
        std::fs::read_to_string(directory.join(name))
            .map_err(|_| format!("key configuration: cannot read {name}"))?,
    );
    let mut bytes = Zeroizing::new([0; 32]);
    hex::decode_to_slice(text.trim(), bytes.as_mut())
        .map_err(|_| format!("key configuration: {name} must contain 64 hex digits"))?;
    Ok(bytes)
}

fn load_keyrings_from_env() -> Result<(LocalEncryptionKeyring, LocalBlindIndexKeyring)> {
    let directory =
        env::var("CRYPTBOX_KEY_DIR").map_err(|_| "key configuration: CRYPTBOX_KEY_DIR required")?;
    let directory = Path::new(&directory);
    // These IDs are immutable companions of the provisioned files; never reassign them.
    let encryption_1 = EncryptionKey::new(
        key_id!("10000000-0000-4000-8000-000000000001"),
        *load_root_key(directory, "encryption-1.hex")?,
    );
    let index_1 = BlindIndexKey::new(
        index_key_id!("30000000-0000-4000-8000-000000000003"),
        *load_root_key(directory, "index-1.hex")?,
    );
    let (encryption_state, index_state) =
        match (env::var("CRYPTBOX_ENCRYPTION"), env::var("CRYPTBOX_INDEX")) {
            (Ok(encryption), Ok(index)) => (encryption, index),
            (Err(env::VarError::NotPresent), Err(env::VarError::NotPresent)) => {
                // Preserve the introductory tutorial's both-readable shorthand.
                let state = match env::var("CRYPTBOX_GENERATION").as_deref() {
                    Ok("1") => "staged",
                    Ok("2") => "2",
                    _ => return Err("key configuration: CRYPTBOX_GENERATION must be 1 or 2".into()),
                };
                (state.to_owned(), state.to_owned())
            }
            _ => {
                return Err(
                    "key configuration: set both CRYPTBOX_ENCRYPTION and CRYPTBOX_INDEX".into(),
                );
            }
        };
    // State 1 does not even load generation 2. Staging retains generation 1 for writes.
    let encryption = match encryption_state.as_str() {
        "1" => LocalEncryptionKeyring::new(encryption_1, [])?,
        "staged" | "2" | "staged-3" | "3" => {
            let encryption_2 = EncryptionKey::new(
                key_id!("20000000-0000-4000-8000-000000000002"),
                *load_root_key(directory, "encryption-2.hex")?,
            );
            if matches!(encryption_state.as_str(), "staged-3" | "3") {
                let encryption_3 = EncryptionKey::new(
                    key_id!("70000000-0000-4000-8000-000000000007"),
                    *load_root_key(directory, "encryption-3.hex")?,
                );
                if encryption_state == "staged-3" {
                    LocalEncryptionKeyring::new(encryption_2, [encryption_1, encryption_3])?
                } else {
                    LocalEncryptionKeyring::new(encryption_3, [encryption_1, encryption_2])?
                }
            } else if encryption_state == "staged" {
                LocalEncryptionKeyring::new(encryption_1, [encryption_2])?
            } else {
                LocalEncryptionKeyring::new(encryption_2, [encryption_1])?
            }
        }
        _ => {
            return Err(
                "key configuration: CRYPTBOX_ENCRYPTION must be 1, staged, 2, staged-3 or 3".into(),
            );
        }
    };
    let indexes = match index_state.as_str() {
        "1" => LocalBlindIndexKeyring::new(index_1, [])?,
        "staged" | "2" | "staged-3" | "3" => {
            let index_2 = BlindIndexKey::new(
                index_key_id!("40000000-0000-4000-8000-000000000004"),
                *load_root_key(directory, "index-2.hex")?,
            );
            if matches!(index_state.as_str(), "staged-3" | "3") {
                let index_3 = BlindIndexKey::new(
                    index_key_id!("90000000-0000-4000-8000-000000000009"),
                    *load_root_key(directory, "index-3.hex")?,
                );
                if index_state == "staged-3" {
                    LocalBlindIndexKeyring::new(index_2, [index_1, index_3])?
                } else {
                    LocalBlindIndexKeyring::new(index_3, [index_1, index_2])?
                }
            } else if index_state == "staged" {
                LocalBlindIndexKeyring::new(index_1, [index_2])?
            } else {
                LocalBlindIndexKeyring::new(index_2, [index_1])?
            }
        }
        _ => {
            return Err(
                "key configuration: CRYPTBOX_INDEX must be 1, staged, 2, staged-3 or 3".into(),
            );
        }
    };
    Ok((encryption, indexes))
}

const CANARY: &str = "rotation-canary@example.invalid";

#[cfg(feature = "maintenance")]
async fn maintenance(
    connection: &mut DbConnection,
    command: &str,
    run: &str,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    #[cfg(feature = "postgres")]
    use cryptbox::migrate::PostgresSweepStore as Store;
    #[cfg(feature = "sqlite")]
    use cryptbox::migrate::SqliteSweepStore as Store;
    use cryptbox::migrate::{RowPlanner, Sweep, SweepReport, SweepStore, SweepTable};

    // Run identity belongs to the operator; this store persists only (name, cursor).
    let table = SweepTable::new("users", "id", "email")
        .with_index_column("email_lookup")
        .with_progress("cryptbox_migration_progress", run);
    let planner = RowPlanner::<String, UserEmail>::new(&(), encryption)
        .with_index_with::<EmailLookup>(indexes);
    let sweep = Sweep::new(planner).with_batch_size(2);
    let mut store = Store::new(connection, &table);
    store.ensure_progress_table().await?;
    match command {
        "sweep-status" => println!("Checkpoint: {:?}.", store.load_checkpoint().await?),
        "sweep-conflict" => {
            // Fixture only: interleave an application write after loading the exact old pair.
            let rows = store.load_batch(None, 1).await?;
            let row = rows.first().ok_or("conflict rehearsal needs a stale row")?;
            let planner = RowPlanner::<String, UserEmail>::new(&(), encryption)
                .with_index_with::<EmailLookup>(indexes);
            let plan = planner.plan_row(&row.ciphertext, &[&row.indexes[0]])?;
            let replacement = plan.write().ok_or("conflict rehearsal needs a stale row")?;
            let mut writer = DbConnection::connect(&env::var("DATABASE_URL")?).await?;
            put(
                &mut writer,
                row.cursor,
                Some("concurrent@example.com".to_owned()),
                encryption,
                indexes,
            )
            .await?;
            writer.close().await?;
            let updated = store.update(row, replacement).await?;
            if updated {
                return Err("concurrent application write was overwritten".into());
            }
            println!("Conflicts: 1.");
        }
        "sweep-batch" | "sweep-uncheckpointed" => {
            let outcome = if command == "sweep-uncheckpointed" {
                // Rehearse process loss after writes, before durable progress is saved.
                let after = store.load_checkpoint().await?;
                sweep.process_batch(&mut store, after.as_ref()).await?
            } else {
                sweep.run_batch(&mut store).await?
            };
            println!(
                "Checkpoint: {:?}; current: {}; stale: {}; conflicts: {}.",
                outcome.checkpoint,
                outcome.report.current,
                outcome.report.stale,
                outcome.report.conflicts
            );
        }
        "sweep-verify" => {
            // Separate, fresh cursor: never resume verification from rewrite progress.
            let mut cursor = None;
            let mut report = SweepReport::default();
            loop {
                let batch = sweep.verify_batch(&mut store, cursor.as_ref()).await?;
                report.merge(batch.report);
                cursor = batch.checkpoint;
                if cursor.is_none() {
                    break;
                }
            }
            println!(
                "Complete: {}; current: {}; stale: {}; legacy: {}; malformed: {}.",
                report.is_terminal(),
                report.current,
                report.stale,
                report.legacy,
                report.malformed
            );
        }
        _ => return Err("unknown maintenance command".into()),
    }
    Ok(())
}

fn rotation_canary(
    path: &str,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    let value = Encrypted::<_, UserEmail>::new(CANARY.to_owned());
    let prepared = value
        .prepare_with(&(), encryption)?
        .with_index_with::<EmailLookup>(indexes)?;
    // Out-of-band synthetic data: never put a future generation in the live users table.
    std::fs::write(
        path,
        format!(
            "{}\n{}\n",
            hex::encode(prepared.ciphertext().as_bytes()),
            hex::encode(prepared.index::<EmailLookup>()?.as_bytes())
        ),
    )?;
    println!("Canary saved.");
    Ok(())
}

fn rotation_ready(
    path: &str,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    let text = std::fs::read_to_string(path)?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 2 {
        return Err("invalid canary".into());
    }
    let ciphertext = EmailCiphertext::from_bytes(hex::decode(lines[0])?)?;
    if ciphertext.decrypt_with(&(), encryption)?.expose_secret() != CANARY {
        return Err("canary plaintext mismatch".into());
    }
    let token = hex::decode(lines[1])?;
    let probes =
        blind_index_probes::<EmailLookup, str, FieldBound<UserEmail>>(CANARY, &(), indexes)?;
    if !probes.iter().any(|probe| probe.as_bytes() == token) {
        return Err("canary index generation unavailable or mismatched".into());
    }
    println!("Ready.");
    Ok(())
}

async fn put(
    connection: &mut DbConnection,
    id: i64,
    email: Option<String>,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
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

#[cfg(feature = "macro-check")]
async fn macro_put(
    connection: &mut DbConnection,
    id: i64,
    email: String,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    let value = Encrypted::<_, UserEmail>::new(email);
    let prepared = value
        .prepare_with(&(), encryption)?
        .with_index_with::<EmailLookup>(indexes)?;
    let ciphertext = prepared.ciphertext();
    let index = prepared.index::<EmailLookup>()?.as_bytes();
    // PostgreSQL's macro sees BYTEA, not the custom wrapper: override input inference.
    sqlx::query!("INSERT INTO users (id, email, email_lookup) VALUES ($1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET email = excluded.email, email_lookup = excluded.email_lookup",
        id, ciphertext as _, index)
        .execute(connection).await?;
    println!("Stored {id}.");
    Ok(())
}

#[cfg(feature = "macro-check")]
async fn macro_get(
    connection: &mut DbConnection,
    id: i64,
    keys: &LocalEncryptionKeyring,
) -> Result<()> {
    // `?` preserves SQL NULL; the alias selects CryptBox's SQLx Decode implementation.
    let row = sqlx::query!(
        r#"SELECT email AS "email?: EmailCiphertext" FROM users WHERE id = $1"#,
        id
    )
    .fetch_one(connection)
    .await?;
    match row.email {
        Some(ciphertext) => println!(
            "{id}: {}",
            ciphertext.decrypt_with(&(), keys)?.expose_secret()
        ),
        None => println!("{id}: NULL"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let (encryption, indexes) = load_keyrings_from_env()?; // Fail before opening storage if key loading fails.
    let args: Vec<String> = env::args().skip(1).collect();
    if let [command, path] = args.as_slice() {
        match command.as_str() {
            "rotation-canary" => return rotation_canary(path, &encryption, &indexes),
            "rotation-ready" => return rotation_ready(path, &encryption, &indexes),
            _ => {}
        }
    }
    let mut connection = DbConnection::connect(&env::var("DATABASE_URL")?).await?;
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["init"] => {
            #[cfg(feature = "postgres")]
            let schema = include_str!("postgres.sql");
            #[cfg(feature = "sqlite")]
            let schema = include_str!("sqlite.sql");
            sqlx::raw_sql(schema).execute(&mut connection).await?;
            println!("Schema ready.");
        }
        ["put", id, email] => {
            put(
                &mut connection,
                id.parse()?,
                Some((*email).to_owned()),
                &encryption,
                &indexes,
            )
            .await?
        }
        ["put-null", id] => put(&mut connection, id.parse()?, None, &encryption, &indexes).await?,
        ["get", id] => get(&mut connection, id.parse()?, &encryption).await?,
        #[cfg(feature = "maintenance")]
        [
            command @ ("sweep-status"
            | "sweep-batch"
            | "sweep-uncheckpointed"
            | "sweep-verify"
            | "sweep-conflict"),
            run,
        ] => {
            maintenance(&mut connection, command, run, &encryption, &indexes).await?;
        }
        ["generations", id] => {
            let row = sqlx::query("SELECT email, email_lookup FROM users WHERE id = $1")
                .bind(id.parse::<i64>()?)
                .fetch_one(&mut connection)
                .await?;
            let ciphertext: EmailCiphertext = row.try_get("email")?;
            let index: Vec<u8> = row.try_get("email_lookup")?;
            // Structural metadata only; use get/search for authenticated reads.
            println!(
                "Encryption: {}; index: {}.",
                inspect_ciphertext(ciphertext.as_bytes())?.key_id(),
                inspect_blind_index(&index)?.index_key_id()
            );
        }
        #[cfg(feature = "macro-check")]
        ["macro-get", id] => macro_get(&mut connection, id.parse()?, &encryption).await?,
        #[cfg(feature = "macro-check")]
        ["macro-put", id, email] => {
            macro_put(
                &mut connection,
                id.parse()?,
                (*email).to_owned(),
                &encryption,
                &indexes,
            )
            .await?
        }
        ["search", query] => search(&mut connection, query, &encryption, &indexes).await?,
        ["demo-false-candidate", target, source] => {
            // Test fixture ONLY: deliberately break index/plaintext consistency.
            sqlx::query("UPDATE users SET email_lookup = (SELECT email_lookup FROM users WHERE id = $1) WHERE id = $2")
                .bind(source.parse::<i64>()?).bind(target.parse::<i64>()?)
                .execute(&mut connection).await?;
            println!("False candidate injected.");
        }
        _ => {
            return Err(concat!(
                "usage: init | put ID EMAIL | put-null ID | get ID | search EMAIL | ",
                "generations ID | rotation-canary FILE | rotation-ready FILE; ",
                "with maintenance: sweep-status RUN | sweep-batch RUN | sweep-verify RUN | ",
                "sweep-uncheckpointed RUN | sweep-conflict RUN"
            )
            .into());
        }
    }
    connection.close().await?;
    Ok(())
}
```

<!-- END SHARED: searchable -->

`put` is a prepared **upsert**: a new ID inserts, an existing ID updates both
columns. Ciphertext and index are derived from one authoritative plaintext value
and written in one atomic SQL statement. For related writes across tables, wrap
them in your application's SQLx transaction. This example gives concurrent full
updates last-writer-wins behavior; applications needing lost-update protection
should add their normal version check. Binding an `Encrypted` value can trigger
automatic encryption, but **does not maintain a separate index column**.

`get` decodes `Option<Ciphertext<String, UserEmail>>`, preserving nullability and
deferring authentication/decryption until the explicit `decrypt_with` call.
Structural SQLx decoding alone does not authenticate. Local providers are passed
explicitly: no global key context is installed, and `&()` is the field-bound
profile's unit binding context. The demonstration prints plaintext only so you
can observe results; avoid printing actual user emails or putting them in shell
arguments/history in a deployed application.

## 5. Write, update, exit and search

Define a shell helper for your chosen backend so the rest of the commands are
identical. PostgreSQL:

```sh
consumer() { cargo run -- "$@"; }
```

SQLite:

```sh
consumer() { cargo run --no-default-features --features sqlite -- "$@"; }
```

Then run:

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

Expect `Schema ready.`, `Stored 1.`, and `Stored 2.` for writes. `get 2` prints
`2: NULL`. The searches print `Matches: []; rejected: 0.` and
`Matches: [2]; rejected: 0.`: updating ciphertext also updates the lookup token.
The final command clears both columns. Each command exits, closing its connection.

Now open a **new terminal**, return to the same consumer directory, and reload
configuration pointing to the **same keys and database**:

```sh
export CRYPTBOX_KEY_DIR="$PWD/keys"
export CRYPTBOX_GENERATION=2
export DATABASE_URL='postgres://cryptbox:cryptbox@127.0.0.1:55432/cryptbox?sslmode=disable'
# SQLite instead: export DATABASE_URL="sqlite://$PWD/users.db?mode=rwc"
consumer() { cargo run -- "$@"; }
# SQLite instead: consumer() { cargo run --no-default-features --features sqlite -- "$@"; }
consumer get 1
consumer put 3 alice@example.com
consumer search ALICE@example.com
```

`get 1` prints `1:  Alice@Example.com `, including the original surrounding
whitespace. Search prints `Matches: [1, 3]; rejected: 0.`. Row 1 still uses
generation-1 ciphertext and index; row 3 uses generation 2. Both sets of roots
are reloaded and readable in this new process. The query probes **every readable
index generation**, including a staged generation when generation 1 is current.

### Reject a controlled false candidate

Do this only in the disposable tutorial database:

```sh
consumer put 4 bob@example.com
consumer demo-false-candidate 4 3
consumer search ' ALICE@EXAMPLE.COM '
consumer get 4
```

The fixture command intentionally copies row 3's index onto row 4 without changing
its ciphertext. This simulates a false index hit deterministically instead of
waiting for a random 128-bit collision. Expect `False candidate injected.`, then
`Matches: [1, 3]; rejected: 1.`, and `4: bob@example.com`. A false candidate is
filtered normally. Authentication/decoding errors instead fail lookup; they are
not silently treated as collisions. Restore consistency with `put 4 bob@example.com`
after this exercise. The fixture command is not a production write path.

### Why lookup needs verification

<!-- BEGIN SHARED: lookup -->

```mermaid
flowchart TD
    Q[Application query] --> N[Normalize using the stored index policy]
    N --> P[Derive one probe per readable index generation]
    P --> DB[Query complete stored tokens with IN]
    DB --> C[Candidate rows, not confirmed matches]
    C --> D[Authenticate and decrypt ciphertext]
    D --> V{Normalized plaintext equals query?}
    V -->|yes| M[Return match]
    V -->|no| R[Discard false candidate]
    D -->|authentication or decoding error| E[Fail lookup; investigate separately]
```

<!-- END SHARED: lookup -->

In words: normalize the query, derive a probe for **each** readable index
generation, query complete tokens with `IN`, authenticate/decrypt each candidate,
and return only normalized plaintext matches. One `IN` query avoids duplicate
rows across probes. The tutorial fetches all candidates for a small dataset;
larger applications should bound/paginate candidates without skipping final
verification. Missing rows cannot be recovered by candidate filtering: tampered
indexes can hide results, and verification does not authenticate index metadata.

Normalization and precision are **application choices**. Here trimming whitespace
and ASCII lowercasing illustrate case-insensitive lookup. They are not a general
email canonicalization algorithm: local parts may be case-sensitive, Unicode and
internationalized domains need policy, and provider-specific dot/plus rules are
not universal. Validate addresses separately. Indexing and final comparison use
the same normalization implementation.

128 retained bits make accidental collisions rare, but reveal equality and
frequency within a generation. Fewer bits increase false candidates; they do not
remove leakage. Low-cardinality values (booleans, small status sets, predictable
categories) can be especially revealing through frequency or known/chosen values.
Do not infer plaintext secrecy from the absence of an unkeyed hash. A blind index
is **not a uniqueness constraint**: collisions and separate generation tokens
break that interpretation. Enforcing logical email uniqueness needs a separate
application/concurrency design. `NoPadding` also reveals encoded plaintext length;
field binding does not prevent same-field row substitution or replay.

## 6. Verify SQLx query macros and type overrides

The primary `query`/`QueryBuilder` path compiles without a database. SQLx macros
add a **build-time** prerequisite: the selected backend's database must be reachable
through `DATABASE_URL`, with the schema already applied. For PostgreSQL:

```sh
cargo run -- init
cargo check --features macro-check
cargo run --features macro-check -- macro-get 1
cargo run --features macro-check -- macro-get 2
cargo run --features macro-check -- macro-put 5 macro@example.com
cargo run -- search MACRO@example.com
```

SQLite equivalent:

```sh
cargo run --no-default-features --features sqlite -- init
cargo check --no-default-features --features sqlite,macro-check
cargo run --no-default-features --features sqlite,macro-check -- macro-get 1
cargo run --no-default-features --features sqlite,macro-check -- macro-get 2
cargo run --no-default-features --features sqlite,macro-check -- macro-put 5 macro@example.com
cargo run --no-default-features --features sqlite -- search MACRO@example.com
```

Expect the same plaintext for row 1, `2: NULL`, `Stored 5.`, then
`Matches: [5]; rejected: 0.`. The tested read `query!` expression
uses `email AS "email?: EmailCiphertext"`: `?` forces nullable output and the
type alias selects the CryptBox decoder instead of SQLx's default `Vec<u8>`.
Use `!` only for a guaranteed non-null expression; forcing non-null here would
break legitimate null reads. `query_as!` with an application row struct also
supports an explicit alias, or `"email: _"` to infer the custom type from that
struct. Deriving `FromRow` for dynamic `query_as` is another option and needs
SQLx's `derive` feature. The complete example uses the tested `query!` route.

The tested `macro-put` uses `ciphertext as _` to override PostgreSQL macro input
inference for the custom `Ciphertext` wrapper bound to `BYTEA`. It prepares
ciphertext and index together and writes both in a single statement. Dynamic
`.bind(prepared.ciphertext())` avoids this macro inference issue in the primary
write path. Rust trait checks still apply; an
override does not encrypt a separate index or validate candidate plaintext.

For offline builds, install a compatible SQLx 0.8 CLI and run `cargo sqlx prepare
-- --features macro-check` against this schema (SQLite: pass
`--no-default-features --features sqlite,macro-check`). Commit its `.sqlx` query
metadata and use `SQLX_OFFLINE=true` during offline compilation. Regenerate/check
it when queries/schema change, separately for each advertised backend. No offline
cache is needed for the live build-time route tested here.

## 7. Continue rotation and verify the integration

This application's provider is a startup snapshot. Follow the
[staggered fleet rotation procedure](key-rotation.md) to distribute new readable
generations to **all readers**, verify readiness, then promote writers. It uses
the same source with independent `CRYPTBOX_ENCRYPTION` and `CRYPTBOX_INDEX`
selectors. Leave those unset for this introductory tutorial's
`CRYPTBOX_GENERATION` shorthand. The additional canary and generation-inspection
commands support that continuation. Promotion does not rewrite old ciphertext or
indexes; retain historical keys/probes and recovery pairs even after live convergence.
Use the [maintenance sweep guide](reencryption-sweep.md) for later rewriting.

Check startup failures without changing the real key files (use the `consumer`
helper for your selected backend):

```sh
(export CRYPTBOX_KEY_DIR="$PWD/no-such-keys"; consumer get 1)
bad_keys=$(mktemp -d)
printf '%s\n' 'not-hex' > "$bad_keys/encryption-1.hex"
(export CRYPTBOX_KEY_DIR="$bad_keys"; consumer get 1)
printf '%s\n' '00' > "$bad_keys/encryption-1.hex"
(export CRYPTBOX_KEY_DIR="$bad_keys"; consumer get 1)
rm -r "$bad_keys"
consumer get 1
```

The first three reads must exit nonzero with a sanitized `key configuration`
error (unreadable, invalid hex, and wrong length respectively). The subshells
preserve your original configuration; the last read must still return row 1.
Never repair missing keys by generating new bytes under the same IDs.

The [consumer verification instructions](testing.md#durable-searchable-consumer)
exercise this exact source/manifests on both backends, using separate processes
for every command, including SQLx macro compilation and execution. See the
[docs-only integration trial](searchable-sqlx-walk.md) for the reader task and results.

When finished, stop the disposable service with
`docker stop cryptbox-searchable-postgres`. Its data disappears; keep it running
through the restart exercise. SQLite's `users.db` and the provisioned key files
persist until you remove them. Next: add [application testing and diagnostics](testing.md)
and plan [maintenance](reencryption-sweep.md).
