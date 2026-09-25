use std::{env, error::Error, path::Path};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Ciphertext, Encrypted,
    EncryptionKey, FieldBound, IndexId, LocalBlindIndexKeyring, LocalEncryptionKeyring,
    blind_index_probes, index_id, index_key_id, inspect_blind_index, inspect_ciphertext, key_id,
    verify_blind_index_candidate,
};
use sqlx::{Connection, QueryBuilder, Row};
use zeroize::Zeroizing;

#[cfg(feature = "legacy-migration")]
mod migration;

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

fn validate_email(value: &str) -> Result<()> {
    // Match the lookup policy's trimming while preserving the original stored value.
    // Illustrative application syntax only, not general email validation or provenance.
    let bytes = value.trim().as_bytes();
    if bytes.len() > 254
        || !bytes.contains(&b'@')
        || !bytes.iter().all(|byte| byte.is_ascii_graphic())
    {
        return Err("application email validation failed".into());
    }
    Ok(())
}

fn database_url() -> Result<Zeroizing<String>> {
    env::var("DATABASE_URL")
        .map(Zeroizing::new)
        // NotUnicode contains the original bytes, potentially including credentials.
        .map_err(|_| "database configuration: DATABASE_URL must be valid UTF-8 and present".into())
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
    let encryption_1 = || -> Result<EncryptionKey> {
        Ok(EncryptionKey::new(
            key_id!("10000000-0000-4000-8000-000000000001"),
            *load_root_key(directory, "encryption-1.hex")?,
        ))
    };
    let index_1 = || -> Result<BlindIndexKey> {
        Ok(BlindIndexKey::new(
            index_key_id!("30000000-0000-4000-8000-000000000003"),
            *load_root_key(directory, "index-1.hex")?,
        ))
    };
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
        "1" => LocalEncryptionKeyring::new(encryption_1()?, [])?,
        "2-only" => LocalEncryptionKeyring::new(
            EncryptionKey::new(
                key_id!("20000000-0000-4000-8000-000000000002"),
                *load_root_key(directory, "encryption-2.hex")?,
            ),
            [],
        )?,
        "staged" | "2" | "staged-3" | "3" => {
            let encryption_1 = encryption_1()?;
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
                "key configuration: CRYPTBOX_ENCRYPTION must be 1, staged, 2, 2-only, staged-3 or 3".into(),
            );
        }
    };
    let indexes = match index_state.as_str() {
        "1" => LocalBlindIndexKeyring::new(index_1()?, [])?,
        "2-only" => LocalBlindIndexKeyring::new(
            BlindIndexKey::new(
                index_key_id!("40000000-0000-4000-8000-000000000004"),
                *load_root_key(directory, "index-2.hex")?,
            ),
            [],
        )?,
        "staged" | "2" | "staged-3" | "3" => {
            let index_1 = index_1()?;
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
                "key configuration: CRYPTBOX_INDEX must be 1, staged, 2, 2-only, staged-3 or 3"
                    .into(),
            );
        }
    };
    Ok((encryption, indexes))
}

const CANARY: &str = "rotation-canary@example.invalid";

#[cfg(feature = "maintenance")]
async fn audit_current(
    connection: &mut DbConnection,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<usize> {
    // Operator holds a write/restore pause across the full audit and retirement gate.
    let mut after: Option<i64> = None;
    let mut count = 0;
    loop {
        let rows = sqlx::query("SELECT id, email, email_lookup FROM users WHERE ($1 IS NULL OR id > $1) ORDER BY id LIMIT 2")
            .bind(after).fetch_all(&mut *connection).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            // This maintenance fixture requires non-NULL values, as does its packaged sweep.
            let ciphertext: EmailCiphertext = row.try_get("email")?;
            let value = ciphertext.decrypt_with(&(), encryption)?;
            validate_email(value.expose_secret())?;
            let expected = cryptbox::derive_blind_index::<
                EmailLookup,
                String,
                FieldBound<UserEmail>,
            >(value.expose_secret(), &(), indexes)?;
            if expected.as_bytes() != row.try_get::<Vec<u8>, _>("email_lookup")? {
                return Err("index consistency check failed".into());
            }
            after = Some(row.try_get("id")?);
            count += 1;
        }
    }
    Ok(count)
}

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
    #[cfg(feature = "legacy-migration")]
    let legacy = migration::PreviousEncryption::load()?;
    #[cfg(feature = "legacy-migration")]
    let planner = planner.with_legacy(&legacy);
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
            let mut writer = DbConnection::connect(&database_url()?).await?;
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

// ANCHOR: searchable-put
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
// ANCHOR_END: searchable-put

// ANCHOR: searchable-get
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
// ANCHOR_END: searchable-get

// ANCHOR: searchable-search
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
// ANCHOR_END: searchable-search

#[cfg(feature = "macro-check")]
async fn macro_put(
    connection: &mut DbConnection,
    id: i64,
    email: String,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    validate_email(&email)?;
    let value = Encrypted::<_, UserEmail>::new(email);
    let prepared = value
        .prepare_with(&(), encryption)?
        .with_index_with::<EmailLookup>(indexes)?;
    let ciphertext = prepared.ciphertext();
    let index = prepared.index::<EmailLookup>()?.as_bytes();
    // PostgreSQL's macro sees BYTEA, not the custom wrapper: override input inference.
    // ANCHOR: searchable-macro-put
    sqlx::query!("INSERT INTO users (id, email, email_lookup) VALUES ($1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET email = excluded.email, email_lookup = excluded.email_lookup",
        id, ciphertext as _, index)
        .execute(connection).await?;
    // ANCHOR_END: searchable-macro-put
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
    // ANCHOR: searchable-macro-get
    let row = sqlx::query!(
        r#"SELECT email AS "email?: EmailCiphertext" FROM users WHERE id = $1"#,
        id
    )
    .fetch_one(connection)
    .await?;
    // ANCHOR_END: searchable-macro-get
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
    run().await.map_err(sanitize_database_error)
}

fn sanitize_database_error(error: Box<dyn Error>) -> Box<dyn Error> {
    let mut cause: Option<&(dyn Error + 'static)> = Some(error.as_ref());
    while let Some(current) = cause {
        // Also covers database errors wrapped in SweepError::Store.
        if current.is::<sqlx::Error>() {
            return "database operation failed".into();
        }
        cause = current.source();
    }
    // Configuration values are sanitized at their read boundary. Other operations
    // use static categories, sanitized CryptBox errors, or non-value-bearing IO/parse
    // errors. Review newly introduced upstream errors before passing them through.
    error
}

async fn run() -> Result<()> {
    let (encryption, indexes) = load_keyrings_from_env()?; // Fail before opening storage if key loading fails.
    let args: Vec<String> = env::args().skip(1).collect();
    if let [command, path] = args.as_slice() {
        match command.as_str() {
            "rotation-canary" => return rotation_canary(path, &encryption, &indexes),
            "rotation-ready" => return rotation_ready(path, &encryption, &indexes),
            _ => {}
        }
    }
    let mut connection = DbConnection::connect(&database_url()?).await?;
    #[cfg(feature = "legacy-migration")]
    if args
        .first()
        .is_some_and(|arg| arg.starts_with("migration-"))
    {
        migration::command(&mut connection, &args, &encryption, &indexes).await?;
        connection.close().await?;
        return Ok(());
    }
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
        #[cfg(all(feature = "maintenance", feature = "sqlite"))]
        ["recovery-copy", path] => {
            // SQLite makes a consistent standalone copy, including any committed WAL data.
            // Refuse replacement even of an empty artifact; SQL also rejects nonempty targets.
            if Path::new(path).exists() {
                return Err("database copy destination already exists".into());
            }
            sqlx::query("VACUUM INTO $1")
                .bind(path)
                .execute(&mut connection)
                .await?;
            println!("Database copy saved.");
        }
        #[cfg(feature = "maintenance")]
        ["audit-current"] => {
            let count = audit_current(&mut connection, &encryption, &indexes).await?;
            println!("Audited: {count} authenticated, current-index rows.");
        }
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
                "sweep-uncheckpointed RUN | sweep-conflict RUN | audit-current; ",
                "with sqlite,maintenance: recovery-copy NEW_FILE"
            )
            .into());
        }
    }
    connection.close().await?;
    Ok(())
}
