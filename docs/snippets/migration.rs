//! Illustrative migration application, not a production legacy wire format.
use super::*;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use cryptbox::migrate::{LegacyError, LegacyErrorKind, LegacyFormat, MaybeEncrypted};

const HEADER: &[u8] = b"illustrative-legacy-v1\0";
const COLLISION: &[u8] = b"CBX\0illustrative-legacy-v1\0";

pub(super) struct PreviousEncryption(Zeroizing<[u8; 32]>);

impl PreviousEncryption {
    pub(super) fn load() -> Result<Self> {
        Ok(Self(load_root_key(
            Path::new(&env::var("CRYPTBOX_KEY_DIR")?),
            "legacy.hex",
        )?))
    }

    fn seal(&self, header: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| "legacy fixture entropy failed")?;
        let sealed = XChaCha20Poly1305::new((&*self.0).into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: header,
                },
            )
            .map_err(|_| "legacy fixture encryption failed")?;
        Ok([header, &nonce, &sealed].concat())
    }
}

impl LegacyFormat for PreviousEncryption {
    fn recover(&self, bytes: &[u8]) -> std::result::Result<Zeroizing<Vec<u8>>, LegacyError> {
        let header = [HEADER, COLLISION]
            .into_iter()
            .find(|header| bytes.starts_with(header));
        let plaintext = if let Some(header) = header {
            let payload = &bytes[header.len()..];
            if payload.len() < 24 + 16 {
                return Err(LegacyError::new(LegacyErrorKind::Malformed));
            }
            let nonce: &[u8; 24] = payload[..24]
                .try_into()
                .map_err(|_| LegacyError::new(LegacyErrorKind::Malformed))?;
            Zeroizing::new(
                XChaCha20Poly1305::new((&*self.0).into())
                    .decrypt(
                        nonce.into(),
                        Payload {
                            msg: &payload[24..],
                            aad: header,
                        },
                    )
                    .map_err(|_| LegacyError::new(LegacyErrorKind::AuthenticationFailed))?,
            )
        } else {
            Zeroizing::new(bytes.to_vec())
        };
        // Application syntax policy only: this does NOT establish legacy provenance.
        validate(&plaintext).map_err(|_| LegacyError::new(LegacyErrorKind::Malformed))?;
        Ok(plaintext)
    }
}

fn validate(bytes: &[u8]) -> Result<()> {
    if bytes.len() > 254
        || !bytes.contains(&b'@')
        || !bytes.iter().all(|byte| byte.is_ascii_graphic())
    {
        return Err("application email validation failed".into());
    }
    Ok(())
}

fn recover(
    bytes: Vec<u8>,
    collision: bool,
    keys: &LocalEncryptionKeyring,
    legacy: &PreviousEncryption,
) -> Result<Encrypted<String, UserEmail>> {
    let stored: MaybeEncrypted<String, UserEmail> = if collision {
        // Only a trusted application discriminator can authorize this bypass.
        MaybeEncrypted::from_legacy_bytes(bytes)
    } else {
        MaybeEncrypted::from_bytes(bytes)?
    };
    let value = stored.decrypt_with_legacy(&(), keys, legacy)?;
    validate(value.expose_secret().as_bytes())?;
    Ok(value)
}

async fn seed(
    db: &mut DbConnection,
    keys: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    // Disposable fixture only. These records model trusted application metadata.
    sqlx::query("CREATE TABLE migration_formats (id BIGINT PRIMARY KEY, format TEXT NOT NULL)")
        .execute(&mut *db)
        .await?;
    sqlx::query("CREATE TABLE migration_quarantine AS SELECT id, email, email_lookup, 0 AS resolved FROM users WHERE 1 = 0")
        .execute(&mut *db).await?;
    let legacy = PreviousEncryption::load()?;
    for (id, bytes) in [
        (10_i64, b"mixed@example.com".to_vec()),
        (20, legacy.seal(HEADER, b"mixed@example.com")?),
        (60, legacy.seal(COLLISION, b"mixed@example.com")?),
        (70, b"other@example.com".to_vec()),
    ] {
        sqlx::query("INSERT INTO users (id, email, email_lookup) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(bytes)
            .bind(Vec::<u8>::new())
            .execute(&mut *db)
            .await?;
    }
    sqlx::query("INSERT INTO migration_formats VALUES (60, 'legacy-collision')")
        .execute(&mut *db)
        .await?;
    let directory = env::var("CRYPTBOX_KEY_DIR")?;
    let old_keys = LocalEncryptionKeyring::new(
        EncryptionKey::new(
            key_id!("10000000-0000-4000-8000-000000000001"),
            *load_root_key(Path::new(&directory), "encryption-1.hex")?,
        ),
        [],
    )?;
    let old_indexes = LocalBlindIndexKeyring::new(
        BlindIndexKey::new(
            index_key_id!("30000000-0000-4000-8000-000000000003"),
            *load_root_key(Path::new(&directory), "index-1.hex")?,
        ),
        [],
    )?;
    // Avoid CLI output from put: the prepared pair still uses one atomic statement.
    for (id, encryption, index) in [
        (30_i64, &old_keys, &old_indexes),
        (40, keys, indexes),
        (50, keys, indexes),
    ] {
        let value = Encrypted::<_, UserEmail>::new("mixed@example.com".to_owned());
        let prepared = value
            .prepare_with(&(), encryption)?
            .with_index_with::<EmailLookup>(index)?;
        let token = if id == 50 {
            &[]
        } else {
            prepared.index::<EmailLookup>()?.as_bytes()
        };
        sqlx::query("INSERT INTO users (id, email, email_lookup) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(prepared.ciphertext())
            .bind(token)
            .execute(&mut *db)
            .await?;
    }
    println!("Mixed-format fixture ready.");
    Ok(())
}

async fn lookup(
    db: &mut DbConnection,
    query: &str,
    keys: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    let mut tx = db.begin().await?;
    #[cfg(feature = "postgres")]
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    // The quarantine gate and candidate read must observe the same snapshot.
    quarantine_gate(&mut tx).await?;
    let legacy = PreviousEncryption::load()?;
    let probes =
        blind_index_probes::<EmailLookup, str, FieldBound<UserEmail>>(query, &(), indexes)?;
    // One statement selects a row once, even when it matches both predicates.
    // A single statement snapshot avoids moving rows between a scan and probe query.
    let mut sql = QueryBuilder::<Db>::new(
        "SELECT u.id, u.email, f.format FROM users u LEFT JOIN migration_formats f ON f.id = u.id \
         WHERE u.email IS NOT NULL AND (length(u.email_lookup) = 0 OR u.email_lookup IN (",
    );
    let mut values = sql.separated(", ");
    for probe in &probes {
        values.push_bind(probe.as_bytes());
    }
    values.push_unseparated(")) ORDER BY u.id");
    let rows = sql.build().fetch_all(&mut *tx).await?;
    let mut matches = Vec::<i64>::new();
    let mut rejected = 0;
    for row in rows {
        let collision =
            row.try_get::<Option<String>, _>("format")?.as_deref() == Some("legacy-collision");
        let candidate = recover(row.try_get("email")?, collision, keys, &legacy)?;
        if verify_blind_index_candidate::<EmailLookup, str>(query, candidate.expose_secret())? {
            matches.push(row.try_get("id")?);
        } else {
            rejected += 1;
        }
    }
    tx.commit().await?;
    // Any recovery error fails the entire lookup; never publish a partial result.
    println!("Matches: {matches:?}; rejected: {rejected}.");
    Ok(())
}

async fn quarantine_gate(db: &mut DbConnection) -> Result<()> {
    let pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM migration_quarantine WHERE resolved = 0")
            .fetch_one(db)
            .await?;
    if pending != 0 {
        return Err("unresolved quarantine: lookup and closure blocked".into());
    }
    Ok(())
}

async fn repair(
    db: &mut DbConnection,
    id: i64,
    collision: bool,
    keys: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    let mut tx = db.begin().await?;
    let row = sqlx::query("SELECT u.email, u.email_lookup, f.format FROM users u LEFT JOIN migration_formats f ON f.id = u.id WHERE u.id = $1")
        .bind(id).fetch_one(&mut *tx).await?;
    let bytes = Zeroizing::new(row.try_get::<Vec<u8>, _>("email")?);
    let old_index: Vec<u8> = row.try_get("email_lookup")?;
    let format: Option<String> = row.try_get("format")?;
    if collision && format.as_deref() != Some("legacy-collision") {
        return Err("trusted legacy discriminator required".into());
    }
    if !collision && !old_index.is_empty() {
        return Err("missing projection required".into());
    }
    let value = recover(
        bytes.to_vec(),
        collision,
        keys,
        &PreviousEncryption::load()?,
    )?;
    let prepared = value
        .prepare_with(&(), keys)?
        .with_index_with::<EmailLookup>(indexes)?;
    let changed = sqlx::query("UPDATE users SET email = $1, email_lookup = $2 WHERE id = $3 AND email = $4 AND email_lookup = $5")
        .bind(prepared.ciphertext()).bind(prepared.index::<EmailLookup>()?.as_bytes())
        .bind(id).bind(bytes.as_slice()).bind(&old_index).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err("guarded repair conflict: reload and investigate".into());
    }
    if collision {
        let removed = sqlx::query(
            "DELETE FROM migration_formats WHERE id = $1 AND format = 'legacy-collision'",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if removed != 1 {
            return Err("discriminator changed: repair rolled back".into());
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn close(
    db: &mut DbConnection,
    keys: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    // Operator prerequisite: writers/restore jobs paused and in-flight work drained.
    quarantine_gate(db).await?;
    let discriminators: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM migration_formats")
        .fetch_one(&mut *db)
        .await?;
    if discriminators != 0 {
        return Err("unresolved legacy discriminators".into());
    }
    #[cfg(feature = "postgres")]
    use cryptbox::migrate::PostgresSweepStore as Store;
    #[cfg(feature = "sqlite")]
    use cryptbox::migrate::SqliteSweepStore as Store;
    use cryptbox::migrate::{RowPlanner, Sweep, SweepTable};
    let table = SweepTable::new("users", "id", "email").with_index_column("email_lookup");
    let planner =
        RowPlanner::<String, UserEmail>::new(&(), keys).with_index_with::<EmailLookup>(indexes);
    let report = Sweep::new(planner)
        .with_batch_size(2)
        .verify(&mut Store::new(db, &table))
        .await?;
    if !report.is_terminal() {
        return Err("migration-state convergence required".into());
    }
    let mut after: Option<i64> = None;
    let mut count = 0;
    loop {
        let rows = sqlx::query("SELECT id, email, email_lookup FROM users WHERE ($1 IS NULL OR id > $1) ORDER BY id LIMIT 2")
            .bind(after).fetch_all(&mut *db).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let ciphertext: EmailCiphertext = row.try_get("email")?;
            let value = ciphertext.decrypt_with(&(), keys)?;
            validate(value.expose_secret().as_bytes())?;
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
    println!("Closure verified: {count} authenticated, validated, indexed rows.");
    Ok(())
}

pub(super) async fn command(
    db: &mut DbConnection,
    args: &[String],
    keys: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["migration-seed"] => seed(db, keys, indexes).await?,
        ["migration-search", query] => lookup(db, query, keys, indexes).await?,
        ["migration-close"] => close(db, keys, indexes).await?,
        ["migration-damage"] => {
            // Fixture only: flip the authentication tag of the previous solution.
            let mut bytes: Vec<u8> = sqlx::query_scalar("SELECT email FROM users WHERE id = 20")
                .fetch_one(&mut *db)
                .await?;
            *bytes.last_mut().ok_or("empty fixture")? ^= 1;
            sqlx::query("UPDATE users SET email = $1 WHERE id = 20")
                .bind(bytes)
                .execute(db)
                .await?;
            println!("Legacy authentication failure injected.");
        }
        ["migration-quarantine"] => {
            let mut tx = db.begin().await?;
            let row = sqlx::query("SELECT email, email_lookup FROM users WHERE id = 20")
                .fetch_one(&mut *tx)
                .await?;
            let bytes = Zeroizing::new(row.try_get::<Vec<u8>, _>("email")?);
            let index: Vec<u8> = row.try_get("email_lookup")?;
            sqlx::query("INSERT INTO migration_quarantine (id, email, email_lookup, resolved) VALUES (20, $1, $2, 0)")
                .bind(bytes.as_slice()).bind(&index).execute(&mut *tx).await?;
            let removed =
                sqlx::query("DELETE FROM users WHERE id = 20 AND email = $1 AND email_lookup = $2")
                    .bind(bytes.as_slice())
                    .bind(&index)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
            if removed != 1 {
                return Err("quarantine conflict: rolled back".into());
            }
            tx.commit().await?;
            println!("Quarantined 20; closure blocked.");
        }
        ["migration-restore"] => {
            // Fixture-only trusted source. In production require investigated, approved data.
            let value = Encrypted::<_, UserEmail>::new("mixed@example.com".to_owned());
            let prepared = value
                .prepare_with(&(), keys)?
                .with_index_with::<EmailLookup>(indexes)?;
            let mut tx = db.begin().await?;
            // INSERT, not upsert: a concurrently recreated row must not be overwritten.
            sqlx::query("INSERT INTO users (id, email, email_lookup) VALUES (20, $1, $2)")
                .bind(prepared.ciphertext())
                .bind(prepared.index::<EmailLookup>()?.as_bytes())
                .execute(&mut *tx)
                .await?;
            let resolved = sqlx::query(
                "UPDATE migration_quarantine SET resolved = 1 WHERE id = 20 AND resolved = 0",
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if resolved != 1 {
                return Err("one unresolved case required".into());
            }
            tx.commit().await?;
            println!("Restored 20 from approved fixture source.");
        }
        ["migration-classify", id] => {
            let bytes: Vec<u8> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
                .bind(id.parse::<i64>()?)
                .fetch_one(db)
                .await?;
            MaybeEncrypted::<String, UserEmail>::from_bytes(bytes)?;
            println!("Ordinary classification succeeded.");
        }
        ["migration-repair-collision"] => {
            repair(db, 60, true, keys, indexes).await?;
            println!("Repaired discriminator-known row 60.");
        }
        ["migration-repair-missing"] => {
            repair(db, 50, false, keys, indexes).await?;
            println!("Backfilled missing projection on row 50.");
        }
        ["migration-get", id] => {
            let id = id.parse::<i64>()?;
            let row = sqlx::query("SELECT u.email, f.format FROM users u LEFT JOIN migration_formats f ON f.id = u.id WHERE u.id = $1")
                .bind(id).fetch_one(db).await?;
            let collision =
                row.try_get::<Option<String>, _>("format")?.as_deref() == Some("legacy-collision");
            let value = recover(
                row.try_get("email")?,
                collision,
                keys,
                &PreviousEncryption::load()?,
            )?;
            println!("{id}: {}", value.expose_secret());
        }
        _ => return Err("unknown migration command".into()),
    }
    Ok(())
}
