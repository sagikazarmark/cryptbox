//! Sweeps a table after encryption-key and blind-index-key rotation.

use std::error::Error;

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyProvider, BlindIndexMetadata,
    BlindIndexSpec, Ciphertext, Encrypted, EncryptionKey, EncryptionKeyProvider, EncryptionProfile,
    Field, FieldBound, GlobalKeyContext, IndexId, IndexKeyId, KeyId, LocalBlindIndexKeyring,
    LocalEncryptionKeyring, Utf8, blind_index_probes, derive_blind_index, field_id, index_id,
    index_key_id, inspect_blind_index, key_id,
};
use sqlx::{Connection, Row, sqlite::SqliteConnection};
use zeroize::Zeroizing;

const OLD_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const CURRENT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");
const OLD_INDEX_KEY_ID: IndexKeyId = index_key_id!("30000000-0000-4000-8000-000000000003");
const CURRENT_INDEX_KEY_ID: IndexKeyId = index_key_id!("40000000-0000-4000-8000-000000000004");
const BATCH_SIZE: i64 = 2;
const MIGRATION_NAME: &str = "users-email-current-generations";

struct UserEmail;

impl Field for UserEmail {
    const ID: cryptbox::FieldId = field_id!("50000000-0000-4000-8000-000000000005");
    const NAME: &'static str = "user-email";
}

impl EncryptionProfile<String> for UserEmail {
    type Binding = FieldBound<Self>;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = cryptbox::NoPadding;
}

struct EmailLookup;

impl BlindIndexMetadata for EmailLookup {
    const ID: IndexId = index_id!("60000000-0000-4000-8000-000000000006");
    const BITS: usize = 128;
}

impl BlindIndexSpec<String> for EmailLookup {
    fn normalize(input: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(
            input.trim().to_ascii_lowercase().into_bytes(),
        ))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    futures_executor::block_on(run())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut connection = SqliteConnection::connect("sqlite::memory:").await?;
    sqlx::query(
        "CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_ciphertext BLOB NOT NULL,
            email_bidx BLOB NOT NULL
        )",
    )
    .execute(&mut connection)
    .await?;
    sqlx::query(
        "CREATE TABLE migration_progress (
            name TEXT PRIMARY KEY,
            last_id INTEGER NOT NULL
        )",
    )
    .execute(&mut connection)
    .await?;
    sqlx::query("INSERT INTO migration_progress (name, last_id) VALUES (?, 0)")
        .bind(MIGRATION_NAME)
        .execute(&mut connection)
        .await?;

    // Demo-only material. Load independently generated roots from secret storage.
    let old_key = EncryptionKey::new(OLD_KEY_ID, [0x11; 32]);
    let current_key = EncryptionKey::new(CURRENT_KEY_ID, [0x22; 32]);
    let old_index_key = BlindIndexKey::new(OLD_INDEX_KEY_ID, [0x33; 32]);
    let current_index_key = BlindIndexKey::new(CURRENT_INDEX_KEY_ID, [0x44; 32]);
    let old_keys = LocalEncryptionKeyring::new(old_key.clone(), [])?;
    let old_index_keys = LocalBlindIndexKeyring::new(old_index_key.clone(), [])?;

    for email in [
        "first@example.com",
        "second@example.com",
        "third@example.com",
    ] {
        insert_email(&mut connection, email, &old_keys, &old_index_keys).await?;
    }

    // Deploy these current-plus-historical keyrings to every writer before sweeping.
    let rotated_keys = LocalEncryptionKeyring::new(current_key.clone(), [old_key])?;
    let rotated_index_keys =
        LocalBlindIndexKeyring::new(current_index_key.clone(), [old_index_key])?;
    insert_email(
        &mut connection,
        "already-current@example.com",
        &rotated_keys,
        &rotated_index_keys,
    )
    .await?;
    let current_before: Vec<u8> =
        sqlx::query_scalar("SELECT email_ciphertext FROM users WHERE id = 4")
            .fetch_one(&mut connection)
            .await?;

    // The worker persists its checkpoint only after a whole batch succeeds.
    sweep_batch(&mut connection, &rotated_keys, &rotated_index_keys)
        .await?
        .expect("the example seeded rows");

    // A later worker invocation reloads the durable checkpoint. If a process stops
    // before storing it, replay is safe because current rows are skipped.
    while sweep_batch(&mut connection, &rotated_keys, &rotated_index_keys)
        .await?
        .is_some()
    {}

    assert!(verify_sweep(&mut connection, &rotated_keys, &rotated_index_keys).await?);
    let current_after: Vec<u8> =
        sqlx::query_scalar("SELECT email_ciphertext FROM users WHERE id = 4")
            .fetch_one(&mut connection)
            .await?;
    assert_eq!(current_after, current_before);

    // Only after verification may deployments remove the historical keys and old probe.
    let current_keys = LocalEncryptionKeyring::new(current_key, [])?;
    let current_index_keys = LocalBlindIndexKeyring::new(current_index_key, [])?;
    assert!(verify_sweep(&mut connection, &current_keys, &current_index_keys).await?);
    assert_eq!(
        blind_index_probes::<EmailLookup, String, FieldBound<UserEmail>>(
            &"first@example.com".to_owned(),
            &(),
            &current_index_keys,
        )?
        .len(),
        1
    );

    Ok(())
}

async fn insert_email(
    connection: &mut SqliteConnection,
    email: &str,
    keys: &dyn EncryptionKeyProvider,
    index_keys: &dyn BlindIndexKeyProvider,
) -> Result<(), Box<dyn Error>> {
    let value = Encrypted::<_, UserEmail>::new(email.to_owned());
    let prepared = value
        .prepare_with(&(), keys)?
        .with_index_with::<EmailLookup>(index_keys)?;

    sqlx::query("INSERT INTO users (email_ciphertext, email_bidx) VALUES (?, ?)")
        .bind(prepared.ciphertext())
        .bind(prepared.index::<EmailLookup>()?)
        .execute(connection)
        .await?;

    Ok(())
}

async fn sweep_batch(
    connection: &mut SqliteConnection,
    keys: &dyn EncryptionKeyProvider,
    index_keys: &dyn BlindIndexKeyProvider,
) -> Result<Option<i64>, Box<dyn Error>> {
    let current_index_key_id = index_keys.current_key()?.id();
    let after_id: i64 = sqlx::query_scalar("SELECT last_id FROM migration_progress WHERE name = ?")
        .bind(MIGRATION_NAME)
        .fetch_one(&mut *connection)
        .await?;
    let rows = sqlx::query(
        "SELECT id, email_ciphertext, email_bidx
         FROM users
         WHERE id > ?
         ORDER BY id
         LIMIT ?",
    )
    .bind(after_id)
    .bind(BATCH_SIZE)
    .fetch_all(&mut *connection)
    .await?;
    let checkpoint = rows.last().map(|row| row.get::<i64, _>("id"));

    for row in rows {
        let id: i64 = row.try_get("id")?;
        let old_ciphertext_bytes: Vec<u8> = row.try_get("email_ciphertext")?;
        let old_index_bytes: Vec<u8> = row.try_get("email_bidx")?;
        let ciphertext = Ciphertext::<String, UserEmail>::from_bytes(old_ciphertext_bytes.clone())?;
        let index = BlindIndex::<EmailLookup>::from_bytes(old_index_bytes.clone())?;
        let ciphertext_is_stale = ciphertext.needs_reencryption_with(keys)?;
        let index_is_stale =
            inspect_blind_index(index.as_bytes())?.index_key_id() != current_index_key_id;

        if !ciphertext_is_stale && !index_is_stale {
            continue;
        }

        let rewritten_ciphertext = if ciphertext_is_stale {
            ciphertext.reencrypt_with(&(), keys)?
        } else {
            ciphertext
        };
        let rewritten_index = if index_is_stale {
            let plaintext = rewritten_ciphertext.decrypt_with(&(), keys)?;
            derive_blind_index::<EmailLookup, String, FieldBound<UserEmail>>(
                plaintext.expose_secret(),
                &(),
                index_keys,
            )?
        } else {
            index
        };

        let result = sqlx::query(
            "UPDATE users
             SET email_ciphertext = ?, email_bidx = ?
             WHERE id = ? AND email_ciphertext = ? AND email_bidx = ?",
        )
        .bind(&rewritten_ciphertext)
        .bind(&rewritten_index)
        .bind(id)
        .bind(old_ciphertext_bytes)
        .bind(old_index_bytes)
        .execute(&mut *connection)
        .await?;

        // Zero rows means a concurrent writer won. Never overwrite its newer value.
        // Writers already using current keys need no follow-up; verification catches
        // any stale value left by an incorrectly configured writer.
        assert!(result.rows_affected() <= 1);
    }

    if let Some(checkpoint) = checkpoint {
        sqlx::query("UPDATE migration_progress SET last_id = ? WHERE name = ?")
            .bind(checkpoint)
            .bind(MIGRATION_NAME)
            .execute(&mut *connection)
            .await?;
    }

    Ok(checkpoint)
}

async fn verify_sweep(
    connection: &mut SqliteConnection,
    keys: &dyn EncryptionKeyProvider,
    index_keys: &dyn BlindIndexKeyProvider,
) -> Result<bool, Box<dyn Error>> {
    let current_index_key_id = index_keys.current_key()?.id();
    let rows = sqlx::query("SELECT email_ciphertext, email_bidx FROM users")
        .fetch_all(connection)
        .await?;

    for row in rows {
        let ciphertext: Ciphertext<String, UserEmail> = row.try_get("email_ciphertext")?;
        let index: BlindIndex<EmailLookup> = row.try_get("email_bidx")?;
        if ciphertext.needs_reencryption_with(keys)?
            || inspect_blind_index(index.as_bytes())?.index_key_id() != current_index_key_id
        {
            return Ok(false);
        }
    }

    Ok(true)
}
