//! Migrates a column from legacy plaintext to encrypted storage.

use std::error::Error;

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Ciphertext, EncryptionKey,
    EncryptionProfile, Field, FieldBound, GlobalKeyContext, IndexId, IndexKeyId, KeyId,
    LocalBlindIndexKeyring, LocalEncryptionKeyring, Utf8, blind_index_probes, field_id, index_id,
    index_key_id, key_id,
    migrate::{MaybeEncrypted, RowPlanner, SqliteSweepStore, Sweep, SweepTable},
};
use sqlx::{Connection, Row, sqlite::SqliteConnection};
use zeroize::Zeroizing;

const OLD_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const CURRENT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");
const OLD_INDEX_KEY_ID: IndexKeyId = index_key_id!("30000000-0000-4000-8000-000000000003");
const CURRENT_INDEX_KEY_ID: IndexKeyId = index_key_id!("40000000-0000-4000-8000-000000000004");

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

    // Legacy rows predate encryption: raw plaintext bytes and no index yet.
    for email in ["first@example.com", "second@example.com"] {
        sqlx::query("INSERT INTO users (email_ciphertext, email_bidx) VALUES (?, ?)")
            .bind(email.as_bytes().to_vec())
            .bind(Vec::<u8>::new())
            .execute(&mut connection)
            .await?;
    }

    // Demo-only material. Load independently generated roots from secret storage.
    let old_key = EncryptionKey::new(OLD_KEY_ID, [0x11; 32]);
    let current_key = EncryptionKey::new(CURRENT_KEY_ID, [0x22; 32]);
    let old_index_key = BlindIndexKey::new(OLD_INDEX_KEY_ID, [0x33; 32]);
    let current_index_key = BlindIndexKey::new(CURRENT_INDEX_KEY_ID, [0x44; 32]);

    // One row was encrypted before a key rotation, one after it.
    let old_keys = LocalEncryptionKeyring::new(old_key.clone(), [])?;
    let old_index_keys = LocalBlindIndexKeyring::new(old_index_key.clone(), [])?;
    insert_encrypted(
        &mut connection,
        "third@example.com",
        &old_keys,
        &old_index_keys,
    )
    .await?;
    let keys = LocalEncryptionKeyring::new(current_key, [old_key])?;
    let index_keys = LocalBlindIndexKeyring::new(current_index_key, [old_index_key])?;
    insert_encrypted(&mut connection, "fourth@example.com", &keys, &index_keys).await?;

    // The steady-state decoding path stays strict: legacy plaintext fails.
    let legacy: Vec<u8> = sqlx::query_scalar("SELECT email_ciphertext FROM users WHERE id = 1")
        .fetch_one(&mut connection)
        .await?;
    assert!(matches!(
        Ciphertext::<String, UserEmail>::from_bytes(legacy),
        Err(cryptbox::Error::NotCiphertext),
    ));

    // During the bounded migration window, reads are permissive. Writes are
    // not: MaybeEncrypted has no Encode, so storing always encrypts.
    let rows = sqlx::query("SELECT id, email_ciphertext FROM users ORDER BY id")
        .fetch_all(&mut connection)
        .await?;
    for row in rows {
        let id: i64 = row.try_get("id")?;
        let value: MaybeEncrypted<String, UserEmail> = row.try_get("email_ciphertext")?;
        assert_eq!(value.is_legacy(), id <= 2);
        let email = value.decrypt_with(&(), &keys)?;
        assert!(email.expose_secret().ends_with("@example.com"));
    }

    // One sweep encrypts the legacy rows and re-encrypts the stale one.
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_index_with::<EmailLookup>(&index_keys);
    let sweep = Sweep::new(planner).with_batch_size(2);
    let table = SweepTable::new("users", "id", "email_ciphertext").with_index_column("email_bidx");
    let mut store = SqliteSweepStore::new(&mut connection, &table);
    store.ensure_progress_table().await?;

    let report = sweep.run(&mut store).await?;
    assert_eq!(report.legacy, 2);
    assert_eq!(report.stale, 1);
    assert_eq!(report.current, 1);
    assert_eq!(report.conflicts, 0);

    // The read-only verification pass proves the terminal state: no legacy,
    // stale, or malformed rows remain, so the permissive reads and the
    // `migrate` feature can be removed, and historical keys retired.
    let report = sweep.verify(&mut store).await?;
    assert!(report.is_terminal());
    assert_eq!(report.current, 4);

    // Every row now decodes strictly and is reachable through the index.
    let probes = blind_index_probes::<EmailLookup, String, FieldBound<UserEmail>>(
        &"first@example.com".to_owned(),
        &(),
        &index_keys,
    )?;
    let mut matched = 0;
    for probe in probes {
        let rows = sqlx::query("SELECT email_ciphertext FROM users WHERE email_bidx = ?")
            .bind(probe.as_bytes().to_vec())
            .fetch_all(&mut connection)
            .await?;
        for row in rows {
            let ciphertext: Ciphertext<String, UserEmail> = row.try_get("email_ciphertext")?;
            let candidate = ciphertext.decrypt_with(&(), &keys)?;
            assert_eq!(candidate.expose_secret(), "first@example.com");
            matched += 1;
        }
    }
    assert_eq!(matched, 1);

    println!("migration complete: {report:?}");

    Ok(())
}

async fn insert_encrypted(
    connection: &mut SqliteConnection,
    email: &str,
    keys: &LocalEncryptionKeyring,
    index_keys: &LocalBlindIndexKeyring,
) -> Result<(), Box<dyn Error>> {
    let value = cryptbox::Encrypted::<_, UserEmail>::new(email.to_owned());
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
