//! End-to-end plaintext migration over the `SQLx` `SQLite` adapter.

#![cfg(all(feature = "migrate", feature = "sqlx-sqlite"))]

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, IndexId, IndexKeyId, KeyId, Padding, Seal, Sealed, Utf8, index_id,
    index_key_id, key_id,
    migrate::{
        LegacyError, LegacyFormat, MaybeSealed, RowPlanner, SqliteSweepStore, Sweep, SweepError,
        SweepTable,
    },
    seal_id,
};
use sqlx::{
    Connection, Row,
    sqlite::{SqliteConnection, SqliteRow},
};
use zeroize::Zeroizing;

const OLD_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const CURRENT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");
const OLD_INDEX_KEY_ID: IndexKeyId = index_key_id!("30000000-0000-4000-8000-000000000003");
const CURRENT_INDEX_KEY_ID: IndexKeyId = index_key_id!("40000000-0000-4000-8000-000000000004");

struct UserEmail;

impl Seal for UserEmail {
    const ID: cryptbox::SealId = seal_id!("50000000-0000-4000-8000-000000000005");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct EmailLookup;

struct ToyLegacy;

static TOY_LEGACY: ToyLegacy = ToyLegacy;

impl LegacyFormat for ToyLegacy {
    fn recover(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, LegacyError> {
        Ok(Zeroizing::new(
            bytes.strip_prefix(b"legacy:").unwrap_or(bytes).to_vec(),
        ))
    }
}

impl BlindIndexSpec for EmailLookup {
    type Seal = UserEmail;
    const ID: IndexId = index_id!("60000000-0000-4000-8000-000000000006");
    const BITS: u16 = 128;
    const NORMALIZER: &'static str = "email/1";
    type Query = str;

    fn normalize_query(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(
            input.trim().to_ascii_lowercase().into_bytes(),
        ))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

fn assert_strict_decode(row: &SqliteRow, is_legacy: bool) {
    let result = row.try_get::<Sealed<UserEmail>, _>("email_ciphertext");
    if !is_legacy {
        result.unwrap();
        return;
    }

    let sqlx::Error::ColumnDecode { source, .. } = result.unwrap_err() else {
        panic!("expected a column decode error");
    };
    assert_eq!(source.downcast_ref::<Error>(), Some(&Error::NotCiphertext));
}

#[test]
fn migrates_a_sqlite_table_from_plaintext_to_a_terminal_state() {
    futures_executor::block_on(async {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_ciphertext BLOB NOT NULL,
                email_bidx BLOB NOT NULL
            )",
        )
        .execute(&mut connection)
        .await
        .unwrap();

        let old_key = EncryptionKey::new(OLD_KEY_ID, [0x11; 32]);
        let current_key = EncryptionKey::new(CURRENT_KEY_ID, [0x22; 32]);
        let old_index_key = BlindIndexKey::new(OLD_INDEX_KEY_ID, [0x33; 32]);
        let current_index_key = BlindIndexKey::new(CURRENT_INDEX_KEY_ID, [0x44; 32]);
        let old_keys = EncryptionKeyring::new(old_key.clone(), []).unwrap();
        let old_index_keys = BlindIndexKeyring::new(old_index_key.clone(), []).unwrap();
        let keys = EncryptionKeyring::new(current_key, [old_key]).unwrap();
        let index_keys = BlindIndexKeyring::new(current_index_key, [old_index_key]).unwrap();

        // One plaintext row, one foreign-ciphertext row, one stale encrypted
        // row, and one current row.
        for bytes in [
            b"first@example.com".to_vec(),
            b"legacy:second@example.com".to_vec(),
        ] {
            sqlx::query("INSERT INTO users (email_ciphertext, email_bidx) VALUES (?, ?)")
                .bind(bytes)
                .bind(Vec::<u8>::new())
                .execute(&mut connection)
                .await
                .unwrap();
        }
        for (email, keyring, index_keyring) in [
            ("third@example.com", &old_keys, &old_index_keys),
            ("fourth@example.com", &keys, &index_keys),
        ] {
            let value = email.to_owned();
            let sealed = Sealed::<UserEmail>::seal(&value, keyring).unwrap();
            let index = BlindIndex::<EmailLookup>::derive(&value, index_keyring).unwrap();
            sqlx::query("INSERT INTO users (email_ciphertext, email_bidx) VALUES (?, ?)")
                .bind(&sealed)
                .bind(&index)
                .execute(&mut connection)
                .await
                .unwrap();
        }

        // The strict decode path fails on legacy plaintext; the permissive
        // migration read classifies and still decrypts every row.
        let rows = sqlx::query("SELECT id, email_ciphertext FROM users ORDER BY id")
            .fetch_all(&mut connection)
            .await
            .unwrap();
        for row in rows {
            let id: i64 = row.try_get("id").unwrap();
            assert_strict_decode(&row, id <= 2);
            let read: MaybeSealed<UserEmail> = row.try_get("email_ciphertext").unwrap();
            assert_eq!(read.is_legacy(), id <= 2);
            read.open_legacy(&keys, &TOY_LEGACY).unwrap();
        }

        // Batch size one exercises pagination and per-batch checkpoints.
        let planner = RowPlanner::<UserEmail>::new(&keys)
            .with_legacy(&TOY_LEGACY)
            .with_index::<EmailLookup>(&index_keys);
        let sweep = Sweep::new(planner).with_batch_size(1);
        let table =
            SweepTable::new("users", "id", "email_ciphertext").with_index_column("email_bidx");
        let mut store = SqliteSweepStore::new(&mut connection, &table);
        store.ensure_progress_table().await.unwrap();

        let report = sweep.run(&mut store).await.unwrap();
        assert_eq!(report.legacy, 2);
        assert_eq!(report.stale, 1);
        assert_eq!(report.current, 1);
        assert_eq!(report.conflicts, 0);

        // A resumed worker finds the durable checkpoint and rewrites nothing.
        let report = sweep.run(&mut store).await.unwrap();
        assert_eq!(report.current, 0);
        assert_eq!(report.legacy + report.stale + report.conflicts, 0);

        let report = sweep.verify(&mut store).await.unwrap();
        assert!(report.is_terminal());
        assert_eq!(report.current, 4);

        let checkpoint: i64 =
            sqlx::query_scalar("SELECT last_id FROM cryptbox_migration_progress WHERE name = ?")
                .bind("users.email_ciphertext")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(checkpoint, 4);

        // After the terminal state, the strict path decodes every row.
        let rows = sqlx::query("SELECT email_ciphertext FROM users")
            .fetch_all(&mut connection)
            .await
            .unwrap();
        for row in rows {
            let ciphertext: Sealed<UserEmail> = row.try_get("email_ciphertext").unwrap();
            assert!(!ciphertext.needs_reseal(&keys).unwrap());
        }
    });
}

#[test]
fn permissive_decode_propagates_hard_errors() {
    futures_executor::block_on(async {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE rows (bytes BLOB NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("INSERT INTO rows (bytes) VALUES (?)")
            .bind(b"CBX\0garbage".to_vec())
            .execute(&mut connection)
            .await
            .unwrap();

        // Magic-prefixed garbage must not fall back to plaintext.
        let row = sqlx::query("SELECT bytes FROM rows")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        let result = row.try_get::<MaybeSealed<UserEmail>, _>("bytes");
        let error = result.unwrap_err();
        let sqlx::Error::ColumnDecode { source, .. } = error else {
            panic!("expected a column decode error");
        };
        assert_eq!(
            source.downcast_ref::<Error>(),
            Some(&Error::InvalidEnvelope)
        );
    });
}

#[test]
fn migrates_plaintext_stored_as_text() {
    futures_executor::block_on(async {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL,
                email_bidx BLOB NOT NULL DEFAULT ''
            )",
        )
        .execute(&mut connection)
        .await
        .unwrap();

        // Applications usually bind existing plaintext as text, and an index
        // column added with a `''` default holds text as well.
        sqlx::query("INSERT INTO users (email) VALUES (?)")
            .bind("first@example.com")
            .execute(&mut connection)
            .await
            .unwrap();

        let keys =
            EncryptionKeyring::new(EncryptionKey::new(CURRENT_KEY_ID, [0x22; 32]), []).unwrap();
        let index_keys =
            BlindIndexKeyring::new(BlindIndexKey::new(CURRENT_INDEX_KEY_ID, [0x44; 32]), [])
                .unwrap();
        let planner = RowPlanner::<UserEmail>::new(&keys).with_index::<EmailLookup>(&index_keys);
        let sweep = Sweep::new(planner);
        let table = SweepTable::new("users", "id", "email").with_index_column("email_bidx");
        let mut store = SqliteSweepStore::new(&mut connection, &table);
        store.ensure_progress_table().await.unwrap();

        let report = sweep.run(&mut store).await.unwrap();
        assert_eq!(report.legacy, 1);
        assert_eq!(report.conflicts, 0);

        let report = sweep.verify(&mut store).await.unwrap();
        assert!(report.is_terminal());

        let row = sqlx::query("SELECT email, email_bidx FROM users")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        let email: Sealed<UserEmail> = row.try_get("email").unwrap();
        let email = email.open(&keys).unwrap();
        assert_eq!(email, "first@example.com");
        let index: Vec<u8> = row.try_get("email_bidx").unwrap();
        let index = BlindIndex::<EmailLookup>::from_bytes(index).unwrap();
        assert!(index.is_consistent_with(&email, &index_keys).unwrap());
    });
}

#[test]
fn rejects_null_in_a_swept_column() {
    futures_executor::block_on(async {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY, email BLOB NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (email) VALUES (?)")
            .bind(b"first@example.com".to_vec())
            .execute(&mut connection)
            .await
            .unwrap();
        // The natural way to add an index column leaves it nullable.
        sqlx::query("ALTER TABLE users ADD COLUMN email_bidx BLOB")
            .execute(&mut connection)
            .await
            .unwrap();

        let keys =
            EncryptionKeyring::new(EncryptionKey::new(CURRENT_KEY_ID, [0x22; 32]), []).unwrap();
        let index_keys =
            BlindIndexKeyring::new(BlindIndexKey::new(CURRENT_INDEX_KEY_ID, [0x44; 32]), [])
                .unwrap();
        let planner = RowPlanner::<UserEmail>::new(&keys).with_index::<EmailLookup>(&index_keys);
        let sweep = Sweep::new(planner);
        let table = SweepTable::new("users", "id", "email").with_index_column("email_bidx");
        let mut store = SqliteSweepStore::new(&mut connection, &table);
        store.ensure_progress_table().await.unwrap();

        // NULL has no packaged policy: the sweep stops instead of skipping
        // the row as a conflict and checkpointing past it.
        let error = sweep.run(&mut store).await.unwrap_err();
        let SweepError::Store(sqlx::Error::ColumnDecode { index, .. }) = error else {
            panic!("expected a column decode error, got {error:?}");
        };
        assert_eq!(index, "2");

        let checkpoint: Option<i64> =
            sqlx::query_scalar("SELECT last_id FROM cryptbox_migration_progress")
                .fetch_optional(&mut connection)
                .await
                .unwrap();
        assert_eq!(checkpoint, None);
    });
}
