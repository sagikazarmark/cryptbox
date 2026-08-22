//! End-to-end plaintext migration over the `SQLx` `SQLite` adapter.

#![cfg(all(feature = "migrate", feature = "sqlx-sqlite"))]

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Ciphertext, Encrypted,
    EncryptionKey, EncryptionProfile, Error, Field, FieldBound, GlobalKeyContext, IndexId,
    IndexKeyId, KeyId, LocalBlindIndexKeyring, LocalEncryptionKeyring, Utf8, field_id, index_id,
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
        let old_keys = LocalEncryptionKeyring::new(old_key.clone(), []).unwrap();
        let old_index_keys = LocalBlindIndexKeyring::new(old_index_key.clone(), []).unwrap();
        let keys = LocalEncryptionKeyring::new(current_key, [old_key]).unwrap();
        let index_keys = LocalBlindIndexKeyring::new(current_index_key, [old_index_key]).unwrap();

        // Two legacy plaintext rows, one stale encrypted row, one current row.
        for email in ["first@example.com", "second@example.com"] {
            sqlx::query("INSERT INTO users (email_ciphertext, email_bidx) VALUES (?, ?)")
                .bind(email.as_bytes().to_vec())
                .bind(Vec::<u8>::new())
                .execute(&mut connection)
                .await
                .unwrap();
        }
        for (email, keyring, index_keyring) in [
            ("third@example.com", &old_keys, &old_index_keys),
            ("fourth@example.com", &keys, &index_keys),
        ] {
            let value = Encrypted::<_, UserEmail>::new(email.to_owned());
            let prepared = value
                .prepare_with(&(), keyring)
                .unwrap()
                .with_index_with::<EmailLookup>(index_keyring)
                .unwrap();
            sqlx::query("INSERT INTO users (email_ciphertext, email_bidx) VALUES (?, ?)")
                .bind(prepared.ciphertext())
                .bind(prepared.index::<EmailLookup>().unwrap())
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
            let strict = row.try_get::<Ciphertext<String, UserEmail>, _>("email_ciphertext");
            assert_eq!(strict.is_err(), id <= 2);
            let read: MaybeEncrypted<String, UserEmail> = row.try_get("email_ciphertext").unwrap();
            assert_eq!(read.is_plaintext(), id <= 2);
            read.decrypt_with(&(), &keys).unwrap();
        }

        // Batch size one exercises pagination and per-batch checkpoints.
        let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
            .with_index_with::<EmailLookup>(&index_keys);
        let sweep = Sweep::new(planner).with_batch_size(1);
        let table =
            SweepTable::new("users", "id", "email_ciphertext").with_index_column("email_bidx");
        let mut store = SqliteSweepStore::new(&mut connection, &table);
        store.ensure_progress_table().await.unwrap();

        let report = sweep.run(&mut store).await.unwrap();
        assert_eq!(report.plaintext, 2);
        assert_eq!(report.stale, 1);
        assert_eq!(report.current, 1);
        assert_eq!(report.conflicts, 0);

        // A resumed worker finds the durable checkpoint and rewrites nothing.
        let report = sweep.run(&mut store).await.unwrap();
        assert_eq!(report.current, 0);
        assert_eq!(report.plaintext + report.stale + report.conflicts, 0);

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
            let ciphertext: Ciphertext<String, UserEmail> =
                row.try_get("email_ciphertext").unwrap();
            assert!(!ciphertext.needs_reencryption_with(&keys).unwrap());
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
        let result = row.try_get::<MaybeEncrypted<String, UserEmail>, _>("bytes");
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
