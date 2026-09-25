//! Live public-boundary coverage for the packaged `PostgreSQL` sweep store.
//! Run with `DATABASE_URL` and `--include-ignored`; see `docs/testing.md`.

#![cfg(all(feature = "migrate", feature = "sqlx-postgres"))]

use std::{future::Future, panic::AssertUnwindSafe};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Ciphertext, Encrypted,
    EncryptionKey, EncryptionProfile, Error, Field, FieldBound, GlobalKeyContext, IndexId,
    LocalBlindIndexKeyring, LocalEncryptionKeyring, Utf8, blind_index_probes, field_id, index_id,
    index_key_id, key_id,
    migrate::{
        LegacyError, LegacyFormat, MaybeEncrypted, PostgresSweepStore, RowPlanner, Sweep,
        SweepReport, SweepStore, SweepTable,
    },
    verify_blind_index_candidate,
};
use sqlx::{Connection, PgConnection, Row};
use zeroize::Zeroizing;

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

struct ToyLegacy;

impl LegacyFormat for ToyLegacy {
    fn recover(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, LegacyError> {
        // A fixture format, not an authenticated legacy encryption scheme.
        Ok(Zeroizing::new(
            bytes.strip_prefix(b"legacy:").unwrap_or(bytes).to_vec(),
        ))
    }
}

fn keyrings() -> (
    LocalEncryptionKeyring,
    LocalEncryptionKeyring,
    LocalBlindIndexKeyring,
    LocalBlindIndexKeyring,
) {
    let old = EncryptionKey::new(key_id!("10000000-0000-4000-8000-000000000001"), [0x11; 32]);
    let current = EncryptionKey::new(key_id!("20000000-0000-4000-8000-000000000002"), [0x22; 32]);
    let old_index = BlindIndexKey::new(
        index_key_id!("30000000-0000-4000-8000-000000000003"),
        [0x33; 32],
    );
    let current_index = BlindIndexKey::new(
        index_key_id!("40000000-0000-4000-8000-000000000004"),
        [0x44; 32],
    );
    (
        LocalEncryptionKeyring::new(old.clone(), []).unwrap(),
        LocalEncryptionKeyring::new(current, [old]).unwrap(),
        LocalBlindIndexKeyring::new(old_index.clone(), []).unwrap(),
        LocalBlindIndexKeyring::new(current_index, [old_index]).unwrap(),
    )
}

async fn connect(url: &str, schema: &str) -> PgConnection {
    let mut connection = PgConnection::connect(url).await.unwrap();
    sqlx::query(&format!("SET search_path TO \"{schema}\""))
        .execute(&mut connection)
        .await
        .unwrap();
    connection
}

// Real tables allow reconnects and independent writers. Each test owns a random
// schema, including its progress table, and cleans it up even after an assertion panic.
fn with_database<F: Future<Output = ()>>(scenario: impl FnOnce(PgConnection, String, String) -> F) {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must point at a test PostgreSQL database");
    let schema = format!(
        "cryptbox_sweep_{}",
        EncryptionKey::generate()
            .unwrap()
            .id()
            .to_string()
            .replace('-', "")
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut admin = runtime.block_on(PgConnection::connect(&url)).unwrap();
    runtime
        .block_on(sqlx::query(&format!("CREATE SCHEMA \"{schema}\"")).execute(&mut admin))
        .unwrap();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async {
            let mut connection = connect(&url, &schema).await;
            sqlx::query(
                "CREATE TABLE users (
                    id BIGINT PRIMARY KEY,
                    email_ciphertext BYTEA NOT NULL,
                    email_bidx BYTEA NOT NULL
                )",
            )
            .execute(&mut connection)
            .await
            .unwrap();
            scenario(connection, url, schema.clone()).await;
        });
    }));
    runtime
        .block_on(sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE")).execute(&mut admin))
        .unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn insert(
    connection: &mut PgConnection,
    id: i64,
    email: &str,
    keys: &LocalEncryptionKeyring,
    index_keys: &LocalBlindIndexKeyring,
) {
    let value = Encrypted::<_, UserEmail>::new(email.to_owned());
    let prepared = value
        .prepare_with(&(), keys)
        .unwrap()
        .with_index_with::<EmailLookup>(index_keys)
        .unwrap();
    sqlx::query("INSERT INTO users VALUES ($1, $2, $3)")
        .bind(id)
        .bind(prepared.ciphertext())
        .bind(prepared.index::<EmailLookup>().unwrap())
        .execute(connection)
        .await
        .unwrap();
}

async fn search(
    connection: &mut PgConnection,
    keys: &LocalEncryptionKeyring,
    index_keys: &LocalBlindIndexKeyring,
) -> (Vec<i64>, Vec<i64>) {
    let query = " ALICE@example.com ".to_owned();
    let probes =
        blind_index_probes::<EmailLookup, String, FieldBound<UserEmail>>(&query, &(), index_keys)
            .unwrap();
    let mut candidates = Vec::new();
    let mut matches = Vec::new();
    for probe in probes {
        let rows = sqlx::query("SELECT id, email_ciphertext FROM users WHERE email_bidx = $1")
            .bind(probe)
            .fetch_all(&mut *connection)
            .await
            .unwrap();
        for row in rows {
            let id: i64 = row.get("id");
            candidates.push(id);
            let ciphertext: Ciphertext<String, UserEmail> = row.get("email_ciphertext");
            let value = ciphertext.decrypt_with(&(), keys).unwrap();
            if verify_blind_index_candidate::<EmailLookup, String>(&query, value.expose_secret())
                .unwrap()
            {
                matches.push(id);
            }
        }
    }
    candidates.sort_unstable();
    matches.sort_unstable();
    (candidates, matches)
}

async fn assert_readable_rows(
    connection: &mut PgConnection,
    keys: &LocalEncryptionKeyring,
    migrated: bool,
) {
    let rows = sqlx::query("SELECT id, email_ciphertext FROM users ORDER BY id")
        .fetch_all(connection)
        .await
        .unwrap();
    assert_eq!(rows.len(), 6);
    for row in rows {
        let id: i64 = row.get("id");
        let is_legacy = !migrated && id <= 20;
        let strict = row.try_get::<Ciphertext<String, UserEmail>, _>("email_ciphertext");
        let expected = match id {
            10 => "Alice@example.com",
            60 => "bob@example.com",
            _ => "alice@example.com",
        };
        if is_legacy {
            let sqlx::Error::ColumnDecode { source, .. } = strict.unwrap_err() else {
                panic!("expected strict decoding to reject legacy bytes");
            };
            assert_eq!(source.downcast_ref::<Error>(), Some(&Error::NotCiphertext));
        } else {
            let ciphertext = strict.unwrap();
            if migrated {
                assert!(!ciphertext.needs_reencryption_with(keys).unwrap());
            }
            // Authentication is asserted separately from generation convergence.
            assert_eq!(
                ciphertext.decrypt_with(&(), keys).unwrap().expose_secret(),
                expected
            );
        }
        let permissive: MaybeEncrypted<String, UserEmail> = row.get("email_ciphertext");
        assert_eq!(permissive.is_legacy(), is_legacy);
        assert_eq!(
            permissive
                .decrypt_with_legacy(&(), keys, &ToyLegacy)
                .unwrap()
                .expose_secret(),
            expected,
        );
    }
}

#[test]
#[ignore = "requires a PostgreSQL server; set DATABASE_URL and run with --include-ignored"]
fn postgres_sweep_converts_mixed_rows_and_resumes_stored_progress() {
    with_database(|mut connection, url, schema| async move {
        let (old_keys, keys, old_index_keys, index_keys) = keyrings();
        for (id, bytes) in [
            (10_i64, b"Alice@example.com".as_slice()),
            (20, b"legacy:alice@example.com".as_slice()),
        ] {
            sqlx::query("INSERT INTO users VALUES ($1, $2, $3)")
                .bind(id)
                .bind(bytes)
                .bind(Vec::<u8>::new())
                .execute(&mut connection)
                .await
                .unwrap();
        }
        insert(
            &mut connection,
            30,
            "alice@example.com",
            &old_keys,
            &old_index_keys,
        )
        .await;
        insert(&mut connection, 40, "alice@example.com", &keys, &index_keys).await;
        // Current ciphertext with a historical index must also be swept.
        insert(
            &mut connection,
            50,
            "alice@example.com",
            &keys,
            &old_index_keys,
        )
        .await;
        insert(&mut connection, 60, "bob@example.com", &keys, &index_keys).await;
        // Deliberately inject a false candidate without relying on a random collision.
        // Current index metadata does not prove agreement with the ciphertext.
        sqlx::query("UPDATE users SET email_bidx = (SELECT email_bidx FROM users WHERE id = 40) WHERE id = 60")
            .execute(&mut connection).await.unwrap();

        assert_readable_rows(&mut connection, &keys, false).await;
        // All readable index generations are searched, but unindexed legacy rows
        // cannot be found by probes until backfilled. The false candidate is rejected.
        assert_eq!(
            search(&mut connection, &keys, &index_keys).await,
            (vec![30, 40, 50, 60], vec![30, 40, 50])
        );

        let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
            .with_legacy(&ToyLegacy)
            .with_index_with::<EmailLookup>(&index_keys);
        let sweep = Sweep::new(planner).with_batch_size(1);
        let table =
            SweepTable::new("users", "id", "email_ciphertext").with_index_column("email_bidx");
        {
            let mut store = PostgresSweepStore::new(&mut connection, &table);
            store.ensure_progress_table().await.unwrap();
            assert_eq!(store.load_checkpoint().await.unwrap(), None);
            let before = sweep.verify(&mut store).await.unwrap();
            assert_eq!((before.legacy, before.stale, before.current), (2, 2, 2));
            let first = sweep.run_batch(&mut store).await.unwrap();
            assert_eq!(first.checkpoint, Some(10));
            assert_eq!(first.report.legacy, 1);
            assert_eq!(store.load_checkpoint().await.unwrap(), Some(10));
        }
        connection.close().await.unwrap();
        let mut connection = connect(&url, &schema).await;
        {
            let mut store = PostgresSweepStore::new(&mut connection, &table);
            assert_eq!(store.load_checkpoint().await.unwrap(), Some(10));
            let report = sweep.run(&mut store).await.unwrap();
            assert_eq!(
                (
                    report.legacy,
                    report.stale,
                    report.current,
                    report.conflicts
                ),
                (1, 2, 2, 0)
            );
            assert_eq!(store.load_checkpoint().await.unwrap(), Some(60));
            assert_eq!(sweep.run(&mut store).await.unwrap(), SweepReport::default());
            let verified = sweep.verify(&mut store).await.unwrap();
            assert!(verified.is_terminal());
            assert_eq!(verified.current, 6);
        }
        let checkpoint: i64 =
            sqlx::query_scalar("SELECT last_id FROM cryptbox_migration_progress WHERE name = $1")
                .bind("users.email_ciphertext")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(checkpoint, 60);

        assert_readable_rows(&mut connection, &keys, true).await;
        assert_eq!(
            search(&mut connection, &keys, &index_keys).await,
            (vec![10, 20, 30, 40, 50, 60], vec![10, 20, 30, 40, 50])
        );
    });
}

#[test]
#[ignore = "requires a PostgreSQL server; set DATABASE_URL and run with --include-ignored"]
fn postgres_guarded_updates_preserve_competing_ciphertext_and_index_writes() {
    with_database(|mut connection, url, schema| async move {
        let (old_keys, keys, old_index_keys, index_keys) = keyrings();
        insert(
            &mut connection,
            10,
            "alice@example.com",
            &old_keys,
            &old_index_keys,
        )
        .await;
        let table =
            SweepTable::new("users", "id", "email_ciphertext").with_index_column("email_bidx");
        let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
            .with_index_with::<EmailLookup>(&index_keys);
        let mut writer = connect(&url, &schema).await;

        // Interleave a real second connection between the public load and update
        // calls, deterministically, without sleeps or a mocked store.
        for column in ["email_ciphertext", "email_bidx"] {
            let mut store = PostgresSweepStore::new(&mut connection, &table);
            let rows = store.load_batch(None, 1).await.unwrap();
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            let plan = planner
                .plan_row(&row.ciphertext, &[&row.indexes[0]])
                .unwrap();
            let replacement = plan.write().unwrap();

            let other_value = Encrypted::<_, UserEmail>::new("other@example.com".to_owned());
            let prepared = other_value
                .prepare_with(&(), &old_keys)
                .unwrap()
                .with_index_with::<EmailLookup>(&old_index_keys)
                .unwrap();
            let changed_bytes = if column == "email_ciphertext" {
                prepared.ciphertext().as_bytes().to_vec()
            } else {
                prepared.index::<EmailLookup>().unwrap().as_bytes().to_vec()
            };
            let result = sqlx::query(&format!("UPDATE users SET {column} = $1 WHERE id = 10"))
                .bind(&changed_bytes)
                .execute(&mut writer)
                .await
                .unwrap();
            assert_eq!(result.rows_affected(), 1);

            assert!(
                !store.update(row, replacement).await.unwrap(),
                "a change to {column} must lose the compare-and-swap"
            );
            let stored = store.load_batch(None, 1).await.unwrap();
            if column == "email_ciphertext" {
                assert_eq!(stored[0].ciphertext, changed_bytes);
                assert_eq!(stored[0].indexes, row.indexes);
            } else {
                assert_eq!(stored[0].indexes[0], changed_bytes);
                assert_eq!(stored[0].ciphertext, row.ciphertext);
            }

            // Restore the fixture for the next independent competing-write case.
            sqlx::query("UPDATE users SET email_ciphertext = $1, email_bidx = $2 WHERE id = 10")
                .bind(&row.ciphertext)
                .bind(&row.indexes[0])
                .execute(&mut writer)
                .await
                .unwrap();
        }

        let mut store = PostgresSweepStore::new(&mut connection, &table);
        let rows = store.load_batch(None, 1).await.unwrap();
        let row = &rows[0];
        let plan = planner
            .plan_row(&row.ciphertext, &[&row.indexes[0]])
            .unwrap();
        let replacement = plan.write().unwrap();
        assert!(store.update(row, replacement).await.unwrap());
        // A stale snapshot now matches zero rows, even if it tries the same write.
        assert!(!store.update(row, replacement).await.unwrap());
        let updated = store.load_batch(None, 1).await.unwrap();
        assert_eq!(updated[0].ciphertext, replacement.ciphertext());
        assert_eq!(updated[0].indexes, replacement.indexes());
        // PostgreSQL counts a matched UPDATE even when its assigned bytes are
        // unchanged. The store must report success rather than a false conflict.
        assert!(store.update(&updated[0], replacement).await.unwrap());
        assert!(store.load_batch(Some(&10), 1).await.unwrap().is_empty());
        assert_eq!(
            search(&mut writer, &keys, &index_keys).await,
            (vec![10], vec![10])
        );
    });
}
