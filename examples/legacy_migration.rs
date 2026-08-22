//! Migrates mixed foreign ciphertext, plaintext, and `CryptBox` rows.

use std::{error::Error, io};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Ciphertext, Encrypted,
    EncryptionKey, EncryptionProfile, Field, FieldBound, GlobalKeyContext, IndexId, IndexKeyId,
    KeyId, LocalBlindIndexKeyring, LocalEncryptionKeyring, Utf8, blind_index_probes, field_id,
    index_id, index_key_id, key_id,
    migrate::{
        LegacyError, LegacyErrorKind, LegacyFormat, MaybeEncrypted, RowPlanner, SqliteSweepStore,
        Sweep, SweepTable,
    },
};
use sqlx::{Connection, Row, sqlite::SqliteConnection};
use zeroize::Zeroizing;

const OLD_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const CURRENT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");
const OLD_INDEX_KEY_ID: IndexKeyId = index_key_id!("30000000-0000-4000-8000-000000000003");
const CURRENT_INDEX_KEY_ID: IndexKeyId = index_key_id!("40000000-0000-4000-8000-000000000004");
const LEGACY_HEADER: &[u8] = b"legacy-xchacha-v1\0";
const LEGACY_NONCE_LEN: usize = 24;

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

/// Demo handler for the application's previous encryption solution.
///
/// The header lets one handler distinguish foreign ciphertext from plaintext
/// stragglers. A real format must define and enforce its own nonce policy.
struct PreviousEncryption {
    key: Zeroizing<[u8; 32]>,
}

impl PreviousEncryption {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    fn seal_for_demo(&self, plaintext: &[u8], nonce_byte: u8) -> Result<Vec<u8>, io::Error> {
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let mut nonce = [0_u8; LEGACY_NONCE_LEN];
        nonce[LEGACY_NONCE_LEN - 1] = nonce_byte;
        let nonce = XNonce::from(nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: LEGACY_HEADER,
                },
            )
            .map_err(|_| io::Error::other("legacy demo encryption failed"))?;

        let mut stored = Vec::with_capacity(LEGACY_HEADER.len() + nonce.len() + ciphertext.len());
        stored.extend_from_slice(LEGACY_HEADER);
        stored.extend_from_slice(nonce.as_slice());
        stored.extend_from_slice(&ciphertext);
        Ok(stored)
    }
}

impl LegacyFormat for PreviousEncryption {
    fn recover(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, LegacyError> {
        let Some(payload) = bytes.strip_prefix(LEGACY_HEADER) else {
            // Plaintext is the identity legacy format. A real mixed-format
            // handler should make this dispatch rule as strict as possible.
            return Ok(Zeroizing::new(bytes.to_vec()));
        };
        if payload.len() < LEGACY_NONCE_LEN + 16 {
            return Err(LegacyError::new(LegacyErrorKind::Malformed));
        }

        let (nonce, ciphertext) = payload.split_at(LEGACY_NONCE_LEN);
        let nonce = <&[u8; LEGACY_NONCE_LEN]>::try_from(nonce)
            .map_err(|_| LegacyError::new(LegacyErrorKind::Malformed))?;
        let nonce: &XNonce = nonce.into();
        XChaCha20Poly1305::new((&*self.key).into())
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: LEGACY_HEADER,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| LegacyError::new(LegacyErrorKind::AuthenticationFailed))
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

    // Demo-only material. Load all roots independently from secret storage.
    let legacy = PreviousEncryption::new([0x55; 32]);
    let old_key = EncryptionKey::new(OLD_KEY_ID, [0x11; 32]);
    let current_key = EncryptionKey::new(CURRENT_KEY_ID, [0x22; 32]);
    let old_index_key = BlindIndexKey::new(OLD_INDEX_KEY_ID, [0x33; 32]);
    let current_index_key = BlindIndexKey::new(CURRENT_INDEX_KEY_ID, [0x44; 32]);
    let old_keys = LocalEncryptionKeyring::new(old_key.clone(), [])?;
    let old_index_keys = LocalBlindIndexKeyring::new(old_index_key.clone(), [])?;
    let keys = LocalEncryptionKeyring::new(current_key, [old_key])?;
    let index_keys = LocalBlindIndexKeyring::new(current_index_key, [old_index_key])?;

    // The table starts with foreign ciphertext, a plaintext straggler, stale
    // CryptBox ciphertext, and current CryptBox ciphertext.
    insert_raw(
        &mut connection,
        legacy.seal_for_demo(b"foreign@example.com", 1)?,
    )
    .await?;
    insert_raw(&mut connection, b"plaintext@example.com".to_vec()).await?;
    insert_encrypted(
        &mut connection,
        "stale@example.com",
        &old_keys,
        &old_index_keys,
    )
    .await?;
    insert_encrypted(&mut connection, "current@example.com", &keys, &index_keys).await?;

    // SQLx Decode only classifies. Recovery is explicit and the same handler
    // reads foreign ciphertext, plaintext, and CryptBox envelopes.
    verify_permissive_reads(&mut connection, &keys, &legacy).await?;

    // The handler is injected only into the bounded migration worker. One
    // sweep recovers legacy rows, encrypts them, and derives every blind index.
    let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
        .with_legacy(&legacy)
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

    // Only a fresh, complete verification pass is authoritative. It needs no
    // legacy recovery because classification is enough to count legacy rows.
    let report = sweep.verify(&mut store).await?;
    assert!(report.is_terminal());
    assert_eq!(report.current, 4);
    drop(store);

    // Every row is now strict CryptBox ciphertext and has a usable blind index.
    let probes = blind_index_probes::<EmailLookup, String, FieldBound<UserEmail>>(
        &"foreign@example.com".to_owned(),
        &(),
        &index_keys,
    )?;
    let mut matches = 0;
    for probe in probes {
        let rows = sqlx::query("SELECT email_ciphertext FROM users WHERE email_bidx = ?")
            .bind(probe.as_bytes().to_vec())
            .fetch_all(&mut connection)
            .await?;
        for row in rows {
            let ciphertext: Ciphertext<String, UserEmail> = row.try_get("email_ciphertext")?;
            let candidate = ciphertext.decrypt_with(&(), &keys)?;
            assert_eq!(candidate.expose_secret(), "foreign@example.com");
            matches += 1;
        }
    }
    assert_eq!(matches, 1);

    // Closing checklist: replace MaybeEncrypted reads with strict reads, delete
    // the handler, disable `migrate`, and retire historical CryptBox keys. Only
    // then, subject to rollback and retention policy, destroy the legacy key.
    drop(sweep);
    drop(legacy); // Zeroizing erases this process-owned key buffer.

    println!("legacy migration complete: {report:?}");
    Ok(())
}

async fn verify_permissive_reads(
    connection: &mut SqliteConnection,
    keys: &LocalEncryptionKeyring,
    legacy: &PreviousEncryption,
) -> Result<(), Box<dyn Error>> {
    let foreign: Vec<u8> = sqlx::query_scalar("SELECT email_ciphertext FROM users WHERE id = 1")
        .fetch_one(&mut *connection)
        .await?;
    assert!(matches!(
        Ciphertext::<String, UserEmail>::from_bytes(foreign),
        Err(cryptbox::Error::NotCiphertext),
    ));

    let rows = sqlx::query("SELECT id, email_ciphertext FROM users ORDER BY id")
        .fetch_all(connection)
        .await?;
    let expected = [
        "foreign@example.com",
        "plaintext@example.com",
        "stale@example.com",
        "current@example.com",
    ];
    for (row, expected) in rows.into_iter().zip(expected) {
        let id: i64 = row.try_get("id")?;
        let value: MaybeEncrypted<String, UserEmail> = row.try_get("email_ciphertext")?;
        assert_eq!(value.is_legacy(), id <= 2);
        assert_eq!(
            value
                .decrypt_with_legacy(&(), keys, legacy)?
                .expose_secret(),
            expected,
        );
    }
    Ok(())
}

async fn insert_raw(connection: &mut SqliteConnection, bytes: Vec<u8>) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO users (email_ciphertext, email_bidx) VALUES (?, ?)")
        .bind(bytes)
        .bind(Vec::<u8>::new())
        .execute(connection)
        .await?;
    Ok(())
}

async fn insert_encrypted(
    connection: &mut SqliteConnection,
    email: &str,
    keys: &LocalEncryptionKeyring,
    index_keys: &LocalBlindIndexKeyring,
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
