//! One automatic-adapter fixture per process.

use std::{error::Error, sync::OnceLock};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyProvider, BlindIndexMetadata, BlindIndexSpec,
    Encrypted, EncryptionKey, EncryptionKeyProvider, KeyContext, KeyProviderError,
    LocalBlindIndexKeyring, LocalEncryptionKeyring,
};
use sqlx::{Connection, Row, sqlite::SqliteConnection};
use zeroize::Zeroizing;

struct TestKeys {
    encryption: LocalEncryptionKeyring,
    indexes: LocalBlindIndexKeyring,
}

static TEST_KEYS: OnceLock<TestKeys> = OnceLock::new();

impl KeyContext for TestKeys {
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, KeyProviderError> {
        TEST_KEYS
            .get()
            .map(|keys| &keys.encryption as &dyn EncryptionKeyProvider)
            .ok_or(KeyProviderError::NotInitialized)
    }

    fn blind_index_keys() -> Result<&'static dyn BlindIndexKeyProvider, KeyProviderError> {
        TEST_KEYS
            .get()
            .map(|keys| &keys.indexes as &dyn BlindIndexKeyProvider)
            .ok_or(KeyProviderError::NotInitialized)
    }
}

cryptbox::profile! {
    UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
        keys: TestKeys,
    }
}

struct EmailLookup;

impl BlindIndexMetadata for EmailLookup {
    const ID: cryptbox::IndexId = cryptbox::index_id!("80000000-0000-4000-8000-000000000008");
    const BITS: usize = 128;
}

impl BlindIndexSpec<String> for EmailLookup {
    fn normalize(input: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(input.as_bytes().to_vec()))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Deliberately conflicting fixture keys for the same IDs, in separate processes.
    // These predictable roots are public test fixtures, never durable keys.
    let (plaintext, encryption_root, index_root) = match std::env::args().nth(1).as_deref() {
        Some("first") => ("first@example.test", 0x11, 0x21),
        Some("second") => ("second@example.test", 0x12, 0x22),
        _ => return Err("expected first or second fixture".into()),
    };
    let keys = TestKeys {
        encryption: LocalEncryptionKeyring::new(
            EncryptionKey::new(
                cryptbox::key_id!("40000000-0000-4000-8000-000000000004"),
                [encryption_root; 32],
            ),
            [],
        )?,
        indexes: LocalBlindIndexKeyring::new(
            BlindIndexKey::new(
                cryptbox::index_key_id!("50000000-0000-4000-8000-000000000005"),
                [index_root; 32],
            ),
            [],
        )?,
    };
    TEST_KEYS
        .set(keys)
        .map_err(|_| "test keys already installed")?;
    futures_executor::block_on(round_trip(plaintext))?;
    println!("Automatic adapter round trip succeeded.");
    Ok(())
}

async fn round_trip(plaintext: &str) -> Result<(), Box<dyn Error>> {
    let mut connection = SqliteConnection::connect("sqlite::memory:").await?;
    sqlx::query("CREATE TABLE users (email BLOB NOT NULL, email_idx BLOB)")
        .execute(&mut connection)
        .await?;
    let email = Encrypted::<_, UserEmail>::new(plaintext.to_owned());

    // Binding Encrypted exercises automatic encryption; this does not write an index.
    sqlx::query("INSERT INTO users (email) VALUES (?)")
        .bind(&email)
        .execute(&mut connection)
        .await?;
    let row = sqlx::query("SELECT email, email_idx FROM users")
        .fetch_one(&mut connection)
        .await?;
    let read: Encrypted<String, UserEmail> = row.try_get("email")?;
    assert_eq!(read.expose_secret(), plaintext); // Automatic authenticated decryption.
    assert!(row.try_get::<Option<Vec<u8>>, _>("email_idx")?.is_none());

    // Context-less preparation resolves BOTH providers through TestKeys.
    // One statement maintains the ciphertext/index pair atomically.
    let prepared = email.prepare()?.with_index::<EmailLookup>()?;
    sqlx::query("UPDATE users SET email = ?, email_idx = ?")
        .bind(prepared.ciphertext())
        .bind(prepared.index::<EmailLookup>()?)
        .execute(&mut connection)
        .await?;
    let row = sqlx::query("SELECT email, email_idx FROM users")
        .fetch_one(&mut connection)
        .await?;
    let read: Encrypted<String, UserEmail> = row.try_get("email")?;
    assert_eq!(read.expose_secret(), plaintext);
    assert_eq!(
        row.try_get::<Vec<u8>, _>("email_idx")?,
        prepared.index::<EmailLookup>()?.as_bytes(),
    );
    Ok(())
}
