//! One automatic-adapter fixture per process.

use std::error::Error;

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexSpec, Encrypted, EncryptionKey, Field, FieldId, Keys,
    LocalBlindIndexKeyring, LocalEncryptionKeyring, Padding, Utf8, keys,
};
use sqlx::{Connection, Row, sqlite::SqliteConnection};
use zeroize::Zeroizing;

struct UserEmail;

impl Field for UserEmail {
    const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Field = UserEmail;
    const ID: cryptbox::IndexId = cryptbox::index_id!("80000000-0000-4000-8000-000000000008");
    const BITS: u16 = 128;
    const NORMALIZER: &'static str = "exact/1";
    type Query = str;

    fn normalize_query(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(input.as_bytes().to_vec()))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
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
    let encryption = LocalEncryptionKeyring::new(
        EncryptionKey::new(
            cryptbox::key_id!("40000000-0000-4000-8000-000000000004"),
            [encryption_root; 32],
        ),
        [],
    )?;
    let indexes = LocalBlindIndexKeyring::new(
        BlindIndexKey::new(
            cryptbox::index_key_id!("50000000-0000-4000-8000-000000000005"),
            [index_root; 32],
        ),
        [],
    )?;
    // Once per process: the global cannot be replaced, so each fixture runs in its own process.
    keys::install(Keys::new(encryption).with_blind_indexes(indexes))?;
    futures_executor::block_on(round_trip(plaintext))?;
    println!("Automatic adapter round trip succeeded.");
    Ok(())
}

async fn round_trip(plaintext: &str) -> Result<(), Box<dyn Error>> {
    let mut connection = SqliteConnection::connect("sqlite::memory:").await?;
    sqlx::query("CREATE TABLE users (email BLOB NOT NULL, email_idx BLOB)")
        .execute(&mut connection)
        .await?;
    let email = Encrypted::<UserEmail>::new(plaintext.to_owned());

    // Binding Encrypted exercises automatic encryption; this does not write an index.
    sqlx::query("INSERT INTO users (email) VALUES (?)")
        .bind(&email)
        .execute(&mut connection)
        .await?;
    let row = sqlx::query("SELECT email, email_idx FROM users")
        .fetch_one(&mut connection)
        .await?;
    let read: Encrypted<UserEmail> = row.try_get("email")?;
    assert_eq!(read.expose_secret(), plaintext); // Automatic authenticated decryption.
    assert!(row.try_get::<Option<Vec<u8>>, _>("email_idx")?.is_none());

    // Implicit preparation resolves BOTH providers through the installed keys.
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
    let read: Encrypted<UserEmail> = row.try_get("email")?;
    assert_eq!(read.expose_secret(), plaintext);
    assert_eq!(
        row.try_get::<Vec<u8>, _>("email_idx")?,
        prepared.index::<EmailLookup>()?.as_bytes(),
    );
    Ok(())
}
