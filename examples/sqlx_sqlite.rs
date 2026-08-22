//! Stores encrypted values in an in-memory `SQLite` database through `SQLx`.

use std::error::Error;

use cryptbox::{
    Ciphertext, Encrypted, EncryptionKey, EncryptionProfile, GlobalKeyContext, GlobalProviders,
    LocalEncryptionKeyring, Unbound, Utf8, key_id,
};
use sqlx::{Connection, Row, sqlite::SqliteConnection};

struct StoredEmail;

impl EncryptionProfile<String> for StoredEmail {
    type Binding = Unbound;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = cryptbox::NoPadding;
}

fn main() -> Result<(), Box<dyn Error>> {
    // Demo-only material. Install runtime-loaded secret providers at startup.
    let keys = LocalEncryptionKeyring::new(
        EncryptionKey::new(key_id!("90000000-0000-4000-8000-000000000009"), [0x64; 32]),
        [],
    )?;
    GlobalKeyContext::install(GlobalProviders::new(keys))?;

    futures_executor::block_on(run())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut connection = SqliteConnection::connect("sqlite::memory:").await?;
    sqlx::query("CREATE TABLE users (email BLOB NOT NULL)")
        .execute(&mut connection)
        .await?;

    let email = Encrypted::<_, StoredEmail>::new("mark@example.com".to_owned());
    sqlx::query("INSERT INTO users (email) VALUES (?)")
        .bind(&email)
        .execute(&mut connection)
        .await?;

    let row = sqlx::query("SELECT email FROM users")
        .fetch_one(&mut connection)
        .await?;
    let ciphertext: Ciphertext<String, StoredEmail> = row.try_get("email")?;
    let decrypted: Encrypted<String, StoredEmail> = row.try_get("email")?;

    assert!(ciphertext.as_bytes().starts_with(b"CBX\0"));
    assert_eq!(decrypted.expose_secret(), "mark@example.com");

    Ok(())
}
