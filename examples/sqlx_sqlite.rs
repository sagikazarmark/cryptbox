//! Stores encrypted values in an in-memory `SQLite` database through `SQLx`.

use std::error::Error;

use cryptbox::{Ciphertext, Encrypted, EncryptionKey, LocalEncryptionKeyring};
use sqlx::{Connection, Row, sqlite::SqliteConnection};

cryptbox::profile! {
    UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Ephemeral keys and database: load stable key/ID pairs for durable storage.
    let keys = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;

    futures_executor::block_on(run(&keys))
}

async fn run(keys: &LocalEncryptionKeyring) -> Result<(), Box<dyn Error>> {
    let mut connection = SqliteConnection::connect("sqlite::memory:").await?;
    sqlx::query("CREATE TABLE users (email BLOB NOT NULL)")
        .execute(&mut connection)
        .await?;

    let email = Encrypted::<_, UserEmail>::new("mark@example.com".to_owned());
    let prepared = email.prepare_with(&(), keys)?;
    sqlx::query("INSERT INTO users (email) VALUES (?)")
        .bind(prepared.ciphertext())
        .execute(&mut connection)
        .await?;

    let row = sqlx::query("SELECT email FROM users")
        .fetch_one(&mut connection)
        .await?;
    let ciphertext: Ciphertext<String, UserEmail> = row.try_get("email")?;
    let decrypted = ciphertext.decrypt_with(&(), keys)?;

    assert!(ciphertext.as_bytes().starts_with(b"CBX\0"));
    assert_eq!(decrypted.expose_secret(), "mark@example.com");
    println!("Field-bound SQLite round trip succeeded.");

    Ok(())
}
