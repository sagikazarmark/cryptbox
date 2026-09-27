//! Writes and reads a persistent `SQLite` field in separate processes through `SQLx`.
//! See README.md beside this source for provisioning and restart instructions.

use std::{error::Error, fs::File, io::Read, path::Path};

use cryptbox::{EncryptionKey, Field, KeyId, LocalEncryptionKeyring, Sealed, key_id};
use sqlx::{Connection, Row, sqlite::SqliteConnectOptions, sqlite::SqliteConnection};
use zeroize::Zeroizing;

// Demo generation ID: preserve this ID AND the independently provisioned root on restart.
const ENCRYPTION_KEY_ID: KeyId = key_id!("40000000-0000-4000-8000-000000000004");
const DEMO_EMAIL: &str = "mark@example.com";

enum Command {
    Write,
    Read,
}

#[derive(Field)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
struct UserEmail;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() || (args.len() == 1 && args[0] == "--help") {
        println!("Usage: sqlx_sqlite <write|read> DATABASE KEY_FILE");
        return Ok(());
    }
    let [command, database, key_file] = args.as_slice() else {
        return Err("Usage: sqlx_sqlite <write|read> DATABASE KEY_FILE".into());
    };
    let command = if command == "write" {
        Command::Write
    } else if command == "read" {
        Command::Read
    } else {
        return Err("Expected write or read".into());
    };

    // Fail before opening storage. Never generate a replacement for a missing root.
    let keys = load_keys(Path::new(key_file))?;
    futures_executor::block_on(run(command, Path::new(database), &keys))
}

fn load_keys(path: &Path) -> Result<LocalEncryptionKeyring, Box<dyn Error>> {
    // Read directly into an erased buffer, including on read/decode failure. Limit input
    // to 64 hex digits plus an optional LF or CRLF; never include input in errors.
    let mut input = Zeroizing::new(Vec::with_capacity(67));
    File::open(path)
        .map_err(|_| "Cannot open encryption key file")?
        .take(67)
        .read_to_end(&mut input)
        .map_err(|_| "Cannot read encryption key file")?;
    let invalid = "Encryption key file must contain 64 hex digits with an optional newline";
    let hex = input
        .strip_suffix(b"\r\n")
        .or_else(|| input.strip_suffix(b"\n"))
        .unwrap_or(&input);
    if hex.len() != 64 {
        return Err(invalid.into());
    }
    let mut root = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(hex, root.as_mut()).map_err(|_| invalid)?;
    Ok(LocalEncryptionKeyring::new(
        EncryptionKey::new(ENCRYPTION_KEY_ID, *root),
        [],
    )?)
}

async fn run(
    command: Command,
    database: &Path,
    keys: &LocalEncryptionKeyring,
) -> Result<(), Box<dyn Error>> {
    let options = SqliteConnectOptions::new()
        .filename(database)
        .create_if_missing(matches!(command, Command::Write))
        .read_only(matches!(command, Command::Read));
    let mut connection = SqliteConnection::connect_with(&options).await?;
    match command {
        Command::Write => write(&mut connection, keys).await?,
        Command::Read => read(&mut connection, keys).await?,
    }
    connection.close().await?;
    match command {
        Command::Write => println!("Encrypted field stored. Run read in a new process."),
        Command::Read => {
            println!("Persistent SQLite read succeeded; demonstration value verified.");
        }
    }
    Ok(())
}

async fn write(
    connection: &mut SqliteConnection,
    keys: &LocalEncryptionKeyring,
) -> Result<(), Box<dyn Error>> {
    let sealed = Sealed::<UserEmail>::seal(&DEMO_EMAIL.to_owned(), (), keys)?;
    let mut transaction = connection.begin().await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email BLOB NOT NULL)")
        .execute(&mut *transaction)
        .await?;

    // A second write fails on the primary key instead of replacing the demonstration row.
    sqlx::query("INSERT INTO users (id, email) VALUES (1, ?)")
        .bind(&sealed)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

async fn read(
    connection: &mut SqliteConnection,
    keys: &LocalEncryptionKeyring,
) -> Result<(), Box<dyn Error>> {
    let row = sqlx::query("SELECT email FROM users WHERE id = 1")
        .fetch_one(connection)
        .await?;
    let sealed: Sealed<UserEmail> = row.try_get("email")?;
    let opened = sealed.open((), keys)?;

    assert!(sealed.as_bytes().starts_with(b"CBX\0"));
    // Unlike assert_eq!, this cannot print plaintext on a failed assertion.
    assert!(opened == DEMO_EMAIL, "Unexpected demo value");
    Ok(())
}
