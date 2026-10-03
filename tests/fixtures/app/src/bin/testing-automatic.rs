//! One automatic-adapter fixture per process.

use std::error::Error;

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Keys, Padding, Plain, Seal, SealId, Sealed, Utf8, keys,
};
use sqlx::{Connection, Row, sqlite::SqliteConnection};
use zeroize::Zeroizing;

struct Nickname;

impl Seal for Nickname {
    const ID: SealId = cryptbox::seal_id!("431cf5b3-5547-4716-a9f8-cfd67749947a");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

// A seal with a blind index is never a `Plain` column: the column would not write the index.
struct UserEmail;

impl Seal for UserEmail {
    const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Seal = UserEmail;
    const ID: cryptbox::IndexId = cryptbox::index_id!("ea0ffec1-651a-4d6b-bb01-d53a58006dfd");
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
    let encryption = EncryptionKeyring::new(
        EncryptionKey::new(
            cryptbox::key_id!("417323bd-b7c0-41fa-a7da-17305a83fadf"),
            [encryption_root; 32],
        ),
        [],
    )?;
    let indexes = BlindIndexKeyring::new(
        BlindIndexKey::new(
            cryptbox::index_key_id!("64c6ad65-0d9d-497d-ab02-4fba13caaff7"),
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
    sqlx::query("CREATE TABLE users (nickname BLOB NOT NULL, email BLOB, email_idx BLOB)")
        .execute(&mut connection)
        .await?;
    let nickname = Plain::<Nickname>::new(plaintext);

    // Plain exercises automatic sealing with the installed keys.
    sqlx::query("INSERT INTO users (nickname) VALUES (?)")
        .bind(&nickname)
        .execute(&mut connection)
        .await?;
    let row = sqlx::query("SELECT nickname FROM users")
        .fetch_one(&mut connection)
        .await?;
    let read: Plain<Nickname> = row.try_get("nickname")?;
    assert_eq!(read.expose_secret(), plaintext); // Automatic authenticated opening.

    // A value of an indexed seal is sealed explicitly, here with the installed keys.
    // One statement maintains the sealed value and index pair atomically.
    let keys = keys::installed()?;
    let email = plaintext.to_owned();
    let prepared = Sealed::<UserEmail>::prepare(&email, keys)?.with_index::<EmailLookup>(keys)?;
    sqlx::query("UPDATE users SET email = ?, email_idx = ?")
        .bind(prepared.sealed())
        .bind(prepared.index::<EmailLookup>()?)
        .execute(&mut connection)
        .await?;
    let row = sqlx::query("SELECT email, email_idx FROM users")
        .fetch_one(&mut connection)
        .await?;
    let read: Sealed<UserEmail> = row.try_get("email")?;
    assert_eq!(read.open(keys)?, plaintext);
    assert_eq!(
        row.try_get::<Vec<u8>, _>("email_idx")?,
        prepared.index::<EmailLookup>()?.as_bytes(),
    );
    Ok(())
}
