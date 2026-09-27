//! One automatic-adapter fixture per process.

use std::error::Error;

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexSpec, EncryptionKey, Field, FieldId, FieldOnly, Keys,
    LocalBlindIndexKeyring, LocalEncryptionKeyring, Padding, Plain, Sealed, Utf8, keys,
};
use sqlx::{Connection, Row, sqlite::SqliteConnection};
use zeroize::Zeroizing;

struct Nickname;

impl Field for Nickname {
    const ID: FieldId = cryptbox::field_id!("60000000-0000-4000-8000-000000000006");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
    type Indexes = ();
}

// A field with a blind index is never a `Plain` column: the column would not write the index.
struct UserEmail;

impl Field for UserEmail {
    const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
    type Indexes = (EmailLookup,);
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
    sqlx::query("CREATE TABLE users (nickname BLOB NOT NULL, email BLOB, email_idx BLOB)")
        .execute(&mut connection)
        .await?;
    let nickname = Plain::<Nickname>::new(plaintext);

    // Binding Plain exercises automatic sealing with the installed keys.
    sqlx::query("INSERT INTO users (nickname) VALUES (?)")
        .bind(&nickname)
        .execute(&mut connection)
        .await?;
    let row = sqlx::query("SELECT nickname FROM users")
        .fetch_one(&mut connection)
        .await?;
    let read: Plain<Nickname> = row.try_get("nickname")?;
    assert_eq!(read.expose_secret(), plaintext); // Automatic authenticated opening.

    // An indexed field is sealed explicitly. Preparation seals with the installed
    // keys, and the implicit `with_index` resolves the installed blind-index keys
    // too. One statement maintains the sealed value and index pair atomically.
    let email = plaintext.to_owned();
    let prepared = Sealed::<UserEmail>::prepare(&email, (), keys::installed()?)?
        .with_index::<EmailLookup>()?;
    sqlx::query("UPDATE users SET email = ?, email_idx = ?")
        .bind(prepared.sealed())
        .bind(prepared.index::<EmailLookup>()?)
        .execute(&mut connection)
        .await?;
    let row = sqlx::query("SELECT email, email_idx FROM users")
        .fetch_one(&mut connection)
        .await?;
    let read: Sealed<UserEmail> = row.try_get("email")?;
    assert_eq!(read.open_global()?, plaintext);
    assert_eq!(
        row.try_get::<Vec<u8>, _>("email_idx")?,
        prepared.index::<EmailLookup>()?.as_bytes(),
    );
    Ok(())
}
