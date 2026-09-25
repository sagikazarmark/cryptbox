use std::{env, error::Error, path::Path};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Ciphertext, Encrypted,
    EncryptionKey, FieldBound, IndexId, LocalBlindIndexKeyring, LocalEncryptionKeyring,
    blind_index_probes, index_id, index_key_id, key_id, verify_blind_index_candidate,
};
use sqlx::{Connection, QueryBuilder, Row};
use zeroize::Zeroizing;

#[cfg(any(
    all(feature = "postgres", feature = "sqlite"),
    not(any(feature = "postgres", feature = "sqlite"))
))]
compile_error!("select exactly one of postgres or sqlite");

#[cfg(feature = "postgres")]
type Db = sqlx::Postgres;
#[cfg(feature = "sqlite")]
type Db = sqlx::Sqlite;
type DbConnection = <Db as sqlx::Database>::Connection;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
type EmailCiphertext = Ciphertext<String, UserEmail>;

cryptbox::profile! {
    UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
    }
}

struct EmailLookup;
impl BlindIndexMetadata for EmailLookup {
    const ID: IndexId = index_id!("80000000-0000-4000-8000-000000000008");
    const BITS: usize = 128;
}
impl BlindIndexSpec<str> for EmailLookup {
    fn normalize(input: &str) -> std::result::Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        // Illustrative ASCII equality policy, not general email canonicalization.
        let mut bytes = Zeroizing::new(input.trim().as_bytes().to_vec());
        bytes.make_ascii_lowercase();
        Ok(bytes)
    }
}
impl BlindIndexSpec<String> for EmailLookup {
    fn normalize(input: &String) -> std::result::Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        <Self as BlindIndexSpec<str>>::normalize(input)
    }
}

fn load_root_key(directory: &Path, name: &str) -> Result<Zeroizing<[u8; 32]>> {
    let text = Zeroizing::new(
        std::fs::read_to_string(directory.join(name))
            .map_err(|_| format!("key configuration: cannot read {name}"))?,
    );
    let mut bytes = Zeroizing::new([0; 32]);
    hex::decode_to_slice(text.trim(), bytes.as_mut())
        .map_err(|_| format!("key configuration: {name} must contain 64 hex digits"))?;
    Ok(bytes)
}

fn load_keyrings_from_env() -> Result<(LocalEncryptionKeyring, LocalBlindIndexKeyring)> {
    let directory =
        env::var("CRYPTBOX_KEY_DIR").map_err(|_| "key configuration: CRYPTBOX_KEY_DIR required")?;
    let directory = Path::new(&directory);
    // These IDs are immutable companions of the provisioned files; never reassign them.
    let encryption_1 = EncryptionKey::new(
        key_id!("10000000-0000-4000-8000-000000000001"),
        *load_root_key(directory, "encryption-1.hex")?,
    );
    let encryption_2 = EncryptionKey::new(
        key_id!("20000000-0000-4000-8000-000000000002"),
        *load_root_key(directory, "encryption-2.hex")?,
    );
    let index_1 = BlindIndexKey::new(
        index_key_id!("30000000-0000-4000-8000-000000000003"),
        *load_root_key(directory, "index-1.hex")?,
    );
    let index_2 = BlindIndexKey::new(
        index_key_id!("40000000-0000-4000-8000-000000000004"),
        *load_root_key(directory, "index-2.hex")?,
    );
    // Both generations are readable before either is promoted for writes.
    match env::var("CRYPTBOX_GENERATION").as_deref() {
        Ok("1") => Ok((
            LocalEncryptionKeyring::new(encryption_1, [encryption_2])?,
            LocalBlindIndexKeyring::new(index_1, [index_2])?,
        )),
        Ok("2") => Ok((
            LocalEncryptionKeyring::new(encryption_2, [encryption_1])?,
            LocalBlindIndexKeyring::new(index_2, [index_1])?,
        )),
        _ => Err("key configuration: CRYPTBOX_GENERATION must be 1 or 2".into()),
    }
}

async fn put(
    connection: &mut DbConnection,
    id: i64,
    email: Option<String>,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    let value = email.map(Encrypted::<_, UserEmail>::new);
    let prepared = value
        .as_ref()
        .map(|value| {
            value
                .prepare_with(&(), encryption)?
                .with_index_with::<EmailLookup>(indexes)
        })
        .transpose()?;
    let ciphertext = prepared.as_ref().map(|p| p.ciphertext());
    let index = prepared
        .as_ref()
        .map(|p| p.index::<EmailLookup>())
        .transpose()?;
    // One statement: insert OR update both representations from the same source.
    sqlx::query("INSERT INTO users (id, email, email_lookup) VALUES ($1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET email = excluded.email, email_lookup = excluded.email_lookup")
        .bind(id).bind(ciphertext).bind(index.map(|i| i.as_bytes()))
        .execute(connection).await?;
    println!("Stored {id}.");
    Ok(())
}

async fn get(connection: &mut DbConnection, id: i64, keys: &LocalEncryptionKeyring) -> Result<()> {
    let row = sqlx::query("SELECT email FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(connection)
        .await?;
    // Decode the stored envelope now; choose when to authenticate/decrypt later.
    let stored: Option<EmailCiphertext> = row.try_get("email")?;
    match stored {
        Some(ciphertext) => println!(
            "{id}: {}",
            ciphertext.decrypt_with(&(), keys)?.expose_secret()
        ),
        None => println!("{id}: NULL"),
    }
    Ok(())
}

async fn search(
    connection: &mut DbConnection,
    query: &str,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    let probes =
        blind_index_probes::<EmailLookup, str, FieldBound<UserEmail>>(query, &(), indexes)?;
    let mut sql = QueryBuilder::<Db>::new("SELECT id, email FROM users WHERE email_lookup IN (");
    let mut values = sql.separated(", ");
    for probe in &probes {
        values.push_bind(probe.as_bytes());
    }
    values.push_unseparated(") ORDER BY id");
    let rows = sql.build().fetch_all(connection).await?;
    let mut matches = Vec::<i64>::new();
    let mut rejected = 0;
    for row in rows {
        let ciphertext: EmailCiphertext = row.try_get("email")?;
        let candidate = ciphertext.decrypt_with(&(), encryption)?;
        if verify_blind_index_candidate::<EmailLookup, str>(query, candidate.expose_secret())? {
            matches.push(row.try_get("id")?);
        } else {
            rejected += 1; // A collision is an ordinary non-match, not an assertion failure.
        }
    }
    println!("Matches: {matches:?}; rejected: {rejected}.");
    Ok(())
}

#[cfg(feature = "macro-check")]
async fn macro_put(
    connection: &mut DbConnection,
    id: i64,
    email: String,
    encryption: &LocalEncryptionKeyring,
    indexes: &LocalBlindIndexKeyring,
) -> Result<()> {
    let value = Encrypted::<_, UserEmail>::new(email);
    let prepared = value
        .prepare_with(&(), encryption)?
        .with_index_with::<EmailLookup>(indexes)?;
    let ciphertext = prepared.ciphertext();
    let index = prepared.index::<EmailLookup>()?.as_bytes();
    // PostgreSQL's macro sees BYTEA, not the custom wrapper: override input inference.
    sqlx::query!("INSERT INTO users (id, email, email_lookup) VALUES ($1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET email = excluded.email, email_lookup = excluded.email_lookup",
        id, ciphertext as _, index)
        .execute(connection).await?;
    println!("Stored {id}.");
    Ok(())
}

#[cfg(feature = "macro-check")]
async fn macro_get(
    connection: &mut DbConnection,
    id: i64,
    keys: &LocalEncryptionKeyring,
) -> Result<()> {
    // `?` preserves SQL NULL; the alias selects CryptBox's SQLx Decode implementation.
    let row = sqlx::query!(
        r#"SELECT email AS "email?: EmailCiphertext" FROM users WHERE id = $1"#,
        id
    )
    .fetch_one(connection)
    .await?;
    match row.email {
        Some(ciphertext) => println!(
            "{id}: {}",
            ciphertext.decrypt_with(&(), keys)?.expose_secret()
        ),
        None => println!("{id}: NULL"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let (encryption, indexes) = load_keyrings_from_env()?; // Fail before opening storage if key loading fails.
    let mut connection = DbConnection::connect(&env::var("DATABASE_URL")?).await?;
    let args: Vec<String> = env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["init"] => {
            #[cfg(feature = "postgres")]
            let schema = include_str!("postgres.sql");
            #[cfg(feature = "sqlite")]
            let schema = include_str!("sqlite.sql");
            sqlx::raw_sql(schema).execute(&mut connection).await?;
            println!("Schema ready.");
        }
        ["put", id, email] => {
            put(
                &mut connection,
                id.parse()?,
                Some((*email).to_owned()),
                &encryption,
                &indexes,
            )
            .await?
        }
        ["put-null", id] => put(&mut connection, id.parse()?, None, &encryption, &indexes).await?,
        ["get", id] => get(&mut connection, id.parse()?, &encryption).await?,
        #[cfg(feature = "macro-check")]
        ["macro-get", id] => macro_get(&mut connection, id.parse()?, &encryption).await?,
        #[cfg(feature = "macro-check")]
        ["macro-put", id, email] => {
            macro_put(
                &mut connection,
                id.parse()?,
                (*email).to_owned(),
                &encryption,
                &indexes,
            )
            .await?
        }
        ["search", query] => search(&mut connection, query, &encryption, &indexes).await?,
        ["demo-false-candidate", target, source] => {
            // Test fixture ONLY: deliberately break index/plaintext consistency.
            sqlx::query("UPDATE users SET email_lookup = (SELECT email_lookup FROM users WHERE id = $1) WHERE id = $2")
                .bind(source.parse::<i64>()?).bind(target.parse::<i64>()?)
                .execute(&mut connection).await?;
            println!("False candidate injected.");
        }
        _ => return Err("usage: init | put ID EMAIL | put-null ID | get ID | search EMAIL".into()),
    }
    connection.close().await?;
    Ok(())
}
