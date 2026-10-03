//! Records bound to their record IDs, with a keyring per org: an org's customers
//! in SQLite, a search across its workspaces, and a record carried as a JSON
//! message.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, EncryptionKey, EncryptionKeyring, Error,
    Json, Keys, Record,
};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, SqliteConnection};
use uuid::Uuid;
use zeroize::Zeroizing;

/// An org, the tenant: each org has its own keys.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
struct OrgId(Uuid);

/// A workspace within an org.
#[derive(Clone, Copy, Debug, PartialEq, sqlx::Type)]
#[sqlx(transparent)]
struct WorkspaceId(Uuid);

#[allow(clippy::unnecessary_wraps)] // Normalizers are fallible by contract.
fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(
        email.trim().to_ascii_lowercase().into_bytes(),
    ))
}

/// A customer of one workspace of an org.
#[derive(Clone, Debug, PartialEq, Record)]
#[cryptbox(stored(derive(sqlx::FromRow)))]
struct Customer {
    #[cryptbox(record_id)]
    id: Uuid,
    #[cryptbox(plaintext)]
    org: OrgId,
    #[cryptbox(plaintext)]
    workspace: WorkspaceId,
    /// Searchable across the org's workspaces.
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        bits = 32,
        normalize = normalize_email,
        normalizer = "email/1",
    ))]
    email: String,
    #[cryptbox(seal = "5d1f0c3a-8f6e-4b1d-9a7c-2e4b6d8f0a13")]
    note: Option<String>,
    #[cryptbox(plaintext)]
    created_at: i64,
}

// Ephemeral demonstration keys: one set per org, generated on every run.
fn org_keys() -> Result<Keys, Error> {
    Ok(
        Keys::new(EncryptionKeyring::new(EncryptionKey::generate()?, [])?)
            .with_blind_indexes(BlindIndexKeyring::new(BlindIndexKey::generate()?, [])?),
    )
}

const ACME: OrgId = OrgId(Uuid::from_u128(1));
const SALES: WorkspaceId = WorkspaceId(Uuid::from_u128(10));
const SUPPORT: WorkspaceId = WorkspaceId(Uuid::from_u128(11));

async fn create_table(db: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE customer (id BLOB PRIMARY KEY, org BLOB NOT NULL, workspace BLOB NOT NULL,
         email BLOB NOT NULL, email_index BLOB NOT NULL, note BLOB, created_at INTEGER NOT NULL)",
    )
    .execute(db)
    .await?;

    Ok(())
}

async fn insert(db: &mut SqliteConnection, stored: &StoredCustomer) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO customer VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(stored.id)
        .bind(stored.org)
        .bind(stored.workspace)
        .bind(&stored.email)
        .bind(&stored.email_index)
        .bind(&stored.note)
        .bind(stored.created_at)
        .execute(db)
        .await?;

    Ok(())
}

/// Reads one customer of the caller's org, checking the org before decrypting.
async fn get(
    db: &mut SqliteConnection,
    keys: &Keys,
    org: OrgId,
    id: Uuid,
) -> Result<Customer, Box<dyn std::error::Error>> {
    let row: StoredCustomer = sqlx::query_as("SELECT * FROM customer WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await?;

    Ok(Customer::open_expecting(row, keys, |row| row.org == org)?)
}

/// Finds the customers of `org` with `email`, in every workspace, with the org's
/// keys.
async fn search(
    db: &mut SqliteConnection,
    keys: &Keys,
    org: OrgId,
    email: &str,
) -> Result<Vec<Customer>, Box<dyn std::error::Error>> {
    let probes = Customer::EMAIL_INDEX.probes(email, keys)?;
    let placeholders = vec!["?"; probes.len()].join(", ");
    let sql = format!("SELECT * FROM customer WHERE org = ? AND email_index IN ({placeholders})");
    let mut select = sqlx::query_as::<_, StoredCustomer>(&sql).bind(org);
    for probe in &probes {
        select = select.bind(probe);
    }
    let rows = select.fetch_all(db).await?;

    // Opens each candidate and drops false ones; the query selected the org's
    // rows, and a row under another org's keys would fail to open.
    let hits = Customer::EMAIL_INDEX.open_matching(email, rows, keys)?;
    Ok(hits.into_iter().collect::<Result<_, _>>()?)
}

/// A record carried as a JSON message, such as a queue event: its stored form is
/// what travels.
#[derive(Debug, PartialEq, Record)]
#[cryptbox(stored(name = CustomerCreatedEvent, derive(Serialize, Deserialize)))]
struct CustomerCreated {
    #[cryptbox(record_id)]
    #[cryptbox(stored(serde(rename = "eventId")))]
    event_id: Uuid,
    #[cryptbox(plaintext)]
    org: OrgId,
    #[cryptbox(seal = "3a9d4e21-7b6c-4f58-9e0a-1c2b3d4e5f60", codec = Json)]
    address: Address,
    #[cryptbox(plaintext)]
    kind: String,
}

/// A value sealed whole, as JSON.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Address {
    street: String,
    city: String,
}

fn customer(id: u128, workspace: WorkspaceId, email: &str) -> Customer {
    Customer {
        id: Uuid::from_u128(id),
        org: ACME,
        workspace,
        email: email.to_owned(),
        note: None,
        created_at: 1_700_000_000,
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut db = SqliteConnection::connect("sqlite::memory:").await?;
    create_table(&mut db).await?;
    let (acme_keys, globex_keys) = (org_keys()?, org_keys()?);

    // A tenant's customers: seal, store, and read back within the org.
    let ada = Customer {
        note: Some("prefers email".to_owned()),
        ..customer(1, SALES, "ada@example.com")
    };
    insert(&mut db, &ada.seal(&acme_keys)?).await?;
    insert(
        &mut db,
        &customer(2, SUPPORT, "Ada@Example.com ").seal(&acme_keys)?,
    )
    .await?;
    insert(
        &mut db,
        &customer(3, SUPPORT, "grace@example.com").seal(&acme_keys)?,
    )
    .await?;

    assert_eq!(get(&mut db, &acme_keys, ACME, ada.id).await?, ada);
    // Another org's keys don't open it.
    let row: StoredCustomer = sqlx::query_as("SELECT * FROM customer WHERE id = ?")
        .bind(ada.id)
        .fetch_one(&mut db)
        .await?;
    assert!(matches!(
        Customer::open(row, &globex_keys),
        Err(Error::UnknownEncryptionKey(_))
    ));

    // An org-wide search finds matches in both workspaces.
    let found = search(&mut db, &acme_keys, ACME, "ada@example.com").await?;
    let workspaces: Vec<_> = found.iter().map(|customer| customer.workspace).collect();
    assert_eq!(workspaces, [SALES, SUPPORT]);

    // A record as a JSON message: sealed values travel as base64url text.
    let event = CustomerCreated {
        event_id: Uuid::from_u128(7),
        org: ACME,
        address: Address {
            street: "1 Main St".to_owned(),
            city: "Springfield".to_owned(),
        },
        kind: "customer.created".to_owned(),
    };
    let json = serde_json::to_string(&event.seal(acme_keys.encryption())?)?;
    assert!(!json.contains("Springfield"));
    let received: CustomerCreatedEvent = serde_json::from_str(&json)?;
    assert_eq!(CustomerCreated::open(received, &acme_keys)?, event);

    println!("Records round trip, search, and message succeeded.");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    futures_executor::block_on(run())
}

#[cfg(test)]
mod tests {
    #[test]
    fn records_round_trip_search_and_travel() -> Result<(), Box<dyn std::error::Error>> {
        super::main()
    }
}
