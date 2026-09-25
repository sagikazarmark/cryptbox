# Store your first field in SQLite

**Tutorial · published CryptBox 0.5.0 API.** Continue after
[your first round trip](first-field.md), including its schema and durable-key
decisions. [All tasks](README.md).

This exercise keeps the same field ID, `Utf8`, `NoPadding`, and field binding.
It uses an **in-memory database and ephemeral keys**, not durable provisioning.

Create another binary with `cargo new sqlite-consumer`, enter that directory,
and replace `Cargo.toml` with:

<!-- BEGIN SHARED: sqlite-manifest -->

```toml
[package]
name = "sqlite-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
cryptbox = { version = "=0.5.0", features = ["sqlx-sqlite"] }
sqlx = { version = "0.8.6", default-features = false, features = ["sqlite"] }
futures-executor = "0.3.34"
```

<!-- END SHARED: sqlite-manifest -->

Use the same Rust/entropy prerequisites as the first tutorial. SQLite is bundled
by SQLx; building it requires a native C compiler (for example Xcode Command Line
Tools on macOS or `build-essential` on Debian). No database server or TLS setup
is needed. `futures-executor` drives this SQLite-only program; it does not provide
the runtime needed for PostgreSQL network connections.

Replace `src/main.rs` with:

<!-- BEGIN SHARED: sqlite -->

```rust
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
```

<!-- END SHARED: sqlite -->

Run `cargo run`. Expect `Field-bound SQLite round trip succeeded.` and exit
status 0 after Cargo's messages. The program creates the schema, prepares and
inserts ciphertext, reads explicit `Ciphertext`, and authenticates/decrypts with
the local key provider. It installs no global provider. The original `email`
remains plaintext while `prepared` borrows it.

There is only one stored ciphertext column, so the insertion is a single atomic
statement. When adding blind indexes, derive them from the same preparation and
write them with ciphertext atomically; an automatic encrypted column does not
maintain an index column for you.

Next: build the [durable, searchable SQLx application](searchable-sqlx.md) with
stable keys, a persistent database, prepared updates, and verified blind-index lookup.
