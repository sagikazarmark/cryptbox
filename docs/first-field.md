# Encrypt your first field

**Tutorial · published CryptBox 0.5.0.** CryptBox is experimental and
[not production-ready](security.md). [All tasks](README.md).

## 1. Create a consumer project

Use current stable Rust/Cargo (minimum Rust 1.85) on Linux or macOS with OS
entropy and network access for dependencies. No database or optional feature is needed.

```sh
cargo new first-field-consumer
cd first-field-consumer
```

Replace `Cargo.toml` with:

<!-- BEGIN SHARED: first-field-manifest -->

```toml
[package]
name = "first-field-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
cryptbox = "=0.5.0"
```

<!-- END SHARED: first-field-manifest -->

## 2. Encrypt and decrypt

Replace `src/main.rs` with this [example](../examples/first_field.rs).
**Its key is ephemeral:** every run generates a new key/ID pair, lost at exit.

<!-- BEGIN SHARED: first-field -->

```rust
use cryptbox::{Encrypted, EncryptionKey, LocalEncryptionKeyring};

cryptbox::profile! {
    UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
    }
}

fn main() -> Result<(), cryptbox::Error> {
    // Ephemeral demo keys: a new key and generation ID on every run.
    let keys = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
    let email = Encrypted::<_, UserEmail>::new("mark@example.com".to_owned());
    let ciphertext = email.encrypt_with(&(), &keys)?;
    let decrypted = ciphertext.decrypt_with(&(), &keys)?;
    assert_eq!(decrypted.expose_secret(), "mark@example.com");
    assert_eq!(email.expose_secret(), "mark@example.com"); // Source retained.
    println!("Field-bound round trip succeeded.");
    Ok(())
}
```

<!-- END SHARED: first-field -->

```sh
cargo run
```

Expect `Field-bound round trip succeeded.` and exit status 0.

### What just happened?

- `Encrypted` holds **plaintext**; encryption borrows it. `Ciphertext` holds the
  encrypted envelope. Decryption authenticates and returns a new plaintext value.
- `&()` is the unit **binding context**; `&keys` supplies keys separately. These
  explicit-provider calls need no global installation.
- Field binding identifies a logical field, not a row or tenant; it does not stop
  same-field substitution or replay. The default `NoPadding` reveals encoded length.

See [the value lifecycle](concepts.md#the-value-lifecycle) for ownership details.

## 3. Freeze schema decisions before durable storage

Keep the field ID, codec compatibility, binding and padding mode stable; when
adding indexes, also preserve index IDs, normalization and precision. Changes need
a migration plan. See the [persistent-schema contract](https://docs.rs/cryptbox/0.5.0/cryptbox/#persistent-schema).

### Next: keep keys across restarts

Provision independent encryption/index roots once and reload the **same ID/key
pairs** on restart. Never silently replace missing keys; retain generations needed
by stored data and backups. Follow the [durable SQLx guide](searchable-sqlx.md), or
try the [in-memory SQLite example](first-field-sqlite.md) first.
