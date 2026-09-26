# Encrypt your first field

Encrypt and decrypt a field-bound value in a small Rust application.
CryptBox is experimental and [not production-ready](security.md).
[Documentation](README.md).

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

See [how CryptBox works](concepts.md) for the complete picture.

## Next: use durable storage

The round trip is complete. To keep values across restarts, follow
[store your first field in SQLite](first-field-sqlite.md). That tutorial provisions
one durable encryption generation and reads the stored value in a new process.

In your own project, preserve the same key ID/material pairs and the field's
[persistent schema](integration.md#persistent-schema). Missing keys must not be
silently replaced. The [integration explanation](integration.md) covers these
choices before you commit data to storage.

If you need lookup, the [searchable SQLx tutorial](searchable-sqlx.md) adds
independently keyed blind indexes. If the project already has plaintext or
previous-solution ciphertext, review [legacy adoption](legacy-migration.md)
before enabling encrypted writes.
