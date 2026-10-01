# Seal your first value

Seal and open a value bound to its seal in a small Rust application.
CryptBox is experimental and [not production-ready](security.md).
[Documentation](README.md).

To run the complete example from a checkout:

```sh
cargo run --locked --example first_field
```

Expect `Seal-bound round trip succeeded.` To build it yourself, follow the two
steps below using the same source.

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
use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Seal, SealId, Sealed, Utf8};

struct UserEmail;

impl Seal for UserEmail {
    const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Record = ();
    type Indexes = ();
}

fn main() -> Result<(), cryptbox::Error> {
    // Ephemeral demo keys: a new key and generation ID on every run.
    let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
    let email = "mark@example.com".to_owned();
    let sealed = Sealed::<UserEmail>::seal(&email, (), &keys)?;
    let opened = sealed.open((), &keys)?;
    assert_eq!(opened, "mark@example.com");
    assert_eq!(email, "mark@example.com"); // Source retained.
    println!("Seal-bound round trip succeeded.");
    Ok(())
}
```

<!-- END SHARED: first-field -->

```sh
cargo run
```

Expect `Seal-bound round trip succeeded.` and exit status 0.

### What just happened?

- `Sealed::seal` borrows the **plaintext** `String` and returns a `Sealed` value:
  the encrypted envelope you store. `open` authenticates it and returns a new
  plaintext `String`.
- `UserEmail` is a seal. Its `ID` binds the sealed value to this seal; it stores
  a `String` value with the `Utf8` codec and no padding.
- `()` is the binding argument: `Record = ()` binds the value to its seal ID
  alone. A seal can bind a record, and then every call must pass its ID; see
  [bind values to their seal and record](bindings.md).
- `&keys` supplies keys explicitly, so these calls need no global installation.
- A value without a record is bound to its seal alone, not a row or tenant, so it
  does not stop substitution between rows of the same seal, or replay. `Padding::NONE` reveals encoded length.

See [how CryptBox works](concepts.md) for the complete picture.

The seal ID above is a generated UUID. Generate your own, and never copy one
from these pages:

```sh
uuidgen
```

See [ID hygiene](bindings.md#id-hygiene) for the rules that apply to every seal,
index, and binding part ID.

## Next: use durable storage

The round trip is complete. To keep values across restarts, follow
[run the SQLite example](../examples/sqlite/README.md). It provisions
one durable encryption generation and reads the stored value in a new process.

In your own project, preserve the same key ID/material pairs and the seal's
[persistent schema](integration.md#persistent-schema). Missing keys must not be
silently replaced. The [integration explanation](integration.md) covers these
choices before you commit data to storage.

## Then: bind values to a record, with a keyring per tenant

`UserEmail` binds its values to a seal ID alone. When values must not move
between rows, the seal binds a record and every call passes its ID; when they
belong to separate tenants, orgs, or residencies, each tenant has its own
keyring:

```sh
cargo run --locked --example tenant_field
```

Expect `Record-bound round trip with a keyring per tenant succeeded.` Then read
[bind values to their seal and record](bindings.md) for records and record
IDs, and [choosing keyrings](choosing-keyrings.md) for whose keys protect them.

## Other directions

If you need lookup, the [searchable storage example](../examples/searchable/README.md) adds
independently keyed blind indexes. If the project already has plaintext or
previous-solution ciphertext, review [legacy adoption](legacy-migration.md)
before enabling encrypted writes.
