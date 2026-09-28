# Encrypt your first field

Encrypt and decrypt a field-bound value in a small Rust application.
CryptBox is experimental and [not production-ready](security.md).
[Documentation](README.md).

To run the complete example from a checkout:

```sh
cargo run --locked --example first_field
```

Expect `Field-bound round trip succeeded.` To build it yourself, follow the two
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
use cryptbox::{
    EncryptionKey, EncryptionKeyring, Field, FieldId, FieldOnly, Padding, Sealed, Utf8,
};

struct UserEmail;

impl Field for UserEmail {
    const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
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

- `Sealed::seal` borrows the **plaintext** `String` and returns a `Sealed` value:
  the encrypted envelope you store. `open` authenticates it and returns a new
  plaintext `String`.
- `UserEmail` is a field. Its `ID` binds the sealed value to this field; it stores
  a `String` value with the `Utf8` codec and no padding.
- `()` is the binding argument: `Binding = FieldOnly` with no record binds the
  value to its field ID alone. A field can declare a binding such as a tenant, and
  a record, and then every call must pass their values; see
  [bind values to a scope](bindings.md).
- `&keys` supplies keys explicitly, so these calls need no global installation.
- A field-only value is bound to a logical field, not a row or tenant, so it does
  not stop same-field substitution between rows, or replay. `Padding::NONE` reveals encoded length.

See [how CryptBox works](concepts.md) for the complete picture.

The field ID above is a generated UUID. Generate your own, and never copy one
from these pages:

```sh
uuidgen
```

See [ID hygiene](bindings.md#id-hygiene) for the rules that apply to every field,
index, and binding part ID.

## Next: use durable storage

The round trip is complete. To keep values across restarts, follow
[run the SQLite example](../examples/sqlite/README.md). It provisions
one durable encryption generation and reads the stored value in a new process.

In your own project, preserve the same key ID/material pairs and the field's
[persistent schema](integration.md#persistent-schema). Missing keys must not be
silently replaced. The [integration explanation](integration.md) covers these
choices before you commit data to storage.

## Then: bind values to a tenant

`UserEmail` binds its values to a field ID alone. When values belong to separate
tenants, orgs, or residencies, the field declares a binding instead, every call
passes its values, and each scope can have its own keyring:

```sh
cargo run --locked --example tenant_field
```

Expect `Tenant-bound round trip succeeded.` Then read
[bind values to a scope](bindings.md) for part roles and where bound values must
come from, and [choosing keyrings](choosing-keyrings.md) for whose keys protect
each scope.

## Other directions

If you need lookup, the [searchable storage example](../examples/searchable/README.md) adds
independently keyed blind indexes. If the project already has plaintext or
previous-solution ciphertext, review [legacy adoption](legacy-migration.md)
before enabling encrypted writes.
