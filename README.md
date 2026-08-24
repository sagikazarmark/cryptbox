# CryptBox

[![ci](https://img.shields.io/github/actions/workflow/status/sagikazarmark/cryptbox/ci.yaml?style=flat-square)](https://github.com/sagikazarmark/cryptbox/actions/workflows/ci.yaml)
[![openssf scorecard](https://api.securityscorecards.dev/projects/github.com/sagikazarmark/cryptbox/badge?style=flat-square)](https://securityscorecards.dev/viewer/?uri=github.com/sagikazarmark/cryptbox)
[![crates.io](https://img.shields.io/crates/v/cryptbox?style=flat-square)](https://crates.io/crates/cryptbox)
[![docs.rs](https://img.shields.io/docsrs/cryptbox?style=flat-square)](https://docs.rs/cryptbox/latest/cryptbox/)

**Application-layer encryption for sensitive data in Rust.**

> [!WARNING]
> CryptBox has not been independently audited, and its API may change before
> 1.0. Its stored format is stable as of 0.6; 0.6 cannot read values stored by
> 0.5 (see [upgrading stored values from 0.5](docs/operations.md#upgrading-stored-values-from-05)).
> **Use it at your own risk.**
>
> Read the [threat model](docs/security.md) for its security boundaries and
> outstanding review work.

## Features

- 🛡️ **Encryption for your Rust data models.**
- 🔌 **Database and serialization support.**
- 🔑 **Rotate keys at your own pace.**
- 🔎 **Search encrypted data using blind indexes.**
- 🧹 **Prevent sensitive data exposure in logs.**

| Capability | Protection |
| --- | --- |
| ✅ It CAN | Protect encrypted values in a stolen database dump when keys stay separate. |
| ❌ It CAN'T | Protect a compromised application. |
| ❌ It CAN'T | Prevent replay, or cross-row substitution of standalone values. |

## Quick start

```sh
cargo add cryptbox --features derive
cargo add zeroize
```

To store records with SQLx, also enable `sqlx-sqlite` or `sqlx-postgres`; see
[features](docs/features.md) for the `sqlx` features your own dependency needs.

### Seal a record

Mark the sensitive fields of a row, seal it before you store it, and open it
after you load it:

```rust
use cryptbox::{EncryptionKey, EncryptionKeyring, Record, Secret};

#[derive(Record)]
struct User {
    #[cryptbox(record_id)]
    id: i64,
    // Generate a fresh UUID for every seal, such as with `uuidgen`.
    #[cryptbox(seal = "7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13")]
    ssn: Secret<String>,
}

fn main() -> Result<(), cryptbox::Error> {
    // Demo only: this key is lost when the process exits.
    let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;

    let user = User {
        id: 7,
        ssn: Secret::new("123-45-6789".to_owned()),
    };

    // What you store: `id` as it is, and `ssn` sealed.
    let stored: StoredUser = user.seal(&keys)?;

    // What you load: opening authenticates and decrypts every sealed field.
    let user = User::open(stored, &keys)?;
    assert_eq!(user.ssn.expose_secret(), "123-45-6789");
    Ok(())
}
```

`#[derive(Record)]` generates the stored form, `StoredUser`, with a `Sealed`
column for each sealed field. Every sealed field is bound to its seal and to the
row's `id`, so a value copied to another field or row fails to open. The record
ID must exist before sealing, so generate it in the application (UUIDv7 is a good
choice), not with an autoincrement column. `Secret` keeps the SSN out of `Debug`
output and wipes it on drop; read it with `expose_secret`.

### Look it up by email

Encryption is randomized, so equal values never share ciphertext. To find a row
by a sealed field, add a blind index, a keyed hash stored beside it:

```rust
use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, EncryptionKey, EncryptionKeyring, Keys,
    Record, Secret,
};
use zeroize::Zeroizing;

#[derive(Record)]
struct User {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25")]
    #[cryptbox(blind_index(
        id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
        bits = 32,
        normalize = normalize_email,
        normalizer = "email/1",
    ))]
    email: String,
    #[cryptbox(seal = "7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13")]
    ssn: Secret<String>,
}

/// Lookups match emails that differ only in case or surrounding spaces.
fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.trim().to_ascii_lowercase().into_bytes()))
}

fn main() -> Result<(), cryptbox::Error> {
    // Blind indexes have their own, independently generated keys.
    let keys = Keys::new(EncryptionKeyring::new(EncryptionKey::generate()?, [])?)
        .with_blind_indexes(BlindIndexKeyring::new(BlindIndexKey::generate()?, [])?);

    let user = User {
        id: 7,
        email: "Mark@Example.com".to_owned(),
        ssn: Secret::new("123-45-6789".to_owned()),
    };

    // The stored form gains an `email_index` column; write it with the row.
    let stored: StoredUser = user.seal(&keys)?;

    // Select the rows whose `email_index` is one of the probes...
    let probes = User::EMAIL_INDEX.probes("mark@example.com", &keys)?;
    assert!(probes.contains(&stored.email_index));

    // ...then open those rows, keeping only the real matches.
    let found = User::EMAIL_INDEX.open_matching("mark@example.com", [stored], &keys)?;
    let user = found.into_iter().next().expect("one match")?;
    assert_eq!(user.ssn.expose_secret(), "123-45-6789");
    Ok(())
}
```

`normalize` defines which emails are equal, and `normalizer = "email/1"` names
those rules. Stored indexes depend on the rules, not the name: when the rules
change, bump the name and give the index a new `id`, then derive its indexes
again. The name only makes the change visible in a schema snapshot. `User::EMAIL_INDEX` is the index handle the derive generates. An
index reveals which rows share an email, and a 32-bit index also selects some
rows that do not match, so `open_matching` decrypts each candidate and compares
it before returning a match.

Without the derive, implement `Seal` for a value type and seal it with
`Sealed::seal`; see the [API docs](https://docs.rs/cryptbox/latest/cryptbox/).
For real keys, read [loading keys](docs/guide.md#loading-keys) in the guide; it
also covers key rotation and storage with SQLx.

## Documentation

- [Guide](docs/guide.md): records and tenants, how it works, loading and choosing keys, schema, storage and search, testing.
- [Operations](docs/operations.md): key rotation, maintenance sweeps, legacy migration, shredding.
- [Security](docs/security.md): threat model and review status.
- [Wire format](docs/wire-format.md), [features](docs/features.md), [glossary](docs/glossary.md), [API](https://docs.rs/cryptbox/latest/cryptbox/).
- [Examples](examples/README.md): start with the [records example](examples/records/README.md),
  which extends the quick start with SQLx, a keyring per org, and a JSON message.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
