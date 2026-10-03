# CryptBox

[![ci](https://img.shields.io/github/actions/workflow/status/sagikazarmark/cryptbox/ci.yaml?style=flat-square)](https://github.com/sagikazarmark/cryptbox/actions/workflows/ci.yaml)
[![openssf scorecard](https://api.securityscorecards.dev/projects/github.com/sagikazarmark/cryptbox/badge?style=flat-square)](https://securityscorecards.dev/viewer/?uri=github.com/sagikazarmark/cryptbox)
[![crates.io](https://img.shields.io/crates/v/cryptbox?style=flat-square)](https://crates.io/crates/cryptbox)
[![docs.rs](https://img.shields.io/docsrs/cryptbox?style=flat-square)](https://docs.rs/cryptbox/latest/cryptbox/)

**Application-layer encryption for sensitive data in Rust.**

> [!WARNING]
> CryptBox is under development. **Use it at your own risk.**
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
cargo add cryptbox
```

Seal and open a string with an in-memory key:

```rust
use cryptbox::{
    EncryptionKey, EncryptionKeyring, Seal, SealId, Padding, Sealed, Utf8,
};

struct UserEmail;

impl Seal for UserEmail {
    const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

fn main() -> Result<(), cryptbox::Error> {
    // Demo only: this key is lost when the process exits.
    let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
    let email = "mark@example.com".to_owned();

    let sealed = Sealed::<UserEmail>::seal(&email, &keys)?;
    let opened = sealed.open(&keys)?;
    assert_eq!(opened, "mark@example.com");
    Ok(())
}
```

`UserEmail` is a seal: its ID binds every value sealed with it to this seal, and
it stores a `String` as UTF-8 without padding. `Sealed` holds the encrypted value;
`open` returns the plaintext, and `&keys` supplies the keys.

## Documentation

- [Guide](docs/guide.md): how it works, records and tenants, keyrings, schema, storage and search, testing.
- [Operations](docs/operations.md): key rotation, maintenance sweeps, legacy migration, shredding.
- [Security](docs/security.md): threat model and review status.
- [Wire format](docs/wire-format.md), [features](docs/features.md), [glossary](docs/glossary.md), [API](https://docs.rs/cryptbox/latest/cryptbox/).
- [Examples](examples/README.md): start with the [SQLite example](examples/sqlite/README.md).

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
