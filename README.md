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

It can protect encrypted fields in a stolen database dump when keys stay
separate. It does not protect a compromised application, prevent replay or
same-field cross-row substitution, or hide query patterns. Blind indexes leak
equality/frequency; every hit requires decrypted, normalized comparison.

[Try it](docs/first-field.md) · [How it works](docs/concepts.md) ·
[Security](docs/security.md) · [Documentation](docs/README.md) ·
[API](https://docs.rs/cryptbox/latest/cryptbox/)

## Quick start

This in-memory demonstration uses no optional features.
Keys are ephemeral: do not use this provisioning pattern for durable data.
For the complete manifest, file placement, and expected output, follow
[encrypt your first field](docs/first-field.md).

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

The macro selects UTF-8 encoding, field binding, no padding, and the default key
context. `Encrypted` holds plaintext; `Ciphertext` holds the encrypted envelope.
`&()` is the unit **binding context**, not a key provider or an opt-out from
field binding. `&keys` supplies keys explicitly. Encryption borrows `email`, so
the original plaintext remains in memory. See [how CryptBox works](docs/concepts.md).

Next, [store the field durably in SQLite](docs/first-field-sqlite.md), or read
[integration design and trade-offs](docs/integration.md) before applying it to your
project. If you need equality lookup, continue with the
[searchable SQLx tutorial](docs/searchable-sqlx.md). For existing plaintext or
foreign ciphertext, review [legacy adoption](docs/legacy-migration.md) before
changing writes.

## Development

See [development and documentation checks](docs/documentation.md) for local,
GitHub Actions, and Dagger commands.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
