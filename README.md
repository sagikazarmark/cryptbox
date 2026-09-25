# cryptbox

[![ci](https://img.shields.io/github/actions/workflow/status/sagikazarmark/cryptbox/ci.yaml?style=flat-square)](https://github.com/sagikazarmark/cryptbox/actions/workflows/ci.yaml)
[![openssf scorecard](https://api.securityscorecards.dev/projects/github.com/sagikazarmark/cryptbox/badge?style=flat-square)](https://securityscorecards.dev/viewer/?uri=github.com/sagikazarmark/cryptbox)
[![crates.io](https://img.shields.io/crates/v/cryptbox?style=flat-square)](https://crates.io/crates/cryptbox)
[![docs.rs](https://img.shields.io/docsrs/cryptbox?style=flat-square)](https://docs.rs/cryptbox/0.5.0/cryptbox/)

**Strongly typed application-layer encryption for Rust values.**

Encrypt selected values before storage, keeping keys outside the database.
`Encrypted<T, Profile>` contains **plaintext** in application memory;
`Ciphertext<T, Profile>` contains stored encrypted bytes. CryptBox separates
serialization, cryptography, key providers, and storage adapters.

> [!WARNING]
> CryptBox is experimental and **not production-ready**. Crate 0.5.0 uses
> ciphertext/index format 1 and suite 1 (XChaCha20-Poly1305); the historical
> “v0.1 design” is a separate label. Focused cryptographic review, independent
> vectors, accepted usage policy, and target review remain outstanding.
> Read [suitability and security](docs/security.md) before adoption.

It can protect encrypted fields in a stolen database dump when keys stay
separate. It does not protect a compromised application, prevent replay or
same-field cross-row substitution, or hide query patterns. Blind indexes leak
equality/frequency; every hit requires decrypted, normalized comparison.

## Find your task

- **Evaluate:** [suitability, unsuitable uses, and review gates](docs/security.md).
- **Configure:** [feature/platform reference](docs/features.md), shared with the crate landing page.
- **Start:** [encrypt your first field in a fresh Rust project](docs/first-field.md).
- **Integrate:** [durable, searchable PostgreSQL / SQLite application](docs/searchable-sqlx.md) and [stored-value tutorial (unreleased Serde support)](docs/stored-values.md).
- **Operate:** [key rotation](examples/key_rotation.rs), [maintenance sweeps](docs/reencryption-sweep.md), and [legacy migration](docs/legacy-migration.md).
- **Review security:** [review reading path](docs/security.md#security-review-path).
- **Browse:** [all documentation, examples, and document authority](docs/README.md).

The [0.5.0 published API](https://docs.rs/cryptbox/0.5.0/cryptbox/) describes that
release. Repository links describe this development checkout, including unreleased
stored-byte Serde support and later documentation improvements; see the
[version guide](docs/README.md#document-authority-and-versions).

## Features

- Typed profiles select codecs, padding, stable field binding, and key providers.
- Generation-tagged ciphertext supports key rotation without immediate rewrites.
- Separately keyed blind indexes support equality **candidate** lookup.
- Prepared storage derives ciphertext and indexes from one value for atomic writes.
- Optional Serde stored bytes (unreleased), SQLx PostgreSQL/SQLite adapters, and bounded migration support.
- CryptBox-owned keys/plaintext buffers are zeroized and debug output is redacted.

## Quick Start

This in-memory demonstration uses no optional features (`cryptbox = "=0.5.0"`).
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
the original plaintext remains in memory. See [concepts and terminology](docs/concepts.md).

For durable data, load the same key/ID pairs after every restart; generate
encryption and blind-index roots independently. Before storing anything, review
the [schema and durable-key next steps](docs/first-field.md#4-freeze-schema-decisions-before-durable-storage),
then follow the [durable SQLx tutorial](docs/searchable-sqlx.md).

## Testing

Use local providers for parallel-independent tests. See the
[testing and diagnostics guide](docs/testing.md) for automatic-adapter isolation.

## Diagnostics

See [diagnostic metadata](docs/testing.md#diagnostics) for stable field IDs,
safe labels, and application-owned logging.

## Examples

The [example index](docs/README.md#runnable-examples) lists runnable commands.

## Blind Indexes

See [lookup concepts](docs/concepts.md#generations-and-lookup) and the
[blind-index example](examples/blind_indexes.rs). Never use truncated indexes
as uniqueness constraints.

## Serde Ciphertext Storage

The [stored-value tutorial](docs/stored-values.md) explains explicit ciphertext
serialization, structural parsing, authentication, and index consistency.

## Feature Flags

Feature/platform semantics have one owner: the
[feature/platform reference](docs/features.md), included in the crate landing
page. No features are enabled by default.

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
