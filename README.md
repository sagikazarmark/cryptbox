# cryptbox

[![ci](https://img.shields.io/github/actions/workflow/status/sagikazarmark/cryptbox/ci.yaml?style=flat-square)](https://github.com/sagikazarmark/cryptbox/actions/workflows/ci.yaml)
[![openssf scorecard](https://api.securityscorecards.dev/projects/github.com/sagikazarmark/cryptbox/badge?style=flat-square)](https://securityscorecards.dev/viewer/?uri=github.com/sagikazarmark/cryptbox)
[![crates.io](https://img.shields.io/crates/v/cryptbox?style=flat-square)](https://crates.io/crates/cryptbox)
[![docs.rs](https://img.shields.io/docsrs/cryptbox?style=flat-square)](https://docs.rs/cryptbox)

**Strongly typed application-layer encryption for Rust values.**

CryptBox keeps serialization, byte-oriented cryptography, key management, and
storage adapters separate. Its primary `Encrypted<T, Profile>` type contains
plaintext while in application memory and requires explicit plaintext access.

> [!WARNING]
> The v0.1 XChaCha20-Poly1305 suite and binary formats are experimental pending
> focused cryptographic review and independent verification of the provisional
> test vectors. Do not treat this draft implementation as production-ready.

## Features

- **Typed encryption policy.** Profiles select a codec, stable binding, and key context without making application types noisy.
- **Authenticated field binding.** Stable random field IDs prevent valid ciphertext from moving between different logical fields.
- **Non-disruptive rotation.** Ciphertext names one current or historical key generation, so rotation does not require an immediate rewrite.
- **Explicit searchable projections.** Separately keyed, intentionally truncated blind indexes support equality candidate lookup.
- **Storage preparation.** `Prepared` derives ciphertext and blind indexes from the same source value.
- **SQLx integration.** Backend-specific features map encrypted values and blind indexes to PostgreSQL `BYTEA` or SQLite `BLOB` columns.
- **Secret hygiene.** Keys and CryptBox-owned plaintext buffers are zeroized; `Debug` output is redacted.

## Quick Start

```rust
use cryptbox::{
    Encrypted, EncryptionKey, EncryptionProfile, Field, FieldBound,
    GlobalKeyContext, LocalEncryptionKeyring, Utf8, field_id, key_id,
};

fn main() -> Result<(), cryptbox::Error> {
    struct UserEmail;

    impl Field for UserEmail {
        const ID: cryptbox::FieldId =
            field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
        const NAME: &'static str = "user-email";
    }

    impl EncryptionProfile<String> for UserEmail {
        type Codec = Utf8;
        type Binding = FieldBound<Self>;
        type Keys = GlobalKeyContext;
    }

    let keys = LocalEncryptionKeyring::new(
        EncryptionKey::new(
            key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50"),
            [0x42; 32],
        ),
        [],
    )?;
    let email = Encrypted::<_, UserEmail>::new("mark@example.com".to_owned());
    let ciphertext = email.encrypt_with(&(), &keys)?;
    let decrypted = ciphertext.decrypt_with(&(), &keys)?;

    assert_eq!(decrypted.expose_secret(), "mark@example.com");
    Ok(())
}
```

Applications should load random 32-byte root keys through their own secret
configuration path. The literal key above is only an example.

## Diagnostics

`Field::ID` is the stable machine identifier; `Field::NAME` is a human-readable
display label that may change without migrating encrypted data. Include both
when attaching field context to application-owned errors, logs, traces, or
metrics:

```rust,ignore
tracing::warn!(
    error = %error,
    field_id = %UserEmail::ID,
    field_name = UserEmail::NAME,
    operation = "decrypt",
    "CryptBox operation failed",
);
```

Field names must not contain plaintext, record-specific data, or key material.
They may still reveal application schema, so applications decide where to emit
them. CryptBox does not emit logs or require an observability framework.

## Examples

- [Key rotation](examples/key_rotation.rs): `cargo run --example key_rotation`
- [Re-encryption sweep](examples/reencryption_sweep.rs): `cargo run --example reencryption_sweep --features sqlx-sqlite`
- [Blind-index lookup](examples/blind_indexes.rs): `cargo run --example blind_indexes`
- [In-memory SQLite storage](examples/sqlx_sqlite.rs): `cargo run --example sqlx_sqlite --features sqlx-sqlite`

The [maintenance sweep guide](docs/reencryption-sweep.md) covers batching,
optimistic concurrency, interruption recovery, verification, and historical-key
retirement for ciphertext and blind indexes.

## Blind Indexes

Blind indexes intentionally leak equality and frequency information. They are
candidate selectors, not authoritative matches: decrypt candidate rows and
compare normalized plaintext before accepting a result. Do not use a truncated
blind index as a uniqueness constraint, and avoid indexing low-cardinality or
highly skewed sensitive values.

Encryption keys and blind-index keys use independent providers and must be
generated independently. During blind-index key rotation, query with every
probe returned by `blind_index_probes`, then rewrite stored indexes separately.

## Feature Flags

- `json` enables the Serde JSON codec.
- `postcard` enables the Serde Postcard codec.
- `sqlx-postgres` enables SQLx 0.8 `BYTEA` support for PostgreSQL.
- `sqlx-sqlite` enables SQLx 0.8 `BLOB` support for SQLite.

No features are enabled by default. Features are additive and can be combined.
Both SQLx adapters support automatic encryption and decryption only for
unit-context profiles; typed ciphertext and blind indexes remain available for
profiles with explicit binding contexts. The SQLx features activate their
database backends but do not select an application async runtime or TLS stack.
CryptBox intentionally does not implement blanket Serde serialization for
`Encrypted<T, Profile>` because plaintext-versus-ciphertext semantics must be
explicit.

The [crate documentation](https://docs.rs/cryptbox/latest/cryptbox/#features)
is the authoritative reference for feature semantics and constraints.

## Development

Run the standard checks with:

```text
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo deny check
cargo test --locked --all-targets --all-features
cargo test --locked --doc --all-features
cargo doc --locked --no-deps --all-features
```

Run the repository's Dagger checks with `dagger check`.

The exact experimental formats and provisional vectors are documented in
[`docs/wire-format.md`](docs/wire-format.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
