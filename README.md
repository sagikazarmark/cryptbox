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
- **Explicit migration facility.** The opt-in `migrate` feature adds a permissive plaintext-or-ciphertext read type and a resumable sweep driver for adopting encryption over existing data; the default decoding path stays strict.
- **SQLx integration.** Backend-specific features map encrypted values and blind indexes to PostgreSQL `BYTEA` or SQLite `BLOB` columns.
- **Secret hygiene.** Keys and CryptBox-owned plaintext buffers are zeroized; `Debug` output is redacted.

## Quick Start

```rust
use cryptbox::{
    Encrypted, EncryptionKey, EncryptionProfile, Field, FieldBound,
    GlobalKeyContext, LocalEncryptionKeyring, Utf8, field_id,
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
        EncryptionKey::generate()?,
        [],
    )?;
    let email = Encrypted::<_, UserEmail>::new("mark@example.com".to_owned());
    let ciphertext = email.encrypt_with(&(), &keys)?;
    let decrypted = ciphertext.decrypt_with(&(), &keys)?;

    assert_eq!(decrypted.expose_secret(), "mark@example.com");
    Ok(())
}
```

The quick start generates an ephemeral key. Durable data requires the same key
and ID across process restarts, provisioned through the application's secret
management path. Existing 32-byte root keys can be loaded from hex or standard
Base64 after the application fetches its configuration:

```rust,ignore
use cryptbox::{EncryptionKey, key_id};
use zeroize::Zeroizing;

let encoded = Zeroizing::new(std::env::var("MASTER_KEY")?);
let key = EncryptionKey::from_base64(
    key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50"),
    &encoded,
)?;
```

`from_hex` and `from_base64` decode directly into zeroizing key storage, but
cannot erase copies retained by the operating system or process environment.
Generate encryption and blind-index keys independently.

For applications with many profiles, the `profile!` macro generates the same
marker type and trait implementations while keeping the binding choice
explicit:

```rust
cryptbox::profile! {
    pub UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
    }
}
```

Use `binding: unbound` to explicitly opt out of field binding. Add
`keys: ApplicationKeys` to select a custom key context; otherwise the macro
uses `GlobalKeyContext`.

## Testing

Applications that use context-less methods or automatic storage adapters should
install `GlobalKeyContext` once in the binary entry point. Do not install it from
test setup or reusable library code: it is process-global and cannot be replaced
or reset. Most tests should keep their keyring local and use the explicit
`encrypt_with`, `decrypt_with`, `prepare_with`, `with_index_with`,
`needs_reencryption_with`, and `reencrypt_with` methods. This keeps tests
independent and safe to run in parallel.

Tests that exercise automatic storage adapters cannot pass a provider directly.
Such a test binary can select an application-defined `KeyContext` whose provider
delegates through an `RwLock`:

```rust
use std::sync::{OnceLock, RwLock};

use cryptbox::{
    BlindIndexKeyProvider, EncryptionKey, EncryptionKeyProvider, KeyContext,
    KeyId, KeyProviderError, LocalEncryptionKeyring,
};

struct TestKeys(RwLock<LocalEncryptionKeyring>);

static TEST_KEYS: OnceLock<TestKeys> = OnceLock::new();

impl TestKeys {
    fn replace(keys: LocalEncryptionKeyring) -> Result<(), KeyProviderError> {
        let context = TEST_KEYS.get_or_init(|| Self(RwLock::new(keys.clone())));
        *context.0.write().map_err(|_| KeyProviderError::Unavailable)? = keys;
        Ok(())
    }
}

impl EncryptionKeyProvider for TestKeys {
    fn current_key(&self) -> Result<EncryptionKey, KeyProviderError> {
        self.0
            .read()
            .map_err(|_| KeyProviderError::Unavailable)?
            .current_key()
    }

    fn key(&self, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        self.0
            .read()
            .map_err(|_| KeyProviderError::Unavailable)?
            .key(id)
    }
}

impl KeyContext for TestKeys {
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, KeyProviderError> {
        TEST_KEYS
            .get()
            .map(|keys| keys as &dyn EncryptionKeyProvider)
            .ok_or(KeyProviderError::NotInitialized)
    }

    fn blind_index_keys() -> Result<&'static dyn BlindIndexKeyProvider, KeyProviderError> {
        Err(KeyProviderError::Unavailable)
    }
}
```

Set `type Keys = TestKeys` on profiles used by those tests and call
`TestKeys::replace` before each case. The context is still shared across the test
process, so tests that replace it must be serialized. Add a second locked
provider when automatic blind-index operations also need test-specific keys.

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
- [Plaintext migration](examples/plaintext_migration.rs): `cargo run --example plaintext_migration --features migrate,sqlx-sqlite`
- [Blind-index lookup](examples/blind_indexes.rs): `cargo run --example blind_indexes`
- [In-memory SQLite storage](examples/sqlx_sqlite.rs): `cargo run --example sqlx_sqlite --features sqlx-sqlite`

The [maintenance sweep guide](docs/reencryption-sweep.md) covers batching,
optimistic concurrency, interruption recovery, verification, and historical-key
retirement for ciphertext and blind indexes. The
[plaintext migration guide](docs/plaintext-migration.md) covers adopting
encryption over existing plaintext columns with the `migrate` feature.

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
- `migrate` enables the explicit plaintext-to-ciphertext migration facility, intended for a bounded migration window only.
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
