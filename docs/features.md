# Features

No features are enabled by default, and all features are additive:

- `derive` adds `#[derive(Seal)]`, `#[derive(BlindIndexSpec)]`, and
  `#[derive(Record)]`. Each expands to the trait impls you would write by hand,
  plus a record's stored form and index handles; only the derive implements
  `Record`. IDs are UUID literals checked at
  compile time; a codec is never inferred from a type's shape.
- `json` adds the `Json` codec. Its serialized representation is persistent
  schema. It implies `serde`.
- `migrate` adds the `migrate` module for adopting `CryptBox` over plaintext or a
  previous solution's ciphertext: permissive reads, a legacy recovery handler,
  and a resumable sweep. Normal decoding stays strict.
- `serde` serializes `Sealed` and `BlindIndex` stored bytes: unpadded base64url
  in human-readable formats, bytes otherwise.
- `sqlx-postgres` and `sqlx-sqlite` add `SQLx` 0.8 `BYTEA`/`BLOB` storage.
  `migrate::PostgresSweepStore` and `migrate::SqliteSweepStore` additionally
  need `migrate`.

`Sealed` and `BlindIndex` are ordinary columns, and a record's stored form is an
ordinary row. Seal and open every value explicitly, with the keys you pass in.

The `sqlx-*` features turn off `SQLx`'s default features and choose no runtime
or TLS. Depend on `sqlx` directly as well, with your runtime and TLS features,
its `derive` feature for `stored(derive(sqlx::FromRow))`, and its `uuid` feature
for a `Uuid` record ID or column. Likewise, deriving `Serialize` or
`Deserialize` on a stored form needs your own `serde` dependency with its
`derive` feature. docs.rs enables all features.

Deserializing `Sealed` or `BlindIndex` checks structure only: a sealed value is
authenticated when opened, and index candidates must be compared against
decrypted plaintext. See the [stored-value walkthrough].

## Platforms and tested configurations

This is a `std` crate requiring Rust **1.85 or newer** (edition 2024). Encryption
and key generation need a target on which `getrandom` 0.4 can obtain secure
OS entropy; see its
[target support](https://docs.rs/getrandom/0.4.3/getrandom/#supported-targets).
A bare `wasm32-unknown-unknown` build has no entropy backend.

The `RustCrypto` backends assume constant-time integer multiplication; targets
without it, including some 32-bit PowerPC and non-ARM microcontrollers, are not
supported. The production target review is not finished.

CI checks Rust 1.85 and stable on Linux, including live PostgreSQL tests (see
CONTRIBUTING.md). These are tested configurations, not a reviewed allowlist; no
macOS, Windows, browser, or embedded support is claimed.

<!-- Rustdoc supplies repository-qualified definitions before including this page. -->
[stored-value walkthrough]: ../examples/stored_values/README.md
