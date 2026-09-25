# Features

**Reference · current development API, with release differences below.**
This is the canonical feature/platform reference, also included in the crate
landing documentation. The checkout still declares package version 0.5.0, but
contains unreleased changes. The published 0.5.0 archive does **not** have the
`serde` feature or stored-value Serde implementations. In that release, `json`
and `postcard` activate Serde as a codec dependency only, not stored-byte
serialization. The other feature names below are available in 0.5.0.

No features are enabled by default, and all features are additive:

- `json` adds the `Json` codec. Its serialized representation is part of the
  persistent schema. In development it implies `serde`; values need Serde traits.
- `migrate` adds the explicit `migrate` module for adopting `CryptBox` over
  plaintext or data encrypted by a previous solution: permissive reads, a legacy
  recovery handler, and a resumable sweep. Intended for a bounded migration
  window only; the default decoding path stays strict.
- `postcard` adds the `Postcard` codec. Its serialized representation is part of
  the persistent schema. In development it implies `serde`; values need Serde traits.
- `serde` (**unreleased**) adds explicit serialization of `Ciphertext` and `BlindIndex` stored
  bytes. It never adds serialization for plaintext `Encrypted` values.
- `sqlx-postgres` adds `SQLx` 0.8 `BYTEA` storage for `PostgreSQL`.
- `sqlx-sqlite` adds `SQLx` 0.8 `BLOB` storage for `SQLite`.

The `SQLx` adapters automatically encrypt and decrypt `Encrypted` only for
unit-context profiles, using `EncryptionProfile::Keys`. `Ciphertext` and
blind-index storage work with explicit-context profiles. These features do not
choose an async runtime or TLS implementation for the application. Add `SQLx`
0.8 directly with your backend and chosen runtime/TLS features; `CryptBox`'s
dependency disables `SQLx` defaults. Database services, connection configuration,
credentials, TLS trust, and runtime startup belong to the application. Serde
derives likewise require a direct `serde` dependency with `derive`; enabling
`CryptBox`'s `serde` feature does not select derive macros.

Feature-gated availability: `Json` requires `json`; `Postcard` requires
`postcard`; `migrate` and its core types require `migrate`.
`migrate::PostgresSweepStore` additionally requires `sqlx-postgres`,
`migrate::SqliteSweepStore` requires `sqlx-sqlite`, and `migrate::SweepTable`
requires either backend. Stored-value Serde implementations require `serde`;
`SQLx` implementations require the corresponding backend feature. The published
docs.rs build enables all features, so an item appearing there does not mean it
is enabled in a default build.

`CryptBox` deliberately provides no Serde implementation for `Encrypted`, because
it contains plaintext. With `serde`, serialize an explicitly encrypted
`Ciphertext` or derived `BlindIndex` instead. Their deserializers validate stored
structure but do not establish authenticity; ciphertext is authenticated only
when decrypted, and blind-index candidates must still be compared against
decrypted plaintext. That comparison does not authenticate index metadata;
checking stored-index consistency requires separate recomputation. See the
development [stored-value walkthrough](https://github.com/sagikazarmark/cryptbox/blob/main/docs/stored-values.md).

## Platforms and tested configurations

This is a standard-library crate requiring Rust **1.85 or newer** (edition 2024),
not a `no_std` crate. Encryption and random key/identifier generation require a
target on which `getrandom` 0.4 can obtain secure operating-system entropy;
entropy failure is returned as an error. Consult its
[target support](https://docs.rs/getrandom/0.4.3/getrandom/#supported-targets)
before cross-compiling. A bare browser `wasm32-unknown-unknown` build does not
gain an entropy backend from `CryptBox` features. Do not infer browser, embedded,
or arbitrary cross-target support from portable Rust source.

The portable `RustCrypto` backends assume constant-time integer multiplication;
targets where multiplication is variable-time, including certain 32-bit PowerPC
CPUs and some non-ARM microcontrollers, are not supported for secret operations.
The complete production target review is not yet finished.

The repository CI checks Rust 1.85 with locked all-target/all-feature compilation
on Ubuntu, and stable Rust with all-feature tests, independent `SQLx` feature
compilation (each backend with and without `migrate`), and default/all-feature
rustdoc. Dagger uses the configured Rust Linux container, runs examples, and
supplies PostgreSQL to execute the live round-trip and packaged-sweep tests,
including the otherwise ignored cases. See the development
[live-backend check instructions](https://github.com/sagikazarmark/cryptbox/blob/main/docs/testing.md#live-postgresql-sweep-checks).
These are tested configurations, not a reviewed target allowlist; no macOS,
Windows, browser, or embedded CI matrix is claimed.

Next: use the development [task index](https://github.com/sagikazarmark/cryptbox/blob/main/docs/README.md)
or consult the [0.5.0 API](https://docs.rs/cryptbox/0.5.0/cryptbox/).
