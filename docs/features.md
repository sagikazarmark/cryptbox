# Features

This reference describes feature flags and platform requirements. It is also
included in the crate landing documentation.

No features are enabled by default, and all features are additive:

- `derive` adds `#[derive(Seal)]`, `#[derive(Scope)]`,
  `#[derive(BlindIndexSpec)]`, and `#[derive(Record)]`
  from the `cryptbox-derive` proc-macro crate. Each expands to exactly the trait
  impls you would write by hand, plus a record's sealed struct, the seals its
  fields declare, and per-field sealers, so a manual impl remains a first-class
  alternative.
  IDs are UUID string literals checked at compile time; a codec is never
  inferred from a type's shape.
- `json` adds the `Json` codec. Its serialized representation is part of the
  persistent schema. It implies `serde`; values need Serde traits.
- `migrate` adds the explicit `migrate` module for adopting `CryptBox` over
  plaintext or data encrypted by a previous solution: permissive reads, a legacy
  recovery handler, and a resumable sweep. Intended for a bounded migration
  window only; the default decoding path stays strict.
- `postcard` adds the `Postcard` codec. Its serialized representation is part of
  the persistent schema. It implies `serde`; values need Serde traits.
- `restate` adds the `restate` module for [Restate](https://restate.dev) handlers:
  journal codecs for `Sealed` and `BlindIndex`, sealing inside `ctx.run` so replay
  finds the same bytes, error classification, and `ObjectKey`, a strict Virtual
  Object key for a scope, such as a blind index's scope. It uses `restate-sdk` 0.12 and
  implies `serde`. See the [Restate guide].
- `serde` adds explicit serialization of `Sealed` and `BlindIndex` stored
  bytes. It never adds serialization for plaintext `Plain` values.
- `sqlx-postgres` adds `SQLx` 0.8 `BYTEA` storage for `PostgreSQL`.
- `sqlx-sqlite` adds `SQLx` 0.8 `BLOB` storage for `SQLite`.
- `uuid` lets a binding part hold a `uuid::Uuid`, and converts one into a
  `RecordId`. Either binds the UUID's 16 bytes, exactly as a `[u8; 16]` does.

The `SQLx` adapters automatically seal and open `Plain<F>`, the column for a
unscoped seal without a record or blind indexes. `Plain<F>` uses the keys
installed with `keys::install`; name another key source as `Plain<F, K>` to use
application-owned keys. Seal values of every other seal explicitly: `Sealed` and
blind-index storage need no keys. These features do not
choose an async runtime or TLS implementation for the application. Add `SQLx`
0.8 directly with your backend and chosen runtime/TLS features; `CryptBox`'s
dependency disables `SQLx` defaults. Database services, connection configuration,
credentials, TLS trust, and runtime startup belong to the application. Serde
derives likewise require a direct `serde` dependency with `derive`; enabling
`CryptBox`'s `serde` feature does not select derive macros.

Feature-gated availability: the derive macros require `derive`; `Json` requires
`json`; `Postcard` requires `postcard`; `migrate` and its core types require
`migrate`; the `restate` module requires `restate`.
`migrate::PostgresSweepStore` additionally requires `sqlx-postgres`,
`migrate::SqliteSweepStore` requires `sqlx-sqlite`, and `migrate::SweepTable`
requires either backend. Stored-value Serde implementations require `serde`;
`SQLx` implementations require the corresponding backend feature. The docs.rs
build enables all features, so an item appearing there does not mean it
is enabled in a default build.

`CryptBox` deliberately provides no Serde implementation for `Plain`, because
it contains plaintext. With `serde`, serialize an explicitly sealed `Sealed`
value or derived `BlindIndex` instead. Their deserializers validate stored
structure but do not establish authenticity; a sealed value is authenticated
only when opened, and blind-index candidates must still be compared against
decrypted plaintext. That comparison does not authenticate index metadata;
checking stored-index consistency requires separate recomputation. See the
[stored-value walkthrough].

## Platforms and tested configurations

This is a standard-library crate requiring Rust **1.85 or newer** (edition 2024),
not a `no_std` crate. The `restate` feature needs Rust 1.90, as `restate-sdk`
does. Encryption and random key/identifier generation require a target on which
`getrandom` 0.4 can obtain secure operating-system entropy; entropy failure is
returned as an error. Consult its
[target support](https://docs.rs/getrandom/0.4.3/getrandom/#supported-targets)
before cross-compiling. A bare browser `wasm32-unknown-unknown` build does not
gain an entropy backend from `CryptBox` features. Do not infer browser, embedded,
or arbitrary cross-target support from portable Rust source.

The portable `RustCrypto` backends assume constant-time integer multiplication;
targets where multiplication is variable-time, including certain 32-bit PowerPC
CPUs and some non-ARM microcontrollers, are not supported for secret operations.
The complete production target review is not yet finished.

The repository CI checks Rust 1.85 with locked all-target compilation of every
feature except `restate` on Ubuntu, and stable Rust with all-feature tests,
independent `SQLx` feature compilation (each backend with and without
`migrate`), and default/all-feature rustdoc. Dagger uses the configured Rust
Linux container, runs examples, and supplies PostgreSQL to execute the live
round-trip and packaged-sweep tests, including the otherwise ignored cases. It
also runs the Restate adapter's end-to-end test against a real
`restate-server`. See the
[live-backend check instructions].
These are tested configurations, not a reviewed target allowlist; no macOS,
Windows, browser, or embedded CI matrix is claimed.

Next: use the [task index]
or consult the [API reference](https://docs.rs/cryptbox/latest/cryptbox/).

<!-- Rustdoc supplies repository-qualified definitions before including this page. -->
[stored-value walkthrough]: ../examples/stored_values/README.md
[live-backend check instructions]: documentation.md#live-postgresql
[task index]: README.md
[Restate guide]: restate.md
