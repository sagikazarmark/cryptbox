# CryptBox documentation

Repository docs describe this checkout. For released APIs, select your dependency
version on [docs.rs](https://docs.rs/cryptbox/0.5.0/cryptbox/); stored-byte Serde support
is unreleased even though this checkout still declares 0.5.0.

## Understand

- [Concepts](concepts.md): components, ownership, binding, generations, and assurance.
- [Threat model](security.md): protections, assumptions, limitations, and review status.
- [Wire format](wire-format.md): exact encryption/index recipes, padding, and vectors.
- [Features and platforms](features.md): configuration and supported constraints.
- [Glossary](../CONTEXT.md) and [API reference](https://docs.rs/cryptbox/0.5.0/cryptbox/).

## Build

- [Encrypt your first field](first-field.md).
- [Durable SQLx storage and verified search](searchable-sqlx.md).
- Examples: [minimal SQLite](first-field-sqlite.md), [Serde stored values](stored-values.md),
  [custom profiles and providers](custom-profile.md).
- [Application testing and diagnostics](testing.md).

## Operate

- [Key lifecycle](key-rotation.md): stage, promote, roll back, retire, and recover.
- [Maintenance sweeps](reencryption-sweep.md): rewrite and verify existing storage.
- [Legacy migration](legacy-migration.md): adopt encryption over existing data.

## Runnable examples

Run from a checkout. SQLx examples need the indicated backend feature.

| Example | Command |
| --- | --- |
| [First field](../examples/first_field.rs) | `cargo run --locked --example first_field` |
| [Custom profile](../examples/custom_profile.rs) | `cargo run --locked --example custom_profile` |
| [Key rotation](../examples/key_rotation.rs) | `cargo run --locked --example key_rotation` |
| [Maintenance sweep](../examples/reencryption_sweep.rs) | `cargo run --locked --example reencryption_sweep --features sqlx-sqlite` |
| [Legacy migration](../examples/legacy_migration.rs) | `cargo run --locked --example legacy_migration --features migrate,sqlx-sqlite` |
| [Plaintext migration](../examples/plaintext_migration.rs) | `cargo run --locked --example plaintext_migration --features migrate,sqlx-sqlite` |
| [Blind-index lookup](../examples/blind_indexes.rs) | `cargo run --locked --example blind_indexes` |
| [Stored values](../examples/stored_values.rs) | `cargo run --locked --example stored_values --features serde` |
| [SQLite](../examples/sqlx_sqlite.rs) | `cargo run --locked --example sqlx_sqlite --features sqlx-sqlite` |

## Contribute

[Documentation and development checks](documentation.md).
