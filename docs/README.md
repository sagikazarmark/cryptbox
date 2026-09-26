# CryptBox documentation

Repository docs describe this checkout. For released APIs, select your dependency
version on [docs.rs](https://docs.rs/cryptbox/0.5.0/cryptbox/); stored-byte Serde support
is unreleased even though this checkout still declares 0.5.0.

## Start here

Choose the entry point that fits your question:

- **Try it:** [encrypt your first field](first-field.md), a small in-memory tutorial.
- **Understand it:** [how CryptBox works](concepts.md), from application value to storage and back.
- **Assess it:** [security and threat model](security.md), including current review status.

## Integrate into a project

- [Integration design and trade-offs](integration.md): persistent schema, storage boundaries, providers, and search.
- [Store a field durably in SQLite](first-field-sqlite.md): encryption-only tutorial with a separate-process read.
- [Build searchable SQLx storage](searchable-sqlx.md): a complete tutorial for atomic writes and verified equality lookup on PostgreSQL or SQLite.
- [Automatic SQLx adapters](testing.md#automatic-adapters): a runnable example and its key-context lifetime.
- [Serialize stored values](stored-values.md): explicit ciphertext and index serialization with Serde (unreleased).
- [Customize profiles and providers](custom-profile.md): codecs, normalization, key sources, and wrapped plaintext.
- [Testing and diagnostics](testing.md): isolated providers and sanitized failures.
- [Adopt existing data](legacy-migration.md): prerequisites and rollout for plaintext or previous-solution ciphertext.

## Operate

- [Key lifecycle](key-rotation.md): stage, promote, roll back, retire, and recover.
- [Maintenance sweeps](reencryption-sweep.md): rewrite and verify existing storage.
- [Retirement and recovery](key-rotation.md#retirement-and-recovery): backup dependencies, isolated restores, and online key removal.
- [Close a legacy migration](legacy-migration.md#verification-and-closing-the-window): verify converted data and return to strict reads.

## Reference

- [API](https://docs.rs/cryptbox/0.5.0/cryptbox/).
- [Features and platforms](features.md): feature flags, release differences, and supported constraints.
- [Wire format](wire-format.md): exact layouts, encryption/index recipes, padding, and vectors.
- [Plaintext and key ownership](ownership.md): borrowing, cloning, and erasure contracts.
- [What each check establishes](security.md#what-each-check-establishes): parsing, authentication, candidate comparison, and migration-state verification.
- [Glossary](glossary.md).

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
| [SQLite](../examples/sqlx_sqlite.rs) | `cargo run --locked --example sqlx_sqlite --features sqlx-sqlite -- --help` (see [provisioning and write/read steps](first-field-sqlite.md)) |

## Contribute

[Documentation and development checks](documentation.md).
