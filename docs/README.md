# CryptBox documentation

## Start here

Choose the entry point that fits your question:

- **Try it:** [encrypt your first field](first-field.md), a small in-memory tutorial.
- **Understand it:** [how CryptBox works](concepts.md), from application value to storage and back.
- **Assess it:** [security and threat model](security.md), including current review status.

## Integrate into a project

- [Integration design and trade-offs](integration.md): persistent schema, storage boundaries, keys, and search.
- [SQLite example](../examples/sqlite/README.md): run and adapt durable encrypted storage with a separate-process read.
- [Searchable storage example](../examples/searchable/README.md): atomic writes and verified equality lookup on PostgreSQL or SQLite.
- [Automatic SQLx adapters](testing.md#automatic-adapters): a runnable example and its key-context lifetime.
- [Stored-values example](../examples/stored_values/README.md): ciphertext and index serialization with Serde.
- [Custom-field example](../examples/custom_field/README.md): codecs, normalization, key sources, and wrapped plaintext.
- [Testing and diagnostics](testing.md): isolated keys and sanitized failures.
- [Adopt existing data](legacy-migration.md): prerequisites and rollout for plaintext or previous-solution ciphertext.
- [Restate handlers](restate.md): seal inside `ctx.run`, object keys, what the journal exposes, and shredding an org.

## Operate

- [Key lifecycle](key-rotation.md): stage, promote, roll back, retire, and recover.
- [Maintenance sweeps](reencryption-sweep.md): rewrite and verify existing storage.
- [Retirement and recovery](key-rotation.md#retirement-and-recovery): backup dependencies, isolated restores, and online key removal.
- [Close a legacy migration](legacy-migration.md#verification-and-closing-the-window): verify converted data and return to strict reads.

## Reference

- [API](https://docs.rs/cryptbox/latest/cryptbox/).
- [Features and platforms](features.md): feature flags and supported constraints.
- [Wire format](wire-format.md): exact layouts, encryption/index recipes, padding, and vectors.
- [Plaintext and key ownership](ownership.md): borrowing, cloning, and erasure contracts.
- [What each check establishes](security.md#what-each-check-establishes): parsing, authentication, candidate comparison, and migration-state verification.
- [Glossary](glossary.md).

## Runnable examples

The [example index](../examples/README.md) lists runnable commands and prerequisites.
Each complete example keeps its source, setup, expected results, and adaptation
notes together. The first-field example remains the minimal quickstart.

## Contribute

[Documentation and development checks](documentation.md).
