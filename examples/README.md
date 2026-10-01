# Examples

Run a working example, then read its source and explanation to adapt it to your
application. Start with the [quickstart](../docs/first-field.md) for the smallest
round trip, or choose a complete demonstration below.

Run commands from the repository root unless an example's README says otherwise.

| Example | What it demonstrates | Run |
| --- | --- | --- |
| [First seal](first_field.rs) | A seal, local key, encryption, and decryption | `cargo run --locked --example first_field` |
| [Tenant seal](tenant_field.rs) | A record-bound seal with one keyring per tenant | `cargo run --locked --example tenant_field` |
| [Records](records/README.md) | Record-bound rows with a keyring per org, a search within an org, SQLx, and a JSON message | `cargo run --locked --example records --features derive,json,sqlx-sqlite,uuid` |
| [SQLite](sqlite/README.md) | Durable encrypted storage and a separate-process read | Follow the README to provision a key, then run `sqlx_sqlite` |
| [Searchable storage](searchable/README.md) | Atomic ciphertext/index writes and verified lookup with SQLite or PostgreSQL | Follow the README for key and database setup |
| [Stored values](stored_values/README.md) | Serde serialization of ciphertext and blind indexes | `cargo run --locked --example stored_values --features derive,serde` |
| [Custom seal](custom_field/README.md) | A seal over `Secret<String>` with a validating codec, normalizer, and refreshed keys | `cargo run --locked --example custom_field` |

The smaller examples use Cargo example targets from the root package. Searchable
storage is a workspace package because it has its own mutually exclusive backend
features and optional maintenance commands. Its SQL, migration module, and README
live beside the source; end-to-end tests use this same package.

## Focused API demonstrations

These in-memory examples support the [operational guides](../docs/README.md#operate):

| Example | Command |
| --- | --- |
| [Blind-index lookup](blind_indexes.rs) | `cargo run --locked --example blind_indexes --features derive` |
| [Key rotation](key_rotation.rs) | `cargo run --locked --example key_rotation --features derive` |
| [Maintenance sweep](reencryption_sweep.rs) | `cargo run --locked --example reencryption_sweep --features derive,sqlx-sqlite` |
| [Legacy migration](legacy_migration.rs) | `cargo run --locked --example legacy_migration --features derive,migrate,sqlx-sqlite` |
| [Plaintext migration](plaintext_migration.rs) | `cargo run --locked --example plaintext_migration --features derive,migrate,sqlx-sqlite` |

For design questions, read [how CryptBox works](../docs/concepts.md),
[integration trade-offs](../docs/integration.md), or the
[security model](../docs/security.md).
