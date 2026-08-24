# Examples

Run commands from the repository root.

| Example | What it shows | Run |
| --- | --- | --- |
| [First seal](first_seal.rs) | A seal, a local key, seal and open | `cargo run --locked --example first_seal` |
| [Tenant seal](tenant_seal.rs) | One keyring per tenant | `cargo run --locked --example tenant_seal` |
| [Records](records/README.md) | Record-bound rows, a keyring per org, search within an org, SQLx, a JSON message | `cargo run --locked --example records --features derive,json,sqlx-sqlite` |
| [SQLite](sqlite/README.md) | Durable storage read back in a separate process | See its README |
| [Searchable storage](searchable/README.md) | Atomic ciphertext/index writes and verified lookup on SQLite or PostgreSQL | See its README |
| [Stored values](stored_values/README.md) | Serde serialization of ciphertext and blind indexes | `cargo run --locked --example stored_values --features derive,serde` |
| [Custom seal](custom_seal/README.md) | A self-valued seal with a validating codec, normalizer, and refreshed keys | `cargo run --locked --example custom_seal` |
| [Blind-index lookup](blind_indexes.rs) | Probes and candidate comparison | `cargo run --locked --example blind_indexes --features derive` |
| [Key rotation](key_rotation.rs) | Staging and promoting a generation | `cargo run --locked --example key_rotation --features derive` |
| [Maintenance sweep](reencryption_sweep.rs) | Rewriting stored values without the driver | `cargo run --locked --example reencryption_sweep --features derive,sqlx-sqlite` |
| [Legacy migration](legacy_migration.rs) | Adopting a previous solution's ciphertext | `cargo run --locked --example legacy_migration --features derive,migrate,sqlx-sqlite` |
| [Plaintext migration](plaintext_migration.rs) | Adopting plaintext | `cargo run --locked --example plaintext_migration --features derive,migrate,sqlx-sqlite` |

Searchable storage is a separate workspace package because it has its own
backend features; the end-to-end tests build the same package.
