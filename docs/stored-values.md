# Serialize And Read Stored Values

**Example · unreleased development API, not published 0.5.0.** The `serde` feature
requires this checkout. [All tasks](README.md).

## Run The Consumer Example

[`examples/stored_values.rs`](../examples/stored_values.rs) round-trips a JSON
document, authenticates its ciphertext, and separately checks its blind index.
From the repository root:

```sh
cargo run --locked --example stored_values --features serde
```

For a standalone consumer, create `stored-values-consumer/` beside `cryptbox/`,
use [stored-values.toml](snippets/stored-values.toml) as `Cargo.toml`, copy the
example to `src/main.rs`, and run `cargo run`. The manifest's path dependency
selects the checkout. `serde_json` is the storage format; CryptBox's `json` codec
feature is unnecessary because the plaintext codec is `Utf8`.

The fixed keys are public fixtures. For persistence, use [durable key/ID pairs](searchable-sqlx.md#2-provision-durable-key-generations-once)
and write ciphertext and indexes atomically.

## Follow The Value Through Storage

- `Encrypted` holds plaintext and deliberately has **no Serde implementation**.
  Prepare/encrypt explicitly; preparation borrows rather than erases the source.
- `StoredUser` owns `Ciphertext<String, UserEmail>` and `BlindIndex<EmailLookup>`.
  Serde stores their complete bytes (integer arrays in JSON).
- Deserialization, like `from_bytes`, checks **structure only**: no key lookup,
  authentication, decryption or index recomputation. Typed wrappers express the
  caller's intended profile/index, not proof of origin.
- `decrypt_with` authenticates, unpads and decodes. Application validation,
  normalized candidate comparison and stored-index consistency are separate checks.

The example's damaged, current-generation ciphertext still deserializes but fails
decryption. See [assurance distinctions](concepts.md#assurance) and the
[full audit and retirement procedure](reencryption-sweep.md#verification-and-retirement).
