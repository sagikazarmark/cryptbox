# Serialize And Read Stored Values

**Tutorial · unreleased development API, not published 0.5.0.** Learn explicit Serde storage and the assurance
boundaries. [All tasks](README.md) · [Concepts](concepts.md).

This walkthrough describes the current public API. It serializes ciphertext and
blind indexes, parses them, deliberately decrypts the ciphertext, and checks the
separate lookup and consistency guarantees. CryptBox remains experimental; these
checks do not constitute independent cryptographic review.

## Run The Consumer Example

Create a Rust binary project (Rust 1.85 or newer, on a target with OS entropy),
alongside this checkout: the directories should be `cryptbox/` (this repository)
and `stored-values-consumer/` (your binary). Then use this complete `Cargo.toml`
in the consumer. The path dependency is deliberate: published `cryptbox = "0.5"`
does not yet provide the `serde` feature. Use a checkout containing the Serde
support added after v0.5.0, such as the branch containing this guide.

<!-- BEGIN SHARED: stored-values-manifest -->

```toml
[package]
name = "stored-values-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
cryptbox = { path = "../cryptbox", features = ["serde"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
zeroize = "1"
```

<!-- END SHARED: stored-values-manifest -->

Copy [the complete worked program](../examples/stored_values.rs) into `src/main.rs`
and run `cargo run`. In this repository, the same program runs with:

```sh
cargo run --locked --example stored_values --features serde
```

The isolated consumer check compiles and runs this exact manifest/program without
repository development dependencies:

```sh
node scripts/check-consumers.mjs checkout stored-values
```

It is included in checkout-mode CI and Dagger consumer checks. Published mode
intentionally excludes this unreleased recipe; it never substitutes registry
0.5.0 for the checkout-only Serde dependency.

`serde_json` is the consumer's storage format, so CryptBox's `json` codec feature
is not needed. The profile uses `Utf8` for the plaintext encoding. The `serde`
derive feature supplies the document's `Serialize` and `Deserialize` derives;
`zeroize` supplies the normalizer's owned buffer type.

The program uses fixed demonstration keys and one in-memory JSON document. For
durable storage, load stable, independently generated encryption and index roots
from your secret source and preserve their IDs across restarts. Store both
document fields atomically. Do not use these demonstration keys in applications.

## Follow The Value Through Storage

1. `Encrypted<String, UserEmail>` holds **plaintext**. `prepare_with` borrows it
   and derives ciphertext and indexes from the same source. It does not erase or
   consume the source value. `&()` is the unit runtime context, not an unbound
   profile: the macro supplies `FieldBound<UserEmail>`.
2. `StoredUser` owns explicit `Ciphertext` and `BlindIndex` representations.
   Serde serializes their complete stored bytes. JSON represents each as an
   integer array; a binary Serde format can represent them as byte strings.
3. Deserialization checks structure, just like `from_bytes`. It performs no key
   lookup, authentication, decryption, or index recomputation. The phantom
   profile/index types express caller intent, not proof of how bytes originated.
4. `decrypt_with` deliberately authenticates the ciphertext using the key and
   field binding, removes padding, and decodes with the selected codec. Apply
   application-level validation to the resulting value as needed.
5. Index recomputation and candidate comparison are separate checks described below.

`Encrypted` deliberately has **no Serde implementation**, even when its plaintext
type implements Serde. Implicit serialization would blur plaintext and ciphertext
storage; encryption also requires a deliberate profile, context, and provider.
Encrypt first and serialize `Ciphertext`; deserialize that type and decrypt
explicitly when reading.

## Know What Each Check Establishes

| Operation | Establishes | Does not establish |
| --- | --- | --- |
| `Ciphertext::from_bytes`, Serde deserialization, `inspect_ciphertext` | Supported envelope structure | Authenticity, correct key/binding, decoded-value validity |
| `BlindIndex::from_bytes`, Serde deserialization | Canonical stored structure and expected precision | Correct logical index, binding, input, or trustworthy key metadata |
| `inspect_blind_index` | Canonical stored structure and parsed metadata | Agreement with a typed specification, authenticity, or consistency |
| `needs_reencryption_with`, row classification, full terminal sweep report | Structure/generation state within the observed scope | Authenticated readability, codec validity, ciphertext/index consistency |
| Typed `Ciphertext::decrypt_with` | Ciphertext authentication, valid padding, successful codec decoding | Freshness, row identity, business validity, or index consistency |
| `verify_blind_index_candidate` | Equality of normalized query and candidate plaintext | Authentication or consistency of stored index metadata |
| Recompute and compare complete index bytes | Consistency with the authenticated plaintext and intended derivation at the configured precision | Unique identity, provenance, freshness, or collision-free equality |

The example damages a ciphertext payload, serializes the damaged bytes, and
successfully deserializes them as current-generation `Ciphertext`. Decryption
then returns `AuthenticationFailed`. The same distinction applies to a terminal
`Sweep::verify` report: current rows are not decrypted. See the
[maintenance verification procedure](reencryption-sweep.md#verification-and-retirement).

Field binding makes ciphertext authentication fail under a different logical
field. For blind indexes, it **domain-separates derivation**, rather than
authenticating stored index bytes. Neither mechanism binds a value to a row;
same-field substitution and replay of valid older ciphertext remain possible.

## Obtain Additional Assurance

For authenticated readability and index consistency across a store:

1. Fix the intended profile, binding context, codec, index specifications,
   normalization, precision, and allowed key generations from application schema,
   not untrusted stored metadata. Coordinate writers and choose a consistent
   snapshot or repeat a complete bounded scan under your storage guarantees.
2. Read every ciphertext and its indexes together. Parse the typed ciphertext and
   call `decrypt_with` using the intended profile/context and provider. Treat any
   authentication, padding, codec, or key-availability error as a failed check;
   do not count an unread row as verified. Validate application constraints too.
3. Parse each index as `BlindIndex<ExpectedSpec>`. After generation convergence,
   call `derive_blind_index` on the decrypted value using the intended binding and
   current index provider, and compare **the complete stored bytes**, not only
   the key ID. Before convergence, use `blind_index_probes` on that decrypted
   value to derive expected bytes for every allowed readable generation and
   require a complete-byte match. An unknown/disallowed generation is a failure.
4. Record failures and coverage without logging plaintext. Investigate or repair
   mismatches from the authoritative authenticated value. If repairing, update
   ciphertext and index columns atomically with a guard against all originally
   read bytes, so a concurrent writer is not overwritten. Complete the entire
   pass before claiming store-wide coverage.

A matching truncated index provides only consistency at its configured precision.
For **query results**, always search every readable generation, decrypt candidates,
and use `verify_blind_index_candidate` to compare normalized plaintext, discarding
false matches. This function takes no index bytes or keys; it cannot authenticate
index metadata. The worked program shows that the same plaintext comparison
still succeeds when a separately derived index for another value would fail the
consistency check. Index checks also cannot prove that a database returned every
matching row.

Continue with [blind-index lookup](../examples/blind_indexes.rs) or the
[maintenance sweep guide](reencryption-sweep.md) for generation convergence and
backup-aware retirement.
