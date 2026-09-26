# Extend a profile with explicit plaintext ownership

**Example.**
[`examples/custom_profile.rs`](../examples/custom_profile.rs) combines a codec,
normalizer and synchronous provider for a 1–64 character ASCII account handle.
[All tasks](README.md).

## Run the example

From the repository root:

```sh
cargo run --locked --example custom_profile
```

Expect `Custom profile round trip and normalized lookup succeeded.` For a
standalone project, run `cargo new custom-profile-consumer`, replace its manifest
with [custom-profile.toml](snippets/custom-profile.toml), copy the example to
`src/main.rs`, and run `cargo run`. `zeroize` is a direct dependency because the
extension interfaces return `Zeroizing<Vec<u8>>`.

Keys are ephemeral; use [durable key/ID pairs](integration.md#key-providers-and-key-contexts)
before persisting data.

## Why these implementations?

- **`HandleCodec: Codec<Secret<String>>`** validates letters, digits and hyphens,
  preserving case. It returns zeroizing encoded bytes and an owned `Secret<String>`
  on decode. `Utf8` alone does not encode this wrapper.
- **`HandleEquality`** validates the same alphabet and lowercases inside a
  zeroizing buffer. Writes, probes and candidate comparison share that rule.
  The 128-bit index leaks equality/frequency and is not a uniqueness constraint.
- **`CachedEncryptionKeys`** serves a local snapshot without I/O on the encryption
  path. The application owns loading, refresh, synchronization and failure policy.
- **`Secret<String>`** zeroizes its owned string on drop. Preparation still borrows
  the plaintext; dropping `Prepared` does not erase it. `into_secret()` returns
  the decoded type—it does not add zeroization to an ordinary `String` profile.

### Implementor obligations

| Extension | Contract |
| --- | --- |
| [Codec](https://docs.rs/cryptbox/latest/cryptbox/trait.Codec.html) | Preserve encoding compatibility; return zeroizing encoded bytes and owned decoded values. Sanitize input-bearing errors and protect intermediate allocations. |
| [BlindIndexSpec](https://docs.rs/cryptbox/latest/cryptbox/trait.BlindIndexSpec.html) | Use stable, deterministic equality rules for writes, all readable-generation probes and candidate comparison. Process only the indexed value; protect sensitive buffers. |
| [EncryptionKeyProvider](https://docs.rs/cryptbox/latest/cryptbox/trait.EncryptionKeyProvider.html) | Resolve the exact ID. Return `Ok(None)` for an unknown ID in a healthy snapshot, `Unavailable` when resolution fails; never substitute the current key. Preserve immutable ID/material pairs. |
| [BlindIndexKeyProvider](https://docs.rs/cryptbox/latest/cryptbox/trait.BlindIndexKeyProvider.html) | Also enumerate the current generation first, then every other readable generation once. Provision index roots independently from encryption roots. |

Preallocate before copying sensitive bytes: `Zeroizing<Vec<u8>>` wipes its current
allocation, not allocations already released by growth. When growth is unavoidable,
copy into a new zeroizing allocation, then wipe the old allocation before release.
Protect failure paths too. See the [ownership contracts](ownership.md).

`EncryptionProfile`, `Field` and `KeyContext` are also extension points;
**`Binding` and `Padding` are sealed**. Choose built-in policies. A codec or
normalizer cannot add row/tenant authentication. Preserve the
[persistent schema](integration.md#persistent-schema)
when adapting this example, then integrate it into [SQLx storage](first-field-sqlite.md).
