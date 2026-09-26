# Extend a profile with explicit plaintext ownership

[The example](main.rs) combines a codec,
normalizer and synchronous provider for a 1–64 character ASCII account handle.
[Examples](../README.md) · [Documentation](../../docs/README.md).

## Run the example

From the repository root:

```sh
cargo run --locked --example custom_profile
```

Expect `Custom profile round trip and normalized lookup succeeded.` The program
uses fresh in-memory keys each time and leaves no files behind. It can be rerun
without setup.

Keys are ephemeral; use [durable key/ID pairs](../../docs/integration.md#key-providers-and-key-contexts)
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
Protect failure paths too. See the [ownership contracts](../../docs/ownership.md).

`EncryptionProfile`, `Field` and `KeyContext` are also extension points;
**`Padding` is sealed**. Choose a built-in policy. Every profile is bound to its
field ID. A codec or
normalizer cannot add row/tenant authentication. Preserve the
[persistent schema](../../docs/integration.md#persistent-schema)
when adapting this example, then integrate it into [SQLx storage](../sqlite/README.md).

## Use it in your application

Use `HandleCodec`, `HandleEquality`, and `CachedEncryptionKeys` in [main.rs](main.rs)
as starting points for your own value type and key source. Add `zeroize` directly
because the extension interfaces return `Zeroizing<Vec<u8>>`. Keep the codec and
normalizer's validation rules aligned, and replace the demonstration's generated
keys with your application's durable providers. The tests beside the source show
round trips, invalid-input handling, provider failures, and normalized lookup:

```sh
cargo test --locked --example custom_profile
```
