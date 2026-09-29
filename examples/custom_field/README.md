# Declare a custom seal with explicit plaintext ownership

[The example](main.rs) declares `Handle(Secret<String>)`, a seal that is its own
value, for a 1–64 character ASCII account handle, with a validating codec, normalizer and synchronous
key source.
[Examples](../README.md) · [Documentation](../../docs/README.md).

## Run the example

From the repository root:

```sh
cargo run --locked --example custom_field
```

Expect `Custom field round trip and normalized lookup succeeded.` The program
uses fresh in-memory keys each time and leaves no files behind. It can be rerun
without setup.

Keys are ephemeral; use [durable key/ID pairs](../../docs/integration.md#keyrings-and-key-sources)
before persisting data.

## Why these implementations?

- **`Handle`** is its own value (`type Value = Self`): a handle is stored nowhere
  else, so it needs no separate value type, and callers cannot pass another
  string where a handle belongs. It declares `type Indexes = (HandleEquality,)`,
  so storage helpers that would not write the index, such as the automatic
  `Plain` column, reject it.
- **`HandleCodec: Codec<Handle>`** validates letters, digits and hyphens,
  preserving case. It returns zeroizing encoded bytes and an owned `Handle` on
  decode. It stores exactly the bytes `Utf8` would store for the inner
  `Secret<String>`, but `Utf8` would not enforce the handle policy.
- **`HandleEquality`** validates the same alphabet and lowercases inside a
  zeroizing buffer. Queries are bare `Secret<String>`s; stored values are handles. Writes, probes and candidate comparison share that rule.
  The 128-bit index leaks equality/frequency and is not a uniqueness constraint.
- **`CachedEncryptionKeys`** is a key source that serves a local keyring snapshot
  without I/O on the encryption path. The application owns loading, refresh, synchronization and failure policy.
- **`Secret<String>`** zeroizes the handle's string on drop, and its redacting
  `Debug` lets `Handle` derive `Debug` safely. Preparation still borrows the
  plaintext; dropping `Prepared` does not erase it. `open` returns the decoded
  type—it does not add zeroization to a seal over an ordinary `String`.

### Implementor obligations

| Extension | Contract |
| --- | --- |
| [Codec](https://docs.rs/cryptbox/latest/cryptbox/trait.Codec.html) | Preserve encoding compatibility; return zeroizing encoded bytes and owned decoded values. Sanitize input-bearing errors and protect intermediate allocations. |
| [BlindIndexSpec](https://docs.rs/cryptbox/latest/cryptbox/trait.BlindIndexSpec.html) | Declare the index over exactly one seal. `normalize_value` and `normalize_query` must agree on stable, deterministic equality rules for writes, all readable-generation probes and candidate comparison. Process only the indexed value; protect sensitive buffers. |
| [EncryptionKeySource](https://docs.rs/cryptbox/latest/cryptbox/trait.EncryptionKeySource.html) | Return the keyring that protects the seal and key scope from a local snapshot, without I/O. Return `KeysUnavailable` when the snapshot is not loaded. Keep key IDs generated UUIDs, unique, and never shared across keyrings, and keep previous keys while values sealed with them remain. Choosing the wrong keyring seals silently; see [choosing keyrings](../../docs/choosing-keyrings.md). |
| [BlindIndexKeySource](https://docs.rs/cryptbox/latest/cryptbox/trait.BlindIndexKeySource.html) | The same rules for blind-index keyrings, keyed by index. Provision index roots independently from encryption roots. |

Preallocate before copying sensitive bytes: `Zeroizing<Vec<u8>>` wipes its current
allocation, not allocations already released by growth. When growth is unavoidable,
copy into a new zeroizing allocation, then wipe the old allocation before release.
Protect failure paths too. See the [ownership contracts](../../docs/ownership.md).

[`Seal`](https://docs.rs/cryptbox/latest/cryptbox/trait.Seal.html) ties these
together: `Handle` names its ID, value type (itself), codec and padding. With
the `derive` feature, `#[derive(Seal)]` on `Handle` with
`#[cryptbox(id = …, codec = HandleCodec)]` writes the same impl, since a type
with fields is its own value; `transparent` would instead take a codec for the
inner `Secret<String>`. This example writes its impls by hand.
**`Padding` is a closed set**: choose `Padding::NONE`, `Padding::block(n)` or
`Padding::length(n)`. Every seal binds its ciphertext to its seal ID. A codec or
normalizer cannot add row/tenant authentication. Preserve the
[persistent schema](../../docs/integration.md#persistent-schema)
when adapting this example, then integrate it into [SQLx storage](../sqlite/README.md).

## Use it in your application

Use `HandleCodec`, `HandleEquality`, and `CachedEncryptionKeys` in [main.rs](main.rs)
as starting points for your own value type and key source. Add `zeroize` directly
because the extension interfaces return `Zeroizing<Vec<u8>>`. Keep the codec and
normalizer's validation rules aligned, and replace the demonstration's generated
keys with your application's durable keyrings. The tests beside the source show
round trips, invalid-input handling, unavailable keys, and normalized lookup:

```sh
cargo test --locked --example custom_field
```
