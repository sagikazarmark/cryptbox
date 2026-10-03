# A custom seal

[main.rs](main.rs) declares `Handle(Secret<String>)`, a self-valued seal for a
1–64 character ASCII account handle, with a validating codec, a normalizer, and
a refreshed keyring snapshot.

```sh
cargo run --locked --example custom_field
cargo test --locked --example custom_field
```

Expect `Custom field round trip and normalized lookup succeeded.` Keys are
generated per run.

## What it shows

- **`Handle`** is its own value (`type Value = Self`), so callers cannot pass
  another string where a handle belongs. It declares
  `type Indexes = (HandleEquality,)`, so helpers that would not write the index,
  such as the automatic `Plain` column, reject it. With `derive`,
  `#[derive(Seal)]` with `#[cryptbox(id = …, codec = HandleCodec)]` writes the
  same impl; this example writes it by hand.
- **`HandleCodec`** validates letters, digits, and hyphens, returning zeroizing
  bytes. It stores the same bytes `Utf8` would, but enforces the policy.
- **`HandleEquality`** validates the same alphabet and lowercases inside a
  zeroizing buffer. Writes, probes, and candidate comparison share that rule.
- **`CachedEncryptionKeys`** hands out a keyring from a local snapshot without
  I/O, reporting `KeysUnavailable` when not loaded. The application owns
  loading and refresh.
- **`Secret<String>`** zeroizes on drop and redacts `Debug`.

## Implementor obligations

| Extension | Contract |
| --- | --- |
| [Codec](https://docs.rs/cryptbox/latest/cryptbox/trait.Codec.html) | Preserve encoding compatibility; return zeroizing bytes; sanitize errors. |
| [BlindIndexSpec](https://docs.rs/cryptbox/latest/cryptbox/trait.BlindIndexSpec.html) | `normalize_value` and `normalize_query` agree on stable, deterministic rules. |
| Keys you pass in | No I/O on the operation path; keep previous keys while data needs them; see [choosing keyrings](../../docs/guide.md#choosing-keyrings). |

Preallocate before copying sensitive bytes: `Zeroizing<Vec<u8>>` wipes its current
allocation, not ones released by growth. See
[ownership and erasure](../../docs/guide.md#ownership-and-erasure). Codec IDs and
normalization are [persistent schema](../../docs/guide.md#persistent-schema).
