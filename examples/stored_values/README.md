# Serialize and read stored values

Serialize ciphertext and blind indexes with the `serde` feature.
[Examples](../README.md) · [Documentation](../../docs/README.md).

## Run the example

[The example](main.rs) round-trips a JSON
document, authenticates its ciphertext, and separately checks its blind index.
From the repository root:

```sh
cargo run --locked --example stored_values --features derive,serde
```

Expect `Stored bytes round-tripped; authenticated read and index consistency checked.`
The program checks a serialized round trip and demonstrates that damaged
ciphertext can pass structural parsing but fail authentication. It leaves no files
behind and can be rerun without setup. See [main.rs](main.rs) for the assertions.

The fixed keys are public fixtures. For persistence, use [durable key/ID pairs](../../docs/integration.md#keyrings-and-key-sources)
and write ciphertext and indexes atomically.

## Follow the value through storage

- The plaintext is an ordinary `String`, never serialized. Seal it explicitly
  with `Sealed::prepare`, which borrows rather than erases the source.
- `StoredUser` owns `Sealed<UserEmail>` and `BlindIndex<EmailLookup>`.
  Serde stores their complete bytes (integer arrays in JSON).
- Deserialization, like `from_bytes`, checks **structure only**: no key lookup,
  authentication, decryption or index recomputation. Typed wrappers express the
  caller's intended field/index, not proof of origin.
- `open` authenticates, unpads and decodes, returning the bare `String`. Application validation,
  normalized candidate comparison and stored-index consistency are separate checks.

The example's damaged, current-generation ciphertext still deserializes but fails
decryption. See [what each check establishes](../../docs/security.md#what-each-check-establishes)
and [integration design](../../docs/integration.md#storage-boundaries) for storage choices.

## Use it in your application

Enable CryptBox's `serde` feature and add `serde` with `derive` plus your chosen
serialization format. This example uses `serde_json` as the storage format;
CryptBox's `json` codec feature is unnecessary because the plaintext codec is
`Utf8`. Adapt `StoredUser` to hold the sealed values and optional indexes you
need, seal before serializing, and open explicitly after deserializing. Replace
the fixed fixture keys with your application's keyrings.
