# Serialize stored values

Serialize ciphertext and blind indexes with the `serde` feature, then
authenticate the ciphertext and check the index separately.

```sh
cargo run --locked --example stored_values --features derive,serde
```

Expect `Stored bytes round-tripped; authenticated read and index consistency checked.`
The fixed keys are public fixtures.

## What it shows

- `StoredUser` holds `Sealed<UserEmail>` and `BlindIndex<EmailLookup>`, produced
  together by `Sealed::prepare`. Serde stores their bytes as unpadded base64url
  in JSON; the plaintext `String` is never serialized.
- Deserialization checks **structure only**. Damaged ciphertext still
  deserializes, then fails to open. See
  [what each check establishes](../../docs/security.md#what-each-check-establishes).
- `open` authenticates and returns the bare `String`; candidate comparison and
  index consistency are separate checks.

To adapt it, add `serde` with `derive` and your format. The `json` codec feature
is not needed here because the plaintext codec is `Utf8`.
