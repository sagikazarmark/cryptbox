# Extend a profile with explicit plaintext ownership

**How-to · published CryptBox 0.5.0 API, development implementor guidance.** After
[your first field](first-field.md), implement an application codec, equality rule,
and synchronous encryption-key provider. [All tasks](README.md).

This recipe stores an application-defined **ASCII account handle**: 1–64 letters,
digits or hyphens, case-preserving in ciphertext and case-insensitive for lookup.
These are example business rules, not general username, Unicode, or email rules.
The 128-bit index is an example precision choice: it leaks equality/frequency,
can produce false candidates, and must not serve as a uniqueness constraint.

## 1. Create the consumer

Use current stable Rust and Cargo on a native OS-entropy target as in the
[first tutorial](first-field.md#1-create-a-consumer-project). No database, async
runtime, optional CryptBox feature, or library checkout is required.

```sh
cargo new custom-profile-consumer
cd custom-profile-consumer
```

Replace `Cargo.toml` with:

<!-- BEGIN SHARED: custom-profile-manifest -->

```toml
[package]
name = "custom-profile-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
cryptbox = "=0.5.0"
zeroize = { version = "1.8.1", default-features = false, features = ["alloc"] }
```

<!-- END SHARED: custom-profile-manifest -->

`zeroize` is a **direct dependency** because the public codec and normalizer
interfaces return `Zeroizing<Vec<u8>>`; a transitive dependency cannot be imported
by the consumer implicitly.

## 2. Supply the extensions

> **Ephemeral demonstration:** all root keys and generation IDs below are newly
> generated per run. For persistent data, load stable key/ID pairs from the
> [durable secret source](searchable-sqlx.md#2-provision-durable-key-generations-once).
> Never generate replacement material silently on a load failure.

Replace `src/main.rs` with this complete program:

<!-- BEGIN SHARED: custom-profile -->

```rust
use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Codec, CodecError,
    CodecErrorKind, Encrypted, EncryptionKey, EncryptionKeyProvider, KeyId, KeyProviderError,
    LocalBlindIndexKeyring, LocalEncryptionKeyring, Secret,
};
use zeroize::Zeroizing;

struct HandleCodec;

// Application policy: 1–64 ASCII letters, digits or hyphens; preserve case in storage.
fn valid_handle(bytes: &[u8]) -> bool {
    (1..=64).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

impl Codec<Secret<String>> for HandleCodec {
    fn encode(value: &Secret<String>) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        let bytes = value.expose_secret().as_bytes();
        if !valid_handle(bytes) {
            return Err(CodecError::new(CodecErrorKind::Encoding));
        }
        // Allocate once before copying sensitive bytes; no plaintext-bearing growth.
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    fn decode(bytes: &[u8]) -> Result<Secret<String>, CodecError> {
        if !valid_handle(bytes) {
            return Err(CodecError::new(CodecErrorKind::Decoding));
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| CodecError::new(CodecErrorKind::InvalidUtf8))?;
        Ok(Secret::new(text.to_owned()))
    }
}

cryptbox::profile! {
    Handle: Secret<String> {
        id: "dcaa3c69-1767-49a1-8476-36555eaf54bf",
        name: "account-handle",
        codec: HandleCodec,
        binding: field_bound,
    }
}

struct HandleEquality;

impl BlindIndexMetadata for HandleEquality {
    const ID: cryptbox::IndexId = cryptbox::index_id!("6c0e20d5-cb30-4b84-8dd1-995f872b417c");
    const BITS: usize = 128;
}

impl BlindIndexSpec<Secret<String>> for HandleEquality {
    fn normalize(input: &Secret<String>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        let bytes = input.expose_secret().as_bytes();
        if !valid_handle(bytes) {
            return Err(BlindIndexError::new());
        }
        let mut normalized = Zeroizing::new(bytes.to_vec());
        normalized.make_ascii_lowercase();
        Ok(normalized)
    }
}

// An application-owned snapshot. None means loading/refresh failed, not "unknown ID".
struct CachedEncryptionKeys {
    snapshot: Option<LocalEncryptionKeyring>,
}

impl EncryptionKeyProvider for CachedEncryptionKeys {
    fn current_key(&self) -> Result<EncryptionKey, KeyProviderError> {
        self.snapshot
            .as_ref()
            .ok_or(KeyProviderError::Unavailable)?
            .current_key()
    }

    fn key(&self, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        self.snapshot
            .as_ref()
            .ok_or(KeyProviderError::Unavailable)?
            .key(id)
    }
}

fn main() -> Result<(), cryptbox::Error> {
    // Ephemeral demonstration only. Load stable key/ID pairs for durable data.
    let keys = CachedEncryptionKeys {
        snapshot: Some(LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?),
    };
    let old_index_key = BlindIndexKey::generate()?; // Independent of encryption keys.
    let index_writer = LocalBlindIndexKeyring::new(old_index_key.clone(), [])?;
    let value = Encrypted::<_, Handle>::new(Secret::new("Alice-7".to_owned()));
    let prepared = value
        .prepare_with(&(), &keys)?
        .with_index_with::<HandleEquality>(&index_writer)?;
    let ciphertext = prepared.ciphertext().clone();
    let stored_index = prepared.index::<HandleEquality>()?.as_bytes().to_vec();
    // These two representations belong in one atomic storage write.
    drop(prepared); // Releases the borrow, not the source plaintext.

    // After index-key promotion, query every readable generation, including old data.
    let index_reader = LocalBlindIndexKeyring::new(BlindIndexKey::generate()?, [old_index_key])?;
    let query = Secret::new("ALICE-7".to_owned());
    let probes = cryptbox::blind_index_probes::<HandleEquality, _, cryptbox::FieldBound<Handle>>(
        &query,
        &(),
        &index_reader,
    )?;
    assert_eq!(probes.len(), 2);
    assert!(probes.iter().any(|probe| probe.as_bytes() == stored_index));
    // An index hit is only a candidate: authenticate and compare normalized plaintext.
    let decrypted = ciphertext.decrypt_with(&(), &keys)?.into_secret();
    assert!(cryptbox::verify_blind_index_candidate::<HandleEquality, _>(
        &query, &decrypted
    )?);
    assert_eq!(decrypted.expose_secret(), "Alice-7");
    assert_eq!(value.expose_secret().expose_secret(), "Alice-7");
    println!("Custom profile round trip and normalized lookup succeeded.");
    Ok(())
}
```

<!-- END SHARED: custom-profile -->

Run `cargo run`. Expect `Custom profile round trip and normalized lookup succeeded.`
and exit status 0. Assertions verify preserved original spelling, retained source
plaintext, lookup of an older index generation, and normalized candidate equality.
No plaintext or keys are printed. The in-memory representations demonstrate the
storage boundary; they are not a durable database or a fleet rotation procedure.

### Why these implementations?

- **`HandleCodec`** implements `Codec<Secret<String>>`, not `Codec<String>`.
  It validates borrowed bytes before allocation, copies into a single encoding
  allocation, and returns decoded application values already wrapped in `Secret`.
  The borrowed UTF-8 view allocates nothing. `Utf8` alone cannot encode this wrapper.
- **`HandleEquality`** implements `BlindIndexMetadata` and `BlindIndexSpec` for the
  same source type. It validates the same allowed alphabet and lowercases in place
  inside one zeroizing allocation. Storage, probes, and candidate comparison use
  this identical rule. The indexed handle is sensitive and is intentionally processed;
  unrelated secrets and key material do not belong in normalization.
- **`CachedEncryptionKeys`** implements `EncryptionKeyProvider` over a local
  snapshot. It adds an explicit unavailable state while delegating duplicate-ID
  validation and exact-ID resolution to `LocalEncryptionKeyring`. There is no I/O
  or async call on the encryption path. A real application loads a validated
  snapshot before publishing it, and owns refresh, synchronization, and failure policy.
- **Index keys** use the built-in `LocalBlindIndexKeyring`. A custom
  `BlindIndexKeyProvider` must also enumerate the current key first and every other
  readable generation once. The program queries both generations after promotion;
  an index hit still needs authenticated decryption and normalized comparison.

The profile keeps field binding and uses unit context with explicit providers;
it needs no global installation. Applications can implement `Codec`,
`BlindIndexSpec`/`BlindIndexMetadata`, `EncryptionProfile`, `Field`, `KeyContext`,
and the key-provider traits. **`Binding` and `Padding` are sealed**: choose the
built-in policies. Row/tenant binding remains future work; a codec or normalizer
cannot add that authentication guarantee. See [binding versus key context](concepts.md#binding-context-is-not-key-context).

## 3. Account for ownership and failure

Read the canonical [plaintext and key ownership explanation](concepts.md#plaintext-and-key-ownership)
before adapting the recipe. In particular:

- `Encrypted` retains the source while encryption and preparation borrow it.
  `Prepared` owns ciphertext/indexes but borrows that source. Dropping preparation
  does not erase the source; dropping this recipe's `Secret<String>` does invoke
  zeroization of that owned string.
- Decryption returns a new owned application value. Here `into_secret()` removes
  `Encrypted` and yields the already-decoded `Secret<String>`. For a `String`
  profile instead, the usable move is `Secret::new(decrypted.into_secret())`;
  the method name alone does not install zeroization.
- Cloning a plaintext wrapper creates another application value with its own
  lifetime. Cloning a key shares reference-counted key material, which remains
  alive until the last handle drops. Input strings, configuration copies and OS
  copies do not disappear when a provider snapshot drops.

### Implementor obligations

| Extension | Required contract |
| --- | --- |
| Codec | Keep encoded bytes/decode compatibility stable. Return zeroizing encoded bytes; decoded values must own their data. Protect intermediate allocations and discard input-bearing third-party errors in favor of sanitized categories. |
| Normalizer | Use deterministic, stable equality rules identically for writes, probes and candidate verification. Protect returned/intermediate sensitive buffers. Process only the indexed value, never unrelated secrets, key material or process-dependent state. |
| Buffer growth | A `Zeroizing<Vec<u8>>` wipes its current allocation at drop, not a superseded allocation already released by growth. Preallocate before copying sensitive bytes, or copy into a new zeroizing allocation and wipe the old one before releasing it. Apply this on failure paths too. |
| Providers | Serve local synchronous snapshots; fetch/refresh remote material outside storage calls. Resolve exactly the requested generation. Return `Ok(None)` for an unknown ID in a healthy snapshot, and `Err(KeyProviderError::Unavailable)` when resolution cannot be performed. Never substitute the current key. |
| Generations | Keep one current generation for writes and all required readable generations, including staged/retained material. Include each readable index generation once in probes, current first. Preserve key/ID pairs across restarts; never reuse an ID for different material. Generate encryption/index roots independently. |
| Persistent schema | Preserve field/index IDs, codec compatibility, binding, padding mode, normalization and precision. Plan migration and compatible lookups before changing stored projections or accepted encoding. |

The example bounds allocation before handling sensitive data and emits only
`CodecError`/`BlindIndexError` categories, with no input-bearing logging. If you
add a third-party serializer, inspect its allocation and error behavior rather
than assuming the final zeroizing return buffer protects all its intermediate data.

The development API pages keep these contracts beside `Codec`, `BlindIndexSpec`,
`EncryptionKeyProvider`, and `BlindIndexKeyProvider`. Published
[0.5.0 signatures](https://docs.rs/cryptbox/0.5.0/cryptbox/) support this program;
their frozen prose predates this expanded guidance.

## Verification and next steps

The [canonical consumer source](../examples/custom_profile.rs) adds public-boundary
tests for round trips, normalized equality/non-equality, sanitized errors, current
and exact historical key resolution, unknown versus unavailable results, and moving
a decrypted string into `Secret`. Existing [blind-index tests](../tests/blind_indexes.rs)
cover independent index domains and probes. None of these tests proves compiler
or OS memory erasure.

Maintainers run `node scripts/check-consumers.mjs checkout custom-profile` and
`node scripts/check-consumers.mjs published custom-profile`; the complete runner
includes both in GitHub Actions and Dagger. Shared snippets are regenerated and
checked through the [documentation workflow](documentation.md#shared-consumer-examples-and-diagrams).

Next: integrate the policies into the [durable SQLx application](searchable-sqlx.md),
or use [local-provider application tests](testing.md).
