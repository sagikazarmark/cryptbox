# Testing and diagnostics

**How-to · current 0.5.0 API.** These are the existing local-provider and
automatic-adapter patterns, moved from the project landing page. A complete
consumer testing recipe is tracked in
[#56](https://github.com/sagikazarmark/cryptbox/issues/56). [All tasks](README.md).

## Local providers

Applications that use context-less methods or automatic storage adapters should
install `GlobalKeyContext` once in the binary entry point. Do not install it from
test setup or reusable library code: it is process-global and cannot be replaced
or reset. Most tests should keep their keyring local and use the explicit
`encrypt_with`, `decrypt_with`, `prepare_with`, `with_index_with`,
`needs_reencryption_with`, and `reencrypt_with` methods. This keeps tests
independent and safe to run in parallel.

## Automatic adapters

Tests that exercise automatic storage adapters cannot pass a provider directly.
Such a test binary can select an application-defined `KeyContext` whose provider
delegates through an `RwLock`:

```rust
use std::sync::{OnceLock, RwLock};

use cryptbox::{
    BlindIndexKeyProvider, EncryptionKey, EncryptionKeyProvider, KeyContext,
    KeyId, KeyProviderError, LocalEncryptionKeyring,
};

struct TestKeys(RwLock<LocalEncryptionKeyring>);

static TEST_KEYS: OnceLock<TestKeys> = OnceLock::new();

impl TestKeys {
    fn replace(keys: LocalEncryptionKeyring) -> Result<(), KeyProviderError> {
        let context = TEST_KEYS.get_or_init(|| Self(RwLock::new(keys.clone())));
        *context.0.write().map_err(|_| KeyProviderError::Unavailable)? = keys;
        Ok(())
    }
}

impl EncryptionKeyProvider for TestKeys {
    fn current_key(&self) -> Result<EncryptionKey, KeyProviderError> {
        self.0
            .read()
            .map_err(|_| KeyProviderError::Unavailable)?
            .current_key()
    }

    fn key(&self, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        self.0
            .read()
            .map_err(|_| KeyProviderError::Unavailable)?
            .key(id)
    }
}

impl KeyContext for TestKeys {
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, KeyProviderError> {
        TEST_KEYS
            .get()
            .map(|keys| keys as &dyn EncryptionKeyProvider)
            .ok_or(KeyProviderError::NotInitialized)
    }

    fn blind_index_keys() -> Result<&'static dyn BlindIndexKeyProvider, KeyProviderError> {
        Err(KeyProviderError::Unavailable)
    }
}
```

Set `type Keys = TestKeys` on profiles used by those tests and call
`TestKeys::replace` before each case. The context is still shared across the test
process, so tests that replace it must be serialized. Add a second locked
provider when automatic blind-index operations also need test-specific keys.

## Diagnostics

`Field::ID` is the stable machine identifier; `Field::NAME` is a human-readable
display label that may change without migrating encrypted data. Include both
when attaching field context to application-owned errors, logs, traces, or
metrics. This is an illustrative fragment requiring the application's `tracing`
dependency, field declaration, and sanitized error:

```text
tracing::warn!(
    error = %error,
    field_id = %UserEmail::ID,
    field_name = UserEmail::NAME,
    operation = "decrypt",
    "CryptBox operation failed",
);
```

Field names must not contain plaintext, record-specific data, or key material.
They may still reveal application schema, so applications decide where to emit
them. CryptBox does not emit logs or require an observability framework.

Next: follow the [stored-value assurance procedure](stored-values.md#obtain-additional-assurance)
or run the [repository checks](documentation.md).
