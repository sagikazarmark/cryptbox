use std::{collections::BTreeMap, fmt, sync::Arc, sync::OnceLock};

use base64::Engine as _;
use zeroize::Zeroizing;

use crate::{Error, IndexKeyId, KeyId, KeyProviderError};

#[derive(Clone)]
struct KeyMaterial<Id> {
    id: Id,
    bytes: Zeroizing<[u8; 32]>,
}

/// A zeroizing, reference-counted root encryption key.
///
/// Key bytes must come from a cryptographically secure source. The ID is
/// non-secret, must uniquely and permanently identify these exact bytes, and
/// must never be reused for different material.
#[derive(Clone)]
pub struct EncryptionKey(Arc<KeyMaterial<KeyId>>);

impl EncryptionKey {
    /// Generates a root encryption key and independent random generation ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] if the operating-system random
    /// source fails.
    pub fn generate() -> Result<Self, Error> {
        let id = KeyId::from_bytes(random_id()?);
        Ok(Self(generate_key_material(id)?))
    }

    /// Decodes a root encryption key from exactly 64 hexadecimal characters.
    ///
    /// Decoded bytes are written directly into zeroizing key storage. The
    /// caller remains responsible for zeroizing its encoded input when needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyEncoding`] if `encoded` is malformed or does
    /// not represent exactly 32 bytes.
    pub fn from_hex(id: KeyId, encoded: &str) -> Result<Self, Error> {
        Ok(Self(key_material_from_hex(id, encoded)?))
    }

    /// Decodes a root encryption key from standard Base64.
    ///
    /// Decoded bytes are written directly into zeroizing key storage. The
    /// caller remains responsible for zeroizing its encoded input when needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyEncoding`] if `encoded` is malformed or does
    /// not represent exactly 32 bytes.
    pub fn from_base64(id: KeyId, encoded: &str) -> Result<Self, Error> {
        Ok(Self(key_material_from_base64(id, encoded)?))
    }

    /// Creates a root encryption key from 32 bytes of key material.
    ///
    /// Generate this material independently from every blind-index root key.
    #[must_use]
    pub fn new(id: KeyId, bytes: [u8; 32]) -> Self {
        Self(Arc::new(KeyMaterial {
            id,
            bytes: Zeroizing::new(bytes),
        }))
    }

    /// Returns the non-secret key generation identifier.
    #[must_use]
    pub fn id(&self) -> KeyId {
        self.0.id
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0.bytes
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptionKey")
            .field("id", &self.id())
            .field("material", &"[REDACTED]")
            .finish()
    }
}

/// A zeroizing, reference-counted root blind-index key.
///
/// Key bytes must come from a cryptographically secure source and must be
/// generated independently from encryption keys. The ID must uniquely and
/// permanently identify these exact bytes.
#[derive(Clone)]
pub struct BlindIndexKey(Arc<KeyMaterial<IndexKeyId>>);

impl BlindIndexKey {
    /// Generates a root blind-index key and independent random generation ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] if the operating-system random
    /// source fails.
    pub fn generate() -> Result<Self, Error> {
        let id = IndexKeyId::from_bytes(random_id()?);
        Ok(Self(generate_key_material(id)?))
    }

    /// Decodes a root blind-index key from exactly 64 hexadecimal characters.
    ///
    /// Decoded bytes are written directly into zeroizing key storage. The
    /// caller remains responsible for zeroizing its encoded input when needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyEncoding`] if `encoded` is malformed or does
    /// not represent exactly 32 bytes.
    pub fn from_hex(id: IndexKeyId, encoded: &str) -> Result<Self, Error> {
        Ok(Self(key_material_from_hex(id, encoded)?))
    }

    /// Decodes a root blind-index key from standard Base64.
    ///
    /// Decoded bytes are written directly into zeroizing key storage. The
    /// caller remains responsible for zeroizing its encoded input when needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyEncoding`] if `encoded` is malformed or does
    /// not represent exactly 32 bytes.
    pub fn from_base64(id: IndexKeyId, encoded: &str) -> Result<Self, Error> {
        Ok(Self(key_material_from_base64(id, encoded)?))
    }

    /// Creates a root blind-index key from 32 bytes of key material.
    #[must_use]
    pub fn new(id: IndexKeyId, bytes: [u8; 32]) -> Self {
        Self(Arc::new(KeyMaterial {
            id,
            bytes: Zeroizing::new(bytes),
        }))
    }

    /// Returns the non-secret key generation identifier.
    #[must_use]
    pub fn id(&self) -> IndexKeyId {
        self.0.id
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0.bytes
    }
}

impl fmt::Debug for BlindIndexKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlindIndexKey")
            .field("id", &self.id())
            .field("material", &"[REDACTED]")
            .finish()
    }
}

fn random_id() -> Result<[u8; 16], Error> {
    let mut id = [0_u8; 16];
    getrandom::fill(&mut id).map_err(|_| Error::RandomnessUnavailable)?;
    Ok(id)
}

fn generate_key_material<Id>(id: Id) -> Result<Arc<KeyMaterial<Id>>, Error> {
    initialize_key_material(id, |bytes| {
        getrandom::fill(bytes).map_err(|_| Error::RandomnessUnavailable)
    })
}

fn key_material_from_hex<Id>(id: Id, encoded: &str) -> Result<Arc<KeyMaterial<Id>>, Error> {
    initialize_key_material(id, |bytes| {
        hex::decode_to_slice(encoded, bytes).map_err(|_| Error::InvalidKeyEncoding)
    })
}

fn key_material_from_base64<Id>(id: Id, encoded: &str) -> Result<Arc<KeyMaterial<Id>>, Error> {
    initialize_key_material(id, |bytes| {
        let decoded_len = base64::engine::general_purpose::STANDARD
            .decode_slice(encoded, bytes)
            .map_err(|_| Error::InvalidKeyEncoding)?;

        if decoded_len != bytes.len() {
            return Err(Error::InvalidKeyEncoding);
        }

        Ok(())
    })
}

fn initialize_key_material<Id>(
    id: Id,
    initialize: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
) -> Result<Arc<KeyMaterial<Id>>, Error> {
    let mut material = Arc::new(KeyMaterial {
        id,
        bytes: Zeroizing::new([0_u8; 32]),
    });
    let bytes = &mut Arc::get_mut(&mut material).ok_or(Error::Internal)?.bytes;
    initialize(bytes)?;

    Ok(material)
}

/// Resolves current and historical root encryption keys synchronously.
pub trait EncryptionKeyProvider: Send + Sync {
    /// Returns the sole key used for new encryption.
    ///
    /// # Errors
    ///
    /// Returns an error when local key material is unavailable.
    fn current_key(&self) -> Result<EncryptionKey, KeyProviderError>;

    /// Resolves exactly one key generation for decryption.
    ///
    /// # Errors
    ///
    /// Returns an error when local key material is unavailable.
    fn key(&self, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError>;
}

/// Resolves current and historical root blind-index keys synchronously.
pub trait BlindIndexKeyProvider: Send + Sync {
    /// Returns the sole key used for new stored indexes.
    ///
    /// # Errors
    ///
    /// Returns an error when local key material is unavailable.
    fn current_key(&self) -> Result<BlindIndexKey, KeyProviderError>;

    /// Resolves exactly one index-key generation.
    ///
    /// # Errors
    ///
    /// Returns an error when local key material is unavailable.
    fn key(&self, id: IndexKeyId) -> Result<Option<BlindIndexKey>, KeyProviderError>;

    /// Returns the current key first, followed by readable historical keys.
    ///
    /// # Errors
    ///
    /// Returns an error when local key material is unavailable.
    fn readable_keys(&self) -> Result<Vec<BlindIndexKey>, KeyProviderError>;
}

/// An in-memory current-plus-historical encryption keyring.
///
/// New encryption uses `current`; decryption can resolve every retained key.
/// Keep historical keys readable until all ciphertext using them has been
/// rewritten. See the complete [key-rotation example] and [maintenance sweep
/// example].
///
/// [key-rotation example]: https://docs.rs/crate/cryptbox/latest/source/examples/key_rotation.rs
/// [maintenance sweep example]: https://docs.rs/crate/cryptbox/latest/source/examples/reencryption_sweep.rs
#[derive(Clone, Debug)]
pub struct LocalEncryptionKeyring {
    current: EncryptionKey,
    keys: BTreeMap<KeyId, EncryptionKey>,
}

impl LocalEncryptionKeyring {
    /// Builds a keyring and rejects duplicate generation identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateEncryptionKey`] for any repeated key ID.
    pub fn new(
        current: EncryptionKey,
        previous: impl IntoIterator<Item = EncryptionKey>,
    ) -> Result<Self, Error> {
        let mut keys = BTreeMap::new();
        keys.insert(current.id(), current.clone());
        for key in previous {
            if keys.insert(key.id(), key.clone()).is_some() {
                return Err(Error::DuplicateEncryptionKey(key.id()));
            }
        }

        Ok(Self { current, keys })
    }
}

impl EncryptionKeyProvider for LocalEncryptionKeyring {
    fn current_key(&self) -> Result<EncryptionKey, KeyProviderError> {
        Ok(self.current.clone())
    }

    fn key(&self, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        Ok(self.keys.get(&id).cloned())
    }
}

/// An in-memory current-plus-historical blind-index keyring.
///
/// New stored indexes use `current`. During rotation, query with probes derived
/// from every retained key until old indexes have been rewritten. See the
/// complete [blind-index example] and [maintenance sweep example].
///
/// [blind-index example]: https://docs.rs/crate/cryptbox/latest/source/examples/blind_indexes.rs
/// [maintenance sweep example]: https://docs.rs/crate/cryptbox/latest/source/examples/reencryption_sweep.rs
#[derive(Clone, Debug)]
pub struct LocalBlindIndexKeyring {
    current: BlindIndexKey,
    keys: BTreeMap<IndexKeyId, BlindIndexKey>,
}

impl LocalBlindIndexKeyring {
    /// Builds a keyring and rejects duplicate generation identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateBlindIndexKey`] for any repeated key ID.
    pub fn new(
        current: BlindIndexKey,
        previous: impl IntoIterator<Item = BlindIndexKey>,
    ) -> Result<Self, Error> {
        let mut keys = BTreeMap::new();
        keys.insert(current.id(), current.clone());
        for key in previous {
            if keys.insert(key.id(), key.clone()).is_some() {
                return Err(Error::DuplicateBlindIndexKey(key.id()));
            }
        }

        Ok(Self { current, keys })
    }
}

impl BlindIndexKeyProvider for LocalBlindIndexKeyring {
    fn current_key(&self) -> Result<BlindIndexKey, KeyProviderError> {
        Ok(self.current.clone())
    }

    fn key(&self, id: IndexKeyId) -> Result<Option<BlindIndexKey>, KeyProviderError> {
        Ok(self.keys.get(&id).cloned())
    }

    fn readable_keys(&self) -> Result<Vec<BlindIndexKey>, KeyProviderError> {
        let mut keys = Vec::with_capacity(self.keys.len());
        keys.push(self.current.clone());
        keys.extend(
            self.keys
                .values()
                .filter(|key| key.id() != self.current.id())
                .cloned(),
        );

        Ok(keys)
    }
}

/// Supplies statically reachable providers to context-less adapters.
pub trait KeyContext: Sized + 'static {
    /// Returns the installed encryption provider.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider is unavailable or uninitialized.
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, KeyProviderError>;

    /// Returns the installed blind-index provider.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider is unavailable or uninitialized.
    fn blind_index_keys() -> Result<&'static dyn BlindIndexKeyProvider, KeyProviderError>;
}

/// The provider set accepted by [`GlobalKeyContext::install`].
pub struct GlobalProviders {
    encryption: Box<dyn EncryptionKeyProvider>,
    blind_indexes: Option<Box<dyn BlindIndexKeyProvider>>,
}

impl GlobalProviders {
    /// Creates a provider set with encryption keys only.
    pub fn new(provider: impl EncryptionKeyProvider + 'static) -> Self {
        Self {
            encryption: Box::new(provider),
            blind_indexes: None,
        }
    }

    /// Adds the separately keyed blind-index provider.
    #[must_use]
    pub fn with_blind_indexes(mut self, provider: impl BlindIndexKeyProvider + 'static) -> Self {
        self.blind_indexes = Some(Box::new(provider));
        self
    }
}

static GLOBAL_PROVIDERS: OnceLock<GlobalProviders> = OnceLock::new();

/// Process-global initialized-once providers for context-less adapters.
///
/// Install providers once during process startup before using
/// [`crate::Encrypted::encrypt`], [`crate::Encrypted::prepare`], or an automatic
/// storage adapter. Prefer explicit provider APIs where process-global state is
/// undesirable.
///
/// The installed providers cannot be replaced or reset. Applications should
/// therefore call [`Self::install`] only from their binary entry point, not from
/// reusable library code or test setup. Tests should normally inject providers
/// through methods such as [`crate::Encrypted::encrypt_with`] and
/// [`crate::Ciphertext::decrypt_with`]. Tests of automatic storage adapters can
/// instead define their own [`KeyContext`] backed by synchronized, swappable
/// providers.
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalKeyContext;

impl GlobalKeyContext {
    /// Installs runtime-created providers for the remainder of the process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyProviderAlreadyInitialized`] after the first
    /// successful installation.
    pub fn install(providers: GlobalProviders) -> Result<(), Error> {
        GLOBAL_PROVIDERS
            .set(providers)
            .map_err(|_| Error::KeyProviderAlreadyInitialized)
    }
}

impl KeyContext for GlobalKeyContext {
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, KeyProviderError> {
        GLOBAL_PROVIDERS
            .get()
            .map(|providers| providers.encryption.as_ref())
            .ok_or(KeyProviderError::NotInitialized)
    }

    fn blind_index_keys() -> Result<&'static dyn BlindIndexKeyProvider, KeyProviderError> {
        GLOBAL_PROVIDERS
            .get()
            .ok_or(KeyProviderError::NotInitialized)?
            .blind_indexes
            .as_deref()
            .ok_or(KeyProviderError::Unavailable)
    }
}
