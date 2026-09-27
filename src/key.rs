use std::{collections::BTreeMap, fmt, sync::Arc};

use base64::Engine as _;
use zeroize::Zeroizing;

use crate::{Error, FieldId, IndexKeyId, KeyId, KeyProviderError};

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
/// Cloning shares the reference-counted allocation; material is zeroized when
/// the last handle drops, not when any one provider or handle drops. Caller-owned
/// input copies and operating-system copies are outside this guarantee. See the
/// [ownership reference].
///
#[doc = concat!(
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
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
/// permanently identify these exact bytes and must never be reused for different
/// material. Cloning shares the allocation; its key bytes are zeroized only after
/// the last handle drops. Caller-owned input and OS copies are separate. See the
/// [ownership reference].
///
#[doc = concat!(
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
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
///
/// # Implementor obligations
///
/// This interface is extensible and intended for local, synchronous access.
/// Fetch and refresh remote secrets outside these calls; encryption and automatic
/// storage adapters cannot await an asynchronous KMS. Publish a coherent local
/// snapshot using application-owned synchronization and fail closed if unavailable.
///
/// Select one current generation for writes and resolve all readable generations
/// (current, retained, or staged) by exact ID. Never substitute the current key
/// for an unknown ID or try unrelated keys. Keep the ID permanently paired with
/// the same material, including across refreshes/restarts. Generate encryption
/// roots independently from blind-index roots. Retain historical access while
/// ciphertext or recovery artifacts need it; promotion alone does not rewrite data.
/// Returned key clones share ownership and can outlive the provider snapshot.
///
/// Every call names the [`FieldId`] it acts for. A provider that serves every
/// field, such as [`LocalEncryptionKeyring`], may ignore it. A provider that
/// serves only some fields must return [`KeyProviderError::UnroutedField`] for
/// the others rather than substitute keys. Use [`Router`](crate::Router) to
/// assign fields to providers.
///
/// See the [custom-field example] and [ownership reference].
///
#[doc = concat!(
    "[custom-field example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_field/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
pub trait EncryptionKeyProvider: Send + Sync {
    /// Returns the sole key used for new encryption of `field`.
    ///
    /// # Errors
    ///
    /// Returns an error when local key material is unavailable, or when this
    /// provider does not serve `field`.
    fn current_key(&self, field: FieldId) -> Result<EncryptionKey, KeyProviderError>;

    /// Resolves exactly one key generation for decrypting `field`.
    ///
    /// Return `Ok(Some(key))` only if `key.id() == id`; return `Ok(None)` when a
    /// healthy provider does not know that ID. An unavailable provider must return
    /// an error, not pretend that the ID is unknown.
    ///
    /// # Errors
    ///
    /// Returns an error when local key material is unavailable, or when this
    /// provider does not serve `field`.
    fn key(&self, field: FieldId, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError>;
}

/// Resolves current and historical root blind-index keys synchronously.
///
/// # Implementor obligations
///
/// Like [`EncryptionKeyProvider`], this extensible interface provides local,
/// synchronous access; fetch/refresh remote secrets outside storage operations.
/// Maintain a coherent snapshot of current and readable generations. Pair every
/// ID permanently with the same material across refreshes/restarts; never reuse
/// it for different bytes. Generate roots independently from encryption roots.
/// Resolve only the requested ID, never fall back to the current key.
///
/// Readable generations include the current generation, retained historical keys,
/// and keys staged before promotion. Enumerate the current key first, then every
/// other readable generation once, so queries cover still-stored indexes during
/// rotation. Do not silently omit generations when the provider is unavailable.
/// Retention must account for recovery artifacts as well as live data. Returned
/// key clones share ownership and may outlive the provider snapshot.
///
/// Every call names the [`FieldId`] it acts for. The field argument follows the
/// same rules as for [`EncryptionKeyProvider`]: ignore it when serving every
/// field, and return [`KeyProviderError::UnroutedField`] for fields not served.
///
/// See the [custom-field example] and [ownership reference].
///
#[doc = concat!(
    "[custom-field example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_field/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
pub trait BlindIndexKeyProvider: Send + Sync {
    /// Returns the sole key used for new stored indexes of `field`.
    ///
    /// # Errors
    ///
    /// Returns an error when local key material is unavailable, or when this
    /// provider does not serve `field`.
    fn current_key(&self, field: FieldId) -> Result<BlindIndexKey, KeyProviderError>;

    /// Resolves exactly one index-key generation for `field`.
    ///
    /// Return `Ok(Some(key))` only if `key.id() == id`, `Ok(None)` for an unknown
    /// ID in a healthy provider, and an error when local resolution is unavailable.
    ///
    /// # Errors
    ///
    /// Returns an error when local key material is unavailable, or when this
    /// provider does not serve `field`.
    fn key(
        &self,
        field: FieldId,
        id: IndexKeyId,
    ) -> Result<Option<BlindIndexKey>, KeyProviderError>;

    /// Returns the current key for `field` first, followed by every other
    /// readable key once.
    ///
    /// # Errors
    ///
    /// Returns an error when local key material is unavailable, or when this
    /// provider does not serve `field`.
    fn readable_keys(&self, field: FieldId) -> Result<Vec<BlindIndexKey>, KeyProviderError>;
}

impl<P: EncryptionKeyProvider + ?Sized> EncryptionKeyProvider for Arc<P> {
    fn current_key(&self, field: FieldId) -> Result<EncryptionKey, KeyProviderError> {
        (**self).current_key(field)
    }

    fn key(&self, field: FieldId, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        (**self).key(field, id)
    }
}

impl<P: BlindIndexKeyProvider + ?Sized> BlindIndexKeyProvider for Arc<P> {
    fn current_key(&self, field: FieldId) -> Result<BlindIndexKey, KeyProviderError> {
        (**self).current_key(field)
    }

    fn key(
        &self,
        field: FieldId,
        id: IndexKeyId,
    ) -> Result<Option<BlindIndexKey>, KeyProviderError> {
        (**self).key(field, id)
    }

    fn readable_keys(&self, field: FieldId) -> Result<Vec<BlindIndexKey>, KeyProviderError> {
        (**self).readable_keys(field)
    }
}

/// An in-memory current-plus-historical encryption keyring.
///
/// New encryption uses `current`; decryption can resolve every retained key.
/// The keyring serves every field alike.
/// Keep historical keys readable until all ciphertext using them has been
/// rewritten. See the complete [key-rotation example] and [maintenance sweep
/// example].
///
#[doc = concat!(
    "[key-rotation example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/key_rotation.rs\n",
    "[maintenance sweep example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/reencryption_sweep.rs",
)]
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
    fn current_key(&self, _: FieldId) -> Result<EncryptionKey, KeyProviderError> {
        Ok(self.current.clone())
    }

    fn key(&self, _: FieldId, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        Ok(self.keys.get(&id).cloned())
    }
}

/// An in-memory current-plus-historical blind-index keyring.
///
/// New stored indexes use `current`. During rotation, query with probes derived
/// from every retained key until old indexes have been rewritten. The keyring
/// serves every field alike. See the
/// complete [blind-index example] and [maintenance sweep example].
///
#[doc = concat!(
    "[blind-index example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/blind_indexes.rs\n",
    "[maintenance sweep example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/reencryption_sweep.rs",
)]
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
    fn current_key(&self, _: FieldId) -> Result<BlindIndexKey, KeyProviderError> {
        Ok(self.current.clone())
    }

    fn key(&self, _: FieldId, id: IndexKeyId) -> Result<Option<BlindIndexKey>, KeyProviderError> {
        Ok(self.keys.get(&id).cloned())
    }

    fn readable_keys(&self, _: FieldId) -> Result<Vec<BlindIndexKey>, KeyProviderError> {
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

/// The encryption and blind-index providers that operations draw keys from.
///
/// `Keys` is itself a provider for both roles, so it can be passed to any
/// explicit form (`encrypt_with`, `prepare_with`, `probes_with`, …). It is also
/// what [`keys::install`](crate::keys::install) installs for the implicit forms.
/// Each role is usually a [`Router`](crate::Router) that assigns fields to
/// providers.
///
/// Blind-index operations fail with [`Error::BlindIndexKeysNotConfigured`] when no
/// blind-index provider was added.
///
/// # Examples
///
/// ```
/// use cryptbox::{
///     BlindIndexKey, EncryptionKey, Keys, LocalBlindIndexKeyring, LocalEncryptionKeyring,
/// };
///
/// # fn main() -> Result<(), cryptbox::Error> {
/// let keys = Keys::new(LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?)
///     .with_blind_indexes(LocalBlindIndexKeyring::new(BlindIndexKey::generate()?, [])?);
/// # let _ = keys;
/// # Ok(())
/// # }
/// ```
pub struct Keys {
    encryption: Box<dyn EncryptionKeyProvider>,
    blind_indexes: Option<Box<dyn BlindIndexKeyProvider>>,
}

impl Keys {
    /// Creates a key set with an encryption provider only.
    pub fn new(encryption: impl EncryptionKeyProvider + 'static) -> Self {
        Self {
            encryption: Box::new(encryption),
            blind_indexes: None,
        }
    }

    /// Adds the separately keyed blind-index provider.
    #[must_use]
    pub fn with_blind_indexes(mut self, provider: impl BlindIndexKeyProvider + 'static) -> Self {
        self.blind_indexes = Some(Box::new(provider));
        self
    }

    fn blind_indexes(&self) -> Result<&dyn BlindIndexKeyProvider, KeyProviderError> {
        self.blind_indexes
            .as_deref()
            .ok_or(KeyProviderError::BlindIndexKeysNotConfigured)
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Keys")
            .field("blind_indexes", &self.blind_indexes.is_some())
            .finish_non_exhaustive()
    }
}

impl EncryptionKeyProvider for Keys {
    fn current_key(&self, field: FieldId) -> Result<EncryptionKey, KeyProviderError> {
        self.encryption.current_key(field)
    }

    fn key(&self, field: FieldId, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        self.encryption.key(field, id)
    }
}

impl BlindIndexKeyProvider for Keys {
    fn current_key(&self, field: FieldId) -> Result<BlindIndexKey, KeyProviderError> {
        self.blind_indexes()?.current_key(field)
    }

    fn key(
        &self,
        field: FieldId,
        id: IndexKeyId,
    ) -> Result<Option<BlindIndexKey>, KeyProviderError> {
        self.blind_indexes()?.key(field, id)
    }

    fn readable_keys(&self, field: FieldId) -> Result<Vec<BlindIndexKey>, KeyProviderError> {
        self.blind_indexes()?.readable_keys(field)
    }
}

/// The key source of an automatic `SQLx` column, `Encrypted<F, K>`.
///
/// `SQLx` encoding and decoding receive no context, so the column names its
/// keys in its type. The default, [`GlobalKeys`], reads the keys installed with
/// [`keys::install`](crate::keys::install). Implement this trait over your own
/// static to use another keyring (a tenant, a second deployment, a test
/// fixture) without installing the global.
///
/// # Examples
///
/// ```
/// use std::sync::LazyLock;
///
/// use cryptbox::{
///     Encrypted, EncryptionKey, EncryptionKeyProvider, Error, Field, FieldId, KeyContext,
///     LocalEncryptionKeyring, Padding, Utf8,
/// };
///
/// struct UserEmail;
///
/// impl Field for UserEmail {
///     const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
/// }
///
/// struct ArchiveKeys;
///
/// impl KeyContext for ArchiveKeys {
///     fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, Error> {
///         // Load durable key material here; a generated key is for demonstration only.
///         static KEYS: LazyLock<Result<LocalEncryptionKeyring, Error>> =
///             LazyLock::new(|| LocalEncryptionKeyring::new(EncryptionKey::generate()?, []));
///
///         match &*KEYS {
///             Ok(keys) => Ok(keys),
///             Err(error) => Err(error.clone()),
///         }
///     }
/// }
///
/// // A column that encrypts and decrypts with `ArchiveKeys`, never the installed keys.
/// let email = Encrypted::<UserEmail, ArchiveKeys>::new("user@example.com");
/// # let _ = email;
/// ```
pub trait KeyContext: 'static {
    /// Returns the encryption provider for this key source.
    ///
    /// # Errors
    ///
    /// Returns an error when the keys are unavailable, such as
    /// [`Error::KeysNotInstalled`] for [`GlobalKeys`] before installation.
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, Error>;
}

/// The key source that reads the keys installed with
/// [`keys::install`](crate::keys::install).
///
/// This is the default key source of [`Encrypted`](crate::Encrypted).
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalKeys;

impl KeyContext for GlobalKeys {
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, Error> {
        Ok(crate::keys::installed()?)
    }
}
