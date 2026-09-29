use std::{collections::BTreeMap, fmt, sync::Arc};

use base64::Engine as _;
use zeroize::Zeroizing;

use crate::{IndexKeyId, KeyId};

/// A key or keyring could not be created.
///
/// It converts into the same variant of [`Error`](crate::Error), so `?` works in
/// functions that return the crate's error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The operating-system random source failed.
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    /// Encoded root key material is malformed or does not decode to 32 bytes.
    #[error("encoded key material is invalid")]
    InvalidKeyEncoding,
    /// A keyring contains the same encryption key ID more than once.
    #[error("duplicate encryption key ID {0}")]
    DuplicateEncryptionKey(KeyId),
    /// A keyring contains the same blind-index key ID more than once.
    #[error("duplicate blind-index key ID {0}")]
    DuplicateBlindIndexKey(IndexKeyId),
}

#[derive(Clone)]
struct KeyMaterial<Id> {
    id: Id,
    bytes: Zeroizing<[u8; 32]>,
}

/// A zeroizing, reference-counted root encryption key.
///
/// Key bytes must come from a cryptographically secure source. The ID is
/// non-secret, must uniquely and permanently identify these exact bytes, and
/// must never be reused for different material. Generate it as a random UUID,
/// as [`Self::generate`] does, and never share it across keyrings.
/// Cloning shares the reference-counted allocation; material is zeroized when
/// the last handle drops, not when any one keyring or handle drops. Caller-owned
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
    /// Returns [`KeyError::RandomnessUnavailable`] if the operating-system random
    /// source fails.
    pub fn generate() -> Result<Self, KeyError> {
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
    /// Returns [`KeyError::InvalidKeyEncoding`] if `encoded` is malformed or does
    /// not represent exactly 32 bytes.
    pub fn from_hex(id: KeyId, encoded: &str) -> Result<Self, KeyError> {
        Ok(Self(key_material_from_hex(id, encoded)?))
    }

    /// Decodes a root encryption key from standard Base64.
    ///
    /// Decoded bytes are written directly into zeroizing key storage. The
    /// caller remains responsible for zeroizing its encoded input when needed.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::InvalidKeyEncoding`] if `encoded` is malformed or does
    /// not represent exactly 32 bytes.
    pub fn from_base64(id: KeyId, encoded: &str) -> Result<Self, KeyError> {
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
/// material. Generate it as a random UUID, as [`Self::generate`] does, and never
/// share it across keyrings. Cloning shares the allocation; its key bytes are zeroized only after
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
    /// Returns [`KeyError::RandomnessUnavailable`] if the operating-system random
    /// source fails.
    pub fn generate() -> Result<Self, KeyError> {
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
    /// Returns [`KeyError::InvalidKeyEncoding`] if `encoded` is malformed or does
    /// not represent exactly 32 bytes.
    pub fn from_hex(id: IndexKeyId, encoded: &str) -> Result<Self, KeyError> {
        Ok(Self(key_material_from_hex(id, encoded)?))
    }

    /// Decodes a root blind-index key from standard Base64.
    ///
    /// Decoded bytes are written directly into zeroizing key storage. The
    /// caller remains responsible for zeroizing its encoded input when needed.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::InvalidKeyEncoding`] if `encoded` is malformed or does
    /// not represent exactly 32 bytes.
    pub fn from_base64(id: IndexKeyId, encoded: &str) -> Result<Self, KeyError> {
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

fn random_id() -> Result<[u8; 16], KeyError> {
    let mut id = [0_u8; 16];
    getrandom::fill(&mut id).map_err(|_| KeyError::RandomnessUnavailable)?;
    Ok(id)
}

fn generate_key_material<Id: Clone>(id: Id) -> Result<Arc<KeyMaterial<Id>>, KeyError> {
    initialize_key_material(id, |bytes| {
        getrandom::fill(bytes).map_err(|_| KeyError::RandomnessUnavailable)
    })
}

fn key_material_from_hex<Id: Clone>(
    id: Id,
    encoded: &str,
) -> Result<Arc<KeyMaterial<Id>>, KeyError> {
    initialize_key_material(id, |bytes| {
        hex::decode_to_slice(encoded, bytes).map_err(|_| KeyError::InvalidKeyEncoding)
    })
}

fn key_material_from_base64<Id: Clone>(
    id: Id,
    encoded: &str,
) -> Result<Arc<KeyMaterial<Id>>, KeyError> {
    initialize_key_material(id, |bytes| {
        let decoded_len = base64::engine::general_purpose::STANDARD
            .decode_slice(encoded, bytes)
            .map_err(|_| KeyError::InvalidKeyEncoding)?;

        if decoded_len != bytes.len() {
            return Err(KeyError::InvalidKeyEncoding);
        }

        Ok(())
    })
}

fn initialize_key_material<Id: Clone>(
    id: Id,
    initialize: impl FnOnce(&mut [u8; 32]) -> Result<(), KeyError>,
) -> Result<Arc<KeyMaterial<Id>>, KeyError> {
    let mut material = Arc::new(KeyMaterial {
        id,
        bytes: Zeroizing::new([0_u8; 32]),
    });
    // A fresh `Arc` is unique, so `make_mut` writes in place and never clones.
    let bytes = &mut Arc::make_mut(&mut material).bytes;
    initialize(bytes)?;

    Ok(material)
}

/// The current encryption key plus the previous keys that still open stored
/// values.
///
/// Cloning a keyring is cheap: clones share the same keys.
///
/// New values are sealed with the current key. Opening looks up exactly the key
/// ID that the envelope names and fails with [`Error::UnknownEncryptionKey`](crate::Error::UnknownEncryptionKey)
/// when this keyring does not hold it; it never substitutes the current key.
/// Keep previous keys until every value sealed with them has been resealed. See
/// the complete [key-rotation example] and [maintenance sweep example].
///
/// Key IDs must be unique within a keyring. They must be generated UUIDs, as
/// [`EncryptionKey::generate`] creates, and never shared across keyrings: an ID
/// is what makes opening with the wrong keyring fail loudly instead of trying
/// unrelated material.
///
/// A keyring is its own [`EncryptionKeySource`](crate::EncryptionKeySource): it
/// serves every field and scope alike. Which keyring protects which field or
/// scope is application code; see [choosing keyrings] for the mistakes the
/// library cannot detect.
///
#[doc = concat!(
    "[key-rotation example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/key_rotation.rs\n",
    "[maintenance sweep example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/reencryption_sweep.rs\n",
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/choosing-keyrings.md",
)]
#[derive(Clone)]
pub struct EncryptionKeyring(Arc<Ring<KeyId, EncryptionKey>>);

impl EncryptionKeyring {
    /// Builds a keyring from the current key and the previous keys.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::DuplicateEncryptionKey`] for any repeated key ID.
    pub fn new(
        current: EncryptionKey,
        previous: impl IntoIterator<Item = EncryptionKey>,
    ) -> Result<Self, KeyError> {
        Ring::new(
            current,
            previous,
            EncryptionKey::id,
            KeyError::DuplicateEncryptionKey,
        )
        .map(|ring| Self(Arc::new(ring)))
    }

    /// Returns the key that seals new values.
    #[must_use]
    pub fn current(&self) -> &EncryptionKey {
        &self.0.current
    }

    /// Returns the key with ID `id`, current or previous.
    #[must_use]
    pub fn get(&self, id: KeyId) -> Option<&EncryptionKey> {
        self.0.keys.get(&id)
    }
}

impl fmt::Debug for EncryptionKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt("EncryptionKeyring", formatter)
    }
}

/// The current blind-index key plus the previous keys whose stored indexes are
/// still queried.
///
/// Cloning a keyring is cheap: clones share the same keys.
///
/// New stored indexes use the current key. During rotation, query with probes
/// derived from every key in the keyring until old indexes have been rewritten.
/// See the complete [blind-index example] and [maintenance sweep example].
///
/// Key IDs follow the same rules as for [`EncryptionKeyring`]: unique within a
/// keyring, generated UUIDs, and never shared across keyrings. A keyring is its
/// own [`BlindIndexKeySource`](crate::BlindIndexKeySource); see [choosing keyrings].
///
#[doc = concat!(
    "[blind-index example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/blind_indexes.rs\n",
    "[maintenance sweep example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/reencryption_sweep.rs\n",
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/choosing-keyrings.md",
)]
#[derive(Clone)]
pub struct BlindIndexKeyring(Arc<Ring<IndexKeyId, BlindIndexKey>>);

impl BlindIndexKeyring {
    /// Builds a keyring from the current key and the previous keys.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::DuplicateBlindIndexKey`] for any repeated key ID.
    pub fn new(
        current: BlindIndexKey,
        previous: impl IntoIterator<Item = BlindIndexKey>,
    ) -> Result<Self, KeyError> {
        Ring::new(
            current,
            previous,
            BlindIndexKey::id,
            KeyError::DuplicateBlindIndexKey,
        )
        .map(|ring| Self(Arc::new(ring)))
    }

    /// Returns the key that derives new stored indexes.
    #[must_use]
    pub fn current(&self) -> &BlindIndexKey {
        &self.0.current
    }

    /// Returns the key with ID `id`, current or previous.
    #[must_use]
    pub fn get(&self, id: IndexKeyId) -> Option<&BlindIndexKey> {
        self.0.keys.get(&id)
    }

    /// Returns the current key first, followed by every previous key once.
    pub fn readable(&self) -> impl Iterator<Item = &BlindIndexKey> {
        let current = self.current();
        std::iter::once(current).chain(
            self.0
                .keys
                .values()
                .filter(move |key| key.id() != current.id()),
        )
    }
}

impl fmt::Debug for BlindIndexKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt("BlindIndexKeyring", formatter)
    }
}

// The shared contents of a keyring, so that cloning one is cheap.
struct Ring<Id, Key> {
    current: Key,
    keys: BTreeMap<Id, Key>,
}

impl<Id: Ord + Copy, Key: Clone> Ring<Id, Key> {
    fn new(
        current: Key,
        previous: impl IntoIterator<Item = Key>,
        id_of: impl Fn(&Key) -> Id,
        duplicate: impl FnOnce(Id) -> KeyError,
    ) -> Result<Self, KeyError> {
        let mut keys = BTreeMap::new();
        keys.insert(id_of(&current), current.clone());
        for key in previous {
            let id = id_of(&key);
            if keys.insert(id, key).is_some() {
                return Err(duplicate(id));
            }
        }

        Ok(Self { current, keys })
    }
}

impl<Id: fmt::Debug, Key: fmt::Debug> Ring<Id, Key> {
    fn fmt(&self, name: &str, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(name)
            .field("current", &self.current)
            .field("keys", &self.keys)
            .finish()
    }
}

/// An encryption keyring and an optional blind-index keyring, passed together.
///
/// `Keys` is a source for both roles, so it can be passed to any operation
/// (`Sealed::seal`, `Sealed::open`, `probes_with`, …). It is also what
/// [`keys::install`](crate::keys::install) installs for the global conveniences.
///
/// Blind-index operations fail with [`Error::BlindIndexKeysNotConfigured`](crate::Error::BlindIndexKeysNotConfigured) when
/// `blind_indexes` is `None`.
///
/// `Keys` serves every field and scope alike. To keep fields or scopes under
/// separate keys, pass each its own `Keys`, or implement a key source; see
/// [choosing keyrings].
///
#[doc = concat!(
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/choosing-keyrings.md",
)]
///
/// # Examples
///
/// ```
/// use cryptbox::{BlindIndexKey, BlindIndexKeyring, EncryptionKey, EncryptionKeyring, Keys};
///
/// # fn main() -> Result<(), cryptbox::Error> {
/// let keys = Keys::new(EncryptionKeyring::new(EncryptionKey::generate()?, [])?)
///     .with_blind_indexes(BlindIndexKeyring::new(BlindIndexKey::generate()?, [])?);
/// # let _ = keys;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Keys {
    /// The keyring that seals and opens values.
    pub encryption: EncryptionKeyring,
    /// The separately keyed blind-index keyring, if blind indexes are used.
    pub blind_indexes: Option<BlindIndexKeyring>,
}

impl Keys {
    /// Creates keys with an encryption keyring only.
    #[must_use]
    pub const fn new(encryption: EncryptionKeyring) -> Self {
        Self {
            encryption,
            blind_indexes: None,
        }
    }

    /// Adds the separately keyed blind-index keyring.
    #[must_use]
    pub fn with_blind_indexes(mut self, keyring: BlindIndexKeyring) -> Self {
        self.blind_indexes = Some(keyring);
        self
    }
}
