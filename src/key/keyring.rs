use std::{collections::BTreeMap, fmt, sync::Arc};

use super::KeyError;
use super::material::{BlindIndexKey, EncryptionKey, IndexKeyId, KeyId};

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
/// serves every seal and scope alike. Which keyring protects which seal or
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
