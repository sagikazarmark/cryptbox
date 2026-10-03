use std::{fmt, sync::Arc};

use base64::Engine as _;
use zeroize::Zeroizing;

use super::KeyError;
use crate::id::identifier;

identifier!(KeyId, "An opaque encryption-key generation identifier.");
identifier!(
    IndexKeyId,
    "An opaque blind-index-key generation identifier."
);

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
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/guide.md#ownership-and-erasure",
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
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/guide.md#ownership-and-erasure",
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

/// Creates a [`KeyId`](crate::KeyId) from a UUID literal.
#[macro_export]
macro_rules! key_id {
    ($value:literal) => {{
        const ID: $crate::KeyId =
            $crate::KeyId::from_bytes($crate::__private::uuid::uuid!($value).into_bytes());
        ID
    }};
}

/// Creates an [`IndexKeyId`](crate::IndexKeyId) from a UUID literal.
#[macro_export]
macro_rules! index_key_id {
    ($value:literal) => {{
        const ID: $crate::IndexKeyId =
            $crate::IndexKeyId::from_bytes($crate::__private::uuid::uuid!($value).into_bytes());
        ID
    }};
}
