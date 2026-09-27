use std::fmt;

use crate::{
    BlindIndexKeyProvider, BlindIndexMetadata, BlindIndexRef, BlindIndexSpec, Ciphertext,
    Encrypted, EncryptionKeyProvider, Error, Field, GlobalKeyContext, KeyContext,
    derive_blind_index,
};

struct PreparedIndex {
    id: crate::IndexId,
    bytes: Vec<u8>,
}

/// Ciphertext and searchable projections derived from one source value.
///
/// A prepared value borrows its plaintext source so each index is derived from
/// the same value that was encrypted. Keep it short-lived, copy its ciphertext
/// and index bytes into the storage operation, then let it drop.
/// Dropping preparation releases its borrow, not the source plaintext. The
/// application owns persistence and atomicity. See the [ownership reference].
///
#[doc = concat!(
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
pub struct Prepared<'a, F>
where
    F: Field,
{
    source: &'a F::Value,
    ciphertext: Ciphertext<F>,
    indexes: Vec<PreparedIndex>,
}

impl<F> fmt::Debug for Prepared<'_, F>
where
    F: Field,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Prepared")
            .field("source", &"[REDACTED]")
            .field("ciphertext", &self.ciphertext)
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl<F> Encrypted<F>
where
    F: Field,
{
    /// Encrypts this value into a prepared storage representation.
    ///
    /// Blind indexes can then be added with [`Prepared::with_index_with`].
    ///
    /// # Errors
    ///
    /// Returns any codec, provider, randomness, or encryption error.
    pub fn prepare_with<'a>(
        &'a self,
        keys: &dyn EncryptionKeyProvider,
    ) -> Result<Prepared<'a, F>, Error> {
        Ok(Prepared {
            source: self.expose_secret(),
            ciphertext: self.encrypt_with(keys)?,
            indexes: Vec::new(),
        })
    }

    /// Prepares this value with the process-wide [`GlobalKeyContext`] encryption provider.
    ///
    /// # Errors
    ///
    /// Returns an error when providers are uninitialized or encryption fails.
    pub fn prepare(&self) -> Result<Prepared<'_, F>, Error> {
        self.prepare_with(GlobalKeyContext::encryption_keys()?)
    }
}

impl<F> Prepared<'_, F>
where
    F: Field,
{
    /// Returns the encrypted storage value.
    #[must_use]
    pub const fn ciphertext(&self) -> &Ciphertext<F> {
        &self.ciphertext
    }

    /// Adds an index derived from the same source value as the ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate index IDs, normalization failure,
    /// invalid precision, or an unavailable provider.
    pub fn with_index_with<Spec>(mut self, keys: &dyn BlindIndexKeyProvider) -> Result<Self, Error>
    where
        Spec: BlindIndexSpec<F::Value>,
    {
        if self.indexes.iter().any(|index| index.id == Spec::ID) {
            return Err(Error::DuplicatePreparedIndex(Spec::ID));
        }

        let index = derive_blind_index::<Spec, F::Value, F>(self.source, keys)?;
        self.indexes.push(PreparedIndex {
            id: Spec::ID,
            bytes: index.into_bytes(),
        });

        Ok(self)
    }

    /// Adds an index with the process-wide [`GlobalKeyContext`] blind-index provider.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate index IDs, unavailable providers, or
    /// failed index derivation.
    pub fn with_index<Spec>(self) -> Result<Self, Error>
    where
        Spec: BlindIndexSpec<F::Value>,
    {
        self.with_index_with::<Spec>(GlobalKeyContext::blind_index_keys()?)
    }

    /// Returns a prepared logical index by its typed specification.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BlindIndexNotPrepared`] when the index was not added.
    pub fn index<Spec>(&self) -> Result<BlindIndexRef<'_, Spec>, Error>
    where
        Spec: BlindIndexMetadata,
    {
        self.indexes
            .iter()
            .find(|index| index.id == Spec::ID)
            .map(|index| BlindIndexRef::from_validated_bytes(&index.bytes))
            .ok_or(Error::BlindIndexNotPrepared(Spec::ID))
    }
}
