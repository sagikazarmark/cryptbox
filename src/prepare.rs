use std::fmt;

use crate::{
    Binding, BindingDomain, BlindIndexKeyProvider, BlindIndexMetadata, BlindIndexRef,
    BlindIndexSpec, Ciphertext, Encrypted, EncryptionKeyProvider, EncryptionProfile, Error,
    KeyContext, ProfileContext, blind::derive_with_domain,
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
pub struct Prepared<'a, T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    source: &'a T,
    ciphertext: Ciphertext<T, Profile>,
    domain: BindingDomain,
    indexes: Vec<PreparedIndex>,
}

impl<T, Profile> fmt::Debug for Prepared<'_, T, Profile>
where
    Profile: EncryptionProfile<T>,
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

impl<T, Profile> Encrypted<T, Profile>
where
    Profile: EncryptionProfile<T>,
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
        context: &ProfileContext<T, Profile>,
        keys: &dyn EncryptionKeyProvider,
    ) -> Result<Prepared<'a, T, Profile>, Error> {
        Ok(Prepared {
            source: self.expose_secret(),
            ciphertext: self.encrypt_with(context, keys)?,
            domain: BindingDomain::from_binding::<Profile::Binding>(context),
            indexes: Vec::new(),
        })
    }
}

impl<T, Profile> Encrypted<T, Profile>
where
    Profile: EncryptionProfile<T>,
    Profile::Binding: Binding<Context = ()>,
{
    /// Prepares this value with the profile's global encryption provider.
    ///
    /// # Errors
    ///
    /// Returns an error when providers are uninitialized or encryption fails.
    pub fn prepare(&self) -> Result<Prepared<'_, T, Profile>, Error> {
        self.prepare_with(&(), Profile::Keys::encryption_keys()?)
    }
}

impl<T, Profile> Prepared<'_, T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    /// Returns the encrypted storage value.
    #[must_use]
    pub const fn ciphertext(&self) -> &Ciphertext<T, Profile> {
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
        Spec: BlindIndexSpec<T>,
    {
        if self.indexes.iter().any(|index| index.id == Spec::ID) {
            return Err(Error::DuplicatePreparedIndex(Spec::ID));
        }

        let index = derive_with_domain::<Spec, T>(self.source, &self.domain, keys)?;
        self.indexes.push(PreparedIndex {
            id: Spec::ID,
            bytes: index.into_bytes(),
        });
        Ok(self)
    }

    /// Adds an index with the profile's global blind-index provider.
    ///
    /// # Errors
    ///
    /// Returns an error when providers are unavailable or index derivation
    /// fails.
    pub fn with_index<Spec>(self) -> Result<Self, Error>
    where
        Spec: BlindIndexSpec<T>,
    {
        self.with_index_with::<Spec>(Profile::Keys::blind_index_keys()?)
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
