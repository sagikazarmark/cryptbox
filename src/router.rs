use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt,
};

use crate::{
    BlindIndexKey, BlindIndexKeyProvider, EncryptionKey, EncryptionKeyProvider, Error, Field,
    FieldId, IndexKeyId, KeyId, KeyProviderError,
};

/// A key provider that routes each field to the provider that protects it.
///
/// A router serves the encryption role when `P` is an [`EncryptionKeyProvider`]
/// and the blind-index role when `P` is a [`BlindIndexKeyProvider`]. Which
/// provider protects a field is deployment configuration: the envelope records
/// the key ID, so a route can move to another provider that resolves the same
/// key IDs.
///
/// Routing is by [`FieldId`], not Rust type: markers that share one ID resolve
/// to the same route. A second route for an already routed ID is rejected.
///
/// Prefer [`Router::strict`], which fails closed for unrouted fields.
/// [`Router::new`] serves unrouted fields from a default provider, and
/// [`Router::falls_back`] reports which fields do so. Route to providers of
/// different types through `Arc<dyn EncryptionKeyProvider>` or
/// `Arc<dyn BlindIndexKeyProvider>`.
///
/// # Examples
///
/// ```
/// use cryptbox::{EncryptionKey, Field, LocalEncryptionKeyring, Router, decrypt, encrypt};
///
/// cryptbox::profile! { Email: String { id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25" } }
/// cryptbox::profile! { Iban: String { id: "7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13" } }
///
/// # fn main() -> Result<(), cryptbox::Error> {
/// let general = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let payments = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let keys = Router::strict()
///     .route::<Email>(general)?
///     .route::<Iban>(payments)?;
///
/// let ciphertext = encrypt::<Iban>(b"DE89370400440532013000", &keys)?;
/// assert_eq!(decrypt::<Iban>(&ciphertext, &keys)?.as_slice(), b"DE89370400440532013000");
/// assert!(!keys.falls_back(Iban::ID));
/// # Ok(())
/// # }
/// ```
pub struct Router<P> {
    routes: BTreeMap<FieldId, P>,
    fallback: Option<P>,
}

impl<P> Router<P> {
    /// Creates a router that rejects every unrouted field.
    ///
    /// Operations on an unrouted field fail with [`Error::UnroutedField`].
    /// This is the recommended router.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            routes: BTreeMap::new(),
            fallback: None,
        }
    }

    /// Creates a router that serves every unrouted field from `default`.
    ///
    /// Use [`Self::falls_back`] to report which fields rely on the fallback.
    #[must_use]
    pub fn new(default: P) -> Self {
        Self {
            routes: BTreeMap::new(),
            fallback: Some(default),
        }
    }

    /// Routes field `F` to `provider`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateRoute`] when `F::ID` is already routed,
    /// including through another marker that shares the ID.
    pub fn route<F: Field>(self, provider: P) -> Result<Self, Error> {
        self.route_id(F::ID, provider)
    }

    /// Routes the field identified by `field` to `provider`.
    ///
    /// Prefer [`Self::route`] when the field's marker type is in scope.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateRoute`] when `field` is already routed.
    pub fn route_id(mut self, field: FieldId, provider: P) -> Result<Self, Error> {
        match self.routes.entry(field) {
            Entry::Occupied(_) => return Err(Error::DuplicateRoute(field)),
            Entry::Vacant(entry) => entry.insert(provider),
        };

        Ok(self)
    }

    /// Reports whether `field` has no route and is served by the fallback.
    ///
    /// Always `false` for a [strict](Self::strict) router.
    #[must_use]
    pub fn falls_back(&self, field: FieldId) -> bool {
        self.fallback.is_some() && !self.routes.contains_key(&field)
    }

    fn provider(&self, field: FieldId) -> Result<&P, KeyProviderError> {
        self.routes
            .get(&field)
            .or(self.fallback.as_ref())
            .ok_or(KeyProviderError::UnroutedField(field))
    }
}

impl<P> fmt::Debug for Router<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Router")
            .field("routes", &self.routes.keys())
            .field("fallback", &self.fallback.is_some())
            .finish_non_exhaustive()
    }
}

impl<P: EncryptionKeyProvider> EncryptionKeyProvider for Router<P> {
    fn current_key(&self, field: FieldId) -> Result<EncryptionKey, KeyProviderError> {
        self.provider(field)?.current_key(field)
    }

    fn key(&self, field: FieldId, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        self.provider(field)?.key(field, id)
    }
}

impl<P: BlindIndexKeyProvider> BlindIndexKeyProvider for Router<P> {
    fn current_key(&self, field: FieldId) -> Result<BlindIndexKey, KeyProviderError> {
        self.provider(field)?.current_key(field)
    }

    fn key(
        &self,
        field: FieldId,
        id: IndexKeyId,
    ) -> Result<Option<BlindIndexKey>, KeyProviderError> {
        self.provider(field)?.key(field, id)
    }

    fn readable_keys(&self, field: FieldId) -> Result<Vec<BlindIndexKey>, KeyProviderError> {
        self.provider(field)?.readable_keys(field)
    }
}
