use std::fmt;

use crate::{
    BlindIndexKeys, BlindIndexRef, BlindIndexSpec, Error, Seal, Sealed,
    blind::{derive_value, index_domain},
    keys,
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
    F: Seal,
{
    source: &'a F::Value,
    sealed: Sealed<F>,
    indexes: Vec<PreparedIndex>,
}

impl<F> fmt::Debug for Prepared<'_, F>
where
    F: Seal,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Prepared")
            .field("source", &"[REDACTED]")
            .field("sealed", &self.sealed)
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl<'a, F> Prepared<'a, F>
where
    F: Seal,
{
    pub(crate) const fn new(source: &'a F::Value, sealed: Sealed<F>) -> Self {
        Self {
            source,
            sealed,
            indexes: Vec::new(),
        }
    }

    /// Returns the sealed storage value.
    #[must_use]
    pub const fn sealed(&self) -> &Sealed<F> {
        &self.sealed
    }

    /// Consumes the preparation and returns the sealed storage value.
    ///
    /// Copy its indexes out with [`Self::index`] first.
    #[must_use]
    pub fn into_sealed(self) -> Sealed<F> {
        self.sealed
    }

    /// Adds an index derived from the same source value as the sealed value.
    ///
    /// The index must be declared over this seal. Attaching another seal's
    /// index is a type error:
    ///
    /// ```compile_fail,E0271
    /// use cryptbox::{
    ///     BlindIndexError, BlindIndexSpec, Seal, SealId, IndexId,
    ///     BlindIndexKeyring, EncryptionKeyring, Padding, Sealed, Utf8,
    /// };
    /// use zeroize::Zeroizing;
    ///
    /// struct UserEmail;
    ///
    /// impl Seal for UserEmail {
    ///     const ID: SealId = SealId::from_bytes([1; 16]);
    ///     const PADDING: Padding = Padding::NONE;
    ///     type Value = String;
    ///     type Codec = Utf8;
    ///     type Record = ();
    ///     type Indexes = ();
    /// }
    ///
    /// struct InviteEmail;
    ///
    /// impl Seal for InviteEmail {
    ///     const ID: SealId = SealId::from_bytes([2; 16]);
    ///     const PADDING: Padding = Padding::NONE;
    ///     type Value = String;
    ///     type Codec = Utf8;
    ///     type Record = ();
    ///     type Indexes = ();
    /// }
    ///
    /// struct InviteEmailLookup;
    ///
    /// impl BlindIndexSpec for InviteEmailLookup {
    ///     type Seal = InviteEmail;
    ///     const ID: IndexId = IndexId::from_bytes([3; 16]);
    ///     const BITS: u16 = 32;
    ///     const NORMALIZER: &'static str = "exact/1";
    ///     type Query = str;
    ///
    ///     fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    ///         Ok(Zeroizing::new(query.as_bytes().to_vec()))
    ///     }
    ///
    ///     fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    ///         Self::normalize_query(value)
    ///     }
    /// }
    ///
    /// fn prepare(
    ///     keys: &EncryptionKeyring,
    ///     index_keys: &BlindIndexKeyring,
    /// ) -> Result<(), cryptbox::Error> {
    ///     let email = "mark@example.com".to_owned();
    ///     Sealed::<UserEmail>::prepare(&email, (), keys)?
    ///         .with_index_with::<InviteEmailLookup>(index_keys)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate index IDs, normalization failure,
    /// invalid precision, or unavailable keys.
    pub fn with_index_with<Spec>(
        mut self,
        keys: &(impl BlindIndexKeys + ?Sized),
    ) -> Result<Self, Error>
    where
        Spec: BlindIndexSpec<Seal = F>,
    {
        if self.indexes.iter().any(|index| index.id == Spec::ID) {
            return Err(Error::DuplicatePreparedIndex(Spec::ID));
        }

        let index = derive_value::<Spec>(self.source, &index_domain::<Spec>(), keys)?;
        self.indexes.push(PreparedIndex {
            id: Spec::ID,
            bytes: index.into_bytes(),
        });

        Ok(self)
    }

    /// Adds an index with the [installed keys](keys::installed).
    ///
    /// This is exactly `self.with_index_with::<Spec>(keys::installed()?)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeysNotInstalled`] before installation, or an error for
    /// duplicate index IDs, unavailable keys, or failed index derivation.
    pub fn with_index<Spec>(self) -> Result<Self, Error>
    where
        Spec: BlindIndexSpec<Seal = F>,
    {
        self.with_index_with::<Spec>(keys::installed()?)
    }

    /// Returns a prepared logical index by its typed specification.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BlindIndexNotPrepared`] when the index was not added.
    pub fn index<Spec>(&self) -> Result<BlindIndexRef<'_, Spec>, Error>
    where
        Spec: BlindIndexSpec<Seal = F>,
    {
        self.indexes
            .iter()
            .find(|index| index.id == Spec::ID)
            .map(|index| BlindIndexRef::from_validated_bytes(&index.bytes))
            .ok_or(Error::BlindIndexNotPrepared(Spec::ID))
    }
}
