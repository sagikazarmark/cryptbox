use std::{fmt, marker::PhantomData};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    Binding, BindingDomain, BlindIndexError, BlindIndexKey, BlindIndexKeySource, BlindIndexKeyring,
    Error, FieldOnly, IndexId, IndexKeyId, Seal, keys,
};

mod format;
mod recipe;

pub use format::{BlindIndexInfo, inspect_blind_index};
use format::{stored_key_id, valid_bits};
use recipe::derive_index;

/// The query-time arguments of `Spec`: its seal binding's `keys` and `index` part values.
pub(crate) type IndexArgs<Spec> =
    <<<Spec as BlindIndexSpec>::Seal as Seal>::Binding as Binding>::IndexArgs;

/// A logical blind index over one seal.
///
/// A specification binds an index to exactly one [`Seal`]: the seal's ID
/// domain-separates derivation, stored indexes are derived from the seal's
/// value with [`Self::normalize_value`], and lookups normalize a [`Self::Query`]
/// with [`Self::normalize_query`]. Both normalizers must produce identical bytes
/// for inputs that should match. `normalize_value` receives the whole value, so
/// an index can be computed from part of it, such as an email domain, or combine
/// several of its parts.
///
/// Indexes are scoped by the seal's [`Binding`]. Each operation takes the
/// binding's [`IndexArgs`](Binding::IndexArgs), the values of its
/// [`keys`](crate::PartRole::Keys) and [`index`](crate::PartRole::Index)
/// parts, and derives in that scope; a [`FieldOnly`] seal passes `&()`. Equal
/// values under other `keys` or `index` values derive unrelated indexes, and
/// the key source receives the scope's [`KeyScope`](crate::KeyScope).
/// Bound-only parts and the record never scope an index, since a query cannot
/// know them. See the [index binding].
///
/// `BITS` must be between 1 and 256. The logical [`IndexId`] is part of key
/// derivation but is not stored in the index bytes. Changing the ID,
/// normalization, seal, or precision creates a new logical index and
/// requires a migration.
///
/// # Examples
///
/// ```
/// use cryptbox::{BlindIndexError, BlindIndexSpec, Seal, SealId, FieldOnly, IndexId, Padding, Utf8};
/// use zeroize::Zeroizing;
///
/// struct UserEmail;
///
/// impl Seal for UserEmail {
///     const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = ();
/// }
///
/// struct EmailLookup;
///
/// impl BlindIndexSpec for EmailLookup {
///     type Seal = UserEmail;
///     const ID: IndexId = cryptbox::index_id!("2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53");
///     const BITS: u16 = 32;
///     const NORMALIZER: &'static str = "email/1";
///     type Query = str;
///
///     fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
///         Ok(Zeroizing::new(query.trim().to_ascii_lowercase().into_bytes()))
///     }
///
///     fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
///         Self::normalize_query(value)
///     }
/// }
/// ```
///
/// With the `derive` feature, `#[derive(BlindIndexSpec)]` writes exactly this
/// impl from `#[cryptbox(id = "…", seal = UserEmail, bits = 32, query = str,
/// normalize = normalize_email, normalizer = "email/1")]`, given a free
/// `normalize_email` function with `normalize_query`'s body.
///
/// Invalid precision is rejected when the specification is used:
///
/// ```compile_fail,E0080
/// # use cryptbox::{BlindIndex, BlindIndexError, BlindIndexSpec, Seal, SealId, FieldOnly, IndexId, Padding, Raw};
/// # use zeroize::Zeroizing;
/// # struct Bytes;
/// # impl Seal for Bytes {
/// #     const ID: SealId = SealId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = false;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
/// #     type Binding = FieldOnly;
/// #     type Indexes = ();
/// # }
/// struct ZeroBits;
///
/// impl BlindIndexSpec for ZeroBits {
///     type Seal = Bytes;
///     const ID: IndexId = IndexId::from_bytes([0; 16]);
///     const BITS: u16 = 0;
///     const NORMALIZER: &'static str = "exact/1";
///     type Query = [u8];
/// #   fn normalize_query(q: &[u8]) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> { Ok(Zeroizing::new(q.to_vec())) }
/// #   fn normalize_value(v: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> { Ok(Zeroizing::new(v.clone())) }
/// }
///
/// let _ = BlindIndex::<ZeroBits>::from_bytes(Vec::new());
/// ```
///
/// ```compile_fail,E0080
/// # use cryptbox::{BlindIndex, BlindIndexError, BlindIndexSpec, Seal, SealId, FieldOnly, IndexId, Padding, Raw};
/// # use zeroize::Zeroizing;
/// # struct Bytes;
/// # impl Seal for Bytes {
/// #     const ID: SealId = SealId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = false;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
/// #     type Binding = FieldOnly;
/// #     type Indexes = ();
/// # }
/// struct TooManyBits;
///
/// impl BlindIndexSpec for TooManyBits {
///     type Seal = Bytes;
///     const ID: IndexId = IndexId::from_bytes([0; 16]);
///     const BITS: u16 = 300;
///     const NORMALIZER: &'static str = "exact/1";
///     type Query = [u8];
/// #   fn normalize_query(q: &[u8]) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> { Ok(Zeroizing::new(q.to_vec())) }
/// #   fn normalize_value(v: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> { Ok(Zeroizing::new(v.clone())) }
/// }
///
/// let _ = BlindIndex::<TooManyBits>::from_bytes(Vec::new());
/// ```
///
/// # Implementor obligations
///
/// Normalization is persistent schema and must be identical for writes,
/// queries, and candidate verification. Return only the bytes relevant to
/// equality. The indexed value may itself be sensitive; do not incorporate
/// unrelated secrets, key material, randomness, or unstable formatting state.
/// Changes to normalization, index ID, seal, or precision require a migration
/// and compatible queries while old projections remain stored.
///
/// This interface is extensible. Return a zeroizing buffer and protect all
/// intermediate normalized/plaintext allocations on success and error paths.
/// `Zeroizing<Vec<u8>>` alone does not wipe superseded allocations during growth:
/// preallocate before copying sensitive bytes, or copy into a new zeroizing
/// allocation and wipe the old one before releasing it. Normalize deterministically
/// with stable application-defined equality rules, independent of locale or process
/// configuration. Return only sanitized [`BlindIndexError`] values; do not log or
/// retain the input in third-party errors. Candidate verification must use the
/// same normalization after authenticated decryption, not accept an index hit alone.
///
/// Implement only the associated items and the two normalizers; do not override
/// the provided derivation, probe, and verification methods.
///
/// See the [custom-field example] and [ownership reference].
/// Padding is a closed set of policies; a custom normalizer does not add row binding.
///
#[doc = concat!(
    "[custom-field example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_field/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md\n",
    "[index binding]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/wire-format.md#index-binding",
)]
pub trait BlindIndexSpec: Sized + 'static {
    /// The seal whose values this index projects.
    type Seal: Seal;

    /// The stable logical index identifier.
    const ID: IndexId;

    /// The number of most-significant HMAC bits retained for candidate lookup.
    const BITS: u16;

    /// A stable name for the normalization rules, such as `"email/1"`.
    ///
    /// Normalization is persistent schema, but neither stored indexes nor code
    /// review reliably reveal a change to it. The
    /// [schema manifest](crate::schema::Manifest) reports this name; change it
    /// whenever [`Self::normalize_query`] or [`Self::normalize_value`] would
    /// produce different bytes, so a manifest snapshot flags the migration.
    const NORMALIZER: &'static str;

    /// The lookup input, such as `str` for an index over `String` values.
    type Query: ?Sized;

    /// Normalizes a lookup input into bytes owned by a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when this query cannot be normalized.
    fn normalize_query(query: &Self::Query) -> Result<Zeroizing<Vec<u8>>, BlindIndexError>;

    /// Normalizes a sealed value into bytes owned by a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when this value cannot be normalized.
    fn normalize_value(
        value: &<Self::Seal as Seal>::Value,
    ) -> Result<Zeroizing<Vec<u8>>, BlindIndexError>;

    /// Derives the current stored index for a value of [`Self::Seal`] in the
    /// scope of `args`.
    ///
    /// Use this to recompute a stored index from decrypted plaintext. New
    /// writes usually derive indexes through [`crate::Prepared::with_index_with`],
    /// which takes the scope from the binding the value was sealed with.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBinding`] when `args` does not match the
    /// binding's `keys` and `index` parts, or an error for normalization
    /// failure or unavailable keys.
    fn derive_with(
        value: &<Self::Seal as Seal>::Value,
        args: &IndexArgs<Self>,
        keys: &(impl BlindIndexKeySource + ?Sized),
    ) -> Result<BlindIndex<Self>, Error> {
        derive_value::<Self>(value, &index_domain::<Self>(args)?, keys)
    }

    /// Derives one candidate probe in the scope of `args` for every currently
    /// readable index generation.
    ///
    /// Results are candidates only; decrypt candidate rows and verify their
    /// normalized plaintext with [`Self::verify_candidate`].
    /// See the complete [blind-index example].
    ///
    #[doc = concat!(
        "[blind-index example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/blind_indexes.rs",
    )]
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBinding`] when `args` does not match the
    /// binding's `keys` and `index` parts, or an error for normalization
    /// failure or unavailable keys.
    fn probes_with(
        query: &Self::Query,
        args: &IndexArgs<Self>,
        keys: &(impl BlindIndexKeySource + ?Sized),
    ) -> Result<Vec<BlindIndex<Self>>, Error> {
        derive_probes::<Self>(query, args, keys)
    }

    /// Derives probes with the [installed keys](keys::installed).
    ///
    /// This is exactly `Self::probes_with(query, &(), keys::installed()?)`.
    /// The installed keys serve only [`FieldOnly`] seals.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeysNotInstalled`] before installation, or an error when
    /// probe derivation fails.
    fn probes(query: &Self::Query) -> Result<Vec<BlindIndex<Self>>, Error>
    where
        Self::Seal: Seal<Binding = FieldOnly>,
    {
        Self::probes_with(query, &(), keys::installed()?)
    }

    /// Compares a normalized query with normalized candidate plaintext after lookup.
    ///
    /// Decrypt and authenticate the candidate ciphertext before calling this.
    /// This receives no stored index or keys: it rejects false plaintext
    /// matches but does not authenticate index metadata or establish
    /// index/ciphertext consistency; use [`Self::is_consistent_with`] for that.
    ///
    /// Equal-length normalized values are compared in constant time. A normalized
    /// length mismatch returns early, so callers must treat normalized lengths as
    /// observable.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when either input cannot be normalized.
    fn verify_candidate(
        query: &Self::Query,
        candidate: &<Self::Seal as Seal>::Value,
    ) -> Result<bool, Error> {
        compare_normalized::<Self>(query, candidate)
    }

    /// Checks a stored index against the value it should have been derived
    /// from in the scope of `args`.
    ///
    /// Decrypt and authenticate the associated ciphertext before calling this.
    /// This resolves exactly the index-key generation that `stored` names,
    /// re-derives from `value` with [`Self::normalize_value`], and compares the
    /// complete stored representation in constant time. It works alike for
    /// exact, computed, and composite indexes, whether `stored` uses the
    /// current or a historical generation. A match is consistency at the
    /// configured precision, not proof of provenance or freshness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownBlindIndexKey`] when the keyring does not hold
    /// the generation named by `stored`, so an unverifiable index is reported
    /// distinctly from an inconsistent one, and [`Error::InvalidBinding`] when
    /// `args` does not match the binding's `keys` and `index` parts. Also
    /// returns an error for normalization failure or unavailable keys.
    fn is_consistent_with(
        value: &<Self::Seal as Seal>::Value,
        stored: &BlindIndex<Self>,
        args: &IndexArgs<Self>,
        keys: &(impl BlindIndexKeySource + ?Sized),
    ) -> Result<bool, Error> {
        check_consistency::<Self>(value, stored, args, keys)
    }
}

/// The blind indexes declared over seal `F`: `()`, or a tuple of up to eight
/// [`BlindIndexSpec`]s over `F`.
///
/// This is [`Seal::Indexes`]. Listing an index declared over another seal is
/// a type error.
///
/// ```compile_fail,E0271
/// use cryptbox::{
///     BlindIndexError, BlindIndexSpec, Seal, SealId, FieldOnly, IndexId, Padding, Utf8,
/// };
/// use zeroize::Zeroizing;
///
/// struct UserEmail;
///
/// impl Seal for UserEmail {
///     const ID: SealId = SealId::from_bytes([1; 16]);
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = (InviteEmailLookup,);
/// }
///
/// struct InviteEmail;
///
/// impl Seal for InviteEmail {
///     const ID: SealId = SealId::from_bytes([2; 16]);
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = (InviteEmailLookup,);
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
/// ```
pub trait IndexList<F: ?Sized>: 'static {
    /// The declared index IDs, in declaration order.
    const IDS: &'static [IndexId];
}

impl<F: ?Sized> IndexList<F> for () {
    const IDS: &'static [IndexId] = &[];
}

// `F` names the seal, so the spec parameters skip it.
macro_rules! index_list {
    ($($spec:ident),+) => {
        impl<F: Seal, $($spec: BlindIndexSpec<Seal = F>),+> IndexList<F> for ($($spec,)+) {
            const IDS: &'static [IndexId] = &[$($spec::ID),+];
        }
    };
}

index_list!(A);
index_list!(A, B);
index_list!(A, B, C);
index_list!(A, B, C, D);
index_list!(A, B, C, D, E);
index_list!(A, B, C, D, E, G);
index_list!(A, B, C, D, E, G, H);
index_list!(A, B, C, D, E, G, H, I);

trait ValidBlindIndexBits {
    const ASSERT_VALID_BITS: ();
}

impl<Spec: BlindIndexSpec> ValidBlindIndexBits for Spec {
    const ASSERT_VALID_BITS: () = assert!(
        valid_bits(Spec::BITS as usize),
        "BlindIndexSpec::BITS must be between 1 and 256",
    );
}

fn assert_valid_bits<Spec: BlindIndexSpec>() {
    let () = <Spec as ValidBlindIndexBits>::ASSERT_VALID_BITS;
}

/// A stored, typed blind-index value used only for candidate lookup.
///
/// Blind indexes leak equality and frequency information. Avoid indexing
/// low-cardinality or highly skewed sensitive values, never use a truncated
/// index as a uniqueness constraint, and always verify candidate plaintext.
/// `Spec` is phantom and implies the seal. Its [`BlindIndexSpec::ID`] is not stored in the
/// representation. With the `serde` feature, this type serializes only its
/// complete stored binary representation.
/// Deserialization uses [`Self::from_bytes`] for structural and precision checks,
/// without keys. Neither operation authenticates stored metadata or establishes
/// consistency with a ciphertext. Candidate plaintext comparison is a separate
/// operation; see [`BlindIndexSpec::verify_candidate`].
pub struct BlindIndex<Spec> {
    bytes: Vec<u8>,
    marker: PhantomData<fn() -> Spec>,
}

impl<Spec: BlindIndexSpec> BlindIndex<Spec> {
    /// Validates and wraps a stored blind-index representation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBlindIndex`] for malformed, noncanonical, or
    /// incorrectly sized values. `Spec::BITS` is checked at compile time. This
    /// does not authenticate the representation or prove that it was derived
    /// with `Spec::ID`, the expected seal, or the expected input.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        assert_valid_bits::<Spec>();
        let bytes = bytes.into();
        let info = inspect_blind_index(&bytes)?;

        if info.bits() != usize::from(Spec::BITS) {
            return Err(Error::InvalidBlindIndex);
        }

        Ok(Self::from_validated_bytes(bytes))
    }
}

impl<Spec> BlindIndex<Spec> {
    pub(crate) fn from_validated_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            marker: PhantomData,
        }
    }

    /// Returns the complete stored representation, including key generation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the unauthenticated index-key generation named by validated bytes.
    pub(crate) fn index_key_id(&self) -> IndexKeyId {
        stored_key_id(&self.bytes)
    }

    /// Consumes the wrapper and returns its stored representation.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl<Spec: BlindIndexSpec> TryFrom<Vec<u8>> for BlindIndex<Spec> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl<Spec> AsRef<[u8]> for BlindIndex<Spec> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<Spec> Clone for BlindIndex<Spec> {
    fn clone(&self) -> Self {
        Self::from_validated_bytes(self.bytes.clone())
    }
}

impl<Spec> PartialEq for BlindIndex<Spec> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<Spec> Eq for BlindIndex<Spec> {}

impl<Spec> fmt::Debug for BlindIndex<Spec> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlindIndex([REDACTED])")
    }
}

/// A borrowed typed blind-index value, typically obtained from [`crate::Prepared`].
#[derive(Clone, Copy)]
pub struct BlindIndexRef<'a, Spec> {
    bytes: &'a [u8],
    marker: PhantomData<fn() -> Spec>,
}

impl<'a, Spec> BlindIndexRef<'a, Spec> {
    pub(crate) fn from_validated_bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            marker: PhantomData,
        }
    }

    /// Returns the complete stored representation, including key generation.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Copies the borrowed representation into an owned [`BlindIndex`].
    #[must_use]
    pub fn to_blind_index(&self) -> BlindIndex<Spec> {
        BlindIndex::from_validated_bytes(self.bytes.to_vec())
    }
}

impl<Spec> AsRef<[u8]> for BlindIndexRef<'_, Spec> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<Spec> fmt::Debug for BlindIndexRef<'_, Spec> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlindIndexRef([REDACTED])")
    }
}

/// Derives the current stored index of `Spec` in `domain`, an index domain of
/// `Spec`'s seal.
pub(crate) fn derive_value<Spec: BlindIndexSpec>(
    value: &<Spec::Seal as Seal>::Value,
    domain: &BindingDomain,
    keys: &(impl BlindIndexKeySource + ?Sized),
) -> Result<BlindIndex<Spec>, Error> {
    let key = keyring::<Spec>(keys, domain)?.current().clone();

    derive_value_with_key::<Spec>(value, domain, &key)
}

/// Returns the ID of the key that derives new stored indexes of `Spec` in
/// `domain`, an index domain of `Spec`'s seal.
#[cfg(feature = "migrate")]
pub(crate) fn current_key_id<Spec: BlindIndexSpec>(
    domain: &BindingDomain,
    keys: &dyn BlindIndexKeySource,
) -> Result<IndexKeyId, Error> {
    Ok(keyring::<Spec>(keys, domain)?.current().id())
}

fn derive_value_with_key<Spec: BlindIndexSpec>(
    value: &<Spec::Seal as Seal>::Value,
    domain: &BindingDomain,
    key: &BlindIndexKey,
) -> Result<BlindIndex<Spec>, Error> {
    let normalized = Spec::normalize_value(value)?;

    derive_normalized::<Spec>(&normalized, domain, key)
}

fn derive_probes<Spec: BlindIndexSpec>(
    query: &Spec::Query,
    args: &IndexArgs<Spec>,
    keys: &(impl BlindIndexKeySource + ?Sized),
) -> Result<Vec<BlindIndex<Spec>>, Error> {
    probes_in::<Spec>(query, &index_domain::<Spec>(args)?, keys)
}

/// Derives one probe of `Spec` in `domain`, an index domain of `Spec`'s seal,
/// for every readable index generation.
pub(crate) fn probes_in<Spec: BlindIndexSpec>(
    query: &Spec::Query,
    domain: &BindingDomain,
    keys: &(impl BlindIndexKeySource + ?Sized),
) -> Result<Vec<BlindIndex<Spec>>, Error> {
    let normalized = Spec::normalize_query(query)?;

    keyring::<Spec>(keys, domain)?
        .readable()
        .map(|key| derive_normalized::<Spec>(&normalized, domain, key))
        .collect()
}

fn check_consistency<Spec: BlindIndexSpec>(
    value: &<Spec::Seal as Seal>::Value,
    stored: &BlindIndex<Spec>,
    args: &IndexArgs<Spec>,
    keys: &(impl BlindIndexKeySource + ?Sized),
) -> Result<bool, Error> {
    let domain = index_domain::<Spec>(args)?;
    let id = stored.index_key_id();
    let key = keyring::<Spec>(keys, &domain)?
        .get(id)
        .cloned()
        .ok_or(Error::UnknownBlindIndexKey(id))?;
    let derived = derive_value_with_key::<Spec>(value, &domain, &key)?;

    // Both representations carry Spec::BITS, so their lengths always agree.
    Ok(derived.as_bytes().ct_eq(stored.as_bytes()).into())
}

// Blind indexes are domain-separated by their seal and the `keys` and `index`
// parts of its binding, never by bound-only parts or a record.
fn index_domain<Spec: BlindIndexSpec>(args: &IndexArgs<Spec>) -> Result<BindingDomain, Error> {
    BindingDomain::index::<<Spec::Seal as Seal>::Binding>(<Spec::Seal as Seal>::ID, args)
}

// Asks the source for the keyring of the index in the domain's key scope.
fn keyring<Spec: BlindIndexSpec>(
    keys: &(impl BlindIndexKeySource + ?Sized),
    domain: &BindingDomain,
) -> Result<BlindIndexKeyring, Error> {
    keys.blind_index_keyring(Spec::ID, domain.key_scope())
}

fn compare_normalized<Spec: BlindIndexSpec>(
    query: &Spec::Query,
    candidate: &<Spec::Seal as Seal>::Value,
) -> Result<bool, Error> {
    let query = Spec::normalize_query(query)?;
    let candidate = Spec::normalize_value(candidate)?;

    if query.len() != candidate.len() {
        return Ok(false);
    }

    Ok(query.as_slice().ct_eq(candidate.as_slice()).into())
}

fn derive_normalized<Spec: BlindIndexSpec>(
    normalized: &[u8],
    domain: &BindingDomain,
    key: &BlindIndexKey,
) -> Result<BlindIndex<Spec>, Error> {
    assert_valid_bits::<Spec>();
    let stored = derive_index(normalized, domain.as_bytes(), Spec::ID, Spec::BITS, key)?;

    Ok(BlindIndex::from_validated_bytes(stored))
}
