use std::{fmt, marker::PhantomData};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    BlindIndexError, BlindIndexKey, BlindIndexKeys, Error, IndexKeyId, Seal, id::identifier,
    seal_context::SealContext,
};

mod format;
mod recipe;

pub use format::{BlindIndexInfo, inspect_blind_index};
use format::{stored_key_id, valid_bits};
use recipe::derive_index;

identifier!(IndexId, "A stable logical blind-index identifier.");

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
/// An index is derived under its seal ID alone, never a record, since a query
/// cannot know it: equal values of one seal derive equal indexes under the same
/// keys. Separate blind-index keys, such as a keyring per tenant, derive
/// unrelated indexes for equal values. See the [index context].
///
/// `BITS` must be between 1 and 256. The logical [`IndexId`] is part of key
/// derivation but is not stored in the index bytes. Changing the ID,
/// normalization, seal, or precision creates a new logical index and
/// requires a migration.
///
/// # Examples
///
/// ```
/// use cryptbox::{BlindIndexError, BlindIndexSpec, Seal, SealId, IndexId, Padding, Utf8};
/// use zeroize::Zeroizing;
///
/// struct UserEmail;
///
/// impl Seal for UserEmail {
///     const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
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
/// impl from `#[blind_index(id = "…", seal = UserEmail, bits = 32, query = str,
/// normalize = normalize_email, normalizer = "email/1")]`, given a free
/// `normalize_email` function with `normalize_query`'s body.
///
/// Invalid precision is rejected when the specification is used:
///
/// ```compile_fail,E0080
/// # use cryptbox::{BlindIndex, BlindIndexError, BlindIndexSpec, Seal, SealId, IndexId, Padding, Raw};
/// # use zeroize::Zeroizing;
/// # struct Bytes;
/// # impl Seal for Bytes {
/// #     const ID: SealId = SealId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
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
/// # use cryptbox::{BlindIndex, BlindIndexError, BlindIndexSpec, Seal, SealId, IndexId, Padding, Raw};
/// # use zeroize::Zeroizing;
/// # struct Bytes;
/// # impl Seal for Bytes {
/// #     const ID: SealId = SealId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
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
/// [`BlindIndex`] derives, probes, and verifies indexes of a spec, so an
/// implementation supplies only the associated items and the two normalizers.
///
/// See the [custom-seal example] and [ownership reference].
/// Padding is a closed set of policies; a custom normalizer does not bind an index to a row.
///
#[doc = concat!(
    "[custom-seal example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/examples/custom_seal/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/docs/guide.md#ownership-and-erasure\n",
    "[index context]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/docs/wire-format.md#index-context",
)]
pub trait BlindIndexSpec: Sized + 'static {
    /// The seal whose values this index projects.
    type Seal: Seal;

    /// The stable logical index identifier.
    const ID: IndexId;

    /// The number of most-significant HMAC bits retained for candidate lookup.
    const BITS: u16;

    /// A stable name for the normalization rules, such as `"email/1"`: a name,
    /// `/`, and a version from 1.
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
}

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
/// operation; see [`Self::verify_candidate`].
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

        if info.bits() != Spec::BITS {
            return Err(Error::InvalidBlindIndex);
        }

        Ok(Self::from_validated_bytes(bytes))
    }

    /// Derives the current stored index for a value of the spec's seal.
    ///
    /// Derive it from the same value that is sealed into the row, and write both
    /// in one statement; also use this to recompute a stored index from
    /// decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error for normalization failure or unavailable keys.
    pub fn derive(
        value: &<Spec::Seal as Seal>::Value,
        keys: &(impl BlindIndexKeys + ?Sized),
    ) -> Result<Self, Error> {
        derive_value::<Spec>(value, &index_context::<Spec>(), keys)
    }

    /// Derives one candidate probe for every currently readable index
    /// generation.
    ///
    /// Results are candidates only; decrypt candidate rows and verify their
    /// normalized plaintext with [`Self::verify_candidate`].
    /// See the complete [blind-index example].
    ///
    #[doc = concat!(
        "[blind-index example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/examples/blind_indexes.rs",
    )]
    ///
    /// # Errors
    ///
    /// Returns an error for normalization failure or unavailable keys.
    pub fn probes(
        query: &Spec::Query,
        keys: &(impl BlindIndexKeys + ?Sized),
    ) -> Result<Vec<Self>, Error> {
        probes_in::<Spec>(query, &index_context::<Spec>(), keys)
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
    pub fn verify_candidate(
        query: &Spec::Query,
        candidate: &<Spec::Seal as Seal>::Value,
    ) -> Result<bool, Error> {
        compare_normalized::<Spec>(query, candidate)
    }

    /// Checks this stored index against the value it should have been derived
    /// from.
    ///
    /// Decrypt and authenticate the associated ciphertext before calling this.
    /// This resolves exactly the index-key generation this index names,
    /// re-derives from `value` with [`BlindIndexSpec::normalize_value`], and
    /// compares the complete stored representation in constant time. It works
    /// alike for exact, computed, and composite indexes, whether this index uses
    /// the current or a historical generation. A match is consistency at the
    /// configured precision, not proof of provenance or freshness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownBlindIndexKey`] when the keyring does not hold
    /// the generation this index names, so an unverifiable index is reported
    /// distinctly from an inconsistent one. Also returns an error for
    /// normalization failure or unavailable keys.
    pub fn is_consistent_with(
        &self,
        value: &<Spec::Seal as Seal>::Value,
        keys: &(impl BlindIndexKeys + ?Sized),
    ) -> Result<bool, Error> {
        check_consistency::<Spec>(value, self, keys)
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

// Stores the index through `Vec<u8>`, as an ORM's `serialize_as` does.
impl<Spec> From<BlindIndex<Spec>> for Vec<u8> {
    fn from(index: BlindIndex<Spec>) -> Self {
        index.into_bytes()
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

/// Derives the current stored index of `Spec` in `context`, the index context of
/// `Spec`'s seal.
pub(crate) fn derive_value<Spec: BlindIndexSpec>(
    value: &<Spec::Seal as Seal>::Value,
    context: &SealContext,
    keys: &(impl BlindIndexKeys + ?Sized),
) -> Result<BlindIndex<Spec>, Error> {
    let key = keys.blind_index_keyring()?.current().clone();

    derive_value_with_key::<Spec>(value, context, &key)
}

fn derive_value_with_key<Spec: BlindIndexSpec>(
    value: &<Spec::Seal as Seal>::Value,
    context: &SealContext,
    key: &BlindIndexKey,
) -> Result<BlindIndex<Spec>, Error> {
    let normalized = Spec::normalize_value(value)?;

    derive_normalized::<Spec>(&normalized, context, key)
}

/// Derives one probe of `Spec` in `context`, the index context of `Spec`'s seal,
/// for every readable index generation.
pub(crate) fn probes_in<Spec: BlindIndexSpec>(
    query: &Spec::Query,
    context: &SealContext,
    keys: &(impl BlindIndexKeys + ?Sized),
) -> Result<Vec<BlindIndex<Spec>>, Error> {
    let normalized = Spec::normalize_query(query)?;

    keys.blind_index_keyring()?
        .readable()
        .map(|key| derive_normalized::<Spec>(&normalized, context, key))
        .collect()
}

fn check_consistency<Spec: BlindIndexSpec>(
    value: &<Spec::Seal as Seal>::Value,
    stored: &BlindIndex<Spec>,
    keys: &(impl BlindIndexKeys + ?Sized),
) -> Result<bool, Error> {
    let context = index_context::<Spec>();
    let id = stored.index_key_id();
    let key = keys
        .blind_index_keyring()?
        .get(id)
        .cloned()
        .ok_or(Error::UnknownBlindIndexKey(id))?;
    let derived = derive_value_with_key::<Spec>(value, &context, &key)?;

    // Both representations carry Spec::BITS, so their lengths always agree.
    Ok(derived.as_bytes().ct_eq(stored.as_bytes()).into())
}

// Blind indexes are domain-separated by their seal, never by a record.
pub(crate) fn index_context<Spec: BlindIndexSpec>() -> SealContext {
    SealContext::seal_id(&<Spec::Seal as Seal>::ID)
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
    context: &SealContext,
    key: &BlindIndexKey,
) -> Result<BlindIndex<Spec>, Error> {
    assert_valid_bits::<Spec>();
    let stored = derive_index(normalized, context.as_bytes(), Spec::ID, Spec::BITS, key)?;

    Ok(BlindIndex::from_validated_bytes(stored))
}

/// Reports whether `name` is a versioned normalizer name, `<name>/<version>`:
/// a non-empty name, `/`, and a decimal version from 1 without leading zeros.
#[doc(hidden)]
#[must_use]
pub const fn valid_normalizer(name: &str) -> bool {
    let bytes = name.as_bytes();
    let mut slash = bytes.len();
    while slash > 0 {
        slash -= 1;
        if bytes[slash] == b'/' {
            break;
        }
    }
    if slash == 0 || bytes[slash] != b'/' || slash + 1 == bytes.len() || bytes[slash + 1] == b'0' {
        return false;
    }

    let mut index = slash + 1;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
        index += 1;
    }

    true
}

/// Creates an [`IndexId`](crate::IndexId) from a UUID literal.
#[macro_export]
macro_rules! index_id {
    ($value:literal) => {{
        const ID: $crate::IndexId = $crate::IndexId::from_bytes($crate::__private::non_nil(
            $crate::__private::uuid::uuid!($value).into_bytes(),
        ));
        ID
    }};
}

#[cfg(test)]
mod tests {
    use super::valid_normalizer;

    // The same names as the derive's test in cryptbox-derive/src/attr.rs: the
    // derive and `assert_unique_ids!` must agree.
    #[test]
    fn normalizer_names_carry_a_version_from_one() {
        for name in ["email/1", "exact/12", "a/b/3", "email-v2/10"] {
            assert!(valid_normalizer(name), "{name}");
        }
        for name in [
            "", "email", "/1", "email/", "email/0", "email/01", "email/v1", "email/1 ",
        ] {
            assert!(!valid_normalizer(name), "{name}");
        }
    }
}
