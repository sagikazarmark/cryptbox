use std::{fmt, marker::PhantomData};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    BindingDomain, BlindIndexError, BlindIndexKey, BlindIndexKeyProvider, Error, Field, IndexId,
    IndexKeyId,
    crypto::{hkdf_sha256_32, hmac_sha256},
    keys,
};

const INDEX_FORMAT_VERSION: u8 = 1;
const INDEX_HEADER_LEN: usize = 19;
const MAX_INDEX_BITS: usize = 256;
// NUL-terminated labels separate key and value roles: ../docs/wire-format.md#blind-index-recipe.
const INDEX_KEY_LABEL: &[u8] = b"cryptbox/blind-index-key/v1\0";
const INDEX_VALUE_LABEL: &[u8] = b"cryptbox/blind-index-value/v1\0";

/// A logical blind index over one field.
///
/// A specification binds an index to exactly one [`Field`]: the field's ID
/// domain-separates derivation, stored indexes are derived from the field's
/// value with [`Self::normalize_value`], and lookups normalize a [`Self::Query`]
/// with [`Self::normalize_query`]. Both normalizers must produce identical bytes
/// for inputs that should match. `normalize_value` receives the whole value, so
/// an index can be computed from part of it, such as an email domain, or combine
/// several of its parts.
///
/// `BITS` must be between 1 and 256. The logical [`IndexId`] is part of key
/// derivation but is not stored in the index bytes. Changing the ID,
/// normalization, field, or precision creates a new logical index and
/// requires a migration.
///
/// # Examples
///
/// ```
/// use cryptbox::{BlindIndexError, BlindIndexSpec, Field, FieldId, IndexId, Padding, Utf8};
/// use zeroize::Zeroizing;
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
/// struct EmailLookup;
///
/// impl BlindIndexSpec for EmailLookup {
///     type Field = UserEmail;
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
/// impl from `#[cryptbox(id = "…", field = UserEmail, bits = 32, query = str,
/// normalize = normalize_email, normalizer = "email/1")]`, given a free
/// `normalize_email` function with `normalize_query`'s body.
///
/// Invalid precision is rejected when the specification is used:
///
/// ```compile_fail,E0080
/// # use cryptbox::{BlindIndex, BlindIndexError, BlindIndexSpec, Field, FieldId, IndexId, Padding, Raw};
/// # use zeroize::Zeroizing;
/// # struct Bytes;
/// # impl Field for Bytes {
/// #     const ID: FieldId = FieldId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
/// # }
/// struct ZeroBits;
///
/// impl BlindIndexSpec for ZeroBits {
///     type Field = Bytes;
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
/// # use cryptbox::{BlindIndex, BlindIndexError, BlindIndexSpec, Field, FieldId, IndexId, Padding, Raw};
/// # use zeroize::Zeroizing;
/// # struct Bytes;
/// # impl Field for Bytes {
/// #     const ID: FieldId = FieldId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
/// # }
/// struct TooManyBits;
///
/// impl BlindIndexSpec for TooManyBits {
///     type Field = Bytes;
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
/// Changes to normalization, index ID, field, or precision require a migration
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
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
pub trait BlindIndexSpec: Sized + 'static {
    /// The field whose values this index projects.
    type Field: Field;

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

    /// Normalizes a field value into bytes owned by a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when this value cannot be normalized.
    fn normalize_value(
        value: &<Self::Field as Field>::Value,
    ) -> Result<Zeroizing<Vec<u8>>, BlindIndexError>;

    /// Derives the current stored index for a value of [`Self::Field`].
    ///
    /// Use this to recompute a stored index from decrypted plaintext. New
    /// writes usually derive indexes through [`crate::Prepared::with_index_with`].
    ///
    /// # Errors
    ///
    /// Returns an error for normalization failure, an unavailable key provider, or
    /// an unrouted field.
    fn derive_with(
        value: &<Self::Field as Field>::Value,
        keys: &dyn BlindIndexKeyProvider,
    ) -> Result<BlindIndex<Self>, Error> {
        derive_value::<Self>(value, keys)
    }

    /// Derives one candidate probe for every currently readable index generation.
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
    /// Returns an error for normalization failure, an unavailable key provider, or
    /// an unrouted field.
    fn probes_with(
        query: &Self::Query,
        keys: &dyn BlindIndexKeyProvider,
    ) -> Result<Vec<BlindIndex<Self>>, Error> {
        derive_probes::<Self>(query, keys)
    }

    /// Derives probes with the [installed keys](keys::installed).
    ///
    /// This is exactly `Self::probes_with(query, keys::installed()?)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeysNotInstalled`] before installation, or an error when
    /// probe derivation fails.
    fn probes(query: &Self::Query) -> Result<Vec<BlindIndex<Self>>, Error> {
        Self::probes_with(query, keys::installed()?)
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
        candidate: &<Self::Field as Field>::Value,
    ) -> Result<bool, Error> {
        compare_normalized::<Self>(query, candidate)
    }

    /// Checks a stored index against the value it should have been derived from.
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
    /// Returns [`Error::UnknownBlindIndexKey`] when the provider cannot resolve
    /// the generation named by `stored`, so an unverifiable index is reported
    /// distinctly from an inconsistent one. Also returns an error for
    /// normalization failure, an unavailable key provider, or an unrouted field.
    fn is_consistent_with(
        value: &<Self::Field as Field>::Value,
        stored: &BlindIndex<Self>,
        keys: &dyn BlindIndexKeyProvider,
    ) -> Result<bool, Error> {
        check_consistency::<Self>(value, stored, keys)
    }
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
/// `Spec` is phantom and implies the field. Its [`BlindIndexSpec::ID`] is not stored in the
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
    /// with `Spec::ID`, the expected field, or the expected input.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        assert_valid_bits::<Spec>();
        let bytes = bytes.into();
        let info = inspect_blind_index(&bytes)?;

        if info.bits != usize::from(Spec::BITS) {
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
        let mut id = [0_u8; 16];
        id.copy_from_slice(&self.bytes[1..17]);

        IndexKeyId::from_bytes(id)
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

/// Structurally parsed, unauthenticated metadata from a stored blind-index value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlindIndexInfo {
    format_version: u8,
    index_key_id: IndexKeyId,
    bits: usize,
}

impl BlindIndexInfo {
    /// Returns the stored representation's format version.
    #[must_use]
    pub const fn format_version(self) -> u8 {
        self.format_version
    }

    /// Returns the unauthenticated index-key generation named by the value.
    #[must_use]
    pub const fn index_key_id(self) -> IndexKeyId {
        self.index_key_id
    }

    /// Returns the intentionally retained digest precision.
    #[must_use]
    pub const fn bits(self) -> usize {
        self.bits
    }
}

/// Parses and structurally validates a stored blind-index representation.
///
/// This does not authenticate the returned key ID, precision, or digest. Treat
/// all metadata as untrusted. To check index consistency, decrypt the associated
/// ciphertext and call [`BlindIndexSpec::is_consistent_with`] with the intended
/// specification and a provider serving only allowed key generations; it
/// recomputes and compares the complete stored representation. A match is
/// consistency at the configured precision, not proof of provenance or freshness.
/// [`BlindIndexSpec::verify_candidate`] only compares plaintexts; it does not perform
/// this recomputation or authenticate stored index metadata.
///
/// # Errors
///
/// Returns [`Error::InvalidBlindIndex`] for malformed or noncanonical bytes.
pub fn inspect_blind_index(bytes: &[u8]) -> Result<BlindIndexInfo, Error> {
    if bytes.len() < INDEX_HEADER_LEN || bytes[0] != INDEX_FORMAT_VERSION {
        return Err(Error::InvalidBlindIndex);
    }

    let bits = usize::from(u16::from_be_bytes([bytes[17], bytes[18]]));
    validate_bits(bits)?;
    let digest_len = bits.div_ceil(8);

    if bytes.len() != INDEX_HEADER_LEN + digest_len {
        return Err(Error::InvalidBlindIndex);
    }

    if bits % 8 != 0 {
        let unused_bits = 8 - (bits % 8);
        let unused_mask = (1_u8 << unused_bits) - 1;
        if bytes.last().copied().ok_or(Error::InvalidBlindIndex)? & unused_mask != 0 {
            return Err(Error::InvalidBlindIndex);
        }
    }

    let mut key_id = [0_u8; 16];
    key_id.copy_from_slice(&bytes[1..17]);

    Ok(BlindIndexInfo {
        format_version: INDEX_FORMAT_VERSION,
        index_key_id: IndexKeyId::from_bytes(key_id),
        bits,
    })
}

pub(crate) fn derive_value<Spec: BlindIndexSpec>(
    value: &<Spec::Field as Field>::Value,
    keys: &dyn BlindIndexKeyProvider,
) -> Result<BlindIndex<Spec>, Error> {
    let key = keys.current_key(<Spec::Field as Field>::ID)?;

    derive_value_with_key::<Spec>(value, &key)
}

fn derive_value_with_key<Spec: BlindIndexSpec>(
    value: &<Spec::Field as Field>::Value,
    key: &BlindIndexKey,
) -> Result<BlindIndex<Spec>, Error> {
    let normalized = Spec::normalize_value(value)?;
    let domain = BindingDomain::field(<Spec::Field as Field>::ID);

    derive_normalized::<Spec>(&normalized, &domain, key)
}

fn derive_probes<Spec: BlindIndexSpec>(
    query: &Spec::Query,
    keys: &dyn BlindIndexKeyProvider,
) -> Result<Vec<BlindIndex<Spec>>, Error> {
    let normalized = Spec::normalize_query(query)?;
    let field = <Spec::Field as Field>::ID;
    let domain = BindingDomain::field(field);

    keys.readable_keys(field)?
        .iter()
        .map(|key| derive_normalized::<Spec>(&normalized, &domain, key))
        .collect()
}

fn check_consistency<Spec: BlindIndexSpec>(
    value: &<Spec::Field as Field>::Value,
    stored: &BlindIndex<Spec>,
    keys: &dyn BlindIndexKeyProvider,
) -> Result<bool, Error> {
    let id = stored.index_key_id();
    let key = keys
        .key(<Spec::Field as Field>::ID, id)?
        .ok_or(Error::UnknownBlindIndexKey(id))?;
    let derived = derive_value_with_key::<Spec>(value, &key)?;

    // Both representations carry Spec::BITS, so their lengths always agree.
    Ok(derived.as_bytes().ct_eq(stored.as_bytes()).into())
}

fn compare_normalized<Spec: BlindIndexSpec>(
    query: &Spec::Query,
    candidate: &<Spec::Field as Field>::Value,
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
    let bits = Spec::BITS;
    let mut header = [0_u8; INDEX_HEADER_LEN];
    header[0] = INDEX_FORMAT_VERSION;
    header[1..17].copy_from_slice(key.id().as_bytes());
    header[17..19].copy_from_slice(&bits.to_be_bytes());

    // Both HKDF and HMAC commit to this canonical order; changing it breaks stored lookups.
    // See ../docs/wire-format.md#blind-index-recipe.
    let mut context = Vec::with_capacity(header.len() + domain.as_bytes().len() + 16);
    context.extend_from_slice(&header);
    context.extend_from_slice(domain.as_bytes());
    context.extend_from_slice(Spec::ID.as_bytes());

    let mut info = Vec::with_capacity(INDEX_KEY_LABEL.len() + context.len());
    info.extend_from_slice(INDEX_KEY_LABEL);
    info.extend_from_slice(&context);

    let index_key = hkdf_sha256_32(key.bytes(), &info)?;
    let normalized_len = u64::try_from(normalized.len()).map_err(|_| Error::InvalidBlindIndex)?;
    let normalized_len = normalized_len.to_be_bytes();

    let digest = hmac_sha256(
        &index_key[..],
        &[INDEX_VALUE_LABEL, &context, &normalized_len, normalized],
    )?;

    let digest_len = usize::from(bits).div_ceil(8);
    let mut stored = Vec::with_capacity(INDEX_HEADER_LEN + digest_len);
    stored.extend_from_slice(&header);
    stored.extend_from_slice(&digest[..digest_len]);

    if bits % 8 != 0 {
        // One encoding per retained bit string; unused bits must not leak extra precision.
        // Parsing enforces the same rule: ../docs/wire-format.md#blind-index-recipe.
        let retained_bits = bits % 8;
        let mask = u8::MAX << (8 - retained_bits);
        let final_byte = stored.last_mut().ok_or(Error::InvalidBlindIndex)?;
        *final_byte &= mask;
    }

    Ok(BlindIndex::from_validated_bytes(stored))
}

const fn valid_bits(bits: usize) -> bool {
    bits > 0 && bits <= MAX_INDEX_BITS
}

fn validate_bits(bits: usize) -> Result<(), Error> {
    if !valid_bits(bits) {
        return Err(Error::InvalidBlindIndex);
    }

    Ok(())
}
