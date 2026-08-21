use std::{fmt, marker::PhantomData};

use zeroize::Zeroizing;

use crate::{
    Binding, BindingDomain, BlindIndexError, BlindIndexKey, BlindIndexKeyProvider, Error, IndexId,
    IndexKeyId,
    crypto::{hkdf_sha256_32, hmac_sha256},
};

const INDEX_FORMAT_VERSION: u8 = 1;
const INDEX_HEADER_LEN: usize = 19;
const MAX_INDEX_BITS: usize = 256;
const INDEX_KEY_LABEL: &[u8] = b"cryptbox/blind-index-key/v1\0";
const INDEX_VALUE_LABEL: &[u8] = b"cryptbox/blind-index-value/v1\0";

/// Stable metadata for a logical blind index.
///
/// `BITS` must be between 1 and 256. The logical [`IndexId`] is part of key
/// derivation but is not stored in the index bytes. Changing the ID,
/// normalization, binding, or precision creates a new logical index and
/// requires a migration.
pub trait BlindIndexMetadata: Sized + 'static {
    /// The stable logical index identifier.
    const ID: IndexId;
    /// The number of most-significant HMAC bits retained for candidate lookup.
    const BITS: usize;
}

/// Deterministically normalizes an arbitrary input for one logical index.
///
/// Normalization is persistent schema and must be identical for writes,
/// queries, and candidate verification. Return only the bytes relevant to
/// equality; do not include secrets or unstable formatting state.
pub trait BlindIndexSpec<Input: ?Sized>: BlindIndexMetadata {
    /// Returns normalized bytes owned by a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when this input cannot be normalized.
    fn normalize(input: &Input) -> Result<Zeroizing<Vec<u8>>, BlindIndexError>;
}

/// A stored, typed blind-index value used only for candidate lookup.
///
/// Blind indexes leak equality and frequency information. Avoid indexing
/// low-cardinality or highly skewed sensitive values, never use a truncated
/// index as a uniqueness constraint, and always verify candidate plaintext.
/// `Spec` is phantom and its [`BlindIndexMetadata::ID`] is not stored in the
/// representation.
pub struct BlindIndex<Spec> {
    bytes: Vec<u8>,
    marker: PhantomData<fn() -> Spec>,
}

impl<Spec: BlindIndexMetadata> BlindIndex<Spec> {
    /// Validates and wraps a stored blind-index representation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBlindIndex`] for malformed, noncanonical, or
    /// incorrectly sized values. This validates `Spec::BITS`, but cannot prove
    /// that the bytes were originally derived with `Spec::ID`.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        let info = inspect_blind_index(&bytes)?;
        if info.bits != Spec::BITS {
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

    /// Consumes the wrapper and returns its stored representation.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl<Spec: BlindIndexMetadata> TryFrom<Vec<u8>> for BlindIndex<Spec> {
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

/// Structurally parsed metadata from a stored blind-index value.
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

    /// Returns the index-key generation used to produce the value.
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

/// Parses and validates a stored blind-index representation.
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

/// Derives the current stored candidate index for `input`.
///
/// # Errors
///
/// Returns an error for invalid precision, normalization failure, or an
/// unavailable key provider.
pub fn derive_blind_index<Spec, Input, B>(
    input: &Input,
    context: &B::Context,
    keys: &dyn BlindIndexKeyProvider,
) -> Result<BlindIndex<Spec>, Error>
where
    Input: ?Sized,
    Spec: BlindIndexSpec<Input>,
    B: Binding,
{
    let normalized = Spec::normalize(input)?;
    let key = keys.current_key()?;
    derive_normalized::<Spec>(
        &normalized,
        &BindingDomain::from_binding::<B>(context),
        &key,
    )
}

/// Derives one candidate probe for every currently readable index generation.
///
/// Results are candidates only; decrypt matching rows and verify their
/// normalized plaintext with [`verify_blind_index_candidate`].
/// See the complete [blind-index example].
///
/// [blind-index example]: https://docs.rs/crate/cryptbox/latest/source/examples/blind_indexes.rs
///
/// # Errors
///
/// Returns an error for invalid precision, normalization failure, or an
/// unavailable key provider.
pub fn blind_index_probes<Spec, Input, B>(
    input: &Input,
    context: &B::Context,
    keys: &dyn BlindIndexKeyProvider,
) -> Result<Vec<BlindIndex<Spec>>, Error>
where
    Input: ?Sized,
    Spec: BlindIndexSpec<Input>,
    B: Binding,
{
    let normalized = Spec::normalize(input)?;
    let domain = BindingDomain::from_binding::<B>(context);
    keys.readable_keys()?
        .iter()
        .map(|key| derive_normalized::<Spec>(&normalized, &domain, key))
        .collect()
}

/// Compares normalized query and candidate plaintext after candidate lookup.
///
/// # Errors
///
/// Returns a sanitized error when either value cannot be normalized.
pub fn verify_blind_index_candidate<Spec, Input>(
    query: &Input,
    candidate: &Input,
) -> Result<bool, Error>
where
    Input: ?Sized,
    Spec: BlindIndexSpec<Input>,
{
    let query = Spec::normalize(query)?;
    let candidate = Spec::normalize(candidate)?;
    Ok(query.as_slice() == candidate.as_slice())
}

pub(crate) fn derive_with_domain<Spec, Input>(
    input: &Input,
    domain: &BindingDomain,
    keys: &dyn BlindIndexKeyProvider,
) -> Result<BlindIndex<Spec>, Error>
where
    Input: ?Sized,
    Spec: BlindIndexSpec<Input>,
{
    let normalized = Spec::normalize(input)?;
    let key = keys.current_key()?;
    derive_normalized::<Spec>(&normalized, domain, &key)
}

fn derive_normalized<Spec: BlindIndexMetadata>(
    normalized: &[u8],
    domain: &BindingDomain,
    key: &BlindIndexKey,
) -> Result<BlindIndex<Spec>, Error> {
    validate_bits(Spec::BITS)?;
    let bits = u16::try_from(Spec::BITS).map_err(|_| Error::InvalidBlindIndex)?;
    let mut header = [0_u8; INDEX_HEADER_LEN];
    header[0] = INDEX_FORMAT_VERSION;
    header[1..17].copy_from_slice(key.id().as_bytes());
    header[17..19].copy_from_slice(&bits.to_be_bytes());

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

    let digest_len = Spec::BITS.div_ceil(8);
    let mut stored = Vec::with_capacity(INDEX_HEADER_LEN + digest_len);
    stored.extend_from_slice(&header);
    stored.extend_from_slice(&digest[..digest_len]);
    if Spec::BITS % 8 != 0 {
        let retained_bits = Spec::BITS % 8;
        let mask = u8::MAX << (8 - retained_bits);
        let final_byte = stored.last_mut().ok_or(Error::InvalidBlindIndex)?;
        *final_byte &= mask;
    }
    Ok(BlindIndex::from_validated_bytes(stored))
}

fn validate_bits(bits: usize) -> Result<(), Error> {
    if !(1..=MAX_INDEX_BITS).contains(&bits) {
        return Err(Error::InvalidBlindIndex);
    }
    Ok(())
}
