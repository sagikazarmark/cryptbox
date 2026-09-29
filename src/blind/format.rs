use crate::{Error, IndexKeyId};

const INDEX_FORMAT_VERSION: u8 = 1;
const MAX_INDEX_BITS: usize = 256;
// The stored layout: ../../docs/wire-format.md#stored-layout. The version byte, the
// index key ID, then the retained bit count as a big-endian u16.
const INDEX_KEY_ID_OFFSET: usize = 1;
const INDEX_KEY_ID_LEN: usize = 16;
const INDEX_BITS_OFFSET: usize = INDEX_KEY_ID_OFFSET + INDEX_KEY_ID_LEN;
const INDEX_HEADER_LEN: usize = INDEX_BITS_OFFSET + 2;

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
/// ciphertext and call [`BlindIndexSpec::is_consistent_with`](crate::BlindIndexSpec::is_consistent_with) with the intended
/// specification and a keyring holding only allowed key generations; it
/// recomputes and compares the complete stored representation. A match is
/// consistency at the configured precision, not proof of provenance or freshness.
/// [`BlindIndexSpec::verify_candidate`](crate::BlindIndexSpec::verify_candidate) only compares plaintexts; it does not perform
/// this recomputation or authenticate stored index metadata.
///
/// # Errors
///
/// Returns [`Error::InvalidBlindIndex`](crate::Error::InvalidBlindIndex) for malformed or noncanonical bytes.
pub fn inspect_blind_index(bytes: &[u8]) -> Result<BlindIndexInfo, Error> {
    if bytes.len() < INDEX_HEADER_LEN || bytes[0] != INDEX_FORMAT_VERSION {
        return Err(Error::InvalidBlindIndex);
    }

    let bits = usize::from(u16::from_be_bytes([
        bytes[INDEX_BITS_OFFSET],
        bytes[INDEX_BITS_OFFSET + 1],
    ]));
    validate_bits(bits)?;
    let digest_len = bits.div_ceil(8);

    if bytes.len() != INDEX_HEADER_LEN + digest_len {
        return Err(Error::InvalidBlindIndex);
    }

    // Noncanonical: the unused low bits of the final byte must be zero.
    if bytes.last().copied().ok_or(Error::InvalidBlindIndex)? & !final_byte_mask(bits) != 0 {
        return Err(Error::InvalidBlindIndex);
    }

    Ok(BlindIndexInfo {
        format_version: INDEX_FORMAT_VERSION,
        index_key_id: stored_key_id(bytes),
        bits,
    })
}

pub(super) const fn valid_bits(bits: usize) -> bool {
    bits > 0 && bits <= MAX_INDEX_BITS
}

fn validate_bits(bits: usize) -> Result<(), Error> {
    if !valid_bits(bits) {
        return Err(Error::InvalidBlindIndex);
    }

    Ok(())
}

/// Builds the stored header naming `key_id` and `bits`.
pub(super) fn index_header(key_id: IndexKeyId, bits: u16) -> [u8; INDEX_HEADER_LEN] {
    let mut header = [0_u8; INDEX_HEADER_LEN];
    header[0] = INDEX_FORMAT_VERSION;
    header[INDEX_KEY_ID_OFFSET..INDEX_BITS_OFFSET].copy_from_slice(key_id.as_bytes());
    header[INDEX_BITS_OFFSET..].copy_from_slice(&bits.to_be_bytes());

    header
}

/// Appends the canonical truncation of `digest` to `header`: its first `bits`
/// bits, with the unused low bits of the final byte cleared.
pub(super) fn encode_index(
    header: &[u8; INDEX_HEADER_LEN],
    digest: &[u8; 32],
    bits: u16,
) -> Vec<u8> {
    let bits = usize::from(bits);
    let digest_len = bits.div_ceil(8);
    let mut stored = Vec::with_capacity(INDEX_HEADER_LEN + digest_len);
    stored.extend_from_slice(header);
    stored.extend_from_slice(&digest[..digest_len]);

    // One encoding per retained bit string; unused bits must not leak extra precision.
    // Parsing enforces the same rule: ../../docs/wire-format.md#blind-index-recipe.
    if let Some(final_byte) = stored.last_mut() {
        *final_byte &= final_byte_mask(bits);
    }

    stored
}

// The bits a `bits`-bit index keeps in its final digest byte; the rest are zero.
const fn final_byte_mask(bits: usize) -> u8 {
    match bits % 8 {
        0 => u8::MAX,
        retained => u8::MAX << (8 - retained),
    }
}

// Reads the index key ID of a representation whose length is already checked.
pub(super) fn stored_key_id(bytes: &[u8]) -> IndexKeyId {
    let mut key_id = [0_u8; INDEX_KEY_ID_LEN];
    key_id.copy_from_slice(&bytes[INDEX_KEY_ID_OFFSET..INDEX_BITS_OFFSET]);

    IndexKeyId::from_bytes(key_id)
}
