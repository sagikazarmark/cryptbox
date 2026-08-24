use super::format::{encode_index, index_header};
use crate::crypto::{hkdf_sha256_32, hmac_sha256};
use crate::{BlindIndexKey, Error, IndexId};

// NUL-terminated labels separate key and value roles: ../../docs/wire-format.md#blind-index-recipe.
const INDEX_KEY_LABEL: &[u8] = b"cryptbox/blind-index-key/v1\0";
const INDEX_VALUE_LABEL: &[u8] = b"cryptbox/blind-index-value/v1\0";

/// Derives the stored index of `normalized` under `seal_context`, the encoded
/// index context, for the index `index_id` at `bits` of precision.
pub(super) fn derive_index(
    normalized: &[u8],
    seal_context: &[u8],
    index_id: IndexId,
    bits: u16,
    key: &BlindIndexKey,
) -> Result<Vec<u8>, Error> {
    let header = index_header(key.id(), bits);
    let normalized_len = u64::try_from(normalized.len()).map_err(|_| Error::InvalidBlindIndex)?;

    // HKDF and HMAC both commit to context = header || seal_context || index_id, in this
    // order; changing it breaks stored lookups. See ../../docs/wire-format.md#blind-index-recipe.
    let index_key = hkdf_sha256_32(
        key.bytes(),
        &[INDEX_KEY_LABEL, &header, seal_context, index_id.as_bytes()],
    )?;
    let digest = hmac_sha256(
        &index_key[..],
        &[
            INDEX_VALUE_LABEL,
            &header,
            seal_context,
            index_id.as_bytes(),
            &normalized_len.to_be_bytes(),
            normalized,
        ],
    )?;

    Ok(encode_index(&header, &digest, bits))
}
