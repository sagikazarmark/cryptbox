use sha2::{Digest, Sha256};

use super::{PartKind, PartRole, PartSpec, PartValue};
use crate::{Error, SealId};

// A persistent domain separator, not a display string.
// See ../../docs/wire-format.md#binding-fingerprint.
const FINGERPRINT_LABEL: &[u8] = b"cryptbox/binding-fingerprint/v1\0";

/// Encodes a binding as `seal_id ‖ count ‖ parts`, sorting the parts by part
/// ID so the bytes do not depend on part order. A record is one of the parts,
/// under the nil part ID, so it sorts first.
///
/// The seal ID and part bytes are persistent KDF/AAD inputs, independent of Rust
/// names. See ../../docs/wire-format.md#binding.
pub(super) fn encode<'v>(
    seal: SealId,
    parts: impl IntoIterator<Item = (&'v PartSpec, &'v PartValue<'v>)>,
) -> Result<Vec<u8>, Error> {
    let mut parts: Vec<_> = parts.into_iter().collect();
    parts.sort_by_key(|(spec, _)| spec.id);
    let count = u16::try_from(parts.len()).map_err(|_| Error::InvalidBinding)?;

    let mut encoded = Vec::new();
    encoded.extend_from_slice(seal.as_bytes());
    encoded.extend_from_slice(&count.to_be_bytes());
    for (spec, value) in parts {
        encoded.extend_from_slice(&spec.id);
        encode_value(value, &mut encoded)?;
    }

    Ok(encoded)
}

/// Fingerprints a declaration from its part IDs, kinds, and roles, a record's
/// part included, never values; part order does not matter.
pub(super) fn fingerprint(parts: &[PartSpec]) -> [u8; 8] {
    let mut parts = parts.to_vec();
    parts.sort_by_key(|spec| spec.id);
    // A count that does not fit is rejected when the binding is encoded.
    let count = u16::try_from(parts.len()).unwrap_or(u16::MAX);

    // Preserve this canonical order: stored headers carry the result.
    // See ../../docs/wire-format.md#binding-fingerprint.
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_LABEL);
    hasher.update(count.to_be_bytes());
    for spec in parts {
        hasher.update(spec.id);
        hasher.update([kind_code(spec.kind), role_code(spec.role)]);
    }

    let digest = hasher.finalize();
    let mut fingerprint = [0_u8; 8];
    fingerprint.copy_from_slice(&digest[..8]);

    fingerprint
}

// Kind-tagged and length-prefixed, so no two values of any kinds share bytes.
fn encode_value(value: &PartValue<'_>, output: &mut Vec<u8>) -> Result<(), Error> {
    let i64_bytes;
    let bytes: &[u8] = match value {
        PartValue::Uuid(uuid) => uuid,
        PartValue::I64(value) => {
            i64_bytes = value.to_be_bytes();
            &i64_bytes
        }
        PartValue::Bytes(bytes) => bytes,
    };
    let len = u32::try_from(bytes.len()).map_err(|_| Error::InvalidBinding)?;

    output.push(kind_code(value.kind()));
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);

    Ok(())
}

// Kind codes are persistent binding bytes. See ../../docs/wire-format.md#binding.
const fn kind_code(kind: PartKind) -> u8 {
    match kind {
        PartKind::Uuid => 1,
        PartKind::I64 => 2,
        PartKind::Bytes => 3,
    }
}

// Role codes are persistent fingerprint input. See ../../docs/wire-format.md#binding-fingerprint.
const fn role_code(role: PartRole) -> u8 {
    match role {
        PartRole::Keys => 1,
        PartRole::Index => 2,
        PartRole::Bound => 3,
    }
}
