use crate::{Error, KeyId, ShapeFingerprint, SuiteId};

const MAGIC: &[u8; 4] = b"CBX\0";
pub(super) const FORMAT_VERSION: u8 = 2;
const HEADER_LEN: usize = 23;
// A scoped binding extends the header with its shape fingerprint.
// See ../../docs/wire-format.md#shape-fingerprint.
const SCOPED_HEADER_LEN: usize = HEADER_LEN + FINGERPRINT_LEN;
const FINGERPRINT_LEN: usize = 8;
// Format 1 did not record padding; it stays readable until stored data is swept.
// See ../../docs/wire-format.md#format-1.
const FORMAT_1_VERSION: u8 = 1;
const FORMAT_1_HEADER_LEN: usize = 22;
const FLAG_PADDED: u8 = 0x01;
const FLAG_SCOPED: u8 = 0x02;
// Byte offsets in the layout table: ../../docs/wire-format.md#envelope.
const FORMAT_VERSION_OFFSET: usize = 4;
const SUITE_ID_OFFSET: usize = 5;
const FLAGS_OFFSET: usize = 6;

/// Structurally parsed, unauthenticated ciphertext metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CiphertextInfo {
    format_version: u8,
    suite_id: SuiteId,
    padded: Option<bool>,
    key_id: KeyId,
    shape_fingerprint: Option<ShapeFingerprint>,
}

impl CiphertextInfo {
    /// Returns the envelope format version.
    #[must_use]
    pub const fn format_version(self) -> u8 {
        self.format_version
    }

    /// Returns the complete cipher-suite identifier.
    #[must_use]
    pub const fn suite_id(self) -> SuiteId {
        self.suite_id
    }

    /// Returns whether the envelope records a padded payload.
    ///
    /// Format 1 envelopes do not record padding and return `None`; the field's
    /// padding policy describes them.
    #[must_use]
    pub const fn padded(self) -> Option<bool> {
        self.padded
    }

    /// Returns the encryption-key generation named by the envelope.
    #[must_use]
    pub const fn key_id(self) -> KeyId {
        self.key_id
    }

    /// Returns the shape fingerprint of a scoped binding.
    ///
    /// Field-only and format 1 envelopes carry none and return `None`. The
    /// fingerprint is diagnostic: a reader compares it with its own field's
    /// shape, so it can count values written with an older shape.
    #[must_use]
    pub const fn shape_fingerprint(self) -> Option<ShapeFingerprint> {
        self.shape_fingerprint
    }
}

pub(super) struct ParsedEnvelope<'a> {
    pub(super) info: CiphertextInfo,
    // The whole envelope: the header followed by the suite payload.
    pub(super) bytes: &'a [u8],
    pub(super) header: &'a [u8],
    pub(super) suite_payload: &'a [u8],
}

/// Returns whether `bytes` begin with `CryptBox` ciphertext magic.
///
/// This is a migration aid, not validation or authentication.
#[must_use]
pub fn is_ciphertext(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Returns the key ID of an envelope that already passed structural validation.
// Offsets follow the layout table: ../../docs/wire-format.md#envelope.
pub(crate) fn validated_key_id(bytes: &[u8]) -> KeyId {
    let offset = key_id_offset(bytes[FORMAT_VERSION_OFFSET]);
    let mut key_id = [0_u8; 16];
    key_id.copy_from_slice(&bytes[offset..offset + 16]);

    KeyId::from_bytes(key_id)
}

pub(super) fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope<'_>, Error> {
    if !is_ciphertext(bytes) {
        return Err(Error::NotCiphertext);
    }

    // Too short for any format's header: malformed, whatever byte 4 claims.
    if bytes.len() < FORMAT_1_HEADER_LEN {
        return Err(Error::InvalidEnvelope);
    }

    // Offsets follow the layout table: ../../docs/wire-format.md#envelope.
    let format_version = bytes[FORMAT_VERSION_OFFSET];
    let flags = match format_version {
        FORMAT_VERSION => bytes[FLAGS_OFFSET],
        FORMAT_1_VERSION => 0,
        _ => return Err(Error::UnsupportedFormatVersion(format_version)),
    };

    // Reject reserved bits so a flag this reader does not know is never ignored.
    if flags & !(FLAG_PADDED | FLAG_SCOPED) != 0 {
        return Err(Error::InvalidEnvelope);
    }

    let header_len = match format_version {
        FORMAT_1_VERSION => FORMAT_1_HEADER_LEN,
        _ if flags & FLAG_SCOPED != 0 => SCOPED_HEADER_LEN,
        _ => HEADER_LEN,
    };
    if bytes.len() < header_len {
        return Err(Error::InvalidEnvelope);
    }

    let suite_id = SuiteId::new(bytes[SUITE_ID_OFFSET]);

    let padded = (format_version == FORMAT_VERSION).then_some(flags & FLAG_PADDED != 0);
    let mut key_id = [0_u8; 16];
    let key_offset = key_id_offset(format_version);
    key_id.copy_from_slice(&bytes[key_offset..key_offset + 16]);
    let shape_fingerprint = (flags & FLAG_SCOPED != 0).then(|| {
        let mut fingerprint = [0_u8; FINGERPRINT_LEN];
        fingerprint.copy_from_slice(&bytes[HEADER_LEN..SCOPED_HEADER_LEN]);

        ShapeFingerprint::from_bytes(fingerprint)
    });

    Ok(ParsedEnvelope {
        bytes,
        info: CiphertextInfo {
            format_version,
            suite_id,
            padded,
            key_id: KeyId::from_bytes(key_id),
            shape_fingerprint,
        },
        header: &bytes[..header_len],
        suite_payload: &bytes[header_len..],
    })
}

pub(super) fn envelope_header(
    suite_id: SuiteId,
    padded: bool,
    key_id: KeyId,
    fingerprint: Option<ShapeFingerprint>,
) -> Vec<u8> {
    let mut flags = if padded { FLAG_PADDED } else { 0 };
    if fingerprint.is_some() {
        flags |= FLAG_SCOPED;
    }

    let mut header = Vec::with_capacity(SCOPED_HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&[FORMAT_VERSION, suite_id.get(), flags]);
    header.extend_from_slice(key_id.as_bytes());
    if let Some(fingerprint) = fingerprint {
        header.extend_from_slice(fingerprint.as_bytes());
    }

    header
}

// Format 1 has no flags byte, so its key ID starts one byte earlier.
const fn key_id_offset(format_version: u8) -> usize {
    if format_version == FORMAT_1_VERSION {
        FLAGS_OFFSET
    } else {
        FLAGS_OFFSET + 1
    }
}
