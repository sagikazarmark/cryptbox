use crate::{Error, KeyId};

const MAGIC: &[u8; 4] = b"CBX\0";
pub(super) const FORMAT_VERSION: u8 = 2;
const FLAG_PADDED: u8 = 0x01;

// The layout table: ../../docs/wire-format.md#envelope. A header is the magic,
// then one byte each of version, suite ID, and flags, then the key ID and the
// context fingerprint. Every header has the same fixed length.
const KEY_ID_LEN: usize = 16;
const FINGERPRINT_LEN: usize = 8;
const FORMAT_VERSION_OFFSET: usize = MAGIC.len();
const SUITE_ID_OFFSET: usize = FORMAT_VERSION_OFFSET + 1;
const FLAGS_OFFSET: usize = SUITE_ID_OFFSET + 1;
const KEY_ID_OFFSET: usize = FLAGS_OFFSET + 1;
// See ../../docs/wire-format.md#context.
const FINGERPRINT_OFFSET: usize = KEY_ID_OFFSET + KEY_ID_LEN;
const HEADER_LEN: usize = FINGERPRINT_OFFSET + FINGERPRINT_LEN;

/// Identifies a complete encryption-suite construction.
///
/// The envelope header records it; the suites define what each value means.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SuiteId(u8);

impl SuiteId {
    pub(crate) const fn new(value: u8) -> Self {
        Self(value)
    }

    pub(crate) const fn get(self) -> u8 {
        self.0
    }
}

/// Structurally parsed, unauthenticated ciphertext metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CiphertextInfo {
    format_version: u8,
    suite_id: SuiteId,
    padded: bool,
    key_id: KeyId,
    context_fingerprint: [u8; 8],
}

impl CiphertextInfo {
    /// Returns the envelope format version.
    #[must_use]
    pub const fn format_version(self) -> u8 {
        self.format_version
    }

    /// Returns the ID of the encryption suite, the complete construction that
    /// sealed the value.
    #[must_use]
    pub const fn suite_id(self) -> u8 {
        self.suite_id.get()
    }

    pub(crate) const fn suite(self) -> SuiteId {
        self.suite_id
    }

    /// Returns whether the envelope records a padded payload.
    #[must_use]
    pub const fn padded(self) -> bool {
        self.padded
    }

    /// Returns the encryption-key generation named by the envelope.
    #[must_use]
    pub const fn key_id(self) -> KeyId {
        self.key_id
    }

    /// Returns the fingerprint of the context the value was sealed under.
    ///
    /// The envelope stores it unchanged, and opening compares it with the
    /// fingerprint of the context the reader expects before any key lookup. It
    /// names the kind of context, never its values, so equal fingerprints do not
    /// imply equal contexts.
    #[must_use]
    pub const fn context_fingerprint(self) -> [u8; 8] {
        self.context_fingerprint
    }
}

pub(super) struct ParsedEnvelope<'a> {
    pub(super) info: CiphertextInfo,
    flags: u8,
    // The whole envelope: the header followed by the suite payload.
    pub(super) bytes: &'a [u8],
    pub(super) header: &'a [u8],
    pub(super) suite_payload: &'a [u8],
}

impl ParsedEnvelope<'_> {
    /// Rejects reserved flag bits, so a flag this reader does not know is never
    /// ignored.
    ///
    /// Check the suite first: a later suite may define a flag, and its values
    /// should report the suite, not the flag.
    pub(super) const fn check_flags(&self) -> Result<(), Error> {
        if self.flags & !FLAG_PADDED != 0 {
            return Err(Error::UnsupportedFlags(self.flags));
        }

        Ok(())
    }
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
    KeyId::from_bytes(field(bytes, KEY_ID_OFFSET))
}

pub(super) fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope<'_>, Error> {
    if !is_ciphertext(bytes) {
        return Err(Error::NotCiphertext);
    }

    // Offsets follow the layout table: ../../docs/wire-format.md#envelope.
    // The magic marks the bytes as an envelope, so the version is checked before
    // the length: a later format may have a shorter header.
    let Some(&format_version) = bytes.get(FORMAT_VERSION_OFFSET) else {
        return Err(Error::InvalidEnvelope);
    };
    if format_version != FORMAT_VERSION {
        return Err(Error::UnsupportedFormatVersion(format_version));
    }

    if bytes.len() < HEADER_LEN {
        return Err(Error::InvalidEnvelope);
    }
    let flags = bytes[FLAGS_OFFSET];
    let suite_id = SuiteId::new(bytes[SUITE_ID_OFFSET]);

    let padded = flags & FLAG_PADDED != 0;
    let key_id = KeyId::from_bytes(field(bytes, KEY_ID_OFFSET));
    let context_fingerprint = field(bytes, FINGERPRINT_OFFSET);

    Ok(ParsedEnvelope {
        bytes,
        info: CiphertextInfo {
            format_version,
            suite_id,
            padded,
            key_id,
            context_fingerprint,
        },
        flags,
        header: &bytes[..HEADER_LEN],
        suite_payload: &bytes[HEADER_LEN..],
    })
}

pub(super) fn envelope_header(
    suite_id: SuiteId,
    padded: bool,
    key_id: KeyId,
    fingerprint: [u8; 8],
) -> Vec<u8> {
    let flags = if padded { FLAG_PADDED } else { 0 };

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&[FORMAT_VERSION, suite_id.get(), flags]);
    header.extend_from_slice(key_id.as_bytes());
    header.extend_from_slice(&fingerprint);

    header
}

// Copies the fixed-size field at `offset` of a header whose length is already checked.
fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut field = [0_u8; N];
    field.copy_from_slice(&bytes[offset..offset + N]);

    field
}
