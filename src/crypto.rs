use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInOut};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::padding::unpad;
use crate::{
    BindingDomain, EncryptionKey, EncryptionKeySource, EncryptionKeyring, Error, FieldId, KeyId,
    Padding, ShapeFingerprint, SuiteId,
};

const MAGIC: &[u8; 4] = b"CBX\0";
const FORMAT_VERSION: u8 = 2;
const HEADER_LEN: usize = 23;
// A scoped binding extends the header with its shape fingerprint.
// See ../docs/wire-format.md#shape-fingerprint.
const SCOPED_HEADER_LEN: usize = HEADER_LEN + FINGERPRINT_LEN;
const FINGERPRINT_LEN: usize = 8;
// Format 1 did not record padding; it stays readable until stored data is swept.
// See ../docs/wire-format.md#format-1.
const FORMAT_1_VERSION: u8 = 1;
const FORMAT_1_HEADER_LEN: usize = 22;
const FLAG_PADDED: u8 = 0x01;
const FLAG_SCOPED: u8 = 0x02;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MAX_PLAINTEXT_LEN: u64 = 274_877_906_880;

// Labels, including NULs, are persistent domain separators, not display strings.
// See ../docs/wire-format.md#encryption-recipe.
const HKDF_SALT: &[u8] = b"cryptbox/hkdf-sha256/v1\0";
const ENCRYPTION_KEY_LABEL: &[u8] = b"cryptbox/encryption-key/v1\0";
const ENVELOPE_AAD_LABEL: &[u8] = b"cryptbox/envelope-aad/v1\0";

/// The provisional suite ID for HKDF-SHA-256 plus XChaCha20-Poly1305.
///
/// This construction and its wire format are experimental pending focused
/// cryptographic review and independently verified test vectors.
pub const EXPERIMENTAL_XCHACHA20_POLY1305: SuiteId = SuiteId::new(1);

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

struct ParsedEnvelope<'a> {
    info: CiphertextInfo,
    header: &'a [u8],
    suite_payload: &'a [u8],
}

trait EncryptionSuite: Sync {
    fn id(&self) -> SuiteId;

    fn validate_payload(&self, payload: &[u8]) -> Result<(), Error>;

    fn seal(
        &self,
        header: &[u8],
        plaintext: &[u8],
        binding: &[u8],
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error>;

    fn open(
        &self,
        header: &[u8],
        payload: &[u8],
        binding: &[u8],
        key: &EncryptionKey,
    ) -> Result<Zeroizing<Vec<u8>>, Error>;
}

struct XChaCha20Poly1305Suite;

static XCHACHA20_POLY1305_SUITE: XChaCha20Poly1305Suite = XChaCha20Poly1305Suite;
static DECRYPTION_SUITES: [&dyn EncryptionSuite; 1] = [&XCHACHA20_POLY1305_SUITE];

/// Returns whether `bytes` begin with `CryptBox` ciphertext magic.
///
/// This is a migration aid, not validation or authentication.
#[must_use]
pub fn is_ciphertext(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Parses supported envelope metadata without authenticating it.
///
/// The bytes and returned metadata remain untrusted until authenticated
/// decryption succeeds. Parsing does not look up keys or validate a codec.
///
/// # Errors
///
/// Returns a structured error when the envelope is malformed or unsupported.
pub fn inspect_ciphertext(bytes: &[u8]) -> Result<CiphertextInfo, Error> {
    parse_envelope(bytes).map(|parsed| parsed.info)
}

/// Encrypts opaque plaintext bytes for `field` with the current key of its keyring.
///
/// `padding` is applied before encryption and recorded in the authenticated
/// envelope, so [`decrypt`] removes it regardless of the policy in effect when
/// the value is read.
///
/// # Errors
///
/// Returns an error for unavailable keys, plaintext that
/// does not fit fixed padding, failed OS randomness, or messages longer than
/// the active suite's 274,877,906,880-byte limit.
pub fn encrypt(
    field: FieldId,
    padding: Padding,
    plaintext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Vec<u8>, Error> {
    encrypt_bound(&BindingDomain::field(field), padding, plaintext, keys)
}

/// Encrypts under `domain`, recording a scoped binding's shape fingerprint.
pub(crate) fn encrypt_bound(
    domain: &BindingDomain,
    padding: Padding,
    plaintext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Vec<u8>, Error> {
    let key = keyring(keys, domain)?.current().clone();
    let suite = active_suite();
    let header = envelope_header(
        suite.id(),
        padding.is_padded(),
        key.id(),
        domain.fingerprint(),
    );

    match padding.pad(plaintext)? {
        Some(padded) => suite.seal(&header, &padded, domain.as_bytes(), &key),
        None => suite.seal(&header, plaintext, domain.as_bytes(), &key),
    }
}

/// Authenticates and decrypts opaque ciphertext bytes.
///
/// The keyring is asked only for the exact key ID named by the envelope.
/// Success authenticates the envelope under the supplied key and `field`;
/// it does not establish freshness, row identity, or codec validity.
/// Padding recorded by the envelope is removed. A format 1 envelope does not
/// record padding, so its payload is returned as stored.
/// Use [`crate::Sealed::open`] to also decode a typed value.
///
/// # Errors
///
/// Returns a structured envelope, key-source,
/// unknown-key, authentication, or padding error. A different field and
/// modified ciphertext both report authentication failure. An envelope sealed
/// with a scoped binding reports [`Error::BindingMismatch`].
pub fn decrypt(
    field: FieldId,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Zeroizing<Vec<u8>>, Error> {
    decrypt_with_policy(field, Padding::NONE, ciphertext, keys)
}

/// Decrypts and unpads, reading a format 1 payload with the field's `padding`.
pub(crate) fn decrypt_with_policy(
    field: FieldId,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Zeroizing<Vec<u8>>, Error> {
    decrypt_bound(&BindingDomain::field(field), padding, ciphertext, keys)
}

/// Decrypts under the expected `domain`, reading a format 1 payload with `padding`.
pub(crate) fn decrypt_bound(
    domain: &BindingDomain,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let parsed = parse_envelope(ciphertext)?;
    check_shape(parsed.info, domain)?;
    let key = keyring(keys, domain)?
        .get(parsed.info.key_id)
        .cloned()
        .ok_or(Error::UnknownEncryptionKey(parsed.info.key_id))?;
    let plaintext = registered_suite(parsed.info.suite_id)?.open(
        parsed.header,
        parsed.suite_payload,
        domain.as_bytes(),
        &key,
    )?;

    // Only the authenticated flag decides unpadding; the current policy must not,
    // or policy changes would silently misread stored values.
    // See ../docs/adr/0002-authenticated-padding-flag.md.
    match parsed.info.padded {
        Some(true) => unpad(plaintext),
        Some(false) => Ok(plaintext),
        None => padding.unpad(plaintext),
    }
}

// Asks the source for the keyring of the domain's field and key scope.
fn keyring(
    keys: &(impl EncryptionKeySource + ?Sized),
    domain: &BindingDomain,
) -> Result<EncryptionKeyring, Error> {
    keys.encryption_keyring(domain.field_id(), domain.key_scope())
}

// The expected shape always comes from the reader, never from the envelope; the
// fingerprint only names the mismatch before any key or AEAD work.
// See ../docs/wire-format.md#reader-rules.
fn check_shape(info: CiphertextInfo, domain: &BindingDomain) -> Result<(), Error> {
    if info.shape_fingerprint != domain.fingerprint() {
        return Err(Error::BindingMismatch);
    }

    Ok(())
}

/// Reports whether an envelope differs from what `field` currently writes.
///
/// That is an older format, a non-active suite, a non-current key, or a padding
/// flag that disagrees with `padding`. Padding parameters are not recorded, so
/// changing only a block size or fixed length is not reported.
///
/// This reads unauthenticated metadata and does not decrypt the payload.
/// A `false` result does not establish that the ciphertext can be
/// authenticated or decoded.
///
/// # Errors
///
/// Returns an error for malformed or unsupported envelopes, unavailable
/// keys. An envelope sealed with a scoped binding
/// reports [`Error::BindingMismatch`].
pub fn needs_reencryption(
    field: FieldId,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<bool, Error> {
    needs_reencryption_bound(&BindingDomain::field(field), padding, ciphertext, keys)
}

/// Reports whether an envelope differs from what `domain` currently writes.
pub(crate) fn needs_reencryption_bound(
    domain: &BindingDomain,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<bool, Error> {
    let info = inspect_ciphertext(ciphertext)?;
    check_shape(info, domain)?;
    let current = keyring(keys, domain)?.current().clone();

    Ok(info.format_version != FORMAT_VERSION
        || info.suite_id != active_suite().id()
        || info.key_id != current.id()
        || info.padded != Some(padding.is_padded()))
}

/// Decrypts an envelope and encrypts it as `field` currently writes it.
///
/// The value is rewritten with the current format, active suite, current key,
/// and `padding`, so a sweep can enable or disable padding. A format 1 payload,
/// which does not record padding, is read with `padding`.
///
/// # Errors
///
/// Returns any decryption, padding, or encryption error.
pub fn reencrypt(
    field: FieldId,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Vec<u8>, Error> {
    let plaintext = decrypt_with_policy(field, padding, ciphertext, keys)?;

    encrypt(field, padding, &plaintext, keys)
}

#[cfg(test)]
fn seal_with_nonce(
    plaintext: &[u8],
    padded: bool,
    domain: &BindingDomain,
    key: &EncryptionKey,
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, Error> {
    let header = envelope_header(
        EXPERIMENTAL_XCHACHA20_POLY1305,
        padded,
        key.id(),
        domain.fingerprint(),
    );

    XCHACHA20_POLY1305_SUITE.seal_with_nonce(&header, plaintext, domain.as_bytes(), key, nonce)
}

/// Returns the key ID of an envelope that already passed structural validation.
// Offsets follow the layout table: ../docs/wire-format.md#envelope.
pub(crate) fn validated_key_id(bytes: &[u8]) -> KeyId {
    let offset = if bytes[4] == FORMAT_1_VERSION { 6 } else { 7 };
    let mut key_id = [0_u8; 16];
    key_id.copy_from_slice(&bytes[offset..offset + 16]);

    KeyId::from_bytes(key_id)
}

fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope<'_>, Error> {
    if !is_ciphertext(bytes) {
        return Err(Error::NotCiphertext);
    }

    // Too short for any format's header: malformed, whatever byte 4 claims.
    if bytes.len() < FORMAT_1_HEADER_LEN {
        return Err(Error::InvalidEnvelope);
    }

    // Offsets follow the layout table: ../docs/wire-format.md#envelope.
    let format_version = bytes[4];
    let (key_offset, flags) = match format_version {
        FORMAT_VERSION => (7, bytes[6]),
        FORMAT_1_VERSION => (6, 0),
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

    let suite_id = SuiteId::new(bytes[5]);
    registered_suite(suite_id)?.validate_payload(&bytes[header_len..])?;

    let padded = (format_version == FORMAT_VERSION).then_some(flags & FLAG_PADDED != 0);
    let mut key_id = [0_u8; 16];
    key_id.copy_from_slice(&bytes[key_offset..key_offset + 16]);
    let shape_fingerprint = (flags & FLAG_SCOPED != 0).then(|| {
        let mut fingerprint = [0_u8; FINGERPRINT_LEN];
        fingerprint.copy_from_slice(&bytes[HEADER_LEN..SCOPED_HEADER_LEN]);

        ShapeFingerprint::from_bytes(fingerprint)
    });

    Ok(ParsedEnvelope {
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

fn derive_encryption_key(
    root: &EncryptionKey,
    binding: &[u8],
    format_version: u8,
    suite_id: SuiteId,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    // Preserve this canonical order: changing it makes stored ciphertext unreadable.
    // See ../docs/wire-format.md#encryption-recipe.
    let mut info = Vec::with_capacity(ENCRYPTION_KEY_LABEL.len() + 18 + binding.len());
    info.extend_from_slice(ENCRYPTION_KEY_LABEL);
    info.push(format_version);
    info.push(suite_id.get());
    info.extend_from_slice(root.id().as_bytes());
    info.extend_from_slice(binding);

    hkdf_sha256_32(root.bytes(), &info)
}

fn envelope_aad(prefix: &[u8], binding: &[u8]) -> Vec<u8> {
    // Authenticate the exact stored prefix together with the caller's expected binding.
    // The envelope must not choose its own binding: ../docs/wire-format.md#encryption-recipe.
    let mut aad = Vec::with_capacity(ENVELOPE_AAD_LABEL.len() + prefix.len() + binding.len());
    aad.extend_from_slice(ENVELOPE_AAD_LABEL);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(binding);

    aad
}

fn validate_plaintext_len(len: usize) -> Result<(), Error> {
    let len = u64::try_from(len).map_err(|_| Error::MessageTooLong)?;

    if len > MAX_PLAINTEXT_LEN {
        return Err(Error::MessageTooLong);
    }

    Ok(())
}

impl XChaCha20Poly1305Suite {
    fn seal_with_nonce(
        &self,
        header: &[u8],
        plaintext: &[u8],
        binding: &[u8],
        key: &EncryptionKey,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Vec<u8>, Error> {
        validate_plaintext_len(plaintext.len())?;

        let nonce = XNonce::from(nonce);
        let mut prefix = Vec::with_capacity(header.len() + NONCE_LEN);
        prefix.extend_from_slice(header);
        prefix.extend_from_slice(&nonce);

        let operational_key = derive_encryption_key(key, binding, header[4], self.id())?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&operational_key[..]).map_err(|_| Error::Internal)?;
        let aad = envelope_aad(&prefix, binding);
        // The working copy can still contain plaintext if sealing fails; erase on every exit.
        // See ../docs/wire-format.md#key-and-buffer-lifetime.
        let mut sealed = Zeroizing::new(plaintext.to_vec());
        cipher
            .encrypt_in_place(&nonce, &aad, &mut *sealed)
            .map_err(|_| Error::Internal)?;

        let capacity = prefix
            .len()
            .checked_add(sealed.len())
            .ok_or(Error::MessageTooLong)?;
        let mut envelope = Vec::with_capacity(capacity);
        envelope.extend_from_slice(&prefix);
        envelope.extend_from_slice(&sealed);

        Ok(envelope)
    }
}

impl EncryptionSuite for XChaCha20Poly1305Suite {
    fn id(&self) -> SuiteId {
        EXPERIMENTAL_XCHACHA20_POLY1305
    }

    fn validate_payload(&self, payload: &[u8]) -> Result<(), Error> {
        let minimum_len = NONCE_LEN
            .checked_add(TAG_LEN)
            .ok_or(Error::InvalidEnvelope)?;

        if payload.len() < minimum_len {
            return Err(Error::InvalidEnvelope);
        }

        validate_plaintext_len(payload.len() - minimum_len)
    }

    fn seal(
        &self,
        header: &[u8],
        plaintext: &[u8],
        binding: &[u8],
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error> {
        // Fresh OS randomness avoids caller-managed nonce reuse; failure must stop encryption.
        // See ../docs/wire-format.md#encryption-recipe.
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

        self.seal_with_nonce(header, plaintext, binding, key, nonce)
    }

    fn open(
        &self,
        header: &[u8],
        payload: &[u8],
        binding: &[u8],
        key: &EncryptionKey,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate_payload(payload)?;

        let nonce: &XNonce = payload[..NONCE_LEN]
            .try_into()
            .map_err(|_| Error::InvalidEnvelope)?;
        let mut prefix = Vec::with_capacity(header.len() + NONCE_LEN);
        prefix.extend_from_slice(header);
        prefix.extend_from_slice(nonce);

        let operational_key = derive_encryption_key(key, binding, header[4], self.id())?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&operational_key[..]).map_err(|_| Error::Internal)?;
        let aad = envelope_aad(&prefix, binding);
        // Never return unauthenticated bytes, even if the AEAD mutates before failing.
        // Zeroizing also covers that error path: ../docs/wire-format.md#key-and-buffer-lifetime.
        let mut plaintext = Zeroizing::new(payload[NONCE_LEN..].to_vec());
        cipher
            .decrypt_in_place(nonce, &aad, &mut *plaintext)
            .map_err(|_| Error::AuthenticationFailed)?;

        Ok(plaintext)
    }
}

fn active_suite() -> &'static dyn EncryptionSuite {
    &XCHACHA20_POLY1305_SUITE
}

fn registered_suite(id: SuiteId) -> Result<&'static dyn EncryptionSuite, Error> {
    DECRYPTION_SUITES
        .iter()
        .copied()
        .find(|suite| suite.id() == id)
        .ok_or(Error::UnsupportedSuite(id))
}

fn envelope_header(
    suite_id: SuiteId,
    padded: bool,
    key_id: KeyId,
    shape_fingerprint: Option<ShapeFingerprint>,
) -> Vec<u8> {
    let mut flags = if padded { FLAG_PADDED } else { 0 };
    if shape_fingerprint.is_some() {
        flags |= FLAG_SCOPED;
    }

    let mut header = Vec::with_capacity(SCOPED_HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&[FORMAT_VERSION, suite_id.get(), flags]);
    header.extend_from_slice(key_id.as_bytes());
    if let Some(fingerprint) = shape_fingerprint {
        header.extend_from_slice(fingerprint.as_bytes());
    }

    header
}

pub(crate) fn hkdf_sha256_32(
    input_key_material: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    hkdf_sha256_32_with_salt(input_key_material, HKDF_SALT, info)
}

fn hkdf_sha256_32_with_salt(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let (mut pseudo_random_key, hkdf) = Hkdf::<Sha256>::extract(Some(salt), input_key_material);
    // HKDF retains keyed expansion state, so the separately returned PRK is no longer needed.
    // Keep outputs zeroizing too: ../docs/wire-format.md#key-and-buffer-lifetime.
    pseudo_random_key.as_mut_slice().zeroize();
    let mut output = Zeroizing::new([0_u8; 32]);

    hkdf.expand(info, &mut output[..])
        .map_err(|_| Error::Internal)?;

    Ok(output)
}

pub(crate) fn hmac_sha256(key: &[u8], input: &[&[u8]]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Internal)?;

    for component in input {
        hmac.update(component);
    }

    let digest = hmac.finalize();
    let mut output = Zeroizing::new([0_u8; 32]);
    output.copy_from_slice(digest.as_bytes());

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{
        NONCE_LEN, decrypt_bound, encrypt_bound, hkdf_sha256_32_with_salt, inspect_ciphertext,
        seal_with_nonce,
    };
    use crate::binding::{BindingShape, PartKind, PartRole, PartSpec, PartValue};
    use crate::{
        BindingDomain, EncryptionKey, EncryptionKeySource, EncryptionKeyring, Error, FieldId,
        KeyId, KeyScope, Padding,
    };

    const VECTOR_FIELD: FieldId =
        FieldId::from_uuid_literal("12345678-1234-4234-8234-1234567890ab");

    const TENANT: PartSpec = PartSpec::new([0x11; 16], PartKind::Uuid, PartRole::Keys);
    const WORKSPACE: PartSpec = PartSpec::new([0x22; 16], PartKind::Bytes, PartRole::Bound);
    const SCOPE: [PartSpec; 2] = [TENANT, WORKSPACE];

    fn vector_key() -> EncryptionKey {
        EncryptionKey::new(
            KeyId::from_uuid_literal("11111111-2222-4333-8444-555555555555"),
            [0x11; 32],
        )
    }

    fn vector_nonce() -> [u8; NONCE_LEN] {
        let mut nonce = [0_u8; NONCE_LEN];

        for (value, byte) in nonce.iter_mut().zip(0_u8..) {
            *value = byte;
        }

        nonce
    }

    fn keyring() -> EncryptionKeyring {
        EncryptionKeyring::new(vector_key(), []).unwrap()
    }

    fn scope(workspace: &[u8], record: Option<PartValue<'_>>) -> BindingDomain {
        BindingDomain::scoped(
            VECTOR_FIELD,
            BindingShape::new(&SCOPE, record.is_some()),
            &[PartValue::Uuid([0x33; 16]), PartValue::Bytes(workspace)],
            record,
        )
        .unwrap()
    }

    #[test]
    fn scoped_vector_is_stable() {
        let domain = scope(b"ws-1", None);
        let envelope = seal_with_nonce(
            b"cryptbox vector",
            false,
            &domain,
            &vector_key(),
            vector_nonce(),
        )
        .unwrap();

        assert_eq!(hex::encode(domain.as_bytes()), SCOPED_BINDING);
        assert_eq!(
            hex::encode(&envelope[..55]),
            concat!(
                "4342580002010211111111222243338444555555555555",
                // Shape fingerprint, then the nonce.
                "cda083fe6eae1bf1",
                "000102030405060708090a0b0c0d0e0f1011121314151617",
            )
        );
        assert_eq!(hex::encode(envelope), SCOPED_VECTOR);
    }

    #[test]
    fn scoped_record_vector_is_stable() {
        let domain = scope(b"ws-1", Some(PartValue::I64(7)));
        let envelope = seal_with_nonce(
            b"cryptbox vector",
            false,
            &domain,
            &vector_key(),
            vector_nonce(),
        )
        .unwrap();

        assert_eq!(hex::encode(domain.as_bytes()), SCOPED_RECORD_BINDING);
        assert_eq!(hex::encode(&envelope[23..31]), "505a9cd2bc286636");
        assert_eq!(hex::encode(envelope), SCOPED_RECORD_VECTOR);
    }

    // docs/wire-format.md#provisional-scoped-vectors
    const SCOPED_BINDING: &str = "02123456781234423482341234567890ab0000021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31";
    const SCOPED_RECORD_BINDING: &str = "02123456781234423482341234567890ab0200000008000000000000000700021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31";
    const SCOPED_VECTOR: &str = "4342580002010211111111222243338444555555555555cda083fe6eae1bf1000102030405060708090a0b0c0d0e0f1011121314151617b51d411fdf173c5725d9000dae571d2bc413649bd09198dd576ab7879aeb42";
    const SCOPED_RECORD_VECTOR: &str = "4342580002010211111111222243338444555555555555505a9cd2bc286636000102030405060708090a0b0c0d0e0f10111213141516172619b76ce657aac8910c65d99b49a02880a201078edb80702123597f908f71";

    #[test]
    fn scoped_vectors_decrypt_under_their_binding() {
        for (vector, domain) in [
            (SCOPED_VECTOR, scope(b"ws-1", None)),
            (
                SCOPED_RECORD_VECTOR,
                scope(b"ws-1", Some(PartValue::I64(7))),
            ),
        ] {
            let envelope = hex::decode(vector).unwrap();

            assert_eq!(
                decrypt_bound(&domain, Padding::NONE, &envelope, &keyring())
                    .unwrap()
                    .as_slice(),
                b"cryptbox vector"
            );
        }
    }

    #[test]
    fn scoped_value_round_trips_and_reports_its_fingerprint() {
        let domain = scope(b"ws-1", Some(PartValue::I64(7)));
        let envelope = encrypt_bound(&domain, Padding::NONE, b"secret", &keyring()).unwrap();

        assert_eq!(
            inspect_ciphertext(&envelope).unwrap().shape_fingerprint(),
            domain.fingerprint()
        );
        assert_eq!(
            decrypt_bound(&domain, Padding::NONE, &envelope, &keyring())
                .unwrap()
                .as_slice(),
            b"secret"
        );
    }

    #[test]
    fn field_only_envelopes_carry_no_fingerprint() {
        let domain = BindingDomain::field(VECTOR_FIELD);
        let envelope = encrypt_bound(&domain, Padding::NONE, b"secret", &keyring()).unwrap();

        assert_eq!(envelope.len(), 47 + 6 + 16);
        assert_eq!(
            inspect_ciphertext(&envelope).unwrap().shape_fingerprint(),
            None
        );
    }

    #[test]
    fn different_values_fail_authentication() {
        let envelope = encrypt_bound(
            &scope(b"ws-1", Some(PartValue::I64(7))),
            Padding::NONE,
            b"secret",
            &keyring(),
        )
        .unwrap();

        for (case, reader) in [
            ("part value", scope(b"ws-2", Some(PartValue::I64(7)))),
            ("record", scope(b"ws-1", Some(PartValue::I64(8)))),
            (
                "record kind",
                scope(b"ws-1", Some(PartValue::Uuid([7; 16]))),
            ),
        ] {
            assert_eq!(
                decrypt_bound(&reader, Padding::NONE, &envelope, &keyring()).unwrap_err(),
                Error::AuthenticationFailed,
                "{case}"
            );
        }
    }

    #[test]
    fn a_different_shape_reports_binding_mismatch() {
        let field_only = BindingDomain::field(VECTOR_FIELD);
        let scoped = scope(b"ws-1", None);
        let with_record = scope(b"ws-1", Some(PartValue::I64(7)));
        let field_only_envelope =
            encrypt_bound(&field_only, Padding::NONE, b"secret", &keyring()).unwrap();
        let scoped_envelope = encrypt_bound(&scoped, Padding::NONE, b"secret", &keyring()).unwrap();

        for (case, reader, envelope) in [
            ("FieldOnly reads scoped", &field_only, &scoped_envelope),
            ("scoped reads FieldOnly", &scoped, &field_only_envelope),
            ("record flag", &with_record, &scoped_envelope),
        ] {
            assert_eq!(
                decrypt_bound(reader, Padding::NONE, envelope, &keyring()).unwrap_err(),
                Error::BindingMismatch,
                "{case}"
            );
        }
    }

    #[test]
    fn a_changed_fingerprint_reports_binding_mismatch_before_key_lookup() {
        struct NoKeys;

        impl EncryptionKeySource for NoKeys {
            fn encryption_keyring(
                &self,
                _: FieldId,
                _: &KeyScope,
            ) -> Result<EncryptionKeyring, Error> {
                Err(Error::KeysUnavailable)
            }
        }

        let domain = scope(b"ws-1", None);
        let mut envelope = encrypt_bound(&domain, Padding::NONE, b"secret", &keyring()).unwrap();
        envelope[23] ^= 1;

        assert_eq!(
            decrypt_bound(&domain, Padding::NONE, &envelope, &NoKeys).unwrap_err(),
            Error::BindingMismatch
        );
    }

    #[test]
    fn a_resealed_fingerprint_fails_authentication() {
        // A role change keeps the binding bytes but changes the fingerprint.
        let index_tenant = PartSpec::new([0x11; 16], PartKind::Uuid, PartRole::Index);
        let reader_shape = [index_tenant, WORKSPACE];
        let reader = BindingDomain::scoped(
            VECTOR_FIELD,
            BindingShape::new(&reader_shape, false),
            &[PartValue::Uuid([0x33; 16]), PartValue::Bytes(b"ws-1")],
            None,
        )
        .unwrap();
        let writer = scope(b"ws-1", None);
        assert_eq!(reader.as_bytes(), writer.as_bytes());

        let mut envelope = encrypt_bound(&writer, Padding::NONE, b"secret", &keyring()).unwrap();
        envelope[23..31].copy_from_slice(reader.fingerprint().unwrap().as_bytes());

        assert_eq!(
            decrypt_bound(&reader, Padding::NONE, &envelope, &keyring()).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn hkdf_matches_rfc_5869_case_one() {
        let input_key_material = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let output = hkdf_sha256_32_with_salt(&input_key_material, &salt, &info).unwrap();

        assert_eq!(
            hex::encode(output.as_slice()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn experimental_padded_format_2_vector_is_stable() {
        let key = EncryptionKey::new(
            KeyId::from_uuid_literal("11111111-2222-4333-8444-555555555555"),
            [0x11; 32],
        );
        let mut nonce = [0_u8; NONCE_LEN];

        for (value, byte) in nonce.iter_mut().zip(0_u8..) {
            *value = byte;
        }

        let envelope = seal_with_nonce(
            b"cryptbox vector\x80",
            true,
            &BindingDomain::field(VECTOR_FIELD),
            &key,
            nonce,
        )
        .unwrap();

        assert_eq!(
            hex::encode(envelope),
            "4342580002010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f10111213141516173f7195595232290da92d72b42bb6fd489a56ec6e125f07deaa76f7502ad2613f"
        );
    }

    #[test]
    fn experimental_format_2_vector_is_stable() {
        let key = EncryptionKey::new(
            KeyId::from_uuid_literal("11111111-2222-4333-8444-555555555555"),
            [0x11; 32],
        );
        let mut nonce = [0_u8; NONCE_LEN];

        for (value, byte) in nonce.iter_mut().zip(0_u8..) {
            *value = byte;
        }

        let envelope = seal_with_nonce(
            b"cryptbox vector",
            false,
            &BindingDomain::field(VECTOR_FIELD),
            &key,
            nonce,
        )
        .unwrap();

        assert_eq!(
            hex::encode(envelope),
            "4342580002010011111111222243338444555555555555000102030405060708090a0b0c0d0e0f10111213141516173f7195595232290da92d72b42bb6fd4f8e9c4e8454cd34732e7966a50994cd"
        );
    }
}
