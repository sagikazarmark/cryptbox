use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{Binding, BindingDomain, EncryptionKey, EncryptionKeyProvider, Error, KeyId, SuiteId};

const MAGIC: &[u8; 4] = b"CBX\0";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 22;
const NONCE_LEN: usize = 24;
const PREFIX_LEN: usize = HEADER_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;
const MAX_PLAINTEXT_LEN: u64 = 274_877_906_880;

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
    key_id: KeyId,
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

    /// Returns the encryption-key generation named by the envelope.
    #[must_use]
    pub const fn key_id(self) -> KeyId {
        self.key_id
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
        domain: &BindingDomain,
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error>;

    fn open(
        &self,
        header: &[u8],
        payload: &[u8],
        domain: &BindingDomain,
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
/// # Errors
///
/// Returns a structured error when the envelope is malformed or unsupported.
pub fn inspect_ciphertext(bytes: &[u8]) -> Result<CiphertextInfo, Error> {
    parse_envelope(bytes).map(|parsed| parsed.info)
}

/// Encrypts opaque plaintext bytes with the provider's current key.
///
/// # Errors
///
/// Returns an error for unavailable keys, failed OS randomness, or messages
/// beyond the suite limit.
pub fn encrypt<B: Binding>(
    plaintext: &[u8],
    context: &B::Context,
    keys: &dyn EncryptionKeyProvider,
) -> Result<Vec<u8>, Error> {
    let key = keys.current_key()?;
    let suite = active_suite();
    let header = envelope_header(suite.id(), key.id());
    suite.seal(
        &header,
        plaintext,
        &BindingDomain::from_binding::<B>(context),
        &key,
    )
}

/// Authenticates and decrypts opaque ciphertext bytes.
///
/// The provider is asked only for the exact key ID named by the envelope.
///
/// # Errors
///
/// Returns a structured envelope, key-provider, unknown-key, or authentication
/// error. Wrong binding and modified ciphertext both report authentication
/// failure.
pub fn decrypt<B: Binding>(
    ciphertext: &[u8],
    context: &B::Context,
    keys: &dyn EncryptionKeyProvider,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let parsed = parse_envelope(ciphertext)?;
    let key = keys
        .key(parsed.info.key_id)?
        .ok_or(Error::UnknownEncryptionKey(parsed.info.key_id))?;
    let domain = BindingDomain::from_binding::<B>(context);
    registered_suite(parsed.info.suite_id)?.open(parsed.header, parsed.suite_payload, &domain, &key)
}

/// Reports whether an envelope does not use the active suite or current key.
///
/// This reads unauthenticated metadata and does not decrypt the payload.
///
/// # Errors
///
/// Returns an error for malformed envelopes or unavailable providers.
pub fn needs_reencryption(
    ciphertext: &[u8],
    keys: &dyn EncryptionKeyProvider,
) -> Result<bool, Error> {
    let info = inspect_ciphertext(ciphertext)?;
    let current = keys.current_key()?;

    Ok(info.suite_id != active_suite().id() || info.key_id != current.id())
}

/// Decrypts an envelope and encrypts it with the active suite and current key.
///
/// # Errors
///
/// Returns any decryption or encryption error.
pub fn reencrypt<B: Binding>(
    ciphertext: &[u8],
    context: &B::Context,
    keys: &dyn EncryptionKeyProvider,
) -> Result<Vec<u8>, Error> {
    let plaintext = decrypt::<B>(ciphertext, context, keys)?;
    encrypt::<B>(&plaintext, context, keys)
}

#[cfg(test)]
fn seal_with_nonce(
    plaintext: &[u8],
    domain: BindingDomain,
    key: &EncryptionKey,
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, Error> {
    let header = envelope_header(EXPERIMENTAL_XCHACHA20_POLY1305, key.id());
    XCHACHA20_POLY1305_SUITE.seal_with_nonce(&header, plaintext, &domain, key, nonce)
}

fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope<'_>, Error> {
    if !is_ciphertext(bytes) {
        return Err(Error::NotCiphertext);
    }
    if bytes.len() < HEADER_LEN {
        return Err(Error::InvalidEnvelope);
    }
    if bytes[4] != FORMAT_VERSION {
        return Err(Error::UnsupportedFormatVersion(bytes[4]));
    }

    let suite_id = SuiteId::new(bytes[5]);
    registered_suite(suite_id)?.validate_payload(&bytes[HEADER_LEN..])?;

    let mut key_id = [0_u8; 16];
    key_id.copy_from_slice(&bytes[6..HEADER_LEN]);

    Ok(ParsedEnvelope {
        info: CiphertextInfo {
            format_version: FORMAT_VERSION,
            suite_id,
            key_id: KeyId::from_bytes(key_id),
        },
        header: &bytes[..HEADER_LEN],
        suite_payload: &bytes[HEADER_LEN..],
    })
}

fn derive_encryption_key(
    root: &EncryptionKey,
    domain: &BindingDomain,
    suite_id: SuiteId,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut info = Vec::with_capacity(ENCRYPTION_KEY_LABEL.len() + 18 + domain.as_bytes().len());
    info.extend_from_slice(ENCRYPTION_KEY_LABEL);
    info.push(FORMAT_VERSION);
    info.push(suite_id.get());
    info.extend_from_slice(root.id().as_bytes());
    info.extend_from_slice(domain.as_bytes());

    hkdf_sha256_32(root.bytes(), &info)
}

fn envelope_aad(prefix: &[u8], domain: &BindingDomain) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(ENVELOPE_AAD_LABEL.len() + prefix.len() + domain.as_bytes().len());
    aad.extend_from_slice(ENVELOPE_AAD_LABEL);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(domain.as_bytes());
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
        domain: &BindingDomain,
        key: &EncryptionKey,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Vec<u8>, Error> {
        validate_plaintext_len(plaintext.len())?;
        let mut prefix = Vec::with_capacity(PREFIX_LEN);
        prefix.extend_from_slice(header);
        prefix.extend_from_slice(&nonce);

        let operational_key = derive_encryption_key(key, domain, self.id())?;
        let cipher = XChaCha20Poly1305::new_from_slice(&operational_key[..])
            .map_err(|_| Error::InvalidEnvelope)?;
        let aad = envelope_aad(&prefix, domain);
        let mut sealed = Zeroizing::new(plaintext.to_vec());
        cipher
            .encrypt_in_place(XNonce::from_slice(&nonce), &aad, &mut *sealed)
            .map_err(|_| Error::MessageTooLong)?;

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
        domain: &BindingDomain,
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, Error> {
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
        self.seal_with_nonce(header, plaintext, domain, key, nonce)
    }

    fn open(
        &self,
        header: &[u8],
        payload: &[u8],
        domain: &BindingDomain,
        key: &EncryptionKey,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate_payload(payload)?;
        let nonce: &[u8; NONCE_LEN] = payload[..NONCE_LEN]
            .try_into()
            .map_err(|_| Error::InvalidEnvelope)?;
        let mut prefix = Vec::with_capacity(PREFIX_LEN);
        prefix.extend_from_slice(header);
        prefix.extend_from_slice(nonce);

        let operational_key = derive_encryption_key(key, domain, self.id())?;
        let cipher = XChaCha20Poly1305::new_from_slice(&operational_key[..])
            .map_err(|_| Error::InvalidEnvelope)?;
        let aad = envelope_aad(&prefix, domain);
        let mut plaintext = Zeroizing::new(payload[NONCE_LEN..].to_vec());
        cipher
            .decrypt_in_place(XNonce::from_slice(nonce), &aad, &mut *plaintext)
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

fn envelope_header(suite_id: SuiteId, key_id: KeyId) -> [u8; HEADER_LEN] {
    let mut header = [0_u8; HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4] = FORMAT_VERSION;
    header[5] = suite_id.get();
    header[6..].copy_from_slice(key_id.as_bytes());
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
    let pseudo_random_key = hmac_sha256(salt, &[input_key_material])?;
    hmac_sha256(&pseudo_random_key[..], &[info, &[1]])
}

pub(crate) fn hmac_sha256(key: &[u8], input: &[&[u8]]) -> Result<Zeroizing<[u8; 32]>, Error> {
    const BLOCK_LEN: usize = 64;
    if key.len() > BLOCK_LEN {
        return Err(Error::InvalidEnvelope);
    }

    let mut pad = Zeroizing::new([0_u8; BLOCK_LEN]);
    pad[..key.len()].copy_from_slice(key);
    for byte in pad.iter_mut() {
        *byte ^= 0x36;
    }

    let mut inner = Sha256::new();
    inner.update(&pad[..]);
    for component in input {
        inner.update(component);
    }
    let mut inner_digest = inner.finalize();

    for byte in pad.iter_mut() {
        *byte ^= 0x36 ^ 0x5c;
    }
    let mut outer = Sha256::new();
    outer.update(&pad[..]);
    outer.update(&inner_digest[..]);
    let mut digest = outer.finalize();

    let mut output = Zeroizing::new([0_u8; 32]);
    output.copy_from_slice(&digest);
    inner_digest.as_mut_slice().zeroize();
    digest.as_mut_slice().zeroize();
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{NONCE_LEN, hkdf_sha256_32_with_salt, seal_with_nonce};
    use crate::{BindingDomain, EncryptionKey, Field, FieldBound, FieldId, KeyId};

    struct VectorField;

    impl Field for VectorField {
        const ID: FieldId = FieldId::from_uuid_literal("12345678-1234-4234-8234-1234567890ab");
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
    fn experimental_envelope_vector_is_stable() {
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
            BindingDomain::from_binding::<crate::Unbound>(&()),
            &key,
            nonce,
        )
        .unwrap();

        assert_eq!(
            hex::encode(envelope),
            "43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f1011121314151617c5ecf67a1ebf136378025485a1e4b961044c53838d7bf1c05cc81b81ae89d5"
        );
    }

    #[test]
    fn experimental_field_bound_envelope_vector_is_stable() {
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
            BindingDomain::from_binding::<FieldBound<VectorField>>(&()),
            &key,
            nonce,
        )
        .unwrap();

        assert_eq!(
            hex::encode(envelope),
            "43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f101112131415161790fc94db1267819912c4b5abc48bfceb1074e9691ed9f65c6b1ee8ddf1219d"
        );
    }
}
