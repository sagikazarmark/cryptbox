//! Public-boundary tests for explicit ciphertext Serde representations.

#![cfg(any(feature = "json", feature = "postcard"))]

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Encrypted,
    EncryptionKey, EncryptionProfile, GlobalKeyContext, IndexId, LocalBlindIndexKeyring,
    LocalEncryptionKeyring, Unbound, Utf8, derive_blind_index, index_id, index_key_id, key_id,
};
#[cfg(feature = "json")]
use serde_json::Value;
use zeroize::Zeroizing;

struct EmailProfile;

impl EncryptionProfile<String> for EmailProfile {
    type Binding = Unbound;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = cryptbox::NoPadding;
}

struct EmailExact;

impl BlindIndexMetadata for EmailExact {
    const ID: IndexId = index_id!("a0000000-0000-4000-8000-00000000000a");
    const BITS: usize = 128;
}

impl BlindIndexSpec<str> for EmailExact {
    fn normalize(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(input.as_bytes().to_vec()))
    }
}

fn blind_index() -> BlindIndex<EmailExact> {
    let keys = LocalBlindIndexKeyring::new(
        BlindIndexKey::new(
            index_key_id!("70000000-0000-4000-8000-000000000007"),
            [41; 32],
        ),
        [],
    )
    .unwrap();

    derive_blind_index::<EmailExact, str, Unbound>("mark@example.com", &(), &keys).unwrap()
}

fn encryption_keys() -> LocalEncryptionKeyring {
    LocalEncryptionKeyring::new(
        EncryptionKey::new(key_id!("20000000-0000-4000-8000-000000000002"), [7; 32]),
        [],
    )
    .unwrap()
}

fn ciphertext(keys: &LocalEncryptionKeyring) -> cryptbox::Ciphertext<String, EmailProfile> {
    Encrypted::<_, EmailProfile>::new("mark@example.com".to_owned())
        .encrypt_with(&(), keys)
        .unwrap()
}

#[cfg(feature = "json")]
fn json_bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| u8::try_from(byte.as_u64().unwrap()).unwrap())
        .collect()
}

#[test]
#[cfg(feature = "json")]
fn ciphertext_serde_round_trips_only_the_envelope_bytes() {
    let keys = encryption_keys();
    let ciphertext = ciphertext(&keys);

    let json = serde_json::to_string(&ciphertext).unwrap();
    assert!(!json.contains("mark@example.com"));
    assert_eq!(
        json_bytes(&serde_json::from_str(&json).unwrap()),
        ciphertext.as_bytes()
    );

    let restored = serde_json::from_str(&json).unwrap();
    assert_eq!(ciphertext, restored);
    assert_eq!(
        restored.decrypt_with(&(), &keys).unwrap().expose_secret(),
        "mark@example.com"
    );
}

#[test]
#[cfg(feature = "json")]
fn ciphertext_serde_rejects_malformed_envelopes() {
    let error =
        serde_json::from_str::<cryptbox::Ciphertext<String, EmailProfile>>("[1,2,3]").unwrap_err();

    assert!(
        error
            .to_string()
            .contains("input is not CryptBox ciphertext")
    );
}

#[test]
#[cfg(feature = "json")]
fn blind_index_serde_round_trips_only_the_stored_bytes() {
    let index = blind_index();

    let json = serde_json::to_string(&index).unwrap();
    assert!(!json.contains("mark@example.com"));
    assert_eq!(
        json_bytes(&serde_json::from_str(&json).unwrap()),
        index.as_bytes()
    );

    let restored: BlindIndex<EmailExact> = serde_json::from_str(&json).unwrap();
    assert_eq!(index, restored);
}

#[test]
#[cfg(feature = "json")]
fn blind_index_serde_rejects_noncanonical_values() {
    let mut bytes = blind_index().into_bytes();
    bytes[17..19].copy_from_slice(&64_u16.to_be_bytes());
    let json = serde_json::to_string(&bytes).unwrap();

    let error = serde_json::from_str::<BlindIndex<EmailExact>>(&json).unwrap_err();
    assert!(error.to_string().contains("blind index is invalid"));
}

#[test]
#[cfg(feature = "postcard")]
fn binary_serde_round_trips_ciphertext_and_blind_index_bytes() {
    let ciphertext = ciphertext(&encryption_keys());
    let index = blind_index();

    let bytes = postcard::to_allocvec(&(ciphertext.clone(), index.clone())).unwrap();
    let restored: (
        cryptbox::Ciphertext<String, EmailProfile>,
        BlindIndex<EmailExact>,
    ) = postcard::from_bytes(&bytes).unwrap();

    assert_eq!(restored, (ciphertext, index));
}
