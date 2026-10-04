//! Public-boundary tests for explicit sealed-value Serde representations.

#![cfg(feature = "serde")]

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, IndexId, Padding, Seal, Sealed, Utf8, index_id, index_key_id, key_id,
};
#[cfg(feature = "json")]
use serde_json::Value;
use zeroize::Zeroizing;

struct EmailSeal;

impl Seal for EmailSeal {
    const ID: cryptbox::SealId = cryptbox::seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct EmailExact;

impl BlindIndexSpec for EmailExact {
    type Seal = EmailSeal;
    const ID: IndexId = index_id!("a0000000-0000-4000-8000-00000000000a");
    const BITS: u16 = 128;
    const NORMALIZER: &'static str = "exact/1";
    type Query = str;

    fn normalize_query(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(input.as_bytes().to_vec()))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

fn blind_index() -> BlindIndex<EmailExact> {
    let keys = BlindIndexKeyring::new(
        BlindIndexKey::new(
            index_key_id!("70000000-0000-4000-8000-000000000007"),
            [41; 32],
        ),
        [],
    )
    .unwrap();

    BlindIndex::<EmailExact>::derive(&"mark@example.com".to_owned(), &keys).unwrap()
}

fn encryption_keys() -> EncryptionKeyring {
    EncryptionKeyring::new(
        EncryptionKey::new(key_id!("20000000-0000-4000-8000-000000000002"), [7; 32]),
        [],
    )
    .unwrap()
}

fn sealed(keys: &EncryptionKeyring) -> Sealed<EmailSeal> {
    Sealed::seal(&"mark@example.com".to_owned(), keys).unwrap()
}

/// The bytes of a JSON form: unpadded base64url text.
#[cfg(feature = "json")]
fn json_bytes(value: &Value) -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
}

#[test]
#[cfg(feature = "json")]
fn sealed_serde_round_trips_only_the_envelope_bytes() {
    let keys = encryption_keys();
    let sealed = sealed(&keys);

    let json = serde_json::to_string(&sealed).unwrap();
    assert!(!json.contains("mark@example.com"));
    assert_eq!(
        json_bytes(&serde_json::from_str(&json).unwrap()),
        sealed.as_bytes()
    );

    let restored: Sealed<EmailSeal> = serde_json::from_str(&json).unwrap();
    assert_eq!(sealed, restored);
    assert_eq!(restored.open(&keys).unwrap(), "mark@example.com");
}

#[test]
#[cfg(feature = "json")]
fn json_reads_the_byte_array_form_too() {
    let keys = encryption_keys();
    let sealed = sealed(&keys);
    let index = blind_index();

    let array = serde_json::to_string(sealed.as_bytes()).unwrap();
    assert_eq!(
        serde_json::from_str::<Sealed<EmailSeal>>(&array).unwrap(),
        sealed
    );
    let array = serde_json::to_string(index.as_bytes()).unwrap();
    assert_eq!(
        serde_json::from_str::<BlindIndex<EmailExact>>(&array).unwrap(),
        index
    );
}

#[test]
#[cfg(feature = "json")]
fn json_rejects_other_spellings_of_the_text_form() {
    let sealed = sealed(&encryption_keys());
    let text: String = serde_json::from_value(serde_json::to_value(&sealed).unwrap()).unwrap();
    let other = [
        ("padded", format!("\"{text}==\"")),
        (
            "outside the url-safe alphabet",
            format!("\"+{}\"", &text[1..]),
        ),
        ("not base64", "\"not base64!\"".to_owned()),
    ];

    for (case, json) in other {
        assert!(
            serde_json::from_str::<Sealed<EmailSeal>>(&json).is_err(),
            "{case}"
        );
    }
}

/// The seal of the envelope vectors: docs/wire-format.md#envelope-vectors.
#[cfg(feature = "json")]
struct VectorSeal;

#[cfg(feature = "json")]
impl Seal for VectorSeal {
    const ID: cryptbox::SealId = cryptbox::seal_id!("12345678-1234-4234-8234-1234567890ab");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

// docs/wire-format.md#text-form: the unpadded envelope vector, as text.
// Independently encoded from the documented envelope bytes.
#[cfg(feature = "json")]
const VECTOR_TEXT: &str = "Q0JYAAIBABEREREiIkMzhERVVVVVVVVQLej8-4OMgAABAgMEBQYHCAkKCwwNDg8QERITFBUWFzqOBYgDci9WsP_J7Lu34wYkxEQjnGLXO-Xqx0WcVI8";

#[test]
#[cfg(feature = "json")]
fn the_text_form_is_unpadded_base64url() {
    let envelope = hex::decode(concat!(
        "4342580002010011111111222243338444555555555555502de8fcfb838c80",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "3a8e058803722f56b0ffc9ecbbb7e30624c444239c62d73be5eac7459c548f",
    ))
    .unwrap();
    let sealed = Sealed::<VectorSeal>::from_bytes(envelope).unwrap();
    let keys = EncryptionKeyring::new(
        EncryptionKey::new(key_id!("11111111-2222-4333-8444-555555555555"), [0x11; 32]),
        [],
    )
    .unwrap();

    assert_eq!(
        serde_json::to_string(&sealed).unwrap(),
        format!("\"{VECTOR_TEXT}\"")
    );
    let read: Sealed<VectorSeal> = serde_json::from_str(&format!("\"{VECTOR_TEXT}\"")).unwrap();
    assert_eq!(read, sealed);
    assert_eq!(read.open(&keys).unwrap(), "cryptbox vector");
}

#[test]
#[cfg(feature = "json")]
fn the_text_form_rejects_other_base64_spellings() {
    let other = [
        // 86 bytes leave a 3-character final group, padded with one `=`.
        ("padded", format!("{VECTOR_TEXT}=")),
        (
            "standard alphabet",
            VECTOR_TEXT.replace('-', "+").replace('_', "/"),
        ),
        (
            "nonzero unused bits",
            format!("{}9", &VECTOR_TEXT[..VECTOR_TEXT.len() - 1]),
        ),
        ("whitespace", format!("{VECTOR_TEXT}\\n")),
    ];

    for (case, text) in other {
        assert!(
            serde_json::from_str::<Sealed<VectorSeal>>(&format!("\"{text}\"")).is_err(),
            "{case}"
        );
    }
}

#[test]
#[cfg(feature = "json")]
fn sealed_serde_rejects_malformed_envelopes() {
    let error = serde_json::from_str::<Sealed<EmailSeal>>("[1,2,3]").unwrap_err();

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
fn binary_serde_round_trips_sealed_and_blind_index_bytes() {
    let sealed = sealed(&encryption_keys());
    let index = blind_index();

    let bytes = postcard::to_allocvec(&(sealed.clone(), index.clone())).unwrap();
    let restored: (Sealed<EmailSeal>, BlindIndex<EmailExact>) =
        postcard::from_bytes(&bytes).unwrap();

    assert_eq!(restored, (sealed, index));
}

#[test]
fn stored_values_convert_to_and_from_their_bytes() {
    let sealed = sealed(&encryption_keys());
    let index = blind_index();

    let bytes: Vec<u8> = sealed.clone().into();
    assert_eq!(Sealed::<EmailSeal>::try_from(bytes).unwrap(), sealed);
    let bytes: Vec<u8> = index.clone().into();
    assert_eq!(BlindIndex::<EmailExact>::try_from(bytes).unwrap(), index);
}
