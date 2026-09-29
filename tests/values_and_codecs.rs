//! Public-boundary tests for typed values and codecs.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use cryptbox::{Codec, FieldOnly, Padding, Plain, Raw, Seal, Secret, Utf8};
use zeroize::Zeroize;

struct ExampleField;

impl Seal for ExampleField {
    const ID: cryptbox::SealId = cryptbox::seal_id!("7c1e6a52-0d3b-4f8e-9a61-2b5c4d7e8f90");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
    type Indexes = ();
}

#[test]
fn plain_values_require_explicit_plaintext_access() {
    let value = Plain::<ExampleField>::new("mark@example.com".to_owned());

    assert_eq!(value.expose_secret(), "mark@example.com");
    assert_eq!(format!("{value:?}"), "Plain([REDACTED])");
}

/// Generic over the column keys without bounding them: only the `SQLx` column
/// needs `K: ColumnKeys`.
struct Record<K> {
    email: Plain<ExampleField, K>,
}

impl<K> Record<K> {
    fn new(email: &str) -> Self {
        Self {
            email: Plain::new(email),
        }
    }

    fn with_column_keys<K2>(self) -> Record<K2> {
        Record {
            email: self.email.with_column_keys(),
        }
    }
}

#[test]
fn column_keys_bounds_do_not_spread_into_user_generics() {
    struct Unrelated;

    let record = Record::<()>::new("mark@example.com").with_column_keys::<Unrelated>();

    assert_eq!(record.email.clone().expose_secret(), "mark@example.com");
    assert_eq!(format!("{:?}", record.email), "Plain([REDACTED])");
}

#[test]
fn built_in_byte_codecs_round_trip_owned_values() {
    let encoded = <Utf8 as Codec<String>>::encode(&"Zażółć".to_owned()).unwrap();
    assert_eq!(<Utf8 as Codec<String>>::decode(&encoded).unwrap(), "Zażółć");

    let bytes = vec![0, 1, 2, 255];
    let encoded = <Raw as Codec<Vec<u8>>>::encode(&bytes).unwrap();
    assert_eq!(<Raw as Codec<Vec<u8>>>::decode(&encoded).unwrap(), bytes);
}

#[derive(Clone)]
struct ZeroizeProbe {
    dropped: Arc<AtomicBool>,
}

impl Zeroize for ZeroizeProbe {
    fn zeroize(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn secret_redacts_and_zeroizes_its_value_on_drop() {
    let dropped = Arc::new(AtomicBool::new(false));
    let secret = Secret::new(ZeroizeProbe {
        dropped: Arc::clone(&dropped),
    });

    assert!(!secret.expose_secret().dropped.load(Ordering::SeqCst));
    assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
    drop(secret);
    assert!(dropped.load(Ordering::SeqCst));
}

#[cfg(feature = "json")]
#[test]
fn json_codec_round_trips_serde_values() {
    use cryptbox::Json;

    let value = vec!["alpha".to_owned(), "beta".to_owned()];
    let encoded = <Json as Codec<Vec<String>>>::encode(&value).unwrap();

    assert_eq!(
        <Json as Codec<Vec<String>>>::decode(&encoded).unwrap(),
        value
    );
}

#[cfg(feature = "postcard")]
#[test]
fn postcard_codec_round_trips_serde_values() {
    use cryptbox::Postcard;

    let value = vec![1_u32, 2, 3];
    let encoded = <Postcard as Codec<Vec<u32>>>::encode(&value).unwrap();

    assert_eq!(
        <Postcard as Codec<Vec<u32>>>::decode(&encoded).unwrap(),
        value
    );
}

#[cfg(feature = "postcard")]
#[test]
fn postcard_codec_rejects_trailing_bytes_after_a_valid_value() {
    use cryptbox::{CodecErrorKind, Postcard};

    let encoded = <Postcard as Codec<Vec<u32>>>::encode(&vec![1_u32, 2, 3]).unwrap();

    for trailing in [&[0][..], &[0x80, 0, 0, 0], &[1, 2, 3]] {
        let mut bytes = encoded.to_vec();
        bytes.extend_from_slice(trailing);

        assert_eq!(
            <Postcard as Codec<Vec<u32>>>::decode(&bytes)
                .unwrap_err()
                .kind(),
            CodecErrorKind::Decoding,
            "trailing bytes {trailing:?} were accepted",
        );
    }
}
