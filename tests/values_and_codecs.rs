//! Public-boundary tests for typed values and codecs.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use cryptbox::{Codec, Encrypted, EncryptionProfile, GlobalKeyContext, Raw, Secret, Unbound, Utf8};
use zeroize::Zeroize;

struct ExampleProfile;

impl EncryptionProfile<String> for ExampleProfile {
    type Binding = Unbound;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = cryptbox::NoPadding;
}

#[test]
fn encrypted_values_require_explicit_plaintext_access() {
    let value = Encrypted::<_, ExampleProfile>::new("mark@example.com".to_owned());

    assert_eq!(value.expose_secret(), "mark@example.com");
    assert_eq!(format!("{value:?}"), "Encrypted([REDACTED])");
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
