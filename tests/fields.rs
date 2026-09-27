//! Public-boundary tests for field markers over application value types.

use cryptbox::{
    Codec, CodecError, CodecErrorKind, EncryptionKey, Error, Field, FieldId, FieldOnly, IndexId,
    LocalEncryptionKeyring, Padding, Plaintext, Raw, Sealed, Secret, Utf8, field_id, index_id,
};
use zeroize::Zeroizing;

fn keyring() -> LocalEncryptionKeyring {
    LocalEncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap()
}

/// An application value type: it says how it encodes, never where it is stored.
#[derive(Clone, Debug, PartialEq)]
struct Address {
    street: String,
    city: String,
}

/// Encodes an [`Address`] as `street\0city`.
struct AddressCodec;

impl Codec<Address> for AddressCodec {
    const ID: &'static str = "address/1";

    fn encode(value: &Address) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            value.street.len() + 1 + value.city.len(),
        ));
        bytes.extend_from_slice(value.street.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(value.city.as_bytes());

        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Address, CodecError> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| CodecError::new(CodecErrorKind::InvalidUtf8))?;
        let (street, city) = text
            .split_once('\0')
            .ok_or(CodecError::new(CodecErrorKind::Decoding))?;

        Ok(Address {
            street: street.to_owned(),
            city: city.to_owned(),
        })
    }
}

impl Plaintext for Address {
    type Codec = AddressCodec;
}

// Fixtures deliberately mix `<Value as Plaintext>::Codec` and a named codec:
// both forms must resolve to the same stored bytes.

/// Where a user lives.
struct HomeAddress;

impl Field for HomeAddress {
    const ID: FieldId = field_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Address;
    type Codec = <Address as Plaintext>::Codec;
    type Binding = FieldOnly;
    type Indexes = ();
}

/// Where a user's invoices go.
struct BillingAddress;

impl Field for BillingAddress {
    const ID: FieldId = field_id!("5d2e8a17-4c6b-4f93-8e0a-7b1c9d3f6a25");
    const PADDING: Padding = Padding::block(16);
    const RECORD: bool = false;
    type Value = Address;
    type Codec = AddressCodec;
    type Binding = FieldOnly;
    type Indexes = ();
}

fn address() -> Address {
    Address {
        street: "1 Main Street".to_owned(),
        city: "Springfield".to_owned(),
    }
}

#[test]
fn fields_over_one_value_type_round_trip() {
    let keys = keyring();

    let home = Sealed::<HomeAddress>::seal(&address(), (), &keys).unwrap();
    assert_eq!(home.open((), &keys).unwrap(), address());

    let billing = Sealed::<BillingAddress>::seal(&address(), (), &keys).unwrap();
    assert_eq!(billing.open((), &keys).unwrap(), address());
}

#[test]
fn fields_over_one_value_type_have_distinct_ids() {
    assert_ne!(HomeAddress::ID, BillingAddress::ID);
}

#[test]
fn swapping_sealed_values_between_fields_over_one_value_type_fails_authentication() {
    let keys = keyring();
    let home = Sealed::<HomeAddress>::seal(&address(), (), &keys).unwrap();
    let billing = Sealed::<BillingAddress>::seal(&address(), (), &keys).unwrap();

    let home_as_billing = Sealed::<BillingAddress>::from_bytes(home.into_bytes()).unwrap();
    let billing_as_home = Sealed::<HomeAddress>::from_bytes(billing.into_bytes()).unwrap();

    assert!(matches!(
        home_as_billing.open((), &keys),
        Err(Error::AuthenticationFailed)
    ));
    assert!(matches!(
        billing_as_home.open((), &keys),
        Err(Error::AuthenticationFailed)
    ));
}

// These mappings are persistent schema: changing them would silently misread stored data.
#[test]
fn built_in_plaintext_types_name_permanent_codecs() {
    fn assert_codec<T: Plaintext<Codec = C>, C>() {}

    assert_codec::<String, Utf8>();
    assert_codec::<Vec<u8>, Raw>();
    assert_codec::<Secret<String>, Utf8>();
    assert_codec::<Secret<Vec<u8>>, Raw>();
}

struct UserEmail;

impl Field for UserEmail {
    const ID: FieldId = field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = <String as Plaintext>::Codec;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct SecretUserEmail;

impl Field for SecretUserEmail {
    const ID: FieldId = UserEmail::ID;
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Secret<String>;
    type Codec = <Secret<String> as Plaintext>::Codec;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct ApiToken;

impl Field for ApiToken {
    const ID: FieldId = field_id!("de8c983c-7d2b-4c4f-8162-f7193010de55");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct SecretApiToken;

impl Field for SecretApiToken {
    const ID: FieldId = ApiToken::ID;
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Secret<Vec<u8>>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

#[test]
fn secret_values_share_stored_bytes_with_their_plain_counterparts() {
    let keys = keyring();

    let plain = Sealed::<UserEmail>::seal(&"mark@example.com".to_owned(), (), &keys).unwrap();
    let read = Sealed::<SecretUserEmail>::from_bytes(plain.into_bytes()).unwrap();
    assert_eq!(
        read.open((), &keys).unwrap().expose_secret(),
        "mark@example.com"
    );

    let secret =
        Sealed::<SecretUserEmail>::seal(&Secret::new("mark@example.com".to_owned()), (), &keys)
            .unwrap();
    let read = Sealed::<UserEmail>::from_bytes(secret.into_bytes()).unwrap();
    assert_eq!(read.open((), &keys).unwrap(), "mark@example.com");

    let token = vec![0, 1, 2, 255];
    let plain = Sealed::<ApiToken>::seal(&token, (), &keys).unwrap();
    let read = Sealed::<SecretApiToken>::from_bytes(plain.into_bytes()).unwrap();
    assert_eq!(read.open((), &keys).unwrap().expose_secret(), &token);
}

#[test]
fn secret_string_codec_rejects_invalid_utf8() {
    let error = <Utf8 as Codec<Secret<String>>>::decode(&[0xff]).unwrap_err();

    assert_eq!(error.kind(), CodecErrorKind::InvalidUtf8);
}

#[test]
fn an_identifier_from_u128_reads_the_uuid_digits_in_order() {
    assert_eq!(
        FieldId::from_u128(0x0b6f3c2a_8e41_4d57_a9c3_5e1f2d7b8a64),
        field_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64")
    );
    assert_eq!(
        IndexId::from_u128(0x2e4c7b1a_5d3f_4a86_9b20_7f1e6c8d4a53),
        index_id!("2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53")
    );
}
