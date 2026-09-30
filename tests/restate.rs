//! Public-boundary tests for the Restate adapter's codecs, object keys, and
//! error classification. `tests/restate` runs services against a real server.
#![cfg(all(feature = "restate", feature = "derive"))]

use bytes::Bytes;
use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, Sealed, TenantId,
    restate::{self, ObjectKey},
};
use restate_sdk::serde::{Deserialize, PayloadMetadata, Serialize};
use zeroize::Zeroizing;

/// An org's ID.
#[derive(cryptbox::BoundId, Clone, Copy, Debug, PartialEq)]
#[cryptbox(kind = "8f4a6c13-9d2e-4b57-a0c8-6e1f3a5d7b92")]
struct OrgId([u8; 16]);

/// A region.
#[derive(cryptbox::BoundId, Clone, Copy, Debug, PartialEq)]
#[cryptbox(kind = "2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37")]
struct RegionId(i64);

/// A shard.
#[derive(cryptbox::BoundId, Clone, Debug, PartialEq)]
#[cryptbox(kind = "5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61")]
struct ShardId(Vec<u8>);

/// An org search's bound values, led by its org.
type Search = (OrgId, RegionId, ShardId);

/// The object key of an org search.
type SearchKey = ObjectKey<Search>;

#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    value = String,
    bound(TenantId),
    indexes(EmailLookup),
)]
struct CustomerEmail;

#[allow(clippy::unnecessary_wraps)] // Normalizers are fallible by contract.
fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
}

#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(
    id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
    seal = CustomerEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
struct EmailLookup;

const ORG: [u8; 16] = [
    0x01, 0x92, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b,
];
const ORG_KEY: &str = "01923a4b-5c6d-7e8f-9a0b-1c2d3e4f5a6b";

fn search() -> Search {
    (OrgId(ORG), RegionId(-42), ShardId(vec![0x01, 0xab]))
}

fn encode(search: &Search) -> String {
    SearchKey::encode((&search.0, &search.1, &search.2))
}

fn tenant() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn sealed() -> Sealed<CustomerEmail> {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    Sealed::seal(&"ada@example.com".into(), &tenant(), &keys).unwrap()
}

fn blind_index() -> BlindIndex<EmailLookup> {
    let keys = BlindIndexKeyring::new(BlindIndexKey::generate().unwrap(), []).unwrap();
    EmailLookup::probes_with("ada@example.com", &tenant(), &keys)
        .unwrap()
        .remove(0)
}

#[test]
fn a_sealed_value_journals_its_envelope_unchanged() {
    let sealed = sealed();

    let journaled = Serialize::serialize(&sealed).unwrap();

    assert_eq!(&journaled[..], sealed.as_bytes());
    assert_eq!(
        Serialize::serialize(&sealed).unwrap(),
        journaled,
        "replay compares journaled bytes, so the codec never encrypts"
    );
    assert_eq!(
        <Sealed<CustomerEmail> as Deserialize>::deserialize(&mut journaled.clone()).unwrap(),
        sealed
    );
}

#[test]
fn a_blind_index_journals_its_bytes_unchanged() {
    let index = blind_index();

    let journaled = Serialize::serialize(&index).unwrap();

    assert_eq!(&journaled[..], index.as_bytes());
    assert_eq!(
        <BlindIndex<EmailLookup> as Deserialize>::deserialize(&mut journaled.clone()).unwrap(),
        index
    );
}

#[test]
fn journaled_bytes_are_checked_for_structure() {
    assert_eq!(
        <Sealed<CustomerEmail> as Deserialize>::deserialize(&mut Bytes::from_static(b"plain")),
        Err(Error::NotCiphertext)
    );
    assert!(
        <BlindIndex<EmailLookup> as Deserialize>::deserialize(&mut Bytes::from_static(b"x"))
            .is_err()
    );
}

#[test]
fn sealed_payloads_are_octet_streams_without_a_schema() {
    fn assert_octet_stream<T: PayloadMetadata>() {
        assert_eq!(T::json_schema(), None);
        assert_eq!(
            T::input_metadata().accept_content_type,
            "application/octet-stream"
        );
        assert!(T::input_metadata().is_required);
        assert_eq!(
            T::output_metadata().content_type,
            "application/octet-stream"
        );
    }

    assert_octet_stream::<Sealed<CustomerEmail>>();
    assert_octet_stream::<BlindIndex<EmailLookup>>();
}

#[test]
fn an_object_key_holds_its_values_in_list_order() {
    assert_eq!(
        encode(&search()),
        format!("{ORG_KEY}:-0000000000000000042:01ab")
    );
    assert_eq!(ObjectKey::<(TenantId,)>::encode(&tenant()), "61636d65");
}

#[test]
fn an_object_key_parses_back_into_its_values() {
    let key = encode(&search());

    assert_eq!(SearchKey::parse(&key), Ok(search()));
    assert_eq!(ObjectKey::<(TenantId,)>::parse("61636d65"), Ok((tenant(),)));
}

#[test]
fn object_key_integers_are_fixed_width() {
    for (region, encoded) in [
        (0, "+0000000000000000000"),
        (7, "+0000000000000000007"),
        (-1, "-0000000000000000001"),
        (i64::MAX, "+9223372036854775807"),
        (i64::MIN, "-9223372036854775808"),
    ] {
        let values = (OrgId(ORG), RegionId(region), search().2);
        let key = format!("{ORG_KEY}:{encoded}:01ab");

        assert_eq!(encode(&values), key);
        assert_eq!(SearchKey::parse(&key), Ok(values));
    }
}

#[test]
fn tampered_or_non_canonical_object_keys_are_rejected() {
    let valid = format!("{ORG_KEY}:-0000000000000000042:01ab");
    assert!(SearchKey::parse(&valid).is_ok(), "control");

    let cases = [
        ("empty", String::new()),
        ("missing part", format!("{ORG_KEY}:-0000000000000000042")),
        ("extra part", format!("{valid}:01")),
        ("trailing separator", format!("{valid}:")),
        (
            "parts out of order",
            format!("-0000000000000000042:{ORG_KEY}:01ab"),
        ),
        ("uppercase uuid", valid.to_uppercase()),
        ("uuid without hyphens", valid.replacen('-', "", 4)),
        (
            "uuid with misplaced hyphen",
            "01923a4b5-c6d-7e8f-9a0b-1c2d3e4f5a6b:-0000000000000000042:01ab".to_owned(),
        ),
        ("short integer", format!("{ORG_KEY}:-42:01ab")),
        (
            "unsigned integer",
            format!("{ORG_KEY}:00000000000000000042:01ab"),
        ),
        (
            "negative zero",
            format!("{ORG_KEY}:-0000000000000000000:01ab"),
        ),
        (
            "integer overflow",
            format!("{ORG_KEY}:+9223372036854775808:01ab"),
        ),
        (
            "integer digits",
            format!("{ORG_KEY}:+000000000000000004x:01ab"),
        ),
        (
            "uppercase hex",
            format!("{ORG_KEY}:-0000000000000000042:01AB"),
        ),
        ("odd hex", format!("{ORG_KEY}:-0000000000000000042:01a")),
        ("non-hex", format!("{ORG_KEY}:-0000000000000000042:zz")),
    ];

    for (case, key) in cases {
        let error = SearchKey::parse(&key).unwrap_err();

        assert_eq!(error, Error::InvalidObjectKey, "{case}");
        assert!(!restate::is_retryable(&error), "{case} is terminal");
    }
    assert_eq!(
        ObjectKey::<(TenantId,)>::parse(""),
        Err(Error::InvalidObjectKey),
        "an empty tenant"
    );
}

#[test]
fn an_object_key_of_no_values_is_empty() {
    assert_eq!(ObjectKey::<()>::encode(()), "", "no values, no key");
    assert_eq!(ObjectKey::<()>::parse(""), Ok(()));
}

#[test]
fn a_prefix_selects_every_object_key_of_its_leading_values() {
    let key = encode(&search());

    let prefix = SearchKey::prefix::<(OrgId,)>(&OrgId(ORG));
    let longer = SearchKey::prefix::<(OrgId, RegionId)>((&OrgId(ORG), &RegionId(-42)));

    assert_eq!(prefix, ORG_KEY);
    assert!(key.starts_with(&format!("{prefix}:")));
    assert!(key.starts_with(&format!("{longer}:")));
    assert_eq!(
        ObjectKey::<(TenantId,)>::prefix::<(TenantId,)>(&tenant()),
        "61636d65"
    );
}

#[test]
fn data_faults_are_terminal_and_environment_faults_are_retried() {
    let terminal = [
        Error::AuthenticationFailed,
        Error::BindingMismatch,
        Error::CodecFailed(cryptbox::CodecError::new(
            cryptbox::CodecErrorKind::Decoding,
        )),
        Error::UnknownEncryptionKey(sealed().key_id()),
        Error::InvalidEnvelope,
        Error::InvalidObjectKey,
    ];
    let retryable = [
        Error::KeysUnavailable,
        Error::KeysNotInstalled,
        Error::RandomnessUnavailable,
        Error::Internal,
    ];

    for error in terminal {
        assert!(!restate::is_retryable(&error), "{error} is terminal");
        assert!(
            describe(&restate::handler_error(error.clone())).starts_with("Terminal error"),
            "{error} is terminal"
        );
    }
    for error in retryable {
        assert!(restate::is_retryable(&error), "{error} is retried");
        assert!(
            !describe(&restate::handler_error(error.clone())).starts_with("Terminal error"),
            "{error} is retried"
        );
    }
}

#[test]
fn a_rejected_object_key_is_a_client_error() {
    assert!(
        describe(&restate::handler_error(Error::InvalidObjectKey))
            .starts_with("Terminal error [400]")
    );
    assert!(
        describe(&restate::handler_error(Error::AuthenticationFailed))
            .starts_with("Terminal error [500]")
    );
}

/// Restate's description of a handler error, which names its kind.
fn describe(error: &restate_sdk::errors::HandlerError) -> String {
    let error: &dyn std::error::Error = error.as_ref();
    error.to_string()
}
