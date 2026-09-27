//! Test helpers that pin persistent schema to committed fixtures.

use crate::{Codec, Field};

/// Asserts that field `F` encodes `value` as exactly the hex bytes in `expected`,
/// and decodes those bytes back to a value that encodes identically.
///
/// Commit one fixture per field and run this in a test: it fails when the
/// stored bytes would change, as a serde attribute change on a `Json` or
/// `Postcard` value type can do silently. See [guarding the schema in CI].
///
/// The check covers the codec only; padding and encryption are applied after it.
/// Decoding is checked by re-encoding the decoded value, so the value type needs
/// no `PartialEq`.
///
#[doc = concat!(
    "[guarding the schema in CI]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/integration.md#guarding-the-schema-in-ci",
)]
///
/// # Examples
///
/// ```
/// use cryptbox::{Field, FieldId, FieldOnly, Padding, Utf8, testing::assert_encoding};
///
/// struct Nickname;
///
/// impl Field for Nickname {
///     const ID: FieldId = cryptbox::field_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = ();
/// }
///
/// assert_encoding::<Nickname>(&"ada".to_owned(), "616461");
/// ```
///
/// # Panics
///
/// Panics when `expected` is not valid hex, when encoding fails or produces
/// other bytes, or when decoding the fixture fails or yields a value that
/// encodes differently. The message includes the actual bytes in hex, so use
/// synthetic values, never production data.
#[track_caller]
pub fn assert_encoding<F: Field>(value: &F::Value, expected: &str) {
    let expected = hex::decode(expected).expect("fixture must be hex");

    let encoded = F::Codec::encode(value).expect("value must encode");
    assert!(
        encoded.as_slice() == expected.as_slice(),
        "encoding changed: expected {}, got {}",
        hex::encode(&expected),
        hex::encode(encoded.as_slice()),
    );

    let decoded = F::Codec::decode(&expected).expect("fixture must decode");
    let reencoded = F::Codec::encode(&decoded).expect("decoded fixture must encode");
    assert!(
        reencoded.as_slice() == expected.as_slice(),
        "decoding changed: expected {}, got {}",
        hex::encode(&expected),
        hex::encode(reencoded.as_slice()),
    );
}
