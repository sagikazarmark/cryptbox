//! Test helpers that pin persistent schema to committed fixtures and check
//! which keyring protects a value.

use crate::{Codec, ContextKind, EncryptionKeyring, Seal, Sealed};

/// Asserts that seal `F` encodes `value` as exactly the hex bytes in `expected`,
/// and decodes those bytes back to a value that encodes identically.
///
/// Commit one fixture per seal and run this in a test: it fails when the
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
/// use cryptbox::{Seal, SealId, Padding, Utf8, testing::assert_encoding};
///
/// struct Nickname;
///
/// impl Seal for Nickname {
///     const ID: SealId = cryptbox::seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
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
pub fn assert_encoding<F: Seal>(value: &F::Value, expected: &str) {
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

/// Asserts that `sealed` names a key that `keyring` holds, current or previous.
///
/// Choosing which keyring protects which values is application code, and a
/// wrong choice fails silently at write time: the value seals and opens with the
/// wrong keys, and survives destroying the right ones. Seal a value with the keys the
/// application chooses and assert the keyring it should have chosen.
/// See [choosing keyrings].
///
/// Key IDs are unique within a keyring and never shared across keyrings, so the
/// envelope's key ID names the keyring. The check reads that ID without opening
/// the value.
///
#[doc = concat!(
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/adr/0006-keys-are-passed-in.md#consequences",
)]
///
/// # Examples
///
/// ```
/// use cryptbox::{
///     EncryptionKey, EncryptionKeyring, Seal, SealId,
///     Padding, Sealed, Utf8, testing::assert_sealed_under,
/// };
///
/// struct Iban;
///
/// impl Seal for Iban {
///     const ID: SealId = cryptbox::seal_id!("50000000-0000-4000-8000-000000000005");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Indexes = ();
/// }
///
/// /// Keeps payment seals under their own keyring.
/// struct AppKeys {
///     general: EncryptionKeyring,
///     payments: EncryptionKeyring,
/// }
///
/// impl AppKeys {
///     fn for_seal(&self, seal: SealId) -> &EncryptionKeyring {
///         if seal == Iban::ID { &self.payments } else { &self.general }
///     }
/// }
///
/// let keys = AppKeys {
///     general: EncryptionKeyring::new(EncryptionKey::generate()?, [])?,
///     payments: EncryptionKeyring::new(EncryptionKey::generate()?, [])?,
/// };
///
/// let iban = Sealed::<Iban>::seal(
///     &"DE89370400440532013000".to_owned(),
///     keys.for_seal(Iban::ID),
/// )?;
///
/// assert_sealed_under::<Iban>(&iban, &keys.payments);
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// # Panics
///
/// Panics when `keyring` does not hold the key that `sealed` names. The message
/// includes the seal ID and the key ID, never the value.
#[track_caller]
pub fn assert_sealed_under<F: Seal>(
    sealed: &Sealed<F, impl ContextKind>,
    keyring: &EncryptionKeyring,
) {
    let key = sealed.key_id();
    assert!(
        keyring.get(key).is_some(),
        "seal {} is sealed under key {key}, which the keyring does not hold",
        F::ID,
    );
}
