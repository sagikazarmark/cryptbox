//! Public-boundary tests for profile padding policies.

use cryptbox::{
    Ciphertext, Encrypted, EncryptionKey, EncryptionProfile, Error, Field, FieldBound,
    GlobalKeyContext, KeyId, LocalEncryptionKeyring, NoPadding, PadToBlock, PadToLength, Unbound,
    Utf8, field_id, key_id,
};

const KEY_ID: KeyId = key_id!("50000000-0000-4000-8000-000000000005");

fn keyring() -> LocalEncryptionKeyring {
    LocalEncryptionKeyring::new(EncryptionKey::new(KEY_ID, [47; 32]), []).unwrap()
}

struct SharedField;

impl Field for SharedField {
    const ID: cryptbox::FieldId = field_id!("60000000-0000-4000-8000-000000000006");
    const NAME: &'static str = "shared-padding-field";
}

struct Unpadded;

impl EncryptionProfile<String> for Unpadded {
    type Binding = FieldBound<SharedField>;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = NoPadding;
}

struct SharedFieldPadded;

impl EncryptionProfile<String> for SharedFieldPadded {
    type Binding = FieldBound<SharedField>;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = PadToBlock<16>;
}

struct FixedLength;

impl EncryptionProfile<String> for FixedLength {
    type Binding = Unbound;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = PadToLength<16>;
}

struct WiderBlockPadded;

impl EncryptionProfile<String> for WiderBlockPadded {
    type Binding = Unbound;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = PadToBlock<32>;
}

struct BlockPadded;

impl EncryptionProfile<String> for BlockPadded {
    type Binding = Unbound;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = PadToBlock<16>;
}

#[test]
fn block_padded_values_round_trip_without_revealing_length_within_a_bucket() {
    let keys = keyring();
    let ciphertexts = (0..=15)
        .map(|length| {
            Encrypted::<_, BlockPadded>::new("x".repeat(length))
                .encrypt_with(&(), &keys)
                .unwrap()
        })
        .collect::<Vec<_>>();

    let ciphertext_lengths = ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.as_bytes().len())
        .collect::<Vec<_>>();

    assert!(ciphertext_lengths.windows(2).all(|pair| pair[0] == pair[1]));
    for (length, ciphertext) in ciphertexts.iter().enumerate() {
        assert_eq!(
            ciphertext.decrypt_with(&(), &keys).unwrap().expose_secret(),
            &"x".repeat(length)
        );
    }
}

#[test]
fn enabling_padding_for_unpadded_ciphertext_is_a_schema_mismatch() {
    let keys = keyring();
    let unpadded = Encrypted::<_, Unpadded>::new("plaintext without marker".to_owned())
        .encrypt_with(&(), &keys)
        .unwrap();
    let padded =
        Ciphertext::<String, SharedFieldPadded>::from_bytes(unpadded.into_bytes()).unwrap();

    assert!(matches!(
        padded.decrypt_with(&(), &keys),
        Err(Error::InvalidPadding)
    ));
}

#[test]
fn fixed_length_padding_rejects_encoded_plaintext_that_does_not_fit() {
    let keys = keyring();
    let value = Encrypted::<_, FixedLength>::new("x".repeat(16));

    assert!(matches!(
        value.encrypt_with(&(), &keys),
        Err(Error::PaddingOverflow)
    ));
}

#[test]
fn reencryption_normalizes_plaintext_to_the_current_padding_parameters() {
    let keys = keyring();
    let original = Encrypted::<_, BlockPadded>::new("short".to_owned())
        .encrypt_with(&(), &keys)
        .unwrap();
    let current =
        Ciphertext::<String, WiderBlockPadded>::from_bytes(original.into_bytes()).unwrap();

    let rewritten = current.reencrypt_with(&(), &keys).unwrap();

    assert_eq!(rewritten.as_bytes().len(), 62 + 32);
    assert_eq!(
        rewritten.decrypt_with(&(), &keys).unwrap().expose_secret(),
        "short"
    );
}
