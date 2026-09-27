//! Public-boundary tests for field padding policies.

use cryptbox::{
    Ciphertext, Encrypted, EncryptionKey, Error, Field, FieldId, KeyId, LocalEncryptionKeyring,
    Padding, Raw, Utf8, field_id, inspect_ciphertext, key_id,
};

const KEY_ID: KeyId = key_id!("50000000-0000-4000-8000-000000000005");

fn keyring() -> LocalEncryptionKeyring {
    LocalEncryptionKeyring::new(EncryptionKey::new(KEY_ID, [47; 32]), []).unwrap()
}

const SHARED_FIELD: FieldId = field_id!("60000000-0000-4000-8000-000000000006");

struct Unpadded;

impl Field for Unpadded {
    const ID: FieldId = SHARED_FIELD;
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct SharedFieldPadded;

impl Field for SharedFieldPadded {
    const ID: FieldId = SHARED_FIELD;
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
}

struct FixedLength;

impl Field for FixedLength {
    const ID: FieldId = SHARED_FIELD;
    const PADDING: Padding = Padding::length(16);
    type Value = String;
    type Codec = Utf8;
}

struct WiderBlockPadded;

impl Field for WiderBlockPadded {
    const ID: FieldId = SHARED_FIELD;
    const PADDING: Padding = Padding::block(32);
    type Value = String;
    type Codec = Utf8;
}

struct BlockPadded;

impl Field for BlockPadded {
    const ID: FieldId = SHARED_FIELD;
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
}

struct PolicyFixedLength;

impl Field for PolicyFixedLength {
    const ID: FieldId = SHARED_FIELD;
    const PADDING: Padding = Padding::length(1_048_576);
    type Value = String;
    type Codec = Utf8;
}

// Padding/envelope arithmetic from docs/wire-format.md#size-semantics-and-enforcement.
// The 1 MiB cases test size boundaries, not an enforced operational cap.
fn assert_stored_sizes<P: Field<Value = String>>(cases: &[(usize, usize)]) {
    let keys = keyring();
    for &(encoded_bytes, envelope_bytes) in cases {
        let input = "x".repeat(encoded_bytes);
        let ciphertext = Encrypted::<P>::new(input.clone())
            .encrypt_with(&keys)
            .unwrap();
        assert_eq!(ciphertext.as_bytes().len(), envelope_bytes);
        assert_eq!(
            ciphertext.decrypt_with(&keys).unwrap().expose_secret(),
            &input
        );
    }
}

#[test]
fn documented_unpadded_policy_sizes_match_stored_values() {
    assert_stored_sizes::<Unpadded>(&[(0, 63), (1_048_576, 1_048_639), (1_048_577, 1_048_640)]);
}

#[test]
fn documented_block_padding_sizes_include_the_marker_at_boundaries() {
    assert_stored_sizes::<BlockPadded>(&[
        (0, 79),
        (15, 79),
        (16, 95),
        (1_048_575, 1_048_639),
        (1_048_576, 1_048_655),
    ]);
}

#[test]
fn documented_fixed_padding_sizes_reserve_room_for_the_marker() {
    assert_stored_sizes::<PolicyFixedLength>(&[(0, 1_048_639), (1_048_575, 1_048_639)]);
    let value = Encrypted::<PolicyFixedLength>::new("x".repeat(1_048_576));
    assert!(matches!(
        value.encrypt_with(&keyring()),
        Err(Error::PaddingOverflow)
    ));
}

#[test]
fn block_padded_values_round_trip_without_revealing_length_within_a_bucket() {
    let keys = keyring();
    let ciphertexts = (0..=15)
        .map(|length| {
            Encrypted::<BlockPadded>::new("x".repeat(length))
                .encrypt_with(&keys)
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
            ciphertext.decrypt_with(&keys).unwrap().expose_secret(),
            &"x".repeat(length)
        );
    }
}

#[test]
fn a_field_that_enables_padding_reads_old_and_new_values() {
    let keys = keyring();
    let old = Encrypted::<Unpadded>::new("written before padding".to_owned())
        .encrypt_with(&keys)
        .unwrap();
    let old = Ciphertext::<SharedFieldPadded>::from_bytes(old.into_bytes()).unwrap();
    let new = Encrypted::<SharedFieldPadded>::new("written with padding".to_owned())
        .encrypt_with(&keys)
        .unwrap();

    assert_eq!(
        old.decrypt_with(&keys).unwrap().expose_secret(),
        "written before padding"
    );
    assert_eq!(
        new.decrypt_with(&keys).unwrap().expose_secret(),
        "written with padding"
    );
}

struct RawUnpadded;

impl Field for RawUnpadded {
    const ID: FieldId = SHARED_FIELD;
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
}

struct RawPadded;

impl Field for RawPadded {
    const ID: FieldId = SHARED_FIELD;
    const PADDING: Padding = Padding::block(16);
    type Value = Vec<u8>;
    type Codec = Raw;
}

// Format 1 misread these silently under a changed policy (ADR-0002); `Raw` accepts any bytes.
#[test]
fn padded_values_read_after_disabling_padding_keep_no_padding_bytes() {
    let keys = keyring();
    let padded = Encrypted::<RawPadded>::new(b"value".to_vec())
        .encrypt_with(&keys)
        .unwrap();
    let current = Ciphertext::<RawUnpadded>::from_bytes(padded.into_bytes()).unwrap();

    assert_eq!(
        current.decrypt_with(&keys).unwrap().expose_secret(),
        b"value"
    );
}

#[test]
fn unpadded_values_ending_in_marker_bytes_survive_enabling_padding() {
    let keys = keyring();

    for value in [b"value\x80".to_vec(), b"value\x80\x00".to_vec()] {
        let unpadded = Encrypted::<RawUnpadded>::new(value.clone())
            .encrypt_with(&keys)
            .unwrap();
        let current = Ciphertext::<RawPadded>::from_bytes(unpadded.into_bytes()).unwrap();

        assert_eq!(current.decrypt_with(&keys).unwrap().expose_secret(), &value);
    }
}

#[test]
fn a_sweep_converges_values_to_the_current_padding_policy() {
    let keys = keyring();
    let old = Encrypted::<Unpadded>::new("old".to_owned())
        .encrypt_with(&keys)
        .unwrap();
    let new = Encrypted::<SharedFieldPadded>::new("new".to_owned())
        .encrypt_with(&keys)
        .unwrap();

    let padded = [old.into_bytes(), new.as_bytes().to_vec()].map(sweep::<SharedFieldPadded>);
    assert_eq!(
        padded[1], new,
        "a value in the current form is not rewritten"
    );
    assert_swept(&padded, Some(true));

    let unpadded = padded.map(|ciphertext| sweep::<Unpadded>(ciphertext.into_bytes()));
    assert_swept(&unpadded, Some(false));
}

fn sweep<F: Field>(bytes: Vec<u8>) -> Ciphertext<F> {
    let keys = keyring();
    let ciphertext = Ciphertext::<F>::from_bytes(bytes).unwrap();

    if ciphertext.needs_reencryption_with(&keys).unwrap() {
        ciphertext.reencrypt_with(&keys).unwrap()
    } else {
        ciphertext
    }
}

fn assert_swept<F: Field<Value = String>>(swept: &[Ciphertext<F>; 2], padded: Option<bool>) {
    let keys = keyring();

    for (ciphertext, value) in swept.iter().zip(["old", "new"]) {
        assert!(!ciphertext.needs_reencryption_with(&keys).unwrap());
        assert_eq!(
            inspect_ciphertext(ciphertext.as_bytes()).unwrap().padded(),
            padded
        );
        assert_eq!(
            ciphertext.decrypt_with(&keys).unwrap().expose_secret(),
            value
        );
    }
}
#[test]
fn fixed_length_padding_rejects_encoded_plaintext_that_does_not_fit() {
    let keys = keyring();
    let value = Encrypted::<FixedLength>::new("x".repeat(16));

    assert!(matches!(
        value.encrypt_with(&keys),
        Err(Error::PaddingOverflow)
    ));
}

#[test]
fn reencryption_normalizes_plaintext_to_the_current_padding_parameters() {
    let keys = keyring();
    let original = Encrypted::<BlockPadded>::new("short".to_owned())
        .encrypt_with(&keys)
        .unwrap();
    let current = Ciphertext::<WiderBlockPadded>::from_bytes(original.into_bytes()).unwrap();

    let rewritten = current.reencrypt_with(&keys).unwrap();

    assert_eq!(rewritten.as_bytes().len(), 63 + 32);
    assert_eq!(
        rewritten.decrypt_with(&keys).unwrap().expose_secret(),
        "short"
    );
}
