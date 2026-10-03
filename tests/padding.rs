//! Public-boundary tests for seal padding policies.

use cryptbox::envelope::inspect_ciphertext;
use cryptbox::{
    EncryptionKey, EncryptionKeyring, Error, KeyId, Padding, Raw, Seal, SealId, Sealed, Utf8,
    key_id, seal_id,
};

const KEY_ID: KeyId = key_id!("50000000-0000-4000-8000-000000000005");

fn keyring() -> EncryptionKeyring {
    EncryptionKeyring::new(EncryptionKey::new(KEY_ID, [47; 32]), []).unwrap()
}

const SHARED_SEAL: SealId = seal_id!("60000000-0000-4000-8000-000000000006");

struct Unpadded;

impl Seal for Unpadded {
    const ID: SealId = SHARED_SEAL;
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct SharedSealPadded;

impl Seal for SharedSealPadded {
    const ID: SealId = SHARED_SEAL;
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
}

struct FixedLength;

impl Seal for FixedLength {
    const ID: SealId = SHARED_SEAL;
    const PADDING: Padding = Padding::length(16);
    type Value = String;
    type Codec = Utf8;
}

struct WiderBlockPadded;

impl Seal for WiderBlockPadded {
    const ID: SealId = SHARED_SEAL;
    const PADDING: Padding = Padding::block(32);
    type Value = String;
    type Codec = Utf8;
}

struct BlockPadded;

impl Seal for BlockPadded {
    const ID: SealId = SHARED_SEAL;
    const PADDING: Padding = Padding::block(16);
    type Value = String;
    type Codec = Utf8;
}

struct PolicyFixedLength;

impl Seal for PolicyFixedLength {
    const ID: SealId = SHARED_SEAL;
    const PADDING: Padding = Padding::length(1_048_576);
    type Value = String;
    type Codec = Utf8;
}

// Padding/envelope arithmetic from docs/wire-format.md#size-semantics-and-enforcement.
// The 1 MiB cases test size boundaries, not an enforced operational cap.
fn assert_stored_sizes<P: Seal<Value = String>>(cases: &[(usize, usize)]) {
    let keys = keyring();
    for &(encoded_bytes, envelope_bytes) in cases {
        let input = "x".repeat(encoded_bytes);
        let sealed = Sealed::<P>::seal(&input, &keys).unwrap();
        assert_eq!(sealed.as_bytes().len(), envelope_bytes);
        assert_eq!(sealed.open(&keys).unwrap(), input);
    }
}

#[test]
fn documented_unpadded_policy_sizes_match_stored_values() {
    assert_stored_sizes::<Unpadded>(&[(0, 71), (1_048_576, 1_048_647), (1_048_577, 1_048_648)]);
}

#[test]
fn documented_block_padding_sizes_include_the_marker_at_boundaries() {
    assert_stored_sizes::<BlockPadded>(&[
        (0, 87),
        (15, 87),
        (16, 103),
        (1_048_575, 1_048_647),
        (1_048_576, 1_048_663),
    ]);
}

#[test]
fn documented_fixed_padding_sizes_reserve_room_for_the_marker() {
    assert_stored_sizes::<PolicyFixedLength>(&[(0, 1_048_647), (1_048_575, 1_048_647)]);
    let value = "x".repeat(1_048_576);
    assert!(matches!(
        Sealed::<PolicyFixedLength>::seal(&value, &keyring()),
        Err(Error::PaddingOverflow)
    ));
}

#[test]
fn block_padded_values_round_trip_without_revealing_length_within_a_bucket() {
    let keys = keyring();
    let ciphertexts = (0..=15)
        .map(|length| Sealed::<BlockPadded>::seal(&"x".repeat(length), &keys).unwrap())
        .collect::<Vec<_>>();

    let ciphertext_lengths = ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.as_bytes().len())
        .collect::<Vec<_>>();

    assert!(ciphertext_lengths.windows(2).all(|pair| pair[0] == pair[1]));
    for (length, ciphertext) in ciphertexts.iter().enumerate() {
        assert_eq!(ciphertext.open(&keys).unwrap(), "x".repeat(length));
    }
}

#[test]
fn a_seal_that_enables_padding_reads_old_and_new_values() {
    let keys = keyring();
    let old = Sealed::<Unpadded>::seal(&"written before padding".to_owned(), &keys).unwrap();
    let old = Sealed::<SharedSealPadded>::from_bytes(old.into_bytes()).unwrap();
    let new = Sealed::<SharedSealPadded>::seal(&"written with padding".to_owned(), &keys).unwrap();

    assert_eq!(old.open(&keys).unwrap(), "written before padding");
    assert_eq!(new.open(&keys).unwrap(), "written with padding");
}

struct RawUnpadded;

impl Seal for RawUnpadded {
    const ID: SealId = SHARED_SEAL;
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
}

struct RawPadded;

impl Seal for RawPadded {
    const ID: SealId = SHARED_SEAL;
    const PADDING: Padding = Padding::block(16);
    type Value = Vec<u8>;
    type Codec = Raw;
}

// A policy-based reader would misread these silently (ADR-0002); `Raw` accepts any bytes.
#[test]
fn padded_values_read_after_disabling_padding_keep_no_padding_bytes() {
    let keys = keyring();
    let padded = Sealed::<RawPadded>::seal(&b"value".to_vec(), &keys).unwrap();
    let current = Sealed::<RawUnpadded>::from_bytes(padded.into_bytes()).unwrap();

    assert_eq!(current.open(&keys).unwrap(), b"value");
}

#[test]
fn unpadded_values_ending_in_marker_bytes_survive_enabling_padding() {
    let keys = keyring();

    for value in [b"value\x80".to_vec(), b"value\x80\x00".to_vec()] {
        let unpadded = Sealed::<RawUnpadded>::seal(&value.clone(), &keys).unwrap();
        let current = Sealed::<RawPadded>::from_bytes(unpadded.into_bytes()).unwrap();

        assert_eq!(current.open(&keys).unwrap(), value);
    }
}

#[test]
fn a_sweep_converges_values_to_the_current_padding_policy() {
    let keys = keyring();
    let old = Sealed::<Unpadded>::seal(&"old".to_owned(), &keys).unwrap();
    let new = Sealed::<SharedSealPadded>::seal(&"new".to_owned(), &keys).unwrap();

    let padded = [old.into_bytes(), new.as_bytes().to_vec()].map(sweep::<SharedSealPadded>);
    assert_eq!(
        padded[1], new,
        "a value in the current form is not rewritten"
    );
    assert_swept(&padded, true);

    let unpadded = padded.map(|ciphertext| sweep::<Unpadded>(ciphertext.into_bytes()));
    assert_swept(&unpadded, false);
}

fn sweep<F: Seal>(bytes: Vec<u8>) -> Sealed<F> {
    let keys = keyring();
    let ciphertext = Sealed::<F>::from_bytes(bytes).unwrap();

    if ciphertext.needs_reseal(&keys).unwrap() {
        ciphertext.reseal(&keys).unwrap()
    } else {
        ciphertext
    }
}

fn assert_swept<F: Seal<Value = String>>(swept: &[Sealed<F>; 2], padded: bool) {
    let keys = keyring();

    for (ciphertext, value) in swept.iter().zip(["old", "new"]) {
        assert!(!ciphertext.needs_reseal(&keys).unwrap());
        assert_eq!(
            inspect_ciphertext(ciphertext.as_bytes()).unwrap().padded(),
            padded
        );
        assert_eq!(ciphertext.open(&keys).unwrap(), value);
    }
}
#[test]
fn fixed_length_padding_rejects_encoded_plaintext_that_does_not_fit() {
    let keys = keyring();
    let value = "x".repeat(16);

    assert!(matches!(
        Sealed::<FixedLength>::seal(&value, &keys),
        Err(Error::PaddingOverflow)
    ));
}

#[test]
fn resealing_normalizes_plaintext_to_the_current_padding_parameters() {
    let keys = keyring();
    let original = Sealed::<BlockPadded>::seal(&"short".to_owned(), &keys).unwrap();
    let current = Sealed::<WiderBlockPadded>::from_bytes(original.into_bytes()).unwrap();

    let rewritten = current.reseal(&keys).unwrap();

    assert_eq!(rewritten.as_bytes().len(), 71 + 32);
    assert_eq!(rewritten.open(&keys).unwrap(), "short");
}
