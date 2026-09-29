//! Application tests using only local keyrings and public storage operations.
#![cfg(test)]

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, FieldOnly, Padding, Seal, SealId, Sealed, Utf8,
};
use zeroize::Zeroizing;

struct UserEmail;

impl Seal for UserEmail {
    const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
    type Indexes = (EmailLookup,);
}

struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Seal = UserEmail;
    const ID: cryptbox::IndexId = cryptbox::index_id!("558e7d43-9926-498c-962a-19959dddbfc8");
    const BITS: u16 = 128;
    const NORMALIZER: &'static str = "exact/1";
    type Query = str;

    fn normalize_query(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        // Exact-byte equality for this fixture; no email canonicalization claim.
        Ok(Zeroizing::new(input.as_bytes().to_vec()))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

#[test]
fn independent_cases_run_concurrently() {
    // Both cases deliberately reuse the same seal and generation IDs with
    // different fixture roots. Neither case can use the other's keyring.
    std::thread::scope(|scope| {
        let first = scope.spawn(|| round_trip("first@example.test", 0x11, 0x21));
        let second = scope.spawn(|| round_trip("second@example.test", 0x12, 0x22));
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
    });
}

#[test]
fn another_case_needs_no_shared_setup() -> Result<(), cryptbox::Error> {
    round_trip("third@example.test", 0x13, 0x23)
}

fn round_trip(plaintext: &str, encryption_root: u8, index_root: u8) -> Result<(), cryptbox::Error> {
    // Public test fixtures only. Never provision durable keys this way.
    let keys = EncryptionKeyring::new(
        EncryptionKey::new(
            cryptbox::key_id!("7552c7db-c3e5-40c4-bd8e-b3e98c4fadbc"),
            [encryption_root; 32],
        ),
        [],
    )?;
    let indexes = BlindIndexKeyring::new(
        BlindIndexKey::new(
            cryptbox::index_key_id!("7b8cd681-6f38-4182-9e81-b5f161402496"),
            [index_root; 32],
        ),
        [],
    )?;
    let value = plaintext.to_owned();
    let sealed = Sealed::<UserEmail>::seal(&value, (), &keys)?;
    assert_eq!(sealed.open((), &keys)?, plaintext);

    let prepared = Sealed::<UserEmail>::prepare(&value, (), &keys)?
        .with_index_with::<EmailLookup>(&indexes)?;
    let probes = EmailLookup::probes_with(plaintext, &(), &indexes)?;
    let stored_index = prepared.index::<EmailLookup>()?;
    assert!(
        probes
            .iter()
            .any(|probe| probe.as_bytes() == stored_index.as_bytes())
    );
    let candidate = prepared.sealed().open((), &keys)?;
    assert!(EmailLookup::verify_candidate(plaintext, &candidate,)?);
    assert!(!EmailLookup::verify_candidate(
        "not-the-query@example.test",
        &candidate,
    )?);
    Ok(())
}
