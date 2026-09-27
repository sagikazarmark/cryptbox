//! Application tests using only local providers and public storage operations.
#![cfg(test)]

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexSpec, Encrypted, EncryptionKey, Field, FieldId,
    LocalBlindIndexKeyring, LocalEncryptionKeyring, Padding, Utf8,
};
use zeroize::Zeroizing;

struct UserEmail;

impl Field for UserEmail {
    const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Field = UserEmail;
    const ID: cryptbox::IndexId = cryptbox::index_id!("80000000-0000-4000-8000-000000000008");
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
    // Both cases deliberately reuse the same field and generation IDs with
    // different fixture roots. Neither case can use the other's provider.
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
    let keys = LocalEncryptionKeyring::new(
        EncryptionKey::new(
            cryptbox::key_id!("40000000-0000-4000-8000-000000000004"),
            [encryption_root; 32],
        ),
        [],
    )?;
    let indexes = LocalBlindIndexKeyring::new(
        BlindIndexKey::new(
            cryptbox::index_key_id!("50000000-0000-4000-8000-000000000005"),
            [index_root; 32],
        ),
        [],
    )?;
    let value = Encrypted::<UserEmail>::new(plaintext.to_owned());
    let ciphertext = value.encrypt_with(&keys)?;
    assert_eq!(ciphertext.decrypt_with(&keys)?.expose_secret(), plaintext);

    let prepared = value
        .prepare_with(&keys)?
        .with_index_with::<EmailLookup>(&indexes)?;
    let probes = EmailLookup::probes_with(plaintext, &indexes)?;
    let stored_index = prepared.index::<EmailLookup>()?;
    assert!(
        probes
            .iter()
            .any(|probe| probe.as_bytes() == stored_index.as_bytes())
    );
    let candidate = prepared.ciphertext().decrypt_with(&keys)?;
    assert!(EmailLookup::verify_candidate(
        plaintext,
        candidate.expose_secret(),
    )?);
    assert!(!EmailLookup::verify_candidate(
        "not-the-query@example.test",
        candidate.expose_secret(),
    )?);
    Ok(())
}
