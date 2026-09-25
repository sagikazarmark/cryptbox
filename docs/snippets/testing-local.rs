//! Application tests using only local providers and public storage operations.
#![cfg(test)]

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Encrypted, EncryptionKey,
    FieldBound, LocalBlindIndexKeyring, LocalEncryptionKeyring, blind_index_probes,
    verify_blind_index_candidate,
};
use zeroize::Zeroizing;

cryptbox::profile! {
    UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
    }
}

struct EmailLookup;

impl BlindIndexMetadata for EmailLookup {
    const ID: cryptbox::IndexId = cryptbox::index_id!("80000000-0000-4000-8000-000000000008");
    const BITS: usize = 128;
}

impl BlindIndexSpec<String> for EmailLookup {
    fn normalize(input: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        // Exact-byte equality for this fixture; no email canonicalization claim.
        Ok(Zeroizing::new(input.as_bytes().to_vec()))
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
    let value = Encrypted::<_, UserEmail>::new(plaintext.to_owned());
    let ciphertext = value.encrypt_with(&(), &keys)?;
    assert_eq!(
        ciphertext.decrypt_with(&(), &keys)?.expose_secret(),
        plaintext
    );

    let prepared = value
        .prepare_with(&(), &keys)?
        .with_index_with::<EmailLookup>(&indexes)?;
    let query = plaintext.to_owned();
    let probes =
        blind_index_probes::<EmailLookup, String, FieldBound<UserEmail>>(&query, &(), &indexes)?;
    let stored_index = prepared.index::<EmailLookup>()?;
    assert!(
        probes
            .iter()
            .any(|probe| probe.as_bytes() == stored_index.as_bytes())
    );
    let candidate = prepared.ciphertext().decrypt_with(&(), &keys)?;
    assert!(verify_blind_index_candidate::<EmailLookup, String>(
        &query,
        candidate.expose_secret(),
    )?);
    assert!(!verify_blind_index_candidate::<EmailLookup, String>(
        &"not-the-query@example.test".to_owned(),
        candidate.expose_secret(),
    )?);
    Ok(())
}
