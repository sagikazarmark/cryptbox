//! Serializes stored bytes, then deliberately authenticates and checks consistency.
//! See docs/stored-values.md for the complete consumer manifest and trust boundaries.

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Ciphertext,
    Encrypted, EncryptionKey, Error, FieldBound, IndexId, LocalBlindIndexKeyring,
    LocalEncryptionKeyring, blind_index_probes, derive_blind_index, index_id, index_key_id,
    inspect_blind_index, inspect_ciphertext, key_id, profile, verify_blind_index_candidate,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

profile! {
    UserEmail: String {
        id: "70000000-0000-4000-8000-000000000007",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
    }
}

struct EmailLookup;

impl BlindIndexMetadata for EmailLookup {
    const ID: IndexId = index_id!("80000000-0000-4000-8000-000000000008");
    // Demonstration precision; choose precision and normalization for your domain.
    const BITS: usize = 128;
}

impl BlindIndexSpec<String> for EmailLookup {
    fn normalize(input: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        // This example's equality rule is ASCII case-insensitive with trimmed spaces.
        Ok(Zeroizing::new(
            input.trim().to_ascii_lowercase().into_bytes(),
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct StoredUser {
    email: Ciphertext<String, UserEmail>,
    email_lookup: BlindIndex<EmailLookup>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fixed, independent roots are for this demonstration only. Load durable keys
    // securely in applications; never reuse a generation ID with different material.
    let keys = LocalEncryptionKeyring::new(
        EncryptionKey::new(key_id!("40000000-0000-4000-8000-000000000004"), [0x31; 32]),
        [],
    )?;
    let index_keys = LocalBlindIndexKeyring::new(
        BlindIndexKey::new(
            index_key_id!("50000000-0000-4000-8000-000000000005"),
            [0x42; 32],
        ),
        [],
    )?;

    let email = Encrypted::<_, UserEmail>::new("Mark@Example.com".to_owned());
    // &() supplies the unit runtime context; the profile still binds to UserEmail.
    // prepare_with borrows email: it does not remove plaintext from memory.
    let prepared = email
        .prepare_with(&(), &keys)?
        .with_index_with::<EmailLookup>(&index_keys)?;
    let stored = StoredUser {
        email: prepared.ciphertext().clone(),
        email_lookup: BlindIndex::from_bytes(prepared.index::<EmailLookup>()?.as_bytes())?,
    };
    // Persist both fields atomically as one document in the chosen storage system.
    let document = serde_json::to_vec(&stored)?;
    let restored: StoredUser = serde_json::from_slice(&document)?;
    assert_eq!(restored.email, stored.email);
    assert_eq!(restored.email_lookup, stored.email_lookup);

    // Parsing/inspection uses no keys. These IDs remain unauthenticated metadata.
    let _envelope_info = inspect_ciphertext(restored.email.as_bytes())?;
    let _index_info = inspect_blind_index(restored.email_lookup.as_bytes())?;
    assert!(!restored.email.needs_reencryption_with(&keys)?);

    // Explicit decryption authenticates, unpads, and decodes with the chosen profile.
    let plaintext = restored.email.decrypt_with(&(), &keys)?;
    assert_eq!(plaintext.expose_secret(), "Mark@Example.com");

    // Separately check index consistency, here after convergence to the current key.
    let recomputed = derive_blind_index::<EmailLookup, String, FieldBound<UserEmail>>(
        plaintext.expose_secret(),
        &(),
        &index_keys,
    )?;
    assert_eq!(restored.email_lookup, recomputed);

    // Lookup searches every readable generation and compares authenticated plaintext.
    let query = "mark@example.com".to_owned();
    let probes =
        blind_index_probes::<EmailLookup, String, FieldBound<UserEmail>>(&query, &(), &index_keys)?;
    let matches = probes.iter().any(|probe| probe == &restored.email_lookup)
        && verify_blind_index_candidate::<EmailLookup, String>(&query, plaintext.expose_secret())?;
    assert!(matches);

    // Plaintext comparison alone cannot detect a stored index for another value.
    let unrelated_index = derive_blind_index::<EmailLookup, String, FieldBound<UserEmail>>(
        &"other@example.com".to_owned(),
        &(),
        &index_keys,
    )?;
    assert_ne!(unrelated_index, recomputed);
    assert!(verify_blind_index_candidate::<EmailLookup, String>(
        &query,
        plaintext.expose_secret()
    )?);

    // Structurally valid, current-generation bytes can still fail authentication.
    let mut damaged = restored.email.into_bytes();
    *damaged.last_mut().ok_or("empty ciphertext")? ^= 1;
    let damaged_json = serde_json::to_vec(&damaged)?;
    let damaged: Ciphertext<String, UserEmail> = serde_json::from_slice(&damaged_json)?;
    assert!(!damaged.needs_reencryption_with(&keys)?);
    assert_eq!(
        damaged.decrypt_with(&(), &keys).unwrap_err(),
        Error::AuthenticationFailed
    );

    println!("Stored bytes round-tripped; authenticated read and index consistency checked.");
    Ok(())
}
