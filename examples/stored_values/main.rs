//! Serializes stored bytes, then deliberately authenticates and checks consistency.
//! See README.md beside this source for usage and trust boundaries.

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexSpec, Ciphertext, Encrypted,
    EncryptionKey, Error, Field, LocalBlindIndexKeyring, LocalEncryptionKeyring, index_key_id,
    inspect_blind_index, inspect_ciphertext, key_id,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Field)]
#[cryptbox(id = "70000000-0000-4000-8000-000000000007", value = String)]
struct UserEmail;

#[allow(clippy::unnecessary_wraps)] // Normalizers are fallible by contract.
fn normalize_email(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    // This example's equality rule is ASCII case-insensitive with trimmed spaces.
    Ok(Zeroizing::new(
        input.trim().to_ascii_lowercase().into_bytes(),
    ))
}

#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "80000000-0000-4000-8000-000000000008",
    field = UserEmail,
    // Demonstration precision; choose precision and normalization for your domain.
    bits = 128,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
struct EmailLookup;

#[derive(Serialize, Deserialize)]
struct StoredUser {
    email: Ciphertext<UserEmail>,
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

    let email = Encrypted::<UserEmail>::new("Mark@Example.com".to_owned());
    // The UserEmail field binds the ciphertext and index to its field ID.
    // prepare_with borrows email: it does not remove plaintext from memory.
    let prepared = email
        .prepare_with(&keys)?
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

    // Explicit decryption authenticates, unpads, and decodes with the chosen field's codec.
    let plaintext = restored.email.decrypt_with(&keys)?;
    assert_eq!(plaintext.expose_secret(), "Mark@Example.com");

    // Separately check index consistency, here after convergence to the current key.
    let recomputed = EmailLookup::derive_with(plaintext.expose_secret(), &index_keys)?;
    assert_eq!(restored.email_lookup, recomputed);

    // Lookup searches every readable generation and compares authenticated plaintext.
    let query = "mark@example.com";
    let probes = EmailLookup::probes_with(query, &index_keys)?;
    let matches = probes.iter().any(|probe| probe == &restored.email_lookup)
        && EmailLookup::verify_candidate(query, plaintext.expose_secret())?;
    assert!(matches);

    // Plaintext comparison alone cannot detect a stored index for another value.
    let unrelated_index = EmailLookup::derive_with(&"other@example.com".to_owned(), &index_keys)?;
    assert_ne!(unrelated_index, recomputed);
    assert!(EmailLookup::verify_candidate(
        query,
        plaintext.expose_secret()
    )?);

    // Structurally valid, current-generation bytes can still fail authentication.
    let mut damaged = restored.email.into_bytes();
    *damaged.last_mut().ok_or("empty ciphertext")? ^= 1;
    let damaged_json = serde_json::to_vec(&damaged)?;
    let damaged: Ciphertext<UserEmail> = serde_json::from_slice(&damaged_json)?;
    assert!(!damaged.needs_reencryption_with(&keys)?);
    assert_eq!(
        damaged.decrypt_with(&keys).unwrap_err(),
        Error::AuthenticationFailed
    );

    println!("Stored bytes round-tripped; authenticated read and index consistency checked.");
    Ok(())
}
