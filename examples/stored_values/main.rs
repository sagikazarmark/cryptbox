//! Serializes stored bytes, then deliberately authenticates and checks consistency.
//! See README.md beside this source for usage and trust boundaries.

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, Seal, Sealed, index_key_id, inspect_blind_index, inspect_ciphertext,
    key_id,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Seal)]
#[seal(id = "181642fe-59de-4fe3-9576-cb1cb66116ef", value = String)]
struct UserEmail;

#[allow(clippy::unnecessary_wraps)] // Normalizers are fallible by contract.
fn normalize_email(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    // This example's equality rule is ASCII case-insensitive with trimmed spaces.
    Ok(Zeroizing::new(
        input.trim().to_ascii_lowercase().into_bytes(),
    ))
}

#[derive(BlindIndexSpec)]
#[blind_index(
    id = "2ce82e31-6001-4b05-b4e2-8fc262997209",
    seal = UserEmail,
    // Demonstration precision; choose precision and normalization for your domain.
bits = 128,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
struct EmailLookup;

#[derive(Serialize, Deserialize)]
struct StoredUser {
    email: Sealed<UserEmail>,
    email_lookup: BlindIndex<EmailLookup>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fixed, independent roots are for this demonstration only. Load durable keys
    // securely in applications; never reuse a generation ID with different material.
    let keys = EncryptionKeyring::new(
        EncryptionKey::new(key_id!("36ade21a-f637-4b61-9fae-f8d2a8efc70d"), [0x31; 32]),
        [],
    )?;
    let index_keys = BlindIndexKeyring::new(
        BlindIndexKey::new(
            index_key_id!("0b8390e9-6e64-438b-8a7f-12c91da19f25"),
            [0x42; 32],
        ),
        [],
    )?;

    let email = "Mark@Example.com".to_owned();
    // The UserEmail seal binds the sealed value and index to its seal ID.
    // prepare borrows email: it does not remove plaintext from memory.
    let prepared = Sealed::<UserEmail>::prepare(&email, (), &keys)?
        .with_index_with::<EmailLookup>(&index_keys)?;
    let stored = StoredUser {
        email: prepared.sealed().clone(),
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
    assert!(!restored.email.needs_reseal((), &keys)?);

    // Opening authenticates, decrypts, unpads, and decodes with the chosen seal's codec.
    let plaintext = restored.email.open((), &keys)?;
    assert_eq!(plaintext, "Mark@Example.com");

    // Separately check index consistency, here after convergence to the current key.
    let recomputed = EmailLookup::derive_with(&plaintext, &(), &index_keys)?;
    assert_eq!(restored.email_lookup, recomputed);

    // Lookup searches every readable generation and compares authenticated plaintext.
    let query = "mark@example.com";
    let probes = EmailLookup::probes_with(query, &(), &index_keys)?;
    let matches = probes.iter().any(|probe| probe == &restored.email_lookup)
        && EmailLookup::verify_candidate(query, &plaintext)?;
    assert!(matches);

    // Plaintext comparison alone cannot detect a stored index for another value.
    let unrelated_index =
        EmailLookup::derive_with(&"other@example.com".to_owned(), &(), &index_keys)?;
    assert_ne!(unrelated_index, recomputed);
    assert!(EmailLookup::verify_candidate(query, &plaintext)?);

    // Structurally valid, current-generation bytes can still fail authentication.
    let mut damaged = restored.email.into_bytes();
    *damaged.last_mut().ok_or("empty envelope")? ^= 1;
    let damaged_json = serde_json::to_vec(&damaged)?;
    let damaged: Sealed<UserEmail> = serde_json::from_slice(&damaged_json)?;
    assert!(!damaged.needs_reseal((), &keys)?);
    assert_eq!(
        damaged.open((), &keys).unwrap_err(),
        Error::AuthenticationFailed
    );

    println!("Stored bytes round-tripped; authenticated read and index consistency checked.");
    Ok(())
}
