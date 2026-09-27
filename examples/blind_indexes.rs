//! Prepares and safely queries a blind index across index-key rotation.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Field, IndexKeyId, KeyId, Sealed, index_key_id, key_id,
};
use zeroize::Zeroizing;

const ENCRYPTION_KEY_ID: KeyId = key_id!("40000000-0000-4000-8000-000000000004");
const OLD_INDEX_KEY_ID: IndexKeyId = index_key_id!("50000000-0000-4000-8000-000000000005");
const CURRENT_INDEX_KEY_ID: IndexKeyId = index_key_id!("60000000-0000-4000-8000-000000000006");

#[derive(Field)]
#[cryptbox(id = "70000000-0000-4000-8000-000000000007", value = String)]
struct UserEmail;

#[allow(clippy::unnecessary_wraps)] // Normalizers are fallible by contract.
fn normalize_email(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(
        input.trim().to_ascii_lowercase().into_bytes(),
    ))
}

#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "80000000-0000-4000-8000-000000000008",
    field = UserEmail,
    bits = 128,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
struct EmailLookup;

fn main() -> Result<(), cryptbox::Error> {
    // Encryption and blind-index roots must be generated and managed independently.
    let encryption_keys =
        EncryptionKeyring::new(EncryptionKey::new(ENCRYPTION_KEY_ID, [0x31; 32]), [])?;
    let old_index_key = BlindIndexKey::new(OLD_INDEX_KEY_ID, [0x42; 32]);
    let old_index_keys = BlindIndexKeyring::new(old_index_key.clone(), [])?;

    let value = "Mark@Example.com".to_owned();
    let prepared = Sealed::<UserEmail>::prepare(&value, (), &encryption_keys)?
        .with_index_with::<EmailLookup>(&old_index_keys)?;
    let stored = prepared.sealed().clone();
    let stored_index = prepared.index::<EmailLookup>()?.as_bytes().to_vec();

    let index_keys = BlindIndexKeyring::new(
        BlindIndexKey::new(CURRENT_INDEX_KEY_ID, [0x53; 32]),
        [old_index_key],
    )?;
    let query = "mark@example.com";
    let probes = EmailLookup::probes_with(query, &index_keys)?;

    // Stored indexes are lookup tokens, not plaintext secrets, so ordinary
    // equality is appropriate when matching every probe during key rotation.
    let is_candidate = probes.iter().any(|probe| probe.as_bytes() == stored_index);
    assert!(is_candidate);

    // A blind-index hit is only a candidate: open it and compare normalized plaintext.
    let candidate = stored.open((), &encryption_keys)?;
    assert!(EmailLookup::verify_candidate(query, &candidate)?);

    Ok(())
}
