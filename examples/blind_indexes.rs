//! Prepares and safely queries a blind index across index-key rotation.

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, IndexKeyId, KeyId, Seal, Sealed, index_key_id, key_id,
};
use zeroize::Zeroizing;

const ENCRYPTION_KEY_ID: KeyId = key_id!("d0238a8e-7352-4b0b-a089-1fa767e28c35");
const OLD_INDEX_KEY_ID: IndexKeyId = index_key_id!("92ba353d-4a5b-419c-be7b-577ec21a8336");
const CURRENT_INDEX_KEY_ID: IndexKeyId = index_key_id!("1ca61eba-f5d2-4b37-86db-cdc2b8204d88");

#[derive(Seal)]
#[cryptbox(id = "283e5ff6-40ba-45e9-b55f-20ce5cee88c4", value = String)]
struct UserEmail;

#[allow(clippy::unnecessary_wraps)] // Normalizers are fallible by contract.
fn normalize_email(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(
        input.trim().to_ascii_lowercase().into_bytes(),
    ))
}

#[derive(BlindIndexSpec)]
#[cryptbox(
    id = "84651307-589f-4df2-a4b0-f8eaf9e52d3d",
    seal = UserEmail,
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
    let prepared = Sealed::<UserEmail>::prepare(&value, &encryption_keys)?
        .with_index::<EmailLookup>(&old_index_keys)?;
    let stored = prepared.sealed().clone();
    let stored_index = prepared.index::<EmailLookup>()?.as_bytes().to_vec();

    let index_keys = BlindIndexKeyring::new(
        BlindIndexKey::new(CURRENT_INDEX_KEY_ID, [0x53; 32]),
        [old_index_key],
    )?;
    let query = "mark@example.com";
    let probes = BlindIndex::<EmailLookup>::probes(query, &index_keys)?;

    // Stored indexes are lookup tokens, not plaintext secrets, so ordinary
    // equality is appropriate when matching every probe during key rotation.
    let is_candidate = probes.iter().any(|probe| probe.as_bytes() == stored_index);
    assert!(is_candidate);

    // A blind-index hit is only a candidate: open it and compare normalized plaintext.
    let candidate = stored.open(&encryption_keys)?;
    assert!(BlindIndex::<EmailLookup>::verify_candidate(
        query, &candidate
    )?);

    Ok(())
}
