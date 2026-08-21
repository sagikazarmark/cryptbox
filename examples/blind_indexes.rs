//! Prepares and safely queries a blind index across index-key rotation.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Encrypted, EncryptionKey,
    EncryptionProfile, Field, FieldBound, GlobalKeyContext, IndexId, IndexKeyId, KeyId,
    LocalBlindIndexKeyring, LocalEncryptionKeyring, Utf8, blind_index_probes, field_id, index_id,
    index_key_id, key_id, verify_blind_index_candidate,
};
use zeroize::Zeroizing;

const ENCRYPTION_KEY_ID: KeyId = key_id!("40000000-0000-4000-8000-000000000004");
const OLD_INDEX_KEY_ID: IndexKeyId = index_key_id!("50000000-0000-4000-8000-000000000005");
const CURRENT_INDEX_KEY_ID: IndexKeyId = index_key_id!("60000000-0000-4000-8000-000000000006");

struct UserEmail;

impl Field for UserEmail {
    const ID: cryptbox::FieldId = field_id!("70000000-0000-4000-8000-000000000007");
    const NAME: &'static str = "user-email";
}

impl EncryptionProfile<String> for UserEmail {
    type Binding = FieldBound<Self>;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
}

struct EmailLookup;

impl BlindIndexMetadata for EmailLookup {
    const ID: IndexId = index_id!("80000000-0000-4000-8000-000000000008");
    const BITS: usize = 128;
}

impl BlindIndexSpec<str> for EmailLookup {
    fn normalize(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(
            input.trim().to_ascii_lowercase().into_bytes(),
        ))
    }
}

impl BlindIndexSpec<String> for EmailLookup {
    fn normalize(input: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        <Self as BlindIndexSpec<str>>::normalize(input)
    }
}

fn main() -> Result<(), cryptbox::Error> {
    // Encryption and blind-index roots must be generated and managed independently.
    let encryption_keys =
        LocalEncryptionKeyring::new(EncryptionKey::new(ENCRYPTION_KEY_ID, [0x31; 32]), [])?;
    let old_index_key = BlindIndexKey::new(OLD_INDEX_KEY_ID, [0x42; 32]);
    let old_index_keys = LocalBlindIndexKeyring::new(old_index_key.clone(), [])?;

    let value = Encrypted::<_, UserEmail>::new("Mark@Example.com".to_owned());
    let prepared = value
        .prepare_with(&(), &encryption_keys)?
        .with_index_with::<EmailLookup>(&old_index_keys)?;
    let stored_ciphertext = prepared.ciphertext().clone();
    let stored_index = prepared.index::<EmailLookup>()?.as_bytes().to_vec();

    let index_keys = LocalBlindIndexKeyring::new(
        BlindIndexKey::new(CURRENT_INDEX_KEY_ID, [0x53; 32]),
        [old_index_key],
    )?;
    let query = "mark@example.com";
    let probes =
        blind_index_probes::<EmailLookup, str, FieldBound<UserEmail>>(query, &(), &index_keys)?;

    // A database query should match against every probe during index-key rotation.
    let is_candidate = probes.iter().any(|probe| probe.as_bytes() == stored_index);
    assert!(is_candidate);

    // A blind-index hit is only a candidate: decrypt and compare normalized plaintext.
    let candidate = stored_ciphertext.decrypt_with(&(), &encryption_keys)?;
    assert!(verify_blind_index_candidate::<EmailLookup, str>(
        query,
        candidate.expose_secret(),
    )?);

    Ok(())
}
