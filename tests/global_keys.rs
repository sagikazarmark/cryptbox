//! Public-boundary tests for the process-wide key installation.
//!
//! This binary is the only one that installs the global. Its assertions depend
//! on install order, so they run as one sequenced test rather than racing each
//! other on the shared global.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, IndexId, IndexKeyId, KeyId, Keys, Padding, Seal, SealId, Sealed,
    Utf8, index_id, index_key_id, key_id,
    keys::{self, AlreadyInstalled},
    seal_id,
};
use zeroize::Zeroizing;

const INSTALLED_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const EXPLICIT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");
const REJECTED_KEY_ID: KeyId = key_id!("30000000-0000-4000-8000-000000000003");
const INSTALLED_INDEX_KEY_ID: IndexKeyId = index_key_id!("60000000-0000-4000-8000-000000000006");
const EXPLICIT_INDEX_KEY_ID: IndexKeyId = index_key_id!("70000000-0000-4000-8000-000000000007");

struct Email;

impl Seal for Email {
    const ID: SealId = seal_id!("40000000-0000-4000-8000-000000000004");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Indexes = ();
}

struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Seal = Email;
    const ID: IndexId = index_id!("50000000-0000-4000-8000-000000000005");
    const BITS: u16 = 128;
    const NORMALIZER: &'static str = "exact/1";
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(query.as_bytes().to_vec()))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

fn keyring(id: KeyId, byte: u8) -> EncryptionKeyring {
    EncryptionKeyring::new(EncryptionKey::new(id, [byte; 32]), []).unwrap()
}

fn index_keyring(id: IndexKeyId, byte: u8) -> BlindIndexKeyring {
    BlindIndexKeyring::new(BlindIndexKey::new(id, [byte; 32]), []).unwrap()
}

#[test]
fn global_keys_install_once_back_only_the_global_conveniences() {
    let installed = keyring(INSTALLED_KEY_ID, 1);
    let installed_indexes = index_keyring(INSTALLED_INDEX_KEY_ID, 11);
    let explicit = keyring(EXPLICIT_KEY_ID, 2);
    let explicit_indexes = index_keyring(EXPLICIT_INDEX_KEY_ID, 12);
    let email = "mark@example.com".to_owned();

    // Before installation, every global convenience fails closed.
    assert_eq!(keys::installed().unwrap_err(), Error::KeysNotInstalled);
    assert_eq!(
        Sealed::<Email>::seal_global(&email).unwrap_err(),
        Error::KeysNotInstalled
    );
    assert_eq!(
        EmailLookup::probes("mark@example.com").unwrap_err(),
        Error::KeysNotInstalled
    );
    let explicit_sealed = Sealed::<Email>::seal(&email, &explicit).unwrap();
    assert_eq!(
        explicit_sealed.open_global().unwrap_err(),
        Error::KeysNotInstalled
    );
    assert_eq!(
        Sealed::<Email>::prepare(&email, &explicit)
            .unwrap()
            .with_index::<EmailLookup>()
            .unwrap_err(),
        Error::KeysNotInstalled
    );

    keys::install(Keys::new(installed.clone()).with_blind_indexes(installed_indexes.clone()))
        .unwrap();

    // A second installation is rejected and does not replace the first.
    assert_eq!(
        keys::install(Keys::new(keyring(REJECTED_KEY_ID, 3))),
        Err(AlreadyInstalled)
    );

    // Implicit forms use the installed keys.
    let global_sealed = Sealed::<Email>::seal_global(&email).unwrap();
    assert_eq!(global_sealed.open(&installed).unwrap(), "mark@example.com");
    assert_eq!(global_sealed.open_global().unwrap(), "mark@example.com");
    assert_eq!(
        EmailLookup::probes("mark@example.com").unwrap(),
        EmailLookup::probes_with("mark@example.com", &installed_indexes).unwrap()
    );

    // Explicit forms ignore the installed keys.
    let explicit_sealed = Sealed::<Email>::seal(&email, &explicit).unwrap();
    assert_eq!(explicit_sealed.open(&explicit).unwrap(), "mark@example.com");
    assert_eq!(
        explicit_sealed.open_global().unwrap_err(),
        Error::UnknownEncryptionKey(EXPLICIT_KEY_ID)
    );
    assert_eq!(
        global_sealed.open(&explicit).unwrap_err(),
        Error::UnknownEncryptionKey(INSTALLED_KEY_ID)
    );
    let prepared = Sealed::<Email>::prepare(&email, &explicit)
        .unwrap()
        .with_index_with::<EmailLookup>(&explicit_indexes)
        .unwrap();
    assert_eq!(
        prepared.index::<EmailLookup>().unwrap().as_bytes(),
        EmailLookup::probes_with("mark@example.com", &explicit_indexes).unwrap()[0].as_bytes()
    );
    assert_ne!(
        EmailLookup::probes_with("mark@example.com", &explicit_indexes).unwrap(),
        EmailLookup::probes("mark@example.com").unwrap()
    );
}

#[test]
fn keys_without_a_blind_index_keyring_reject_index_operations() {
    let keys = Keys::new(keyring(EXPLICIT_KEY_ID, 2));
    let email = "mark@example.com".to_owned();

    assert_eq!(
        EmailLookup::probes_with("mark@example.com", &keys).unwrap_err(),
        Error::BlindIndexKeysNotConfigured
    );
    assert_eq!(
        Sealed::<Email>::prepare(&email, &keys)
            .unwrap()
            .with_index_with::<EmailLookup>(&keys)
            .unwrap_err(),
        Error::BlindIndexKeysNotConfigured
    );
}
