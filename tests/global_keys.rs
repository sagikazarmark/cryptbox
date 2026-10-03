//! Public-boundary tests for the process-wide key installation.
//!
//! Its assertions depend on install order, starting from no installed keys, so
//! they run as one sequenced test rather than racing each other on the shared
//! global.

#![cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
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

struct Email;

impl Seal for Email {
    const ID: SealId = seal_id!("40000000-0000-4000-8000-000000000004");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
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
fn global_keys_install_once_and_serve_only_what_reads_them() {
    let installed = keyring(INSTALLED_KEY_ID, 1);
    let installed_indexes = index_keyring(INSTALLED_INDEX_KEY_ID, 11);
    let explicit = keyring(EXPLICIT_KEY_ID, 2);
    let email = "mark@example.com".to_owned();

    // Before installation, reading the global fails closed.
    assert_eq!(keys::installed().unwrap_err(), Error::KeysNotInstalled);
    #[cfg(feature = "sqlx-sqlite")]
    {
        use sqlx::{Encode, Sqlite};

        let value = cryptbox::Plain::<Email>::new(email.clone());
        let mut buffer = Vec::new();
        let Err(error) =
            <cryptbox::Plain<Email> as Encode<'_, Sqlite>>::encode_by_ref(&value, &mut buffer)
        else {
            panic!("an automatic column must not encode without installed keys");
        };
        assert_eq!(
            error.downcast_ref::<Error>(),
            Some(&Error::KeysNotInstalled)
        );
    }

    keys::install(Keys::new(installed.clone()).with_blind_indexes(installed_indexes.clone()))
        .unwrap();

    // A second installation is rejected and does not replace the first.
    assert_eq!(
        keys::install(Keys::new(keyring(REJECTED_KEY_ID, 3))),
        Err(AlreadyInstalled)
    );

    // The installed keys are the keys installed.
    let global = keys::installed().unwrap();
    let global_sealed = Sealed::<Email>::seal(&email, global).unwrap();
    assert_eq!(global_sealed.open(&installed).unwrap(), "mark@example.com");
    assert_eq!(
        BlindIndex::<EmailLookup>::probes("mark@example.com", global).unwrap(),
        BlindIndex::<EmailLookup>::probes("mark@example.com", &installed_indexes).unwrap()
    );

    // Explicit keys ignore the installed keys.
    let explicit_sealed = Sealed::<Email>::seal(&email, &explicit).unwrap();
    assert_eq!(explicit_sealed.open(&explicit).unwrap(), "mark@example.com");
    assert_eq!(
        explicit_sealed.open(global).unwrap_err(),
        Error::UnknownEncryptionKey(EXPLICIT_KEY_ID)
    );
    assert_eq!(
        global_sealed.open(&explicit).unwrap_err(),
        Error::UnknownEncryptionKey(INSTALLED_KEY_ID)
    );
}
