//! Public-boundary tests for routing field keys to providers.

use std::sync::Arc;

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, EncryptionKey,
    EncryptionKeyProvider, Error, Field, FieldId, IndexId, IndexKeyId, KeyId, KeyProviderError,
    LocalBlindIndexKeyring, LocalEncryptionKeyring, Router, blind_index_probes, decrypt,
    derive_blind_index, encrypt, field_id, index_id, index_key_id, inspect_blind_index,
    inspect_ciphertext, key_id,
};
use zeroize::Zeroizing;

const GENERAL_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const PAYMENTS_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");
const GENERAL_INDEX_KEY_ID: IndexKeyId = index_key_id!("60000000-0000-4000-8000-000000000006");
const PAYMENTS_INDEX_KEY_ID: IndexKeyId = index_key_id!("70000000-0000-4000-8000-000000000007");

struct Email;

impl Field for Email {
    const ID: FieldId = field_id!("30000000-0000-4000-8000-000000000003");
    const NAME: &'static str = "email";
}

struct Iban;

impl Field for Iban {
    const ID: FieldId = field_id!("40000000-0000-4000-8000-000000000004");
    const NAME: &'static str = "iban";
}

fn keyring(id: KeyId, byte: u8) -> LocalEncryptionKeyring {
    LocalEncryptionKeyring::new(EncryptionKey::new(id, [byte; 32]), []).unwrap()
}

#[test]
fn fields_routed_to_different_providers_use_their_own_keys() {
    let router = Router::strict()
        .route::<Email>(keyring(GENERAL_KEY_ID, 1))
        .unwrap()
        .route::<Iban>(keyring(PAYMENTS_KEY_ID, 2))
        .unwrap();

    let email = encrypt::<Email>(b"mark@example.com", &router).unwrap();
    let iban = encrypt::<Iban>(b"DE89370400440532013000", &router).unwrap();

    assert_eq!(inspect_ciphertext(&email).unwrap().key_id(), GENERAL_KEY_ID);
    assert_eq!(inspect_ciphertext(&iban).unwrap().key_id(), PAYMENTS_KEY_ID);
    assert_eq!(
        decrypt::<Email>(&email, &router).unwrap().as_slice(),
        b"mark@example.com"
    );
    assert_eq!(
        decrypt::<Iban>(&iban, &router).unwrap().as_slice(),
        b"DE89370400440532013000"
    );
}

#[test]
fn strict_router_rejects_unrouted_fields_for_encryption_and_decryption() {
    let general = keyring(GENERAL_KEY_ID, 1);
    let ciphertext = encrypt::<Iban>(b"DE89370400440532013000", &general).unwrap();
    let router = Router::strict().route::<Email>(general).unwrap();

    assert_eq!(
        encrypt::<Iban>(b"DE89370400440532013000", &router),
        Err(Error::UnroutedField(Iban::ID))
    );
    assert_eq!(
        decrypt::<Iban>(&ciphertext, &router),
        Err(Error::UnroutedField(Iban::ID))
    );
}

struct Exact;

impl BlindIndexMetadata for Exact {
    const BITS: usize = 32;
    const ID: IndexId = index_id!("50000000-0000-4000-8000-000000000005");
}

impl BlindIndexSpec<str> for Exact {
    fn normalize(input: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(input.as_bytes().to_vec()))
    }
}

fn index_keyring(id: IndexKeyId, byte: u8) -> LocalBlindIndexKeyring {
    LocalBlindIndexKeyring::new(BlindIndexKey::new(id, [byte; 32]), []).unwrap()
}

#[test]
fn routed_blind_indexes_use_their_fields_provider() {
    let router = Router::strict()
        .route::<Email>(index_keyring(GENERAL_INDEX_KEY_ID, 3))
        .unwrap()
        .route::<Iban>(index_keyring(PAYMENTS_INDEX_KEY_ID, 4))
        .unwrap();

    let email = derive_blind_index::<Exact, str, Email>("mark@example.com", &router).unwrap();
    let iban = blind_index_probes::<Exact, str, Iban>("DE89", &router).unwrap();

    assert_eq!(
        inspect_blind_index(email.as_bytes())
            .unwrap()
            .index_key_id(),
        GENERAL_INDEX_KEY_ID
    );
    assert_eq!(iban.len(), 1);
    assert_eq!(
        inspect_blind_index(iban[0].as_bytes())
            .unwrap()
            .index_key_id(),
        PAYMENTS_INDEX_KEY_ID
    );
}

#[test]
fn strict_router_rejects_unrouted_fields_for_blind_indexes() {
    let router = Router::strict()
        .route::<Email>(index_keyring(GENERAL_INDEX_KEY_ID, 3))
        .unwrap();

    assert_eq!(
        derive_blind_index::<Exact, str, Iban>("DE89", &router).unwrap_err(),
        Error::UnroutedField(Iban::ID)
    );
    assert_eq!(
        blind_index_probes::<Exact, str, Iban>("DE89", &router).unwrap_err(),
        Error::UnroutedField(Iban::ID)
    );
}

/// Deliberately the same logical field as [`Email`].
struct ContactEmail;

impl Field for ContactEmail {
    const ID: FieldId = Email::ID;
    const NAME: &'static str = "contact-email";
}

#[test]
fn markers_sharing_a_field_id_resolve_to_the_same_route() {
    let router = Router::strict()
        .route::<Email>(keyring(GENERAL_KEY_ID, 1))
        .unwrap();

    let ciphertext = encrypt::<ContactEmail>(b"mark@example.com", &router).unwrap();

    assert_eq!(
        inspect_ciphertext(&ciphertext).unwrap().key_id(),
        GENERAL_KEY_ID
    );
    assert_eq!(
        decrypt::<Email>(&ciphertext, &router).unwrap().as_slice(),
        b"mark@example.com"
    );
}

#[test]
fn a_second_route_for_one_field_is_rejected() {
    let duplicate = Router::strict()
        .route::<Email>(keyring(GENERAL_KEY_ID, 1))
        .unwrap()
        .route::<Email>(keyring(GENERAL_KEY_ID, 1));
    let conflicting = Router::strict()
        .route::<Email>(keyring(GENERAL_KEY_ID, 1))
        .unwrap()
        .route::<ContactEmail>(keyring(PAYMENTS_KEY_ID, 2));

    assert_eq!(duplicate.unwrap_err(), Error::DuplicateRoute(Email::ID));
    assert_eq!(conflicting.unwrap_err(), Error::DuplicateRoute(Email::ID));
}

#[test]
fn a_fallback_router_serves_unrouted_fields_visibly() {
    let router = Router::new(keyring(GENERAL_KEY_ID, 1))
        .route::<Iban>(keyring(PAYMENTS_KEY_ID, 2))
        .unwrap();

    let email = encrypt::<Email>(b"mark@example.com", &router).unwrap();
    let iban = encrypt::<Iban>(b"DE89370400440532013000", &router).unwrap();

    assert_eq!(inspect_ciphertext(&email).unwrap().key_id(), GENERAL_KEY_ID);
    assert_eq!(inspect_ciphertext(&iban).unwrap().key_id(), PAYMENTS_KEY_ID);
    assert!(router.falls_back(Email::ID));
    assert!(!router.falls_back(Iban::ID));
}

#[test]
fn a_strict_router_never_falls_back() {
    let router = Router::strict()
        .route::<Email>(keyring(GENERAL_KEY_ID, 1))
        .unwrap();

    assert!(!router.falls_back(Email::ID));
    assert!(!router.falls_back(Iban::ID));
}

/// A provider of a different type than the local keyring, such as a KMS client.
struct PaymentsKms(LocalEncryptionKeyring);

impl EncryptionKeyProvider for PaymentsKms {
    fn current_key(&self, field: FieldId) -> Result<EncryptionKey, KeyProviderError> {
        self.0.current_key(field)
    }

    fn key(&self, field: FieldId, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        self.0.key(field, id)
    }
}

#[test]
fn fields_can_route_to_providers_of_different_types() {
    let router = Router::<Arc<dyn EncryptionKeyProvider>>::strict()
        .route::<Email>(Arc::new(keyring(GENERAL_KEY_ID, 1)))
        .unwrap()
        .route::<Iban>(Arc::new(PaymentsKms(keyring(PAYMENTS_KEY_ID, 2))))
        .unwrap();

    let email = encrypt::<Email>(b"mark@example.com", &router).unwrap();
    let iban = encrypt::<Iban>(b"DE89370400440532013000", &router).unwrap();

    assert_eq!(inspect_ciphertext(&email).unwrap().key_id(), GENERAL_KEY_ID);
    assert_eq!(inspect_ciphertext(&iban).unwrap().key_id(), PAYMENTS_KEY_ID);
    assert_eq!(
        decrypt::<Iban>(&iban, &router).unwrap().as_slice(),
        b"DE89370400440532013000"
    );
}
