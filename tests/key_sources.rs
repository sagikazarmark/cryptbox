//! Public-boundary tests for passing keyrings in through key sources.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeySource, BlindIndexKeyring, BlindIndexSpec,
    EncryptionKey, EncryptionKeySource, EncryptionKeyring, Error, Field, FieldId, FieldOnly,
    IndexId, IndexKeyId, KeyId, KeyScope, Keys, Padding, Raw, Sealed, Tenant, TenantId, field_id,
    index_id, index_key_id, inspect_blind_index, key_id,
};
use zeroize::Zeroizing;

const GENERAL_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const PAYMENTS_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");
const PREVIOUS_KEY_ID: KeyId = key_id!("30000000-0000-4000-8000-000000000003");
const GENERAL_INDEX_KEY_ID: IndexKeyId = index_key_id!("60000000-0000-4000-8000-000000000006");
const PAYMENTS_INDEX_KEY_ID: IndexKeyId = index_key_id!("70000000-0000-4000-8000-000000000007");

struct Email;

impl Field for Email {
    const ID: FieldId = field_id!("40000000-0000-4000-8000-000000000004");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct Iban;

impl Field for Iban {
    const ID: FieldId = field_id!("50000000-0000-4000-8000-000000000005");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct TenantNote;

impl Field for TenantNote {
    const ID: FieldId = field_id!("80000000-0000-4000-8000-000000000008");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = Tenant;
    type Indexes = ();
}

struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Field = Email;
    const ID: IndexId = index_id!("90000000-0000-4000-8000-000000000009");
    const BITS: u16 = 32;
    const NORMALIZER: &'static str = "exact/1";
    type Query = [u8];

    fn normalize_query(query: &[u8]) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(query.to_vec()))
    }

    fn normalize_value(value: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

struct IbanLookup;

impl BlindIndexSpec for IbanLookup {
    type Field = Iban;
    const ID: IndexId = index_id!("a0000000-0000-4000-8000-00000000000a");
    const BITS: u16 = 32;
    const NORMALIZER: &'static str = "exact/1";
    type Query = [u8];

    fn normalize_query(query: &[u8]) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(query.to_vec()))
    }

    fn normalize_value(value: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
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
fn opening_with_a_keyring_without_the_envelopes_key_fails() {
    let sealed = Sealed::<Email>::seal(&b"ada".to_vec(), (), &keyring(GENERAL_KEY_ID, 1)).unwrap();

    assert_eq!(
        sealed.open((), &keyring(PAYMENTS_KEY_ID, 2)),
        Err(Error::UnknownEncryptionKey(GENERAL_KEY_ID))
    );
}

#[test]
fn a_keyring_opens_values_sealed_with_its_previous_keys() {
    let previous = EncryptionKey::new(PREVIOUS_KEY_ID, [3; 32]);
    let sealed = Sealed::<Email>::seal(
        &b"ada".to_vec(),
        (),
        &EncryptionKeyring::new(previous.clone(), []).unwrap(),
    )
    .unwrap();
    let rotated =
        EncryptionKeyring::new(EncryptionKey::new(GENERAL_KEY_ID, [1; 32]), [previous]).unwrap();

    assert_eq!(sealed.open((), &rotated).unwrap(), b"ada");
    assert!(sealed.needs_reseal((), &rotated).unwrap());
    assert_eq!(
        sealed.reseal((), &rotated).unwrap().key_id(),
        GENERAL_KEY_ID
    );
}

#[test]
fn key_ids_are_unique_within_a_keyring() {
    let key = EncryptionKey::new(GENERAL_KEY_ID, [1; 32]);
    let other = EncryptionKey::new(GENERAL_KEY_ID, [2; 32]);
    assert_eq!(
        EncryptionKeyring::new(key.clone(), [other]).unwrap_err(),
        Error::DuplicateEncryptionKey(GENERAL_KEY_ID)
    );
    assert_eq!(
        EncryptionKeyring::new(key.clone(), [key]).unwrap_err(),
        Error::DuplicateEncryptionKey(GENERAL_KEY_ID)
    );

    let index_key = BlindIndexKey::new(GENERAL_INDEX_KEY_ID, [1; 32]);
    assert_eq!(
        BlindIndexKeyring::new(index_key.clone(), [index_key]).unwrap_err(),
        Error::DuplicateBlindIndexKey(GENERAL_INDEX_KEY_ID)
    );
}

#[test]
fn a_blind_index_keyring_lists_its_current_key_first() {
    let previous = BlindIndexKey::new(GENERAL_INDEX_KEY_ID, [1; 32]);
    let current = BlindIndexKey::new(PAYMENTS_INDEX_KEY_ID, [2; 32]);
    let keyring = BlindIndexKeyring::new(current, [previous]).unwrap();

    let ids: Vec<_> = keyring.readable().map(BlindIndexKey::id).collect();
    assert_eq!(ids, [PAYMENTS_INDEX_KEY_ID, GENERAL_INDEX_KEY_ID]);

    let probes = EmailLookup::probes_with(b"ada", &keyring).unwrap();
    let probe_ids: Vec<_> = probes
        .iter()
        .map(|probe| {
            inspect_blind_index(probe.as_bytes())
                .unwrap()
                .index_key_id()
        })
        .collect();
    assert_eq!(probe_ids, ids);
}

/// An application source that keeps payment fields under their own keyring.
struct ByField {
    general: EncryptionKeyring,
    payments: EncryptionKeyring,
}

impl EncryptionKeySource for ByField {
    fn encryption_keyring(
        &self,
        field: FieldId,
        _: &KeyScope,
    ) -> Result<&EncryptionKeyring, Error> {
        Ok(if field == Iban::ID {
            &self.payments
        } else {
            &self.general
        })
    }
}

#[test]
fn a_custom_source_chooses_keyrings_by_field() {
    let keys = ByField {
        general: keyring(GENERAL_KEY_ID, 1),
        payments: keyring(PAYMENTS_KEY_ID, 2),
    };

    let email = Sealed::<Email>::seal(&b"ada@example.com".to_vec(), (), &keys).unwrap();
    let iban = Sealed::<Iban>::seal(&b"DE89370400440532013000".to_vec(), (), &keys).unwrap();

    assert_eq!(email.key_id(), GENERAL_KEY_ID);
    assert_eq!(iban.key_id(), PAYMENTS_KEY_ID);
    assert_eq!(email.open((), &keys).unwrap(), b"ada@example.com");
    assert_eq!(iban.open((), &keys).unwrap(), b"DE89370400440532013000");
    assert_eq!(
        iban.open((), &keys.general),
        Err(Error::UnknownEncryptionKey(PAYMENTS_KEY_ID))
    );
}

/// An application source that keeps one keyring per tenant.
struct ByTenant(HashMap<KeyScope, EncryptionKeyring>);

impl EncryptionKeySource for ByTenant {
    fn encryption_keyring(
        &self,
        _: FieldId,
        scope: &KeyScope,
    ) -> Result<&EncryptionKeyring, Error> {
        self.0.get(scope).ok_or(Error::KeysUnavailable)
    }
}

#[test]
fn a_source_receives_the_key_scope_of_the_binding() {
    let acme = Tenant(TenantId::new(b"acme".to_vec()).unwrap());
    let globex = Tenant(TenantId::new(b"globex".to_vec()).unwrap());
    let initech = Tenant(TenantId::new(b"initech".to_vec()).unwrap());
    let keys = ByTenant(HashMap::from([
        (KeyScope::of(&acme).unwrap(), keyring(GENERAL_KEY_ID, 1)),
        (KeyScope::of(&globex).unwrap(), keyring(PAYMENTS_KEY_ID, 2)),
    ]));

    let note = b"renewal due".to_vec();
    let acme_note = Sealed::<TenantNote>::seal(&note, &acme, &keys).unwrap();
    let globex_note = Sealed::<TenantNote>::seal(&note, &globex, &keys).unwrap();

    assert_eq!(acme_note.key_id(), GENERAL_KEY_ID);
    assert_eq!(globex_note.key_id(), PAYMENTS_KEY_ID);
    assert_eq!(acme_note.open(&acme, &keys).unwrap(), note);
    assert_eq!(
        Sealed::<TenantNote>::seal(&note, &initech, &keys),
        Err(Error::KeysUnavailable)
    );
}

#[test]
fn a_field_only_binding_passes_the_empty_key_scope() {
    struct SeenScopes(Mutex<Vec<KeyScope>>, EncryptionKeyring);

    impl EncryptionKeySource for SeenScopes {
        fn encryption_keyring(
            &self,
            _: FieldId,
            scope: &KeyScope,
        ) -> Result<&EncryptionKeyring, Error> {
            self.0.lock().unwrap().push(scope.clone());
            Ok(&self.1)
        }
    }

    let keys = SeenScopes(Mutex::default(), keyring(GENERAL_KEY_ID, 1));
    Sealed::<Email>::seal(&b"ada".to_vec(), (), &keys).unwrap();

    assert_eq!(*keys.0.lock().unwrap(), [KeyScope::of(&FieldOnly).unwrap()]);
}

/// An application source that keeps payment indexes under their own keyring.
struct ByIndex {
    general: BlindIndexKeyring,
    payments: BlindIndexKeyring,
}

impl BlindIndexKeySource for ByIndex {
    fn blind_index_keyring(
        &self,
        index: IndexId,
        _: &KeyScope,
    ) -> Result<&BlindIndexKeyring, Error> {
        Ok(if index == IbanLookup::ID {
            &self.payments
        } else {
            &self.general
        })
    }
}

#[test]
fn a_custom_source_chooses_blind_index_keyrings_by_index() {
    let keys = ByIndex {
        general: index_keyring(GENERAL_INDEX_KEY_ID, 3),
        payments: index_keyring(PAYMENTS_INDEX_KEY_ID, 4),
    };

    let email = EmailLookup::derive_with(&b"ada@example.com".to_vec(), &keys).unwrap();
    let iban = IbanLookup::probes_with(b"DE89", &keys).unwrap();

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
fn keys_without_a_blind_index_keyring_reject_index_operations() {
    let keys = Keys::new(keyring(GENERAL_KEY_ID, 1));

    assert_eq!(
        EmailLookup::probes_with(b"ada", &keys).unwrap_err(),
        Error::BlindIndexKeysNotConfigured
    );
    assert_eq!(
        Sealed::<Email>::prepare(&b"ada".to_vec(), (), &keys)
            .unwrap()
            .with_index_with::<EmailLookup>(&keys)
            .unwrap_err(),
        Error::BlindIndexKeysNotConfigured
    );
}

#[test]
fn keys_serve_both_roles() {
    let keys = Keys::new(keyring(GENERAL_KEY_ID, 1))
        .with_blind_indexes(index_keyring(GENERAL_INDEX_KEY_ID, 3));
    let value = b"ada@example.com".to_vec();

    let prepared = Sealed::<Email>::prepare(&value, (), &keys)
        .unwrap()
        .with_index_with::<EmailLookup>(&keys)
        .unwrap();

    assert_eq!(prepared.sealed().key_id(), GENERAL_KEY_ID);
    assert_eq!(
        inspect_blind_index(prepared.index::<EmailLookup>().unwrap().as_bytes())
            .unwrap()
            .index_key_id(),
        GENERAL_INDEX_KEY_ID
    );
}

#[test]
fn references_and_shared_encryption_sources_are_sources() {
    fn seal_with(keys: impl EncryptionKeySource) -> KeyId {
        Sealed::<Email>::seal(&b"ada".to_vec(), (), &keys)
            .unwrap()
            .key_id()
    }

    let general = keyring(GENERAL_KEY_ID, 1);
    let dynamic: Arc<dyn EncryptionKeySource> = Arc::new(ByField {
        general: keyring(GENERAL_KEY_ID, 1),
        payments: keyring(PAYMENTS_KEY_ID, 2),
    });

    assert_eq!(seal_with(&general), GENERAL_KEY_ID);
    assert_eq!(seal_with(Arc::new(general.clone())), GENERAL_KEY_ID);
    assert_eq!(seal_with(Arc::clone(&dynamic)), GENERAL_KEY_ID);
    assert_eq!(
        Sealed::<Iban>::seal(&b"DE89".to_vec(), (), &*dynamic)
            .unwrap()
            .key_id(),
        PAYMENTS_KEY_ID
    );
}

#[test]
fn references_and_shared_blind_index_sources_are_sources() {
    fn probe_with(keys: impl BlindIndexKeySource) -> IndexKeyId {
        let probes = EmailLookup::probes_with(b"ada", &keys).unwrap();
        inspect_blind_index(probes[0].as_bytes())
            .unwrap()
            .index_key_id()
    }

    let index_keys = index_keyring(GENERAL_INDEX_KEY_ID, 3);
    assert_eq!(probe_with(&index_keys), GENERAL_INDEX_KEY_ID);
    assert_eq!(probe_with(Arc::new(index_keys)), GENERAL_INDEX_KEY_ID);
}
