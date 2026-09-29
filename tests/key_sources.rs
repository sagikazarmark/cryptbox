//! Public-boundary tests for passing keyrings in through key sources.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeySource, BlindIndexKeyring, BlindIndexSpec,
    EncryptionKey, EncryptionKeySource, EncryptionKeyring, Error, FieldOnly, IndexId, IndexKeyId,
    KeyError, KeyId, KeyScope, Keys, Padding, Raw, Seal, SealId, Sealed, Tenant, TenantId,
    index_id, index_key_id, inspect_blind_index, key_id, seal_id, testing::assert_sealed_under,
};
use zeroize::Zeroizing;

const GENERAL_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const PAYMENTS_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");
const PREVIOUS_KEY_ID: KeyId = key_id!("30000000-0000-4000-8000-000000000003");
const GENERAL_INDEX_KEY_ID: IndexKeyId = index_key_id!("60000000-0000-4000-8000-000000000006");
const PAYMENTS_INDEX_KEY_ID: IndexKeyId = index_key_id!("70000000-0000-4000-8000-000000000007");

struct Email;

impl Seal for Email {
    const ID: SealId = seal_id!("40000000-0000-4000-8000-000000000004");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct Iban;

impl Seal for Iban {
    const ID: SealId = seal_id!("50000000-0000-4000-8000-000000000005");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = FieldOnly;
    type Indexes = ();
}

struct TenantNote;

impl Seal for TenantNote {
    const ID: SealId = seal_id!("80000000-0000-4000-8000-000000000008");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Binding = Tenant;
    type Indexes = ();
}

struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Seal = Email;
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
    type Seal = Iban;
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
        KeyError::DuplicateEncryptionKey(GENERAL_KEY_ID)
    );
    assert_eq!(
        EncryptionKeyring::new(key.clone(), [key]).unwrap_err(),
        KeyError::DuplicateEncryptionKey(GENERAL_KEY_ID)
    );

    let index_key = BlindIndexKey::new(GENERAL_INDEX_KEY_ID, [1; 32]);
    assert_eq!(
        BlindIndexKeyring::new(index_key.clone(), [index_key]).unwrap_err(),
        KeyError::DuplicateBlindIndexKey(GENERAL_INDEX_KEY_ID)
    );
}

#[test]
fn a_blind_index_keyring_lists_its_current_key_first() {
    let previous = BlindIndexKey::new(GENERAL_INDEX_KEY_ID, [1; 32]);
    let current = BlindIndexKey::new(PAYMENTS_INDEX_KEY_ID, [2; 32]);
    let keyring = BlindIndexKeyring::new(current, [previous]).unwrap();

    let ids: Vec<_> = keyring.readable().map(BlindIndexKey::id).collect();
    assert_eq!(ids, [PAYMENTS_INDEX_KEY_ID, GENERAL_INDEX_KEY_ID]);

    let probes = EmailLookup::probes_with(b"ada", &(), &keyring).unwrap();
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
struct BySeal {
    general: EncryptionKeyring,
    payments: EncryptionKeyring,
}

impl EncryptionKeySource for BySeal {
    fn encryption_keyring(&self, seal: SealId, _: &KeyScope) -> Result<EncryptionKeyring, Error> {
        Ok(if seal == Iban::ID {
            self.payments.clone()
        } else {
            self.general.clone()
        })
    }
}

#[test]
fn a_custom_source_chooses_keyrings_by_seal() {
    let keys = BySeal {
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

#[test]
fn a_keyring_test_accepts_values_sealed_under_the_expected_keyring() {
    let previous = EncryptionKey::new(PREVIOUS_KEY_ID, [3; 32]);
    let payments = keyring(PAYMENTS_KEY_ID, 2);
    let keys = BySeal {
        general: keyring(GENERAL_KEY_ID, 1),
        payments: EncryptionKeyring::new(previous.clone(), []).unwrap(),
    };
    let rotated = EncryptionKeyring::new(payments.current().clone(), [previous]).unwrap();

    let iban = Sealed::<Iban>::seal(&b"DE89370400440532013000".to_vec(), (), &keys).unwrap();

    assert_sealed_under::<Iban>(&iban, &keys.payments);
    // A previous key of the keyring still counts.
    assert_sealed_under::<Iban>(&iban, &rotated);
}

#[test]
#[should_panic(
    expected = "seal 50000000-0000-4000-8000-000000000005 is sealed under key \
                10000000-0000-4000-8000-000000000001, which the keyring does not hold"
)]
fn a_keyring_test_fails_for_a_value_sealed_under_another_keyring() {
    // The wrong choice: the IBAN goes to the general keyring.
    let keys = BySeal {
        general: keyring(GENERAL_KEY_ID, 1),
        payments: keyring(PAYMENTS_KEY_ID, 2),
    };
    let iban =
        Sealed::<Iban>::seal(&b"DE89370400440532013000".to_vec(), (), &keys.general).unwrap();

    assert_sealed_under::<Iban>(&iban, &keys.payments);
}

/// An application source that keeps one keyring per tenant.
struct ByTenant(HashMap<KeyScope, EncryptionKeyring>);

impl EncryptionKeySource for ByTenant {
    fn encryption_keyring(&self, _: SealId, scope: &KeyScope) -> Result<EncryptionKeyring, Error> {
        self.0.get(scope).cloned().ok_or(Error::KeysUnavailable)
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

/// An application source that loads each tenant's keyring on first use, as
/// from a KMS, and caches it behind a lock.
struct LazyTenants {
    cache: RwLock<HashMap<KeyScope, EncryptionKeyring>>,
    loads: Mutex<usize>,
}

impl LazyTenants {
    fn load(scope: &KeyScope) -> EncryptionKeyring {
        let acme = KeyScope::of(&Tenant(TenantId::new(b"acme".to_vec()).unwrap())).unwrap();
        if *scope == acme {
            keyring(GENERAL_KEY_ID, 1)
        } else {
            keyring(PAYMENTS_KEY_ID, 2)
        }
    }
}

impl EncryptionKeySource for LazyTenants {
    fn encryption_keyring(&self, _: SealId, scope: &KeyScope) -> Result<EncryptionKeyring, Error> {
        if let Some(keyring) = self.cache.read().unwrap().get(scope) {
            return Ok(keyring.clone());
        }

        *self.loads.lock().unwrap() += 1;
        Ok(self
            .cache
            .write()
            .unwrap()
            .entry(scope.clone())
            .or_insert_with(|| Self::load(scope))
            .clone())
    }
}

#[test]
fn a_source_can_hand_out_keyrings_from_behind_a_lock() {
    let acme = Tenant(TenantId::new(b"acme".to_vec()).unwrap());
    let globex = Tenant(TenantId::new(b"globex".to_vec()).unwrap());
    let keys = LazyTenants {
        cache: RwLock::default(),
        loads: Mutex::default(),
    };

    let note = b"renewal due".to_vec();
    let acme_note = Sealed::<TenantNote>::seal(&note, &acme, &keys).unwrap();
    let globex_note = Sealed::<TenantNote>::seal(&note, &globex, &keys).unwrap();

    assert_eq!(acme_note.key_id(), GENERAL_KEY_ID);
    assert_eq!(globex_note.key_id(), PAYMENTS_KEY_ID);
    assert_eq!(acme_note.open(&acme, &keys).unwrap(), note);
    assert_eq!(globex_note.open(&globex, &keys).unwrap(), note);
    assert_eq!(*keys.loads.lock().unwrap(), 2);
}

#[test]
fn a_field_only_binding_passes_the_empty_key_scope() {
    struct SeenScopes(Mutex<Vec<KeyScope>>, EncryptionKeyring);

    impl EncryptionKeySource for SeenScopes {
        fn encryption_keyring(
            &self,
            _: SealId,
            scope: &KeyScope,
        ) -> Result<EncryptionKeyring, Error> {
            self.0.lock().unwrap().push(scope.clone());
            Ok(self.1.clone())
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
    ) -> Result<BlindIndexKeyring, Error> {
        Ok(if index == IbanLookup::ID {
            self.payments.clone()
        } else {
            self.general.clone()
        })
    }
}

#[test]
fn a_custom_source_chooses_blind_index_keyrings_by_index() {
    let keys = ByIndex {
        general: index_keyring(GENERAL_INDEX_KEY_ID, 3),
        payments: index_keyring(PAYMENTS_INDEX_KEY_ID, 4),
    };

    let email = EmailLookup::derive_with(&b"ada@example.com".to_vec(), &(), &keys).unwrap();
    let iban = IbanLookup::probes_with(b"DE89", &(), &keys).unwrap();

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
        EmailLookup::probes_with(b"ada", &(), &keys).unwrap_err(),
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
    let dynamic: Arc<dyn EncryptionKeySource> = Arc::new(BySeal {
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
        let probes = EmailLookup::probes_with(b"ada", &(), &keys).unwrap();
        inspect_blind_index(probes[0].as_bytes())
            .unwrap()
            .index_key_id()
    }

    let index_keys = index_keyring(GENERAL_INDEX_KEY_ID, 3);
    assert_eq!(probe_with(&index_keys), GENERAL_INDEX_KEY_ID);
    assert_eq!(probe_with(Arc::new(index_keys)), GENERAL_INDEX_KEY_ID);
}

struct TenantNoteLookup;

impl BlindIndexSpec for TenantNoteLookup {
    type Seal = TenantNote;
    const ID: IndexId = index_id!("b0000000-0000-4000-8000-00000000000b");
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

/// An application source that keeps one blind-index keyring per tenant.
struct IndexesByTenant(HashMap<KeyScope, BlindIndexKeyring>);

impl BlindIndexKeySource for IndexesByTenant {
    fn blind_index_keyring(
        &self,
        _: IndexId,
        scope: &KeyScope,
    ) -> Result<BlindIndexKeyring, Error> {
        self.0.get(scope).cloned().ok_or(Error::KeysUnavailable)
    }
}

#[test]
fn a_blind_index_source_receives_the_key_scope_of_the_index_arguments() {
    let acme = Tenant(TenantId::new(b"acme".to_vec()).unwrap());
    let globex = Tenant(TenantId::new(b"globex".to_vec()).unwrap());
    let initech = Tenant(TenantId::new(b"initech".to_vec()).unwrap());
    let index_keys = IndexesByTenant(HashMap::from([
        (
            KeyScope::of(&acme).unwrap(),
            index_keyring(GENERAL_INDEX_KEY_ID, 3),
        ),
        (
            KeyScope::of(&globex).unwrap(),
            index_keyring(PAYMENTS_INDEX_KEY_ID, 4),
        ),
    ]));
    let key_of = |index: &[u8]| inspect_blind_index(index).unwrap().index_key_id();
    let note = b"renewal due".to_vec();

    let derived = TenantNoteLookup::derive_with(&note, &acme, &index_keys).unwrap();
    let probes = TenantNoteLookup::probes_with(b"renewal due", &globex, &index_keys).unwrap();
    let prepared = Sealed::<TenantNote>::prepare(&note, &globex, &keyring(GENERAL_KEY_ID, 1))
        .unwrap()
        .with_index_with::<TenantNoteLookup>(&index_keys)
        .unwrap();

    assert_eq!(key_of(derived.as_bytes()), GENERAL_INDEX_KEY_ID);
    assert_eq!(key_of(probes[0].as_bytes()), PAYMENTS_INDEX_KEY_ID);
    assert_eq!(
        key_of(prepared.index::<TenantNoteLookup>().unwrap().as_bytes()),
        PAYMENTS_INDEX_KEY_ID
    );
    assert!(TenantNoteLookup::is_consistent_with(&note, &derived, &acme, &index_keys).unwrap());
    assert_eq!(
        TenantNoteLookup::derive_with(&note, &initech, &index_keys),
        Err(Error::KeysUnavailable)
    );
}
