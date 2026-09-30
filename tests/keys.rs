//! Public-boundary tests for passing keys in: `Keys` and keyrings.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, IndexId, IndexKeyId, KeyError, KeyId, Keys, Padding, Raw, Seal,
    SealId, Sealed, index_id, index_key_id, inspect_blind_index, key_id, seal_id,
    testing::assert_sealed_under,
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
    type Value = Vec<u8>;
    type Codec = Raw;
    type Scope = ();
    type Indexes = ();
}

struct Iban;

impl Seal for Iban {
    const ID: SealId = seal_id!("50000000-0000-4000-8000-000000000005");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Scope = ();
    type Indexes = ();
}

struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Seal = Email;
    type Scope = ();
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

/// The application's choice of keys: payment seals under their own keyring.
struct AppKeys {
    general: EncryptionKeyring,
    payments: EncryptionKeyring,
}

impl AppKeys {
    fn for_seal(&self, seal: SealId) -> &EncryptionKeyring {
        if seal == Iban::ID {
            &self.payments
        } else {
            &self.general
        }
    }
}

#[test]
fn a_keyring_test_accepts_values_sealed_under_the_expected_keyring() {
    let previous = EncryptionKey::new(PREVIOUS_KEY_ID, [3; 32]);
    let payments = keyring(PAYMENTS_KEY_ID, 2);
    let keys = AppKeys {
        general: keyring(GENERAL_KEY_ID, 1),
        payments: EncryptionKeyring::new(previous.clone(), []).unwrap(),
    };
    let rotated = EncryptionKeyring::new(payments.current().clone(), [previous]).unwrap();

    let iban = Sealed::<Iban>::seal(
        &b"DE89370400440532013000".to_vec(),
        (),
        keys.for_seal(Iban::ID),
    )
    .unwrap();

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
    let keys = AppKeys {
        general: keyring(GENERAL_KEY_ID, 1),
        payments: keyring(PAYMENTS_KEY_ID, 2),
    };
    let iban =
        Sealed::<Iban>::seal(&b"DE89370400440532013000".to_vec(), (), &keys.general).unwrap();

    assert_sealed_under::<Iban>(&iban, &keys.payments);
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
