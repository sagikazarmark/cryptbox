//! Rotates encryption keys without interrupting reads, then reseals old values.

use cryptbox::{EncryptionKey, EncryptionKeyring, KeyId, Seal, Sealed, key_id};

const OLD_KEY_ID: KeyId = key_id!("2a26018a-d8ef-4942-9519-da7e35bcafbf");
const CURRENT_KEY_ID: KeyId = key_id!("e5d53b60-9e45-4ef9-9198-9bc88ac7409e");

/// A user's email, its own value: stored with exactly the bytes of its `String`.
#[derive(Debug, PartialEq, Seal)]
#[seal(id = "9758e010-b78a-43e6-9686-0b0f6790d8eb", transparent)]
struct UserEmail(String);

fn main() -> Result<(), cryptbox::Error> {
    // Demo-only material. Load independently generated 32-byte secrets in production.
    let old_key = EncryptionKey::new(OLD_KEY_ID, [0x11; 32]);
    let old_keys = EncryptionKeyring::new(old_key.clone(), [])?;
    let value = UserEmail("mark@example.com".to_owned());
    let stored = Sealed::<UserEmail>::seal(&value, (), &old_keys)?;

    let current_key = EncryptionKey::new(CURRENT_KEY_ID, [0x22; 32]);
    let rotated_keys = EncryptionKeyring::new(current_key, [old_key])?;

    assert!(stored.needs_reseal((), &rotated_keys)?);
    assert_eq!(
        stored.open((), &rotated_keys)?,
        UserEmail("mark@example.com".to_owned())
    );

    let rewritten = stored.reseal((), &rotated_keys)?;
    assert_eq!(rewritten.key_id(), CURRENT_KEY_ID);
    assert!(!rewritten.needs_reseal((), &rotated_keys)?);

    Ok(())
}
