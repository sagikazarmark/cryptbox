//! Rotates encryption keys without interrupting reads, then reseals old values.

use cryptbox::{
    EncryptionKey, Field, KeyId, LocalEncryptionKeyring, Plaintext, Router, Sealed, key_id,
};

const OLD_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const CURRENT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");

/// An application value type, stored with exactly the bytes of its inner `String`.
#[derive(Debug, PartialEq, Plaintext)]
struct Email(String);

#[derive(Field)]
#[cryptbox(id = "30000000-0000-4000-8000-000000000003", value = Email)]
struct UserEmail;

fn main() -> Result<(), cryptbox::Error> {
    // Demo-only material. Load independently generated 32-byte secrets in production.
    let old_key = EncryptionKey::new(OLD_KEY_ID, [0x11; 32]);
    let old_keys =
        Router::strict().route::<UserEmail>(LocalEncryptionKeyring::new(old_key.clone(), [])?)?;
    let value = Email("mark@example.com".to_owned());
    let stored = Sealed::<UserEmail>::seal(&value, (), &old_keys)?;

    let current_key = EncryptionKey::new(CURRENT_KEY_ID, [0x22; 32]);
    let rotated_keys = Router::strict()
        .route::<UserEmail>(LocalEncryptionKeyring::new(current_key, [old_key])?)?;

    assert!(stored.needs_reseal((), &rotated_keys)?);
    assert_eq!(
        stored.open((), &rotated_keys)?,
        Email("mark@example.com".to_owned())
    );

    let rewritten = stored.reseal((), &rotated_keys)?;
    assert_eq!(rewritten.key_id(), CURRENT_KEY_ID);
    assert!(!rewritten.needs_reseal((), &rotated_keys)?);

    Ok(())
}
