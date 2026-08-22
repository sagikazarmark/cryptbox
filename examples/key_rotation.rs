//! Rotates encryption keys without interrupting reads, then rewrites old ciphertext.

use cryptbox::{
    Encrypted, EncryptionKey, EncryptionProfile, Field, FieldBound, GlobalKeyContext, KeyId,
    LocalEncryptionKeyring, Utf8, field_id, inspect_ciphertext, key_id,
};

const OLD_KEY_ID: KeyId = key_id!("10000000-0000-4000-8000-000000000001");
const CURRENT_KEY_ID: KeyId = key_id!("20000000-0000-4000-8000-000000000002");

struct UserEmail;

impl Field for UserEmail {
    const ID: cryptbox::FieldId = field_id!("30000000-0000-4000-8000-000000000003");
    const NAME: &'static str = "user-email";
}

impl EncryptionProfile<String> for UserEmail {
    type Binding = FieldBound<Self>;
    type Codec = Utf8;
    type Keys = GlobalKeyContext;
    type Padding = cryptbox::NoPadding;
}

fn main() -> Result<(), cryptbox::Error> {
    // Demo-only material. Load independently generated 32-byte secrets in production.
    let old_key = EncryptionKey::new(OLD_KEY_ID, [0x11; 32]);
    let old_keys = LocalEncryptionKeyring::new(old_key.clone(), [])?;
    let value = Encrypted::<_, UserEmail>::new("mark@example.com".to_owned());
    let stored = value.encrypt_with(&(), &old_keys)?;

    let current_key = EncryptionKey::new(CURRENT_KEY_ID, [0x22; 32]);
    let rotated_keys = LocalEncryptionKeyring::new(current_key, [old_key])?;

    assert!(stored.needs_reencryption_with(&rotated_keys)?);
    assert_eq!(
        stored.decrypt_with(&(), &rotated_keys)?.expose_secret(),
        "mark@example.com"
    );

    let rewritten = stored.reencrypt_with(&(), &rotated_keys)?;
    assert_eq!(
        inspect_ciphertext(rewritten.as_bytes())?.key_id(),
        CURRENT_KEY_ID
    );
    assert!(!rewritten.needs_reencryption_with(&rotated_keys)?);

    Ok(())
}
