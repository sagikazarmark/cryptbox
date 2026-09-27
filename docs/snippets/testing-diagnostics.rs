//! Application-owned diagnostics with an allowlist of observable fields.

use cryptbox::{
    Ciphertext, Encrypted, EncryptionKey, Error, Field, FieldId, LocalEncryptionKeyring, Padding,
    Utf8,
};

struct UserEmail;

impl Field for UserEmail {
    const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

// An application-owned schema label: no record data or secrets.
const USER_EMAIL_LABEL: &str = "user-email";

fn error_category(error: &Error) -> &'static str {
    // Allowlisted categories, not arbitrary Display/Debug or error-chain content.
    match error {
        Error::AuthenticationFailed => "authentication_failed",
        Error::UnknownEncryptionKey(_) => "unknown_encryption_key",
        Error::KeyProviderUnavailable => "key_provider_unavailable",
        Error::KeysNotInstalled => "keys_not_installed",
        Error::UnroutedField(_) => "unrouted_field",
        Error::NotCiphertext | Error::InvalidEnvelope => "invalid_ciphertext",
        _ => "cryptbox_error", // Error is non-exhaustive; new variants stay sanitized.
    }
}

fn main() -> Result<(), Error> {
    // Public test key only; never use this fixture for real data.
    let keys = LocalEncryptionKeyring::new(
        EncryptionKey::new(
            cryptbox::key_id!("40000000-0000-4000-8000-000000000004"),
            [0x31; 32],
        ),
        [],
    )?;
    let email = Encrypted::<UserEmail>::new("private-fixture@example.test".to_owned());
    let ciphertext = email.encrypt_with(&keys)?;
    let mut damaged = ciphertext.as_bytes().to_vec();
    // Corrupt the authentication tag while leaving a structurally valid envelope.
    *damaged.last_mut().ok_or(Error::Internal)? ^= 1;
    let damaged = Ciphertext::<UserEmail>::try_from(damaged)?;
    let error = match damaged.decrypt_with(&keys) {
        Err(error) => error,
        Ok(_) => return Err(Error::Internal),
    };
    assert!(matches!(error, Error::AuthenticationFailed));
    println!(
        "field_id={} field_name={} operation=decrypt error={}",
        UserEmail::ID,
        USER_EMAIL_LABEL,
        error_category(&error),
    );
    Ok(())
}
