//! Application-owned diagnostics with an allowlist of observable fields.

use cryptbox::{EncryptionKey, EncryptionKeyring, Error, Padding, Seal, SealId, Sealed, Utf8};

struct UserEmail;

impl Seal for UserEmail {
    const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Scope = ();
    type Indexes = ();
}

// An application-owned schema label: no record data or secrets.
const USER_EMAIL_LABEL: &str = "user-email";

fn error_category(error: &Error) -> &'static str {
    // Allowlisted categories, not arbitrary Display/Debug or error-chain content.
    match error {
        Error::AuthenticationFailed => "authentication_failed",
        Error::UnknownEncryptionKey(_) => "unknown_encryption_key",
        Error::KeysUnavailable => "keys_unavailable",
        Error::KeysNotInstalled => "keys_not_installed",
        Error::NotCiphertext | Error::InvalidEnvelope => "invalid_ciphertext",
        _ => "cryptbox_error", // Error is non-exhaustive; new variants stay sanitized.
    }
}

fn main() -> Result<(), Error> {
    // Public test key only; never use this fixture for real data.
    let keys = EncryptionKeyring::new(
        EncryptionKey::new(
            cryptbox::key_id!("0aff3b14-38c9-4c8e-a0ef-6f06b11c42ac"),
            [0x31; 32],
        ),
        [],
    )?;
    let email = "private-fixture@example.test".to_owned();
    let sealed = Sealed::<UserEmail>::seal(&email, (), &keys)?;
    let mut damaged = sealed.as_bytes().to_vec();
    // Corrupt the authentication tag while leaving a structurally valid envelope.
    *damaged.last_mut().ok_or(Error::Internal)? ^= 1;
    let damaged = Sealed::<UserEmail>::try_from(damaged)?;
    let error = match damaged.open((), &keys) {
        Err(error) => error,
        Ok(_) => return Err(Error::Internal),
    };
    assert!(matches!(error, Error::AuthenticationFailed));
    println!(
        "seal_id={} seal_name={} operation=open error={}",
        UserEmail::ID,
        USER_EMAIL_LABEL,
        error_category(&error),
    );
    Ok(())
}
