//! Application-owned diagnostics with an allowlist of observable fields.

use cryptbox::{Ciphertext, Encrypted, EncryptionKey, Error, Field, LocalEncryptionKeyring};

cryptbox::profile! {
    UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
    }
}

fn error_category(error: &Error) -> &'static str {
    // Allowlisted categories, not arbitrary Display/Debug or error-chain content.
    match error {
        Error::AuthenticationFailed => "authentication_failed",
        Error::UnknownEncryptionKey(_) => "unknown_encryption_key",
        Error::KeyProviderUnavailable => "key_provider_unavailable",
        Error::KeyProviderNotInitialized => "key_provider_not_initialized",
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
    let email = Encrypted::<_, UserEmail>::new("private-fixture@example.test".to_owned());
    let ciphertext = email.encrypt_with(&(), &keys)?;
    let mut damaged = ciphertext.as_bytes().to_vec();
    // Corrupt the authentication tag while leaving a structurally valid envelope.
    *damaged.last_mut().ok_or(Error::Internal)? ^= 1;
    let damaged = Ciphertext::<String, UserEmail>::try_from(damaged)?;
    let error = match damaged.decrypt_with(&(), &keys) {
        Err(error) => error,
        Ok(_) => return Err(Error::Internal),
    };
    assert!(matches!(error, Error::AuthenticationFailed));
    println!(
        "field_id={} field_name={} operation=decrypt error={}",
        UserEmail::ID,
        UserEmail::NAME,
        error_category(&error),
    );
    Ok(())
}
