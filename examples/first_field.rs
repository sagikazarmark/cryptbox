//! First field-bound round trip with explicit, ephemeral keys.

// ANCHOR: first-field
use cryptbox::{Encrypted, EncryptionKey, LocalEncryptionKeyring};

cryptbox::profile! {
    UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: cryptbox::Utf8,
        binding: field_bound,
    }
}

fn main() -> Result<(), cryptbox::Error> {
    // Ephemeral demo keys: a new key and generation ID on every run.
    let keys = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
    let email = Encrypted::<_, UserEmail>::new("mark@example.com".to_owned());
    let ciphertext = email.encrypt_with(&(), &keys)?;
    let decrypted = ciphertext.decrypt_with(&(), &keys)?;
    assert_eq!(decrypted.expose_secret(), "mark@example.com");
    assert_eq!(email.expose_secret(), "mark@example.com"); // Source retained.
    println!("Field-bound round trip succeeded.");
    Ok(())
}
// ANCHOR_END: first-field

#[cfg(test)]
mod tests {
    use super::*;

    cryptbox::profile! {
        BillingEmail: String {
            id: "124f036a-39c6-4197-a9bb-c92c471285ad",
            name: "billing-email",
            codec: cryptbox::Utf8,
            binding: field_bound,
        }
    }

    #[test]
    fn first_field_round_trip() -> Result<(), cryptbox::Error> {
        main()
    }

    #[test]
    fn stored_email_cannot_be_read_as_another_field() -> Result<(), cryptbox::Error> {
        let keys = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
        let email = Encrypted::<_, UserEmail>::new("mark@example.com".to_owned());
        let ciphertext = email.encrypt_with(&(), &keys)?;
        let substituted = cryptbox::Ciphertext::<String, BillingEmail>::from_bytes(
            ciphertext.as_bytes().to_vec(),
        )?;
        assert!(matches!(
            substituted.decrypt_with(&(), &keys),
            Err(cryptbox::Error::AuthenticationFailed)
        ));
        Ok(())
    }
}
