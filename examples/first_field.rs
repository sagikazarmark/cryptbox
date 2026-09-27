//! First field-bound round trip with explicit, ephemeral keys.

// ANCHOR: first-field
use cryptbox::{Encrypted, EncryptionKey, Field, FieldId, LocalEncryptionKeyring, Padding, Utf8};

struct UserEmail;

impl Field for UserEmail {
    const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

fn main() -> Result<(), cryptbox::Error> {
    // Ephemeral demo keys: a new key and generation ID on every run.
    let keys = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
    let email = Encrypted::<UserEmail>::new("mark@example.com".to_owned());
    let ciphertext = email.encrypt_with(&keys)?;
    let decrypted = ciphertext.decrypt_with(&keys)?;
    assert_eq!(decrypted.expose_secret(), "mark@example.com");
    assert_eq!(email.expose_secret(), "mark@example.com"); // Source retained.
    println!("Field-bound round trip succeeded.");
    Ok(())
}
// ANCHOR_END: first-field

#[cfg(test)]
mod tests {
    use super::*;

    struct BillingEmail;

    impl Field for BillingEmail {
        const ID: FieldId = cryptbox::field_id!("124f036a-39c6-4197-a9bb-c92c471285ad");
        const PADDING: Padding = Padding::NONE;
        type Value = String;
        type Codec = Utf8;
    }

    #[test]
    fn first_field_round_trip() -> Result<(), cryptbox::Error> {
        main()
    }

    #[test]
    fn stored_email_cannot_be_read_as_another_field() -> Result<(), cryptbox::Error> {
        let keys = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
        let email = Encrypted::<UserEmail>::new("mark@example.com".to_owned());
        let ciphertext = email.encrypt_with(&keys)?;
        let substituted =
            cryptbox::Ciphertext::<BillingEmail>::from_bytes(ciphertext.as_bytes().to_vec())?;
        assert!(matches!(
            substituted.decrypt_with(&keys),
            Err(cryptbox::Error::AuthenticationFailed)
        ));
        Ok(())
    }
}
