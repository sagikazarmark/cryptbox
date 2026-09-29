//! First field-bound round trip with explicit, ephemeral keys.

// ANCHOR: first-field
use cryptbox::{EncryptionKey, EncryptionKeyring, FieldOnly, Padding, Seal, SealId, Sealed, Utf8};

struct UserEmail;

impl Seal for UserEmail {
    const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
    type Indexes = ();
}

fn main() -> Result<(), cryptbox::Error> {
    // Ephemeral demo keys: a new key and generation ID on every run.
    let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
    let email = "mark@example.com".to_owned();
    let sealed = Sealed::<UserEmail>::seal(&email, (), &keys)?;
    let opened = sealed.open((), &keys)?;
    assert_eq!(opened, "mark@example.com");
    assert_eq!(email, "mark@example.com"); // Source retained.
    println!("Seal-bound round trip succeeded.");
    Ok(())
}
// ANCHOR_END: first-field

#[cfg(test)]
mod tests {
    use super::*;

    struct BillingEmail;

    impl Seal for BillingEmail {
        const ID: SealId = cryptbox::seal_id!("124f036a-39c6-4197-a9bb-c92c471285ad");
        const PADDING: Padding = Padding::NONE;
        const RECORD: bool = false;
        type Value = String;
        type Codec = Utf8;
        type Binding = FieldOnly;
        type Indexes = ();
    }

    #[test]
    fn first_field_round_trip() -> Result<(), cryptbox::Error> {
        main()
    }

    #[test]
    fn stored_email_cannot_be_read_as_another_field() -> Result<(), cryptbox::Error> {
        let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
        let sealed = Sealed::<UserEmail>::seal(&"mark@example.com".to_owned(), (), &keys)?;
        let substituted = Sealed::<BillingEmail>::from_bytes(sealed.as_bytes().to_vec())?;
        assert!(matches!(
            substituted.open((), &keys),
            Err(cryptbox::Error::AuthenticationFailed)
        ));
        Ok(())
    }
}
