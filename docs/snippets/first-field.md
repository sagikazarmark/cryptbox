```rust
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
```
