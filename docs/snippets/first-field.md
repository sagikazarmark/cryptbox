```rust
use cryptbox::{
    EncryptionKey, Field, FieldId, FieldOnly, LocalEncryptionKeyring, Padding, Sealed, Utf8,
};

struct UserEmail;

impl Field for UserEmail {
    const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = String;
    type Codec = Utf8;
    type Binding = FieldOnly;
    type Indexes = ();
}

fn main() -> Result<(), cryptbox::Error> {
    // Ephemeral demo keys: a new key and generation ID on every run.
    let keys = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
    let email = "mark@example.com".to_owned();
    let sealed = Sealed::<UserEmail>::seal(&email, (), &keys)?;
    let opened = sealed.open((), &keys)?;
    assert_eq!(opened, "mark@example.com");
    assert_eq!(email, "mark@example.com"); // Source retained.
    println!("Field-bound round trip succeeded.");
    Ok(())
}
```
