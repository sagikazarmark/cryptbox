```rust
use std::collections::HashMap;

use cryptbox::{EncryptionKey, EncryptionKeyring, Error, Padding, Seal, SealId, Sealed, Utf8};

struct CustomerEmail;

impl Seal for CustomerEmail {
    const ID: SealId = cryptbox::seal_id!("38fc9e4b-f1c5-4d9b-b90a-50f53fe6c792");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Indexes = ();
}

/// One keyring per tenant, so tenants cannot open each other's values and one
/// tenant's data can be shredded on its own.
struct TenantKeyrings(HashMap<&'static str, EncryptionKeyring>);

impl TenantKeyrings {
    /// The keyring of `tenant`. An unknown tenant fails closed.
    fn of(&self, tenant: &str) -> Result<&EncryptionKeyring, Error> {
        self.0.get(tenant).ok_or(Error::KeysUnavailable)
    }
}

fn main() -> Result<(), Error> {
    // Ephemeral demo keys: an independent keyring per tenant on every run.
    let keys = TenantKeyrings(HashMap::from([
        (
            "acme",
            EncryptionKeyring::new(EncryptionKey::generate()?, [])?,
        ),
        (
            "globex",
            EncryptionKeyring::new(EncryptionKey::generate()?, [])?,
        ),
    ]));

    let email = "ada@acme.example".to_owned();
    let sealed = Sealed::<CustomerEmail>::seal(&email, keys.of("acme")?)?;
    assert_eq!(sealed.open(keys.of("acme")?)?, email);

    // Another tenant's keyring does not hold the key this envelope names.
    assert!(matches!(
        sealed.open(keys.of("globex")?),
        Err(Error::UnknownEncryptionKey(_))
    ));

    // Moving the value to another tenant is an explicit reseal under its keys.
    let moved = sealed.reseal_across(keys.of("acme")?, keys.of("globex")?)?;
    assert_eq!(moved.open(keys.of("globex")?)?, email);

    println!("Round trip with a keyring per tenant succeeded.");
    Ok(())
}
```
