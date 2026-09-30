```rust
use std::collections::HashMap;

use cryptbox::{
    EncryptionKey, EncryptionKeyring, Error, Padding, Seal, SealId, Sealed, TenantId, Utf8,
};

struct CustomerEmail;

impl Seal for CustomerEmail {
    const ID: SealId = cryptbox::seal_id!("38fc9e4b-f1c5-4d9b-b90a-50f53fe6c792");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Bound = (TenantId,);
    type Record = [u8; 16];
    type Indexes = ();
}

/// One keyring per tenant, so one tenant's data can be shredded on its own.
struct TenantKeyrings(HashMap<TenantId, EncryptionKeyring>);

impl TenantKeyrings {
    /// The keyring of `tenant`. An unknown tenant fails closed.
    fn of(&self, tenant: &TenantId) -> Result<&EncryptionKeyring, Error> {
        self.0.get(tenant).ok_or(Error::KeysUnavailable)
    }
}

// Client-generated UUIDv7 record IDs, chosen before the row is inserted.
const ADA: [u8; 16] = [
    0x01, 0x99, 0xa0, 0x5c, 0x7b, 0x3e, 0x74, 0x1d, 0x8f, 0x2a, 0x6c, 0x91, 0x0e, 0x45, 0xb8, 0x23,
];
const GRACE: [u8; 16] = [
    0x01, 0x99, 0xa0, 0x5c, 0x9c, 0x40, 0x7a, 0xe2, 0xb1, 0xd6, 0x4f, 0x8a, 0x2e, 0x0b, 0x73, 0xc5,
];

fn main() -> Result<(), Error> {
    // Tenants come from the request's authorized claims, never from a stored row.
    let acme = TenantId::new("acme")?;
    let globex = TenantId::new("globex")?;
    // Ephemeral demo keys: an independent keyring per tenant on every run.
    let keys = TenantKeyrings(HashMap::from([
        (
            acme.clone(),
            EncryptionKeyring::new(EncryptionKey::generate()?, [])?,
        ),
        (
            globex.clone(),
            EncryptionKeyring::new(EncryptionKey::generate()?, [])?,
        ),
    ]));

    let (ada, grace) = (&ADA, &GRACE);
    let email = "ada@acme.example".to_owned();
    let sealed = Sealed::<CustomerEmail>::seal(&email, (&acme, ada), keys.of(&acme)?)?;
    assert_eq!(sealed.open((&acme, ada), keys.of(&acme)?)?, email);

    // Another record of the same tenant is a different binding.
    assert!(matches!(
        sealed.open((&acme, grace), keys.of(&acme)?),
        Err(Error::AuthenticationFailed)
    ));
    // Another tenant's keyring does not hold the key this envelope names.
    assert!(matches!(
        sealed.open((&globex, ada), keys.of(&globex)?),
        Err(Error::UnknownEncryptionKey(_))
    ));

    // Moving the record to another tenant is an explicit reseal under its keys.
    let moved = sealed.reseal_across(
        (&acme, ada),
        keys.of(&acme)?,
        (&globex, ada),
        keys.of(&globex)?,
    )?;
    assert_eq!(moved.open((&globex, ada), keys.of(&globex)?)?, email);

    println!("Tenant-bound round trip succeeded.");
    Ok(())
}
```
