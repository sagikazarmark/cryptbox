```rust
use std::collections::HashMap;

use cryptbox::{
    EncryptionKey, EncryptionKeySource, EncryptionKeyring, Error, Seal, SealId, KeyScope,
    Padding, RecordId, Sealed, Tenant, TenantId, Utf8,
};

struct CustomerEmail;

impl Seal for CustomerEmail {
    const ID: SealId = cryptbox::seal_id!("38fc9e4b-f1c5-4d9b-b90a-50f53fe6c792");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = true;
    type Value = String;
    type Codec = Utf8;
    type Binding = Tenant;
    type Indexes = ();
}

/// One keyring per tenant, so one tenant's data can be shredded on its own.
struct TenantKeyrings(HashMap<KeyScope, EncryptionKeyring>);

impl EncryptionKeySource for TenantKeyrings {
    fn encryption_keyring(&self, _: SealId, scope: &KeyScope) -> Result<EncryptionKeyring, Error> {
        // Cloning a keyring shares its keys. An unknown scope fails closed.
        self.0.get(scope).cloned().ok_or(Error::KeysUnavailable)
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
    let acme = Tenant(TenantId::new("acme")?);
    let globex = Tenant(TenantId::new("globex")?);
    // Ephemeral demo keys: an independent keyring per tenant on every run.
    let keys = TenantKeyrings(HashMap::from([
        (
            KeyScope::of(&acme)?,
            EncryptionKeyring::new(EncryptionKey::generate()?, [])?,
        ),
        (
            KeyScope::of(&globex)?,
            EncryptionKeyring::new(EncryptionKey::generate()?, [])?,
        ),
    ]));

    let ada = RecordId::from(ADA);
    let grace = RecordId::from(GRACE);
    let email = "ada@acme.example".to_owned();
    let sealed = Sealed::<CustomerEmail>::seal(&email, (&acme, ada), &keys)?;
    assert_eq!(sealed.open((&acme, ada), &keys)?, email);

    // Another record of the same tenant is a different binding.
    assert!(matches!(
        sealed.open((&acme, grace), &keys),
        Err(Error::AuthenticationFailed)
    ));
    // Another tenant's keyring does not hold the key this envelope names.
    assert!(matches!(
        sealed.open((&globex, ada), &keys),
        Err(Error::UnknownEncryptionKey(_))
    ));

    // Moving the record to another tenant is an explicit reseal under its keys.
    let moved = sealed.reseal_across((&acme, ada), &keys, (&globex, ada), &keys)?;
    assert_eq!(moved.open((&globex, ada), &keys)?, email);

    println!("Tenant-bound round trip succeeded.");
    Ok(())
}
```
