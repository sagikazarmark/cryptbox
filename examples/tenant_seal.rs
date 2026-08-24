//! Keeps tenants apart with one keyring per tenant.

use std::collections::HashMap;

use cryptbox::{EncryptionKey, EncryptionKeyring, Error, Padding, Seal, SealId, Sealed, Utf8};

struct CustomerEmail;

impl Seal for CustomerEmail {
    const ID: SealId = cryptbox::seal_id!("38fc9e4b-f1c5-4d9b-b90a-50f53fe6c792");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

/// One keyring per tenant, so tenants cannot open each other's values and one
/// tenant's data can be shredded on its own.
struct TenantKeyrings(HashMap<&'static str, EncryptionKeyring>);

impl TenantKeyrings {
    /// The keyring of `tenant`. An unknown tenant fails closed.
    fn of(&self, tenant: &str) -> Result<&EncryptionKeyring, UnknownTenant> {
        self.0.get(tenant).ok_or(UnknownTenant)
    }
}

/// The application's own error for a tenant without keys.
#[derive(Debug)]
struct UnknownTenant;

impl std::fmt::Display for UnknownTenant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("unknown tenant")
    }
}

impl std::error::Error for UnknownTenant {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_seal_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        main()
    }

    #[test]
    fn an_unknown_tenant_fails_closed() {
        let keys = TenantKeyrings(HashMap::new());

        assert!(keys.of("acme").is_err());
    }
}
