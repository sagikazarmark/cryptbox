use cryptbox::BlindIndexError;
use zeroize::Zeroizing;

#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    value = String,
    binding = cryptbox::Tenant,
    record,
    indexes(EmailLookup),
)]
pub struct CustomerEmail;

#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38",
    value = String,
    binding = cryptbox::Tenant,
)]
pub struct CustomerNote;

fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
}

#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(
    id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
    seal = CustomerEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
pub struct EmailLookup;

/// A customer.
#[derive(cryptbox::Record)]
#[cryptbox(record = id, sealed = SealedCustomer, attr(derive(Debug)))]
#[sqlx(rename_all = "snake_case")]
pub struct Customer {
    /// The client-generated record ID.
    #[cryptbox(plaintext)]
    pub id: i64,
    /// The primary contact address.
    #[cryptbox(seal = CustomerEmail, index(EmailLookup as email_lookup))]
    #[sqlx(rename = "email_ciphertext")]
    pub email: String,
    #[cryptbox(seal = CustomerNote)]
    note: String,
}
