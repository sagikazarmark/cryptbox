use cryptbox::BlindIndexError;
use zeroize::Zeroizing;

#[derive(cryptbox::Seal)]
#[seal(
    id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    value = String,
    scope = cryptbox::Recorded<cryptbox::Tenant, i64>,
    indexes(EmailLookup),
)]
pub struct CustomerEmail;

#[derive(cryptbox::Seal)]
#[seal(
    id = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38",
    value = String,
    scope = cryptbox::Tenant,
)]
pub struct CustomerNote;

fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
}

#[derive(cryptbox::BlindIndexSpec)]
#[blind_index(
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
#[record(sealed = SealedCustomer, attr(derive(Debug)))]
#[sqlx(rename_all = "snake_case")]
pub struct Customer {
    /// The client-generated record ID.
    #[record_id]
    pub id: i64,
    /// The primary contact address.
    #[sqlx(rename = "email_ciphertext")]
    #[seal(CustomerEmail)]
    #[blind_index(EmailLookup as email_lookup)]
    pub email: String,
    #[seal(CustomerNote)]
    note: String,
}
