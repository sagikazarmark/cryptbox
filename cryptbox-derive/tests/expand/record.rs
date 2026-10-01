use cryptbox::BlindIndexError;
use zeroize::Zeroizing;

fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
}

/// A customer.
#[derive(cryptbox::Record)]
#[cryptbox(stored(derive(Debug), sqlx(rename_all = "snake_case")))]
pub struct Customer {
    /// The client-generated record ID.
    #[cryptbox(record_id)]
    pub id: i64,
    #[cryptbox(plaintext)]
    pub org: [u8; 16],
    /// The primary contact address.
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        bits = 32,
        normalize = normalize_email,
        normalizer = "email/1",
    ))]
    #[cryptbox(stored(sqlx(rename = "email_ciphertext")))]
    pub email: String,
    #[cryptbox(seal = "5d1f0c3a-8f6e-4b1d-9a7c-2e4b6d8f0a13", padding = block(16))]
    #[cryptbox(legacy(record = false))]
    #[cryptbox(blind_index(
        id = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0",
        bits = 16,
        normalize = normalize_email,
        normalizer = "note/1",
    ))]
    note: Option<String>,
    #[cryptbox(plaintext)]
    pub created_at: i64,
}

fn main() {}
