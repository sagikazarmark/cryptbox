use cryptbox::BlindIndexError;
use zeroize::Zeroizing;

#[derive(cryptbox::Field)]
#[cryptbox(
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = String,
    record,
    indexes(EmailLookup),
)]
struct UserEmail;

fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
}

#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(
    id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
    field = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
struct EmailLookup;

#[derive(cryptbox::Record)]
#[cryptbox(record = id, sealed = SealedUser)]
struct User {
    #[cryptbox(plaintext)]
    id: i64,
    #[cryptbox(field = UserEmail)]
    email: String,
}

fn main() {}
