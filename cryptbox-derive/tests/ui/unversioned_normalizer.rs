use cryptbox::BlindIndexError;
use zeroize::Zeroizing;

#[derive(cryptbox::Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
struct UserEmail;

fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.trim().to_ascii_lowercase().into_bytes()))
}

#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(
    id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
    seal = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "",
)]
struct EmptyName;

#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(
    id = "3f5d8c2b-6e4a-4b97-8c31-8a2f7d9e5b64",
    seal = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email",
)]
struct Unversioned;

#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(
    id = "4a6e9d3c-7f5b-4ca8-9d42-9b3a8e0f6c75",
    seal = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email/0",
)]
struct ZeroVersion;

#[derive(cryptbox::Record)]
struct Customer {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(
        seal = "5b7f0e4d-8a6c-4db9-8e53-0c4b9f1a7d86",
        blind_index(
            id = "6c8a1f5e-9b7d-4eca-9f64-1d5c0a2b8e97",
            bits = 32,
            normalize = normalize_email,
            normalizer = "email/v1",
        ),
    )]
    email: String,
}

fn main() {}
