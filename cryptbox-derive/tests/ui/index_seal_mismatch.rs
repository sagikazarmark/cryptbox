use cryptbox::BlindIndexError;
use zeroize::Zeroizing;

#[derive(cryptbox::Seal)]
#[seal(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = Vec<u8>)]
struct ApiToken;

fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
}

#[derive(cryptbox::BlindIndexSpec)]
#[blind_index(
    id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
    seal = ApiToken,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
struct EmailLookup;

fn main() {}
