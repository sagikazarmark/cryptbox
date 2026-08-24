use std::marker::PhantomData;

use cryptbox::BlindIndexError;
use zeroize::Zeroizing;

#[derive(cryptbox::Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", codec = cryptbox::Raw)]
struct Generic<T>(PhantomData<T>);

#[derive(cryptbox::Seal)]
#[cryptbox(id = "1b3d5f7a-9c2e-4f60-8b4d-6e8a0c2e4f61", codec = cryptbox::Raw)]
union Bytes {
    byte: u8,
}

#[derive(cryptbox::Seal)]
#[cryptbox(id = "2c4e6a8b-0d3f-4a71-9c5e-7f9b1d3f5a72", value = String)]
struct UserEmail;

fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.as_bytes().to_vec()))
}

#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(
    id = "3d5f7b9c-1e4a-4b82-8d6f-8a0c2e4a6b83",
    seal = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
struct GenericLookup<T>(PhantomData<T>);

#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(
    id = "4e6a8c0d-2f5b-4c93-9e7a-9b1d3f5b7c94",
    seal = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
enum EnumLookup {}

#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(
    id = "5f7b9d1e-3a6c-4da4-8f8b-0c2e4a6c8da5",
    seal = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
union UnionLookup {
    byte: u8,
}

fn main() {}
