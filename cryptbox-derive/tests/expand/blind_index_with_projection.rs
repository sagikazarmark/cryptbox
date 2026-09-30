use cryptbox::BlindIndexError;
use zeroize::Zeroizing;

pub struct Address {
    pub street: String,
}

pub struct AddressCodec;

#[derive(cryptbox::Seal)]
#[cryptbox(id = "0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64", value = Address, codec = AddressCodec)]
pub struct HomeAddress;

fn street(address: &Address) -> &str {
    &address.street
}

fn normalize_street(street: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(street.trim().to_ascii_lowercase().into_bytes()))
}

#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(
    id = "3f5d8c2b-6e40-4b97-8c31-8a2f7d9e5b64",
    seal = HomeAddress,
    bits = 64,
    query = str,
    normalize = normalize_street,
    normalizer = "street/1",
    project = street,
)]
pub struct StreetLookup;

fn main() {}
