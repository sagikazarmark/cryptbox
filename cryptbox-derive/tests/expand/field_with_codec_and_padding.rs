pub struct Address {
    pub street: String,
}

pub struct AddressCodec;

#[derive(cryptbox::Field)]
#[cryptbox(
    id = "0B6F3C2A-8E41-4D57-A9C3-5E1F2D7B8A64",
    value = Address,
    codec = AddressCodec,
    padding = block(16),
)]
pub struct HomeAddress;

#[derive(cryptbox::Field)]
#[cryptbox(id = "00000000-0000-4000-8000-000000000001", value = Address)]
#[cryptbox(codec = AddressCodec, padding = length(256usize), crate = "::cryptbox")]
pub struct FixedAddress;

fn main() {}
