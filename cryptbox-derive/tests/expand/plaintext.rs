#[derive(cryptbox::Plaintext)]
#[cryptbox(codec = AddressCodec)]
pub struct Address {
    pub street: String,
}

pub struct AddressCodec;

#[derive(cryptbox::Plaintext)]
pub struct Email(String);

fn main() {}
