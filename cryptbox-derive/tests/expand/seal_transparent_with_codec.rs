pub struct Address {
    pub street: String,
}

#[derive(cryptbox::Seal)]
#[cryptbox(id = "2e4a6c8e-0b1d-4f3a-a5c7-9e1b3d5f7a90", transparent, codec = cryptbox::Json)]
pub struct HomeAddress {
    address: Address,
}

fn main() {}
