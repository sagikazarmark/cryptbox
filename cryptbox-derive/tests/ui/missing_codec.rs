struct Address {
    street: String,
}

#[derive(cryptbox::Seal)]
#[cryptbox(id = "0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64", value = Address)]
struct HomeAddress;

#[derive(cryptbox::Plaintext)]
struct Postcode {
    code: String,
}

fn main() {}
