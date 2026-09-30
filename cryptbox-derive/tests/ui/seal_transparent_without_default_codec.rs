// The inner type has no built-in default codec: name one with `codec`.
struct Address {
    street: String,
}

#[derive(cryptbox::Seal)]
#[seal(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", transparent)]
struct HomeAddress(Address);

fn main() {}
