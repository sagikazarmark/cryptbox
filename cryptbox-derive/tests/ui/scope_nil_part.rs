#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Scope)]
struct Org {
    #[part("00000000-0000-0000-0000-000000000000")]
    org: [u8; 16],
}

fn main() {}
