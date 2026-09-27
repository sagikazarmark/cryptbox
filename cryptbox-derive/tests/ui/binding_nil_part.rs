#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Binding)]
struct Org {
    #[cryptbox(part = "00000000-0000-0000-0000-000000000000", keys)]
    org: [u8; 16],
}

fn main() {}
