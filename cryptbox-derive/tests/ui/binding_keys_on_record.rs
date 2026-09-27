#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Binding)]
#[cryptbox(index_args = OrgSearch)]
struct OrgDocument {
    #[cryptbox(part = "3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90", keys)]
    org: [u8; 16],
    #[cryptbox(record, keys)]
    document: [u8; 16],
}

fn main() {}
