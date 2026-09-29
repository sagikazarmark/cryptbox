#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Scope)]
#[cryptbox(index_args = OrgWorkspace)]
struct OrgWorkspace {
    #[cryptbox(part = "3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90", keys)]
    org: [u8; 16],
    #[cryptbox(part = "c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48")]
    workspace: [u8; 16],
}

fn main() {}
