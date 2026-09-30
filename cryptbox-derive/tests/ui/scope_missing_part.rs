#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Scope)]
struct OrgWorkspace {
    #[cryptbox(part = "3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90")]
    org: [u8; 16],
    workspace: [u8; 16],
}

fn main() {}
