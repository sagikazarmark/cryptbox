#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Scope)]
struct OrgWorkspace {
    #[part("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90")]
    org: [u8; 16],
    #[part("3A1F0C6E-58B2-4D0A-9E57-1C4B8F2D6A90")]
    workspace: [u8; 16],
}

fn main() {}
