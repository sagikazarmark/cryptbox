#[derive(cryptbox::Scope)]
pub struct OrgWorkspace {
    /// Bound only.
    #[part("c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48")]
    pub workspace: Vec<u8>,
    /// The key custody and shred unit, as a seal names it in its keys view.
    #[part("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90")]
    pub org: [u8; 16],
    #[part("5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61")]
    pub(crate) region: i64,
}

fn main() {}
