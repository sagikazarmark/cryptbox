#[derive(cryptbox::Record)]
pub struct Customer {
    #[record_id]
    pub id: i64,
    pub created_at: i64,
    /// The primary contact address.
    #[seal(id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13", bound(cryptbox::TenantId))]
    pub email: String,
    #[seal(
        id = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38",
        bound(cryptbox::TenantId),
        padding = block(16),
        name = PrivateNote,
    )]
    note: String,
}

fn main() {}
