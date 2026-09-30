#[derive(cryptbox::Record)]
#[cryptbox(record_id = id, sealed = SealedCustomer)]
pub struct Customer {
    #[cryptbox(plaintext)]
    pub id: i64,
    /// The primary contact address.
    #[cryptbox(id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13", scope = cryptbox::Tenant)]
    pub email: String,
    #[cryptbox(
        id = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38",
        scope = cryptbox::Tenant,
        padding = block(16),
        name = PrivateNote,
    )]
    note: String,
}

fn main() {}
