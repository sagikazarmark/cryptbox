#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = String,
    binding = cryptbox::Tenant,
)]
struct UserEmail;

#[derive(cryptbox::Seal)]
#[cryptbox(id = "5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01", value = String)]
struct UserNote;

#[derive(cryptbox::Record)]
#[cryptbox(record = id, sealed = SealedUser)]
struct User {
    #[cryptbox(plaintext)]
    id: i64,
    #[cryptbox(seal = UserEmail)]
    email: String,
    #[cryptbox(seal = UserNote)]
    note: String,
}

fn main() {}
