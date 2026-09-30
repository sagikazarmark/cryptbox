#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = String,
    bound(cryptbox::TenantId),
)]
struct UserEmail;

#[derive(cryptbox::Seal)]
#[cryptbox(id = "5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01", value = String)]
struct UserNote;

#[derive(cryptbox::Record)]
#[record(sealed = SealedUser)]
struct User {
    #[record_id]
    id: i64,
    #[seal(UserEmail)]
    email: String,
    #[seal(UserNote)]
    note: String,
}

fn main() {}
