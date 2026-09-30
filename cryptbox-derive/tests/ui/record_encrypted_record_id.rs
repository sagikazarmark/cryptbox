#[derive(cryptbox::Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String, record = i64)]
struct UserEmail;

#[derive(cryptbox::Seal)]
#[cryptbox(id = "5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01", value = String)]
struct UserHandle;

#[derive(cryptbox::Record)]
#[record(sealed = SealedUser)]
struct User {
    #[record_id]
    #[seal(UserHandle)]
    handle: String,
    #[seal(UserEmail)]
    email: String,
}

fn main() {}
