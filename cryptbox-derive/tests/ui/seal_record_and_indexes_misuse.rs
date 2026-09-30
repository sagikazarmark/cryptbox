#[derive(cryptbox::Seal)]
#[seal(
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = String,
    record = true,
    indexes(),
)]
struct UserEmail;

fn main() {}
