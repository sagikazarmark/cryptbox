#[derive(cryptbox::Field)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String, record)]
struct UserEmail;

#[derive(cryptbox::Record)]
#[cryptbox(record = id, sealed = SealedUser)]
struct User {
    #[cryptbox(plaintext)]
    id: i64,
    #[cryptbox(field = UserEmail)]
    email: String,
    nickname: String,
}

fn main() {}
