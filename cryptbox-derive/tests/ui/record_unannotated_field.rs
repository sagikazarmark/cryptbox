#[derive(cryptbox::Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String, scope = cryptbox::Recorded<(), i64>)]
struct UserEmail;

#[derive(cryptbox::Record)]
#[cryptbox(record = id, sealed = SealedUser)]
struct User {
    #[cryptbox(plaintext)]
    id: i64,
    #[cryptbox(seal = UserEmail)]
    email: String,
    nickname: String,
}

fn main() {}
