#[derive(cryptbox::Seal)]
#[cryptbox(id = "00000000-0000-0000-0000-000000000000", value = String)]
struct UserEmail;

#[derive(cryptbox::Record)]
struct Customer {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "00000000-0000-0000-0000-000000000000")]
    email: String,
}

fn main() {}
