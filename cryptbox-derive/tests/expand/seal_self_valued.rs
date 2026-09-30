#[derive(cryptbox::Seal)]
#[seal(id = "5d2f8a61-3c4e-4b7a-9e10-6f8b2c4d1a93", codec = cryptbox::Json)]
pub struct ProfileResponse {
    pub name: String,
    pub email: String,
}

fn main() {}
