#[derive(cryptbox::Seal)]
#[cryptbox(id = "7a1c3e5f-9b2d-4f60-8a4c-1e3b5d7f9a2c", transparent, padding = block(16))]
pub struct UserEmail(String);

fn main() {}
