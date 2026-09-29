const ID: &str = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25";

#[derive(cryptbox::Seal)]
#[cryptbox(id = ID, value = String)]
struct UserEmail;

fn main() {}
