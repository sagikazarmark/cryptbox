#[derive(cryptbox::Binding)]
pub struct Revision {
    #[cryptbox(part = "8f4a6c13-9d2e-4b57-a0c8-6e1f3a5d7b92")]
    pub number: i64,
}

fn main() {}
