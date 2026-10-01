#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = String,
    record = i64,
    indexes(EmailLookup, EmailDomainLookup),
)]
pub struct CustomerEmail;

pub struct EmailLookup;
pub struct EmailDomainLookup;

fn main() {}
