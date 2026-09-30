#[derive(cryptbox::Seal)]
#[seal(
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = String,
    scope = cryptbox::Recorded<cryptbox::Tenant, i64>,
    indexes(EmailLookup, EmailDomainLookup),
)]
pub struct CustomerEmail;

pub struct EmailLookup;
pub struct EmailDomainLookup;

fn main() {}
