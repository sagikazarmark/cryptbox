/// Not a bound ID: a bound field needs one, so the kind of value is declared.
#[derive(cryptbox::Record)]
struct PlainUuid {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(bound)]
    org: [u8; 16],
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    email: String,
}

struct Address {
    city: String,
}

/// A value type without a default codec names one.
#[derive(cryptbox::Record)]
struct NoCodec {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "5d1f0c3a-8f6e-4b1d-9a7c-2e4b6d8f0a13")]
    address: Address,
}

fn main() {}
