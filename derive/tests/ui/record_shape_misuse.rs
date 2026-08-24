#[allow(dead_code)]
fn normalize(input: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, cryptbox::BlindIndexError> {
    Ok(zeroize::Zeroizing::new(input.as_bytes().to_vec()))
}

// Every sealed field is bound to the record's ID.
#[derive(cryptbox::Record)]
struct MissingRecordId {
    #[cryptbox(plaintext)]
    org: i64,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    email: String,
}

#[derive(cryptbox::Record)]
struct TwoRecordIds {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(record_id)]
    uuid: [u8; 16],
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    email: String,
}

#[derive(cryptbox::Record)]
struct NothingSealed {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(plaintext)]
    email: String,
}

// The record ID is bound into every sealed field, so it is always present.
#[derive(cryptbox::Record)]
struct OptionalId {
    #[cryptbox(record_id)]
    id: Option<i64>,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    email: String,
}

// An index column must not clash with a field.
#[derive(cryptbox::Record)]
struct BadIndex {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        bits = 32,
        normalize = normalize,
        normalizer = "email/1",
    ))]
    email: String,
    #[cryptbox(plaintext)]
    email_index: String,
}

fn main() {}
