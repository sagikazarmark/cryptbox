#[allow(dead_code)]
fn normalize(input: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, cryptbox::BlindIndexError> {
    Ok(zeroize::Zeroizing::new(input.as_bytes().to_vec()))
}

// Fields that share a seal ID share a context: their values could be swapped.
#[derive(cryptbox::Record)]
struct SharedSeal {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    home_phone: String,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    work_phone: String,
}

#[derive(cryptbox::Record)]
struct SharedIndex {
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
    #[cryptbox(seal = "8d1f0f3e-5a52-4c1b-9b0e-6a6f2f9d4c11")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        bits = 32,
        normalize = normalize,
        normalizer = "email/1",
    ))]
    backup_email: String,
}

fn main() {}
