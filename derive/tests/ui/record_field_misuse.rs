// A field without a role would be stored as it is by accident.
#[derive(cryptbox::Record)]
struct MissingRole {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    email: String,
    created_at: i64,
}

// A misspelled key is reported alone, not also as a missing role.
#[derive(cryptbox::Record)]
struct UnknownKey {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(sael = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    email: String,
}

// A field has exactly one role.
#[derive(cryptbox::Record)]
struct TwoRoles {
    #[cryptbox(record_id, seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    id: i64,
    #[cryptbox(plaintext)]
    org: i64,
}

// Bound values are retired: an org is a plaintext column.
#[derive(cryptbox::Record)]
struct RetiredBound {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(bound)]
    org: i64,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    email: String,
}

// A seal ID is a whole UUID.
#[derive(cryptbox::Record)]
struct BadUuid {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319")]
    email: String,
}

// Seal settings and blind indexes belong to sealed fields.
#[allow(dead_code)]
fn normalize(input: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, cryptbox::BlindIndexError> {
    Ok(zeroize::Zeroizing::new(input.as_bytes().to_vec()))
}

#[derive(cryptbox::Record)]
struct NotSealed {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    email: String,
    #[cryptbox(plaintext, codec = cryptbox::Json)]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        bits = 32,
        normalize = normalize,
        normalizer = "exact/1",
    ))]
    handle: String,
}

// A field's index is stored in `{field}_index`, so a field takes one.
#[derive(cryptbox::Record)]
struct TwoIndexes {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        bits = 32,
        normalize = normalize,
        normalizer = "exact/1",
    ))]
    #[cryptbox(blind_index(
        id = "5c1f43bb-6d1f-4f43-9a37-0e2a4f6a5f4c",
        bits = 16,
        normalize = normalize,
        normalizer = "exact/1",
    ))]
    email: String,
}

fn main() {}
