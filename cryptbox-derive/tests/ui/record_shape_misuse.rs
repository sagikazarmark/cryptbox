#[derive(cryptbox::BoundId)]
#[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
struct OrgId([u8; 16]);

#[allow(dead_code)]
fn normalize(input: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, cryptbox::BlindIndexError> {
    Ok(zeroize::Zeroizing::new(input.as_bytes().to_vec()))
}

// Every sealed field is bound to the record's ID.
#[derive(cryptbox::Record)]
struct MissingRecordId {
    #[cryptbox(bound)]
    org: OrgId,
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

// Bound values are bound into every sealed field, so each is always present.
#[derive(cryptbox::Record)]
struct OptionalOrg {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(bound)]
    org: Option<OrgId>,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    email: String,
}

// `across` names a bound field; its index column must not clash with a field.
#[derive(cryptbox::Record)]
struct BadIndex {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(bound)]
    org: OrgId,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        across(workspce),
        bits = 32,
        normalize = normalize,
        normalizer = "email/1",
        column = id,
    ))]
    email: String,
}

// A legacy declaration binds some of the record's bound values.
#[derive(cryptbox::Record)]
struct BadLegacy {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(bound)]
    org: OrgId,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30", legacy(bound(tenant)))]
    email: String,
}

fn main() {}
