use cryptbox::Keys;

#[derive(cryptbox::BoundId, Clone)]
#[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
struct OrgId([u8; 16]);

#[derive(cryptbox::BoundId, Clone)]
#[cryptbox(kind = "78f0169a-f024-402b-9cdf-f436864fa17f")]
struct WorkspaceId([u8; 16]);

fn normalize(input: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, cryptbox::BlindIndexError> {
    Ok(zeroize::Zeroizing::new(input.as_bytes().to_vec()))
}

#[derive(cryptbox::Record)]
struct Customer {
    #[cryptbox(record_id)]
    id: i64,
    #[cryptbox(bound)]
    org: OrgId,
    #[cryptbox(bound)]
    workspace: WorkspaceId,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        across(workspace),
        bits = 32,
        normalize = normalize,
        normalizer = "email/1",
    ))]
    email: String,
}

// The index spans workspaces: a query supplies the org.
fn search(keys: &Keys, workspace: &WorkspaceId) {
    let _ = Customer::EMAIL_INDEX.probes("ada@example.com", workspace, keys);
}

fn main() {}
