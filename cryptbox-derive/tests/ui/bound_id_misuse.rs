/// No kind of value.
#[derive(cryptbox::BoundId)]
struct TeamId([u8; 16]);

/// Not a newtype.
#[derive(cryptbox::BoundId)]
#[cryptbox(kind = "78f0169a-f024-402b-9cdf-f436864fa17f")]
struct WorkspaceId {
    id: [u8; 16],
}

/// A key the derive does not know.
#[derive(cryptbox::BoundId)]
#[cryptbox(kind = "2cef6a47-3e20-42dc-a319-56022cb4cf30", id = "ab78afa9-7aaa-499c-8239-037b7e136130")]
struct RegionId(i64);

/// A field that is no part type.
#[derive(cryptbox::BoundId)]
#[cryptbox(kind = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0")]
struct Label(String);

fn main() {}
