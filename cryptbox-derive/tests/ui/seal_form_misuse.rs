// A type with fields is its own value, so it takes no `value`.
#[derive(cryptbox::Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String, codec = cryptbox::Utf8)]
struct WithValue(String);

// A type with fields names its codec or is `transparent`.
#[derive(cryptbox::Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25")]
struct WithoutCodec {
    email: String,
}

// A unit struct is a marker over its `value`; there is no field to store.
#[derive(cryptbox::Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String, transparent)]
struct TransparentMarker;

// `transparent` stores exactly one field.
#[derive(cryptbox::Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", transparent)]
struct TransparentPair(String, String);

// ... and takes no value.
#[derive(cryptbox::Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", transparent = true)]
struct TransparentWithValue(String);

fn main() {}
