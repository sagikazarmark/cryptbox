#[derive(cryptbox::Seal)]
#[seal(
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = String,
    scope = cryptbox::Recorded<(), i64>,
)]
struct UserEmail;

// A record marks the field that holds its ID.
#[derive(cryptbox::Record)]
#[record(sealed = SealedWithoutId)]
struct WithoutId {
    id: i64,
    #[seal(UserEmail)]
    email: String,
}

// `record_id` takes no arguments.
#[derive(cryptbox::Record)]
#[record(sealed = SealedWithArguments)]
struct WithArguments {
    #[record_id(legacy)]
    id: i64,
    #[seal(UserEmail)]
    email: String,
}

// A field stored as it is has no blind indexes.
#[derive(cryptbox::Record)]
#[record(sealed = SealedIndexedPlaintext)]
struct IndexedPlaintext {
    #[record_id]
    id: i64,
    #[blind_index(EmailLookup as email_lookup)]
    email: String,
    #[seal(UserEmail)]
    backup_email: String,
}

fn main() {}
