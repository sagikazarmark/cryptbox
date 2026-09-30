#[derive(cryptbox::Seal)]
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
struct Nickname;

// One seal on two fields: their values could be swapped within a row.
#[derive(cryptbox::Record)]
#[cryptbox(record_id = id, sealed = SealedTwice)]
struct Twice {
    #[cryptbox(plaintext)]
    id: i64,
    #[cryptbox(seal = Nickname)]
    home: String,
    #[cryptbox(seal = Nickname)]
    work: String,
}

// A field's own seal needs its ID.
#[derive(cryptbox::Record)]
#[cryptbox(record_id = id, sealed = SealedWithoutId)]
struct WithoutId {
    #[cryptbox(plaintext)]
    id: i64,
    #[cryptbox(scope = cryptbox::Tenant)]
    email: String,
}

// A field declares its own seal or uses an existing one, not both.
#[derive(cryptbox::Record)]
#[cryptbox(record_id = id, sealed = SealedBoth)]
struct Both {
    #[cryptbox(plaintext)]
    id: i64,
    #[cryptbox(id = "5b7d9f13-2c4e-4a68-8b0d-1f3e5a7c9b24", seal = Nickname)]
    email: String,
}

// `record` is renamed `record_id`.
#[derive(cryptbox::Record)]
#[cryptbox(record = id, sealed = SealedOldKey)]
struct OldKey {
    #[cryptbox(plaintext)]
    id: i64,
    #[cryptbox(id = "5b7d9f13-2c4e-4a68-8b0d-1f3e5a7c9b24")]
    email: String,
}

fn main() {}
