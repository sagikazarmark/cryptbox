#[derive(cryptbox::Seal)]
#[seal(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
struct Nickname;

// One seal on two fields: their values could be swapped within a row.
#[derive(cryptbox::Record)]
#[record(sealed = SealedTwice)]
struct Twice {
    #[record_id]
    id: i64,
    #[seal(Nickname)]
    home: String,
    #[seal(Nickname)]
    work: String,
}

// A field's own seal needs its ID.
#[derive(cryptbox::Record)]
#[record(sealed = SealedWithoutId)]
struct WithoutId {
    #[record_id]
    id: i64,
    #[seal(scope = cryptbox::Tenant)]
    email: String,
}

// A field declares its own seal or uses an existing one, not both.
#[derive(cryptbox::Record)]
#[record(sealed = SealedBoth)]
struct Both {
    #[record_id]
    id: i64,
    #[seal(Nickname)]
    #[seal(id = "5b7d9f13-2c4e-4a68-8b0d-1f3e5a7c9b24")]
    email: String,
}

fn main() {}
