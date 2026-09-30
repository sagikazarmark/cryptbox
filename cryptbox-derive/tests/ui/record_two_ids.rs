#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = String,
    record = i64,
)]
struct UserEmail;

// A record has one record ID.
#[derive(cryptbox::Record)]
#[record(sealed = SealedTwoIds)]
struct TwoIds {
    #[record_id]
    id: i64,
    #[record_id]
    legacy_id: i64,
    #[seal(UserEmail)]
    email: String,
}

fn main() {}
