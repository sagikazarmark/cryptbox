#[cryptbox(id = "5d2f8a61-3c4e-4b7a-9e10-6f8b2c4d1a93", codec = cryptbox::Json)]
pub struct ProfileResponse {
    pub name: String,
    pub email: String,
}
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for ProfileResponse {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x5d2f8a61_3c4e_4b7a_9e10_6f8b2c4d1a93,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
        type Value = Self;
        type Codec = cryptbox::Json;
        type Indexes = ();
    }
};
fn main() {}
