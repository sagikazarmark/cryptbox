#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
pub struct UserEmail;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Field for UserEmail {
        const ID: ::cryptbox::FieldId = ::cryptbox::FieldId::from_u128(
            0xca274e85_63c4_4f7d_a255_2dfecbfe5e25,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
        const RECORD: bool = false;
        type Value = String;
        type Codec = <String as ::cryptbox::Plaintext>::Codec;
        type Binding = ::cryptbox::FieldOnly;
        type Indexes = ();
    }
};
fn main() {}
