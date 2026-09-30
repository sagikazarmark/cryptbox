#[seal(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
pub struct UserEmail;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for UserEmail {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0xca274e85_63c4_4f7d_a255_2dfecbfe5e25,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
        type Value = String;
        type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
        type Scope = ();
        type Keys = ();
        type Indexes = ();
    }
};
fn main() {}
