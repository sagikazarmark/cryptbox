#[cryptbox(
    id = "7a1c3e5f-9b2d-4f60-8a4c-1e3b5d7f9a2c",
    transparent,
    padding = block(16)
)]
pub struct UserEmail(String);
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for UserEmail {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x7a1c3e5f_9b2d_4f60_8a4c_1e3b5d7f9a2c,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::block(16);
        type Value = Self;
        type Codec = Self;
        type Record = ();
        type Indexes = ();
    }
    #[automatically_derived]
    impl ::cryptbox::Codec<Self> for UserEmail {
        const ID: &'static str = <<String as ::cryptbox::__private::DefaultCodec>::Codec as ::cryptbox::Codec<
            String,
        >>::ID;
        fn encode(
            value: &Self,
        ) -> ::core::result::Result<
            ::cryptbox::__private::Zeroizing<::std::vec::Vec<u8>>,
            ::cryptbox::CodecError,
        > {
            <<String as ::cryptbox::__private::DefaultCodec>::Codec as ::cryptbox::Codec<
                String,
            >>::encode(&value.0)
        }
        fn decode(bytes: &[u8]) -> ::core::result::Result<Self, ::cryptbox::CodecError> {
            <<String as ::cryptbox::__private::DefaultCodec>::Codec as ::cryptbox::Codec<
                String,
            >>::decode(bytes)
                .map(Self)
        }
    }
};
fn main() {}
