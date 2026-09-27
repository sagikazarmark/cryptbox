#[cryptbox(codec = AddressCodec)]
pub struct Address {
    pub street: String,
}
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Plaintext for Address {
        type Codec = AddressCodec;
    }
};
pub struct AddressCodec;
pub struct Email(String);
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Plaintext for Email {
        type Codec = Self;
    }
    #[automatically_derived]
    impl ::cryptbox::Codec<Self> for Email {
        fn encode(
            value: &Self,
        ) -> ::core::result::Result<
            ::cryptbox::__private::Zeroizing<::std::vec::Vec<u8>>,
            ::cryptbox::CodecError,
        > {
            <<String as ::cryptbox::Plaintext>::Codec as ::cryptbox::Codec<
                String,
            >>::encode(&value.0)
        }
        fn decode(bytes: &[u8]) -> ::core::result::Result<Self, ::cryptbox::CodecError> {
            <<String as ::cryptbox::Plaintext>::Codec as ::cryptbox::Codec<
                String,
            >>::decode(bytes)
                .map(Self)
        }
    }
};
fn main() {}
