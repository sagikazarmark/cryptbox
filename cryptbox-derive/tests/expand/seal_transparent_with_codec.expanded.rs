pub struct Address {
    pub street: String,
}
#[cryptbox(
    id = "2e4a6c8e-0b1d-4f3a-a5c7-9e1b3d5f7a90",
    transparent,
    codec = cryptbox::Json
)]
pub struct HomeAddress {
    address: Address,
}
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for HomeAddress {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x2e4a6c8e_0b1d_4f3a_a5c7_9e1b3d5f7a90,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
        const RECORD: bool = false;
        type Value = Self;
        type Codec = Self;
        type Scope = ();
        type Indexes = ();
    }
    #[automatically_derived]
    impl ::cryptbox::Codec<Self> for HomeAddress {
        const ID: &'static str = <cryptbox::Json as ::cryptbox::Codec<Address>>::ID;
        fn encode(
            value: &Self,
        ) -> ::core::result::Result<
            ::cryptbox::__private::Zeroizing<::std::vec::Vec<u8>>,
            ::cryptbox::CodecError,
        > {
            <cryptbox::Json as ::cryptbox::Codec<Address>>::encode(&value.address)
        }
        fn decode(bytes: &[u8]) -> ::core::result::Result<Self, ::cryptbox::CodecError> {
            <cryptbox::Json as ::cryptbox::Codec<Address>>::decode(bytes)
                .map(|inner| Self { address: inner })
        }
    }
};
fn main() {}
