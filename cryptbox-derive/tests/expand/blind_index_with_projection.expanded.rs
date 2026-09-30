use cryptbox::BlindIndexError;
use zeroize::Zeroizing;
pub struct Address {
    pub street: String,
}
pub struct AddressCodec;
#[seal(
    id = "0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64",
    value = Address,
    codec = AddressCodec
)]
pub struct HomeAddress;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for HomeAddress {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x0b6f3c2a_8e41_4d57_a9c3_5e1f2d7b8a64,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
        type Value = Address;
        type Codec = AddressCodec;
        type Scope = ();
        type Keys = ();
        type Indexes = ();
    }
};
fn street(address: &Address) -> &str {
    &address.street
}
fn normalize_street(street: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(street.trim().to_ascii_lowercase().into_bytes()))
}
#[blind_index(
    id = "3f5d8c2b-6e40-4b97-8c31-8a2f7d9e5b64",
    seal = HomeAddress,
    bits = 64,
    query = str,
    normalize = normalize_street,
    normalizer = "street/1",
    project = street,
)]
pub struct StreetLookup;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::BlindIndexSpec for StreetLookup {
        type Seal = HomeAddress;
        type Scope = <<HomeAddress as ::cryptbox::Seal>::Scope as ::cryptbox::SealScope>::Parts;
        const ID: ::cryptbox::IndexId = ::cryptbox::IndexId::from_u128(
            0x3f5d8c2b_6e40_4b97_8c31_8a2f7d9e5b64,
        );
        const BITS: u16 = 64;
        const NORMALIZER: &'static str = "street/1";
        type Query = str;
        fn normalize_query(
            query: &str,
        ) -> ::core::result::Result<
            ::cryptbox::__private::Zeroizing<::std::vec::Vec<u8>>,
            ::cryptbox::BlindIndexError,
        > {
            normalize_street(query)
        }
        fn normalize_value(
            value: &<HomeAddress as ::cryptbox::Seal>::Value,
        ) -> ::core::result::Result<
            ::cryptbox::__private::Zeroizing<::std::vec::Vec<u8>>,
            ::cryptbox::BlindIndexError,
        > {
            normalize_street(&street(value))
        }
    }
};
fn main() {}
