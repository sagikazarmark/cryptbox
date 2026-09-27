use cryptbox::BlindIndexError;
use zeroize::Zeroizing;
#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
pub struct UserEmail;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Field for UserEmail {
        const ID: ::cryptbox::FieldId = ::cryptbox::FieldId::from_u128(
            0xca274e85_63c4_4f7d_a255_2dfecbfe5e25,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
        type Value = String;
        type Codec = <String as ::cryptbox::Plaintext>::Codec;
    }
};
fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.trim().to_ascii_lowercase().into_bytes()))
}
#[cryptbox(
    id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
    field = UserEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
)]
pub struct EmailLookup;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::BlindIndexSpec for EmailLookup {
        type Field = UserEmail;
        const ID: ::cryptbox::IndexId = ::cryptbox::IndexId::from_u128(
            0x2e4c7b1a_5d3f_4a86_9b20_7f1e6c8d4a53,
        );
        const BITS: u16 = 32;
        type Query = str;
        fn normalize_query(
            query: &str,
        ) -> ::core::result::Result<
            ::cryptbox::__private::Zeroizing<::std::vec::Vec<u8>>,
            ::cryptbox::BlindIndexError,
        > {
            normalize_email(query)
        }
        fn normalize_value(
            value: &<UserEmail as ::cryptbox::Field>::Value,
        ) -> ::core::result::Result<
            ::cryptbox::__private::Zeroizing<::std::vec::Vec<u8>>,
            ::cryptbox::BlindIndexError,
        > {
            normalize_email(value)
        }
    }
};
fn main() {}
