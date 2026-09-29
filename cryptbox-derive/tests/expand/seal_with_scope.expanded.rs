#[cryptbox(
    id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
    value = String,
    scope = cryptbox::Tenant,
    record,
    indexes(EmailLookup, EmailDomainLookup),
)]
pub struct CustomerEmail;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for CustomerEmail {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0xca274e85_63c4_4f7d_a255_2dfecbfe5e25,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
        const RECORD: bool = true;
        type Value = String;
        type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
        type Scope = cryptbox::Tenant;
        type Indexes = (EmailLookup, EmailDomainLookup);
    }
};
pub struct EmailLookup;
pub struct EmailDomainLookup;
fn main() {}
