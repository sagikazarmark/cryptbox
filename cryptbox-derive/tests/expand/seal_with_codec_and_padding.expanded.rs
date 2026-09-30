pub struct Address {
    pub street: String,
}
pub struct AddressCodec;
#[cryptbox(
    id = "0B6F3C2A-8E41-4D57-A9C3-5E1F2D7B8A64",
    value = Address,
    codec = AddressCodec,
    padding = block(16),
)]
pub struct HomeAddress;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for HomeAddress {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x0b6f3c2a_8e41_4d57_a9c3_5e1f2d7b8a64,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::block(16);
        type Value = Address;
        type Codec = AddressCodec;
        type Scope = ();
        type Indexes = ();
    }
};
#[cryptbox(id = "00000000-0000-4000-8000-000000000001", value = Address)]
#[cryptbox(codec = AddressCodec, padding = length(256usize), crate = "::cryptbox")]
pub struct FixedAddress;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for FixedAddress {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x00000000_0000_4000_8000_000000000001,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::length(256usize);
        type Value = Address;
        type Codec = AddressCodec;
        type Scope = ();
        type Indexes = ();
    }
};
fn main() {}
