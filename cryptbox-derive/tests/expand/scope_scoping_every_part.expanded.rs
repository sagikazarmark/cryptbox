pub struct Org {
    #[cryptbox(part = "3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90", keys)]
    pub id: [u8; 16],
}
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Scope for Org {
        const PARTS: &'static [::cryptbox::PartSpec] = &[
            ::cryptbox::PartSpec::keys(
                ::cryptbox::PartId::from_u128(0x3a1f0c6e_58b2_4d0a_9e57_1c4b8f2d6a90),
                <[u8; 16] as ::cryptbox::PartType>::KIND,
            ),
        ];
        type IndexArgs = Self;
        fn values(&self) -> ::cryptbox::PartValues<'_> {
            ::cryptbox::PartValues::from([
                <[u8; 16] as ::cryptbox::PartType>::part_value(&self.id),
            ])
        }
        fn index_values(args: &Self) -> ::cryptbox::PartValues<'_> {
            ::cryptbox::PartValues::from([
                <[u8; 16] as ::cryptbox::PartType>::part_value(&args.id),
            ])
        }
    }
    #[automatically_derived]
    impl ::cryptbox::FromIndexValues for Org {
        fn from_index_values(
            values: &[::cryptbox::PartValue<'_>],
        ) -> ::core::result::Result<Self, ::cryptbox::Error> {
            match values {
                [value0] => {
                    ::core::result::Result::Ok(Self {
                        id: <[u8; 16] as ::cryptbox::PartType>::from_part_value(*value0)?,
                    })
                }
                _ => ::core::result::Result::Err(::cryptbox::Error::InvalidBinding),
            }
        }
    }
    #[automatically_derived]
    impl ::cryptbox::FromParts for Org {
        fn from_parts(
            values: &[::cryptbox::PartValue<'_>],
        ) -> ::core::result::Result<Self, ::cryptbox::Error> {
            match values {
                [value0] => {
                    ::core::result::Result::Ok(Self {
                        id: <[u8; 16] as ::cryptbox::PartType>::from_part_value(*value0)?,
                    })
                }
                _ => ::core::result::Result::Err(::cryptbox::Error::InvalidBinding),
            }
        }
    }
};
fn main() {}
