pub struct OrgWorkspace {
    /// Bound only.
    #[cryptbox(part = "c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48")]
    pub workspace: Vec<u8>,
    /// Scopes keys.
    #[cryptbox(part = "3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90", keys)]
    pub org: [u8; 16],
    #[cryptbox(part = "5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61")]
    pub(crate) region: i64,
}
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Scope for OrgWorkspace {
        const PARTS: &'static [::cryptbox::PartSpec] = &[
            ::cryptbox::PartSpec::keys(
                ::cryptbox::PartId::from_u128(0x3a1f0c6e_58b2_4d0a_9e57_1c4b8f2d6a90),
                <[u8; 16] as ::cryptbox::PartType>::KIND,
            ),
            ::cryptbox::PartSpec::bound(
                ::cryptbox::PartId::from_u128(0x5d9c2a47_1e6b_4f30_8a5c_3b7e0d9f2c61),
                <i64 as ::cryptbox::PartType>::KIND,
            ),
            ::cryptbox::PartSpec::bound(
                ::cryptbox::PartId::from_u128(0xc7d24e19_0b8a_4f63_a1d5_6e9f3b720c48),
                <Vec<u8> as ::cryptbox::PartType>::KIND,
            ),
        ];
        fn values(&self) -> ::cryptbox::PartValues<'_> {
            ::cryptbox::PartValues::from([
                <[u8; 16] as ::cryptbox::PartType>::part_value(&self.org),
                <i64 as ::cryptbox::PartType>::part_value(&self.region),
                <Vec<u8> as ::cryptbox::PartType>::part_value(&self.workspace),
            ])
        }
    }
    #[automatically_derived]
    impl ::cryptbox::FromParts for OrgWorkspace {
        fn from_parts(
            values: &[::cryptbox::PartValue<'_>],
        ) -> ::core::result::Result<Self, ::cryptbox::Error> {
            match values {
                [value0, value1, value2] => {
                    ::core::result::Result::Ok(Self {
                        org: <[u8; 16] as ::cryptbox::PartType>::from_part_value(
                            *value0,
                        )?,
                        region: <i64 as ::cryptbox::PartType>::from_part_value(*value1)?,
                        workspace: <Vec<
                            u8,
                        > as ::cryptbox::PartType>::from_part_value(*value2)?,
                    })
                }
                _ => ::core::result::Result::Err(::cryptbox::Error::InvalidBinding),
            }
        }
    }
};
fn main() {}
