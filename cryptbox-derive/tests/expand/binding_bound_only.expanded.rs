pub struct Revision {
    #[cryptbox(part = "8f4a6c13-9d2e-4b57-a0c8-6e1f3a5d7b92")]
    pub number: i64,
}
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Binding for Revision {
        const PARTS: &'static [::cryptbox::PartSpec] = &[
            ::cryptbox::PartSpec::bound(
                ::cryptbox::PartId::from_u128(0x8f4a6c13_9d2e_4b57_a0c8_6e1f3a5d7b92),
                <i64 as ::cryptbox::PartType>::KIND,
            ),
        ];
        type IndexArgs = ();
        fn values(&self) -> ::cryptbox::PartValues<'_> {
            ::cryptbox::PartValues::from([
                <i64 as ::cryptbox::PartType>::part_value(&self.number),
            ])
        }
        fn index_values((): &()) -> ::cryptbox::PartValues<'_> {
            ::cryptbox::PartValues::new()
        }
    }
    #[automatically_derived]
    impl ::cryptbox::FromIndexValues for Revision {
        fn from_index_values(
            values: &[::cryptbox::PartValue<'_>],
        ) -> ::core::result::Result<(), ::cryptbox::Error> {
            match values {
                [] => ::core::result::Result::Ok(()),
                _ => ::core::result::Result::Err(::cryptbox::Error::InvalidBinding),
            }
        }
    }
};
fn main() {}
