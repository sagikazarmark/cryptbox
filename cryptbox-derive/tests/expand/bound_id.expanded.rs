#[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
struct OrgId([u8; 16]);
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::PartType for OrgId {
        const KIND: ::cryptbox::PartKind = <[u8; 16] as ::cryptbox::PartType>::KIND;
        fn part_value(&self) -> ::cryptbox::PartValue<'_> {
            <[u8; 16] as ::cryptbox::PartType>::part_value(&self.0)
        }
        fn from_part_value(
            value: ::cryptbox::PartValue<'_>,
        ) -> ::core::result::Result<Self, ::cryptbox::Error> {
            <[u8; 16] as ::cryptbox::PartType>::from_part_value(value).map(Self)
        }
    }
    #[automatically_derived]
    impl ::cryptbox::BoundId for OrgId {
        const KIND_ID: ::cryptbox::PartId = ::cryptbox::PartId::from_u128(
            0x59881c28_3003_4047_847f_d7cc73b140e5,
        );
    }
};
