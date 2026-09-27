#[cryptbox(index_args = OrgSearch)]
pub struct OrgWorkspace {
    /// Bound only.
    #[cryptbox(part = "c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48")]
    pub workspace: Vec<u8>,
    /// Scopes keys and blind indexes.
    #[cryptbox(part = "3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90", keys)]
    pub org: [u8; 16],
    #[cryptbox(part = "5d9c2a47-1e6b-4f30-8a5c-3b7e0d9f2c61", index)]
    pub(crate) region: i64,
}
///The index arguments of [`OrgWorkspace`]: its `keys` and `index` parts.
pub struct OrgSearch {
    /// Scopes keys and blind indexes.
    pub org: [u8; 16],
    pub(crate) region: i64,
}
#[automatically_derived]
impl ::core::clone::Clone for OrgSearch {
    #[inline]
    fn clone(&self) -> OrgSearch {
        OrgSearch {
            org: ::core::clone::Clone::clone(&self.org),
            region: ::core::clone::Clone::clone(&self.region),
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for OrgSearch {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field2_finish(
            f,
            "OrgSearch",
            "org",
            &self.org,
            "region",
            &&self.region,
        )
    }
}
#[automatically_derived]
impl ::core::hash::Hash for OrgSearch {
    #[inline]
    fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) {
        ::core::hash::Hash::hash(&self.org, state);
        ::core::hash::Hash::hash(&self.region, state)
    }
}
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for OrgSearch {}
#[automatically_derived]
impl ::core::cmp::PartialEq for OrgSearch {
    #[inline]
    fn eq(&self, other: &OrgSearch) -> bool {
        self.region == other.region && self.org == other.org
    }
}
#[automatically_derived]
impl ::core::cmp::Eq for OrgSearch {
    #[inline]
    #[doc(hidden)]
    #[coverage(off)]
    fn assert_fields_are_eq(&self) {
        let _: ::core::cmp::AssertParamIsEq<[u8; 16]>;
        let _: ::core::cmp::AssertParamIsEq<i64>;
    }
}
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Binding for OrgWorkspace {
        const PARTS: &'static [::cryptbox::PartSpec] = &[
            ::cryptbox::PartSpec::keys(
                ::cryptbox::PartId::from_u128(0x3a1f0c6e_58b2_4d0a_9e57_1c4b8f2d6a90),
                <[u8; 16] as ::cryptbox::PartType>::KIND,
            ),
            ::cryptbox::PartSpec::index(
                ::cryptbox::PartId::from_u128(0x5d9c2a47_1e6b_4f30_8a5c_3b7e0d9f2c61),
                <i64 as ::cryptbox::PartType>::KIND,
            ),
            ::cryptbox::PartSpec::bound(
                ::cryptbox::PartId::from_u128(0xc7d24e19_0b8a_4f63_a1d5_6e9f3b720c48),
                <Vec<u8> as ::cryptbox::PartType>::KIND,
            ),
        ];
        type IndexArgs = OrgSearch;
        fn values(&self) -> ::cryptbox::PartValues<'_> {
            ::cryptbox::PartValues::from([
                <[u8; 16] as ::cryptbox::PartType>::part_value(&self.org),
                <i64 as ::cryptbox::PartType>::part_value(&self.region),
                <Vec<u8> as ::cryptbox::PartType>::part_value(&self.workspace),
            ])
        }
        fn index_values(args: &OrgSearch) -> ::cryptbox::PartValues<'_> {
            ::cryptbox::PartValues::from([
                <[u8; 16] as ::cryptbox::PartType>::part_value(&args.org),
                <i64 as ::cryptbox::PartType>::part_value(&args.region),
            ])
        }
    }
};
fn main() {}
