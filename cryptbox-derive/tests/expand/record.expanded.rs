use cryptbox::BlindIndexError;
use zeroize::Zeroizing;
#[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
pub struct OrgId(pub [u8; 16]);
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
#[cryptbox(kind = "78f0169a-f024-402b-9cdf-f436864fa17f")]
pub struct WorkspaceId(pub [u8; 16]);
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::PartType for WorkspaceId {
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
    impl ::cryptbox::BoundId for WorkspaceId {
        const KIND_ID: ::cryptbox::PartId = ::cryptbox::PartId::from_u128(
            0x78f0169a_f024_402b_9cdf_f436864fa17f,
        );
    }
};
fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
}
/// A customer.
#[cryptbox(stored(derive(Debug), sqlx(rename_all = "snake_case")))]
pub struct Customer {
    /// The client-generated record ID.
    #[cryptbox(record_id)]
    pub id: i64,
    #[cryptbox(bound)]
    pub org: OrgId,
    #[cryptbox(bound)]
    pub workspace: WorkspaceId,
    /// The primary contact address.
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(
        blind_index(
            id = "ab78afa9-7aaa-499c-8239-037b7e136130",
            across(workspace),
            bits = 32,
            normalize = normalize_email,
            normalizer = "email/1",
        )
    )]
    #[cryptbox(stored(sqlx(rename = "email_ciphertext")))]
    pub email: String,
    #[cryptbox(seal = "5d1f0c3a-8f6e-4b1d-9a7c-2e4b6d8f0a13", padding = block(16))]
    #[cryptbox(
        blind_index(
            id = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0",
            bits = 16,
            normalize = normalize_email,
            normalizer = "note/1",
        )
    )]
    note: Option<String>,
    #[cryptbox(plaintext)]
    pub created_at: i64,
}
const _: fn() = || {
    fn check<T: ::cryptbox::BoundId + ?::core::marker::Sized>() {}
    check::<OrgId>();
};
const _: fn() = || {
    fn check<T: ::cryptbox::BoundId + ?::core::marker::Sized>() {}
    check::<WorkspaceId>();
};
const _: fn() = || {
    fn check<T: ::cryptbox::PartType + ?::core::marker::Sized>() {}
    check::<i64>();
};
///The seal of `Customer::email`, which `#[derive(Record)]` declares.
pub struct CustomerEmail;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for CustomerEmail {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x2cef6a47_3e20_42dc_a319_56022cb4cf30,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
        type Value = String;
        type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
        type Bound = (OrgId, WorkspaceId);
        type Record = i64;
        type Indexes = (CustomerEmailIndex,);
    }
};
///The `email_index` blind index of `Customer::email`.
pub struct CustomerEmailIndex;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::BlindIndexSpec for CustomerEmailIndex {
        type Seal = CustomerEmail;
        type Partition = (OrgId,);
        const ID: ::cryptbox::IndexId = ::cryptbox::IndexId::from_u128(
            0xab78afa9_7aaa_499c_8239_037b7e136130,
        );
        const BITS: u16 = 32;
        const NORMALIZER: &'static str = "email/1";
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
            value: &String,
        ) -> ::core::result::Result<
            ::cryptbox::__private::Zeroizing<::std::vec::Vec<u8>>,
            ::cryptbox::BlindIndexError,
        > {
            normalize_email(value)
        }
    }
};
///The seal of `Customer::note`, which `#[derive(Record)]` declares.
struct CustomerNote;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for CustomerNote {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x5d1f0c3a_8f6e_4b1d_9a7c_2e4b6d8f0a13,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::block(16);
        type Value = String;
        type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
        type Bound = (OrgId, WorkspaceId);
        type Record = i64;
        type Indexes = (CustomerNoteIndex,);
    }
};
///The `note_index` blind index of `Customer::note`.
struct CustomerNoteIndex;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::BlindIndexSpec for CustomerNoteIndex {
        type Seal = CustomerNote;
        type Partition = (OrgId, WorkspaceId);
        const ID: ::cryptbox::IndexId = ::cryptbox::IndexId::from_u128(
            0x0f1e2d3c_4b5a_4968_8776_a5b4c3d2e1f0,
        );
        const BITS: u16 = 16;
        const NORMALIZER: &'static str = "note/1";
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
            value: &String,
        ) -> ::core::result::Result<
            ::cryptbox::__private::Zeroizing<::std::vec::Vec<u8>>,
            ::cryptbox::BlindIndexError,
        > {
            normalize_email(value)
        }
    }
};
///The stored form of [`Customer`].
#[sqlx(rename_all = "snake_case")]
pub struct StoredCustomer {
    /// The client-generated record ID.
    pub id: i64,
    pub org: OrgId,
    pub workspace: WorkspaceId,
    /// The primary contact address.
    #[sqlx(rename = "email_ciphertext")]
    pub email: ::cryptbox::Sealed<CustomerEmail>,
    ///The `email_index` blind index of `email`.
    pub email_index: ::cryptbox::BlindIndex<CustomerEmailIndex>,
    note: ::core::option::Option<::cryptbox::Sealed<CustomerNote>>,
    ///The `note_index` blind index of `note`.
    note_index: ::core::option::Option<::cryptbox::BlindIndex<CustomerNoteIndex>>,
    pub created_at: i64,
}
#[automatically_derived]
impl ::core::fmt::Debug for StoredCustomer {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        let names: &'static _ = &[
            "id",
            "org",
            "workspace",
            "email",
            "email_index",
            "note",
            "note_index",
            "created_at",
        ];
        let values: &[&dyn ::core::fmt::Debug] = &[
            &self.id,
            &self.org,
            &self.workspace,
            &self.email,
            &self.email_index,
            &self.note,
            &self.note_index,
            &&self.created_at,
        ];
        ::core::fmt::Formatter::debug_struct_fields_finish(
            f,
            "StoredCustomer",
            names,
            values,
        )
    }
}
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Record for Customer {
        type Stored = StoredCustomer;
        const SEALS: &'static [::cryptbox::SealId] = &[
            <CustomerEmail as ::cryptbox::Seal>::ID,
            <CustomerNote as ::cryptbox::Seal>::ID,
        ];
        const RECORD_ID: &'static str = "id";
        const BOUND: &'static [&'static str] = &["org", "workspace"];
        const PLAINTEXT: &'static [&'static str] = &["created_at"];
        fn seal<K>(
            &self,
            keys: &K,
        ) -> ::core::result::Result<StoredCustomer, ::cryptbox::Error>
        where
            K: ::cryptbox::RecordKeys + ?::core::marker::Sized,
        {
            let email = {
                let value = &self.email;
                ::cryptbox::Sealed::<
                    CustomerEmail,
                >::seal(value, (&self.org, &self.workspace, &self.id), keys)?
            };
            let email_index = {
                let value = &self.email;
                <CustomerEmailIndex as ::cryptbox::BlindIndexSpec>::derive_with(
                    value,
                    &self.org,
                    ::cryptbox::RecordKeys::record_blind_index_keyring(keys)?,
                )?
            };
            let note = match &self.note {
                ::core::option::Option::Some(value) => {
                    ::core::option::Option::Some(
                        ::cryptbox::Sealed::<
                            CustomerNote,
                        >::seal(value, (&self.org, &self.workspace, &self.id), keys)?,
                    )
                }
                ::core::option::Option::None => ::core::option::Option::None,
            };
            let note_index = match &self.note {
                ::core::option::Option::Some(value) => {
                    ::core::option::Option::Some(
                        <CustomerNoteIndex as ::cryptbox::BlindIndexSpec>::derive_with(
                            value,
                            (&self.org, &self.workspace),
                            ::cryptbox::RecordKeys::record_blind_index_keyring(keys)?,
                        )?,
                    )
                }
                ::core::option::Option::None => ::core::option::Option::None,
            };
            ::core::result::Result::Ok(StoredCustomer {
                id: ::core::clone::Clone::clone(&self.id),
                org: ::core::clone::Clone::clone(&self.org),
                workspace: ::core::clone::Clone::clone(&self.workspace),
                email,
                email_index,
                note,
                note_index,
                created_at: ::core::clone::Clone::clone(&self.created_at),
            })
        }
        fn open<K>(
            stored: StoredCustomer,
            keys: &K,
        ) -> ::core::result::Result<Self, ::cryptbox::Error>
        where
            K: ::cryptbox::EncryptionKeys + ?::core::marker::Sized,
        {
            let email = {
                let value = &stored.email;
                value.open((&stored.org, &stored.workspace, &stored.id), keys)?
            };
            let note = match &stored.note {
                ::core::option::Option::Some(value) => {
                    ::core::option::Option::Some(
                        value.open((&stored.org, &stored.workspace, &stored.id), keys)?,
                    )
                }
                ::core::option::Option::None => ::core::option::Option::None,
            };
            ::core::result::Result::Ok(Self {
                id: stored.id,
                org: stored.org,
                workspace: stored.workspace,
                email,
                note,
                created_at: stored.created_at,
            })
        }
    }
};
///The partition of [`Customer::NOTE_INDEX`]: the bound values its queries supply.
struct CustomerNoteIndexPartition {
    ///The `org` of the rows to search.
    pub org: OrgId,
    ///The `workspace` of the rows to search.
    pub workspace: WorkspaceId,
}
#[automatically_derived]
impl Customer {
    ///The `email_index` blind index of `email`, searched within its partition.
    pub const EMAIL_INDEX: ::cryptbox::Index<Customer, CustomerEmailIndex, OrgId> = ::cryptbox::Index::__new(
        |partition| ::std::vec::Vec::from([::cryptbox::PartType::part_value(partition)]),
        |row: &StoredCustomer, partition| {
            ::cryptbox::PartType::part_value(&row.org)
                == ::cryptbox::PartType::part_value(partition)
        },
        |record: &Customer| -> ::core::option::Option<&String> {
            ::core::option::Option::Some(&record.email)
        },
    );
    ///The `note_index` blind index of `note`, searched within its partition.
    const NOTE_INDEX: ::cryptbox::Index<
        Customer,
        CustomerNoteIndex,
        CustomerNoteIndexPartition,
    > = ::cryptbox::Index::__new(
        |partition| ::std::vec::Vec::from([
            ::cryptbox::PartType::part_value(&partition.org),
            ::cryptbox::PartType::part_value(&partition.workspace),
        ]),
        |row: &StoredCustomer, partition| {
            ::cryptbox::PartType::part_value(&row.org)
                == ::cryptbox::PartType::part_value(&partition.org)
                && ::cryptbox::PartType::part_value(&row.workspace)
                    == ::cryptbox::PartType::part_value(&partition.workspace)
        },
        |record: &Customer| -> ::core::option::Option<&String> { record.note.as_ref() },
    );
}
fn main() {}
