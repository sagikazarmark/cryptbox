use cryptbox::BlindIndexError;
use zeroize::Zeroizing;
fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
}
/// A customer.
#[cryptbox(stored(derive(Debug), sqlx(rename_all = "snake_case")))]
pub struct Customer {
    /// The client-generated record ID.
    #[cryptbox(record_id)]
    pub id: i64,
    #[cryptbox(plaintext)]
    pub org: [u8; 16],
    /// The primary contact address.
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(
        blind_index(
            id = "ab78afa9-7aaa-499c-8239-037b7e136130",
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
    fn check<T: ::cryptbox::RecordKey>() {}
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
    }
};
///The `email_index` blind index of `Customer::email`.
pub struct CustomerEmailIndex;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::BlindIndexSpec for CustomerEmailIndex {
        type Seal = CustomerEmail;
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
    }
};
///The `note_index` blind index of `Customer::note`.
struct CustomerNoteIndex;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::BlindIndexSpec for CustomerNoteIndex {
        type Seal = CustomerNote;
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
    pub org: [u8; 16],
    /// The primary contact address.
    #[sqlx(rename = "email_ciphertext")]
    pub email: ::cryptbox::Sealed<CustomerEmail, ::cryptbox::InRecord<i64>>,
    ///The `email_index` blind index of `email`.
    pub email_index: ::cryptbox::BlindIndex<CustomerEmailIndex>,
    note: ::core::option::Option<
        ::cryptbox::Sealed<CustomerNote, ::cryptbox::InRecord<i64>>,
    >,
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
            "email",
            "email_index",
            "note",
            "note_index",
            "created_at",
        ];
        let values: &[&dyn ::core::fmt::Debug] = &[
            &self.id,
            &self.org,
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
    impl ::cryptbox::__private::DerivedRecord for Customer {}
    #[automatically_derived]
    impl ::cryptbox::Record for Customer {
        type Stored = StoredCustomer;
        type Context = ::cryptbox::InRecord<i64>;
        const SEALS: &'static [::cryptbox::SealId] = &[
            <CustomerEmail as ::cryptbox::Seal>::ID,
            <CustomerNote as ::cryptbox::Seal>::ID,
        ];
        const RECORD_ID: &'static str = "id";
        const PLAINTEXT: &'static [&'static str] = &["org", "created_at"];
        #[allow(clippy::clone_on_copy)]
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
                    ::cryptbox::InRecord<i64>,
                >::seal_in(value, &self.id, keys)?
            };
            let email_index = {
                let value = &self.email;
                ::cryptbox::BlindIndex::<
                    CustomerEmailIndex,
                >::derive(
                    value,
                    ::cryptbox::RecordKeys::record_blind_index_keyring(keys)?,
                )?
            };
            let note = match &self.note {
                ::core::option::Option::Some(value) => {
                    ::core::option::Option::Some(
                        ::cryptbox::Sealed::<
                            CustomerNote,
                            ::cryptbox::InRecord<i64>,
                        >::seal_in(value, &self.id, keys)?,
                    )
                }
                ::core::option::Option::None => ::core::option::Option::None,
            };
            let note_index = match &self.note {
                ::core::option::Option::Some(value) => {
                    ::core::option::Option::Some(
                        ::cryptbox::BlindIndex::<
                            CustomerNoteIndex,
                        >::derive(
                            value,
                            ::cryptbox::RecordKeys::record_blind_index_keyring(keys)?,
                        )?,
                    )
                }
                ::core::option::Option::None => ::core::option::Option::None,
            };
            ::core::result::Result::Ok(StoredCustomer {
                id: ::core::clone::Clone::clone(&self.id),
                org: ::core::clone::Clone::clone(&self.org),
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
                ::cryptbox::Sealed::open_in(value, &stored.id, keys)?
            };
            let note = match &stored.note {
                ::core::option::Option::Some(value) => {
                    ::core::option::Option::Some(
                        ::cryptbox::Sealed::open_in(value, &stored.id, keys)?,
                    )
                }
                ::core::option::Option::None => ::core::option::Option::None,
            };
            ::core::result::Result::Ok(Self {
                id: stored.id,
                org: stored.org,
                email,
                note,
                created_at: stored.created_at,
            })
        }
    }
};
#[automatically_derived]
impl Customer {
    ///The `email_index` blind index of `email`.
    pub const EMAIL_INDEX: ::cryptbox::Index<Customer, CustomerEmailIndex> = ::cryptbox::Index::__new(|
        record: &Customer,
    | -> ::core::option::Option<&String> {
        ::core::option::Option::Some(&record.email)
    });
    ///The `note_index` blind index of `note`.
    const NOTE_INDEX: ::cryptbox::Index<Customer, CustomerNoteIndex> = ::cryptbox::Index::__new(|
        record: &Customer,
    | -> ::core::option::Option<&String> { record.note.as_ref() });
}
fn main() {}
