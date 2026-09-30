use cryptbox::BlindIndexError;
use zeroize::Zeroizing;
#[seal(
    id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    value = String,
    scope = cryptbox::Recorded<cryptbox::Tenant,
    i64>,
    indexes(EmailLookup),
)]
pub struct CustomerEmail;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for CustomerEmail {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x6c3b1f0e_8a24_4d5b_9e71_2f4a6c8d0b13,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
        type Value = String;
        type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
        type Scope = cryptbox::Recorded<cryptbox::Tenant, i64>;
        type Keys = <cryptbox::Recorded<
            cryptbox::Tenant,
            i64,
        > as ::cryptbox::SealScope>::Parts;
        type Indexes = (EmailLookup,);
    }
};
#[seal(
    id = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38",
    value = String,
    scope = cryptbox::Tenant,
)]
pub struct CustomerNote;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for CustomerNote {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x0d7e3a95_4b1c_4e62_8f0a_9c5b2d7e1f38,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
        type Value = String;
        type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
        type Scope = cryptbox::Tenant;
        type Keys = <cryptbox::Tenant as ::cryptbox::SealScope>::Parts;
        type Indexes = ();
    }
};
fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
}
#[blind_index(
    id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
    seal = CustomerEmail,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
pub struct EmailLookup;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::BlindIndexSpec for EmailLookup {
        type Seal = CustomerEmail;
        type Scope = <<CustomerEmail as ::cryptbox::Seal>::Scope as ::cryptbox::SealScope>::Parts;
        const ID: ::cryptbox::IndexId = ::cryptbox::IndexId::from_u128(
            0x2e4c7b1a_5d3f_4a86_9b20_7f1e6c8d4a53,
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
            value: &<CustomerEmail as ::cryptbox::Seal>::Value,
        ) -> ::core::result::Result<
            ::cryptbox::__private::Zeroizing<::std::vec::Vec<u8>>,
            ::cryptbox::BlindIndexError,
        > {
            normalize_email(value)
        }
    }
};
/// A customer.
#[record(sealed = SealedCustomer, attr(derive(Debug)))]
#[sqlx(rename_all = "snake_case")]
pub struct Customer {
    /// The client-generated record ID.
    #[record_id]
    pub id: i64,
    /// The primary contact address.
    #[sqlx(rename = "email_ciphertext")]
    #[seal(CustomerEmail)]
    #[blind_index(EmailLookup as email_lookup)]
    pub email: String,
    #[seal(CustomerNote)]
    note: String,
}
///The sealed form of [`Customer`], as it is stored.
#[sqlx(rename_all = "snake_case")]
pub struct SealedCustomer {
    /// The client-generated record ID.
    pub id: i64,
    /// The primary contact address.
    #[sqlx(rename = "email_ciphertext")]
    pub email: ::cryptbox::Sealed<CustomerEmail>,
    ///The `EmailLookup` blind index of `email`.
    pub email_lookup: ::cryptbox::BlindIndex<EmailLookup>,
    note: ::cryptbox::Sealed<CustomerNote>,
}
#[automatically_derived]
impl ::core::fmt::Debug for SealedCustomer {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field4_finish(
            f,
            "SealedCustomer",
            "id",
            &self.id,
            "email",
            &self.email,
            "email_lookup",
            &self.email_lookup,
            "note",
            &&self.note,
        )
    }
}
const _: () = {
    const _: () = if !::cryptbox::__private::writes_declared_indexes(
        <<CustomerEmail as ::cryptbox::Seal>::Indexes as ::cryptbox::IndexList<
            CustomerEmail,
        >>::IDS,
        &[<EmailLookup as ::cryptbox::BlindIndexSpec>::ID],
    ) {
        {
            ::core::panicking::panic_fmt(
                format_args!(
                    "`email` must write every blind index its seal declares in `indexes(…)`, each once, and no other: list them as `#[blind_index(Spec as column, …)]`",
                ),
            );
        }
    };
    const _: () = if !::cryptbox::__private::writes_declared_indexes(
        <<CustomerNote as ::cryptbox::Seal>::Indexes as ::cryptbox::IndexList<
            CustomerNote,
        >>::IDS,
        &[],
    ) {
        {
            ::core::panicking::panic_fmt(
                format_args!(
                    "`note` must write every blind index its seal declares in `indexes(…)`, each once, and no other: list them as `#[blind_index(Spec as column, …)]`",
                ),
            );
        }
    };
    #[automatically_derived]
    impl Customer {
        ///Seals `email` alone under `binding` and the record ID `record`, with the blind indexes it stores, for a partial update.
        pub fn seal_email<K>(
            value: &<CustomerEmail as ::cryptbox::Seal>::Value,
            binding: &<<CustomerEmail as ::cryptbox::Seal>::Scope as ::cryptbox::SealScope>::Parts,
            record: &i64,
            keys: &K,
        ) -> ::core::result::Result<
            (::cryptbox::Sealed<CustomerEmail>, ::cryptbox::BlindIndex<EmailLookup>),
            ::cryptbox::Error,
        >
        where
            K: ::cryptbox::EncryptionKeySource<<CustomerEmail as ::cryptbox::Seal>::Keys>
                + ::cryptbox::BlindIndexKeySource<
                    <CustomerEmail as ::cryptbox::Seal>::Keys,
                > + ?::core::marker::Sized,
        {
            let prepared = ::cryptbox::Sealed::<
                CustomerEmail,
            >::prepare(value, ::cryptbox::__private::InRecord(binding, record), keys)?
                .with_index_with::<EmailLookup>(keys)?;
            let email_lookup = prepared.index::<EmailLookup>()?.to_blind_index();
            ::core::result::Result::Ok((prepared.into_sealed(), email_lookup))
        }
        ///Seals `note` alone under `binding` and the record ID `record`, for a partial update.
        fn seal_note<K>(
            value: &<CustomerNote as ::cryptbox::Seal>::Value,
            binding: &<<CustomerNote as ::cryptbox::Seal>::Scope as ::cryptbox::SealScope>::Parts,
            record: &i64,
            keys: &K,
        ) -> ::core::result::Result<::cryptbox::Sealed<CustomerNote>, ::cryptbox::Error>
        where
            K: ::cryptbox::EncryptionKeySource<<CustomerNote as ::cryptbox::Seal>::Keys>
                + ?::core::marker::Sized,
        {
            ::cryptbox::Sealed::<
                CustomerNote,
            >::seal(value, ::cryptbox::__private::InRecord(binding, record), keys)
        }
    }
    #[automatically_derived]
    impl ::cryptbox::Record for Customer {
        type Sealed = SealedCustomer;
        type Scope = <<CustomerEmail as ::cryptbox::Seal>::Scope as ::cryptbox::SealScope>::Parts;
        type Keys = <CustomerEmail as ::cryptbox::Seal>::Keys;
        const SEALS: &'static [::cryptbox::SealId] = &[
            <CustomerEmail as ::cryptbox::Seal>::ID,
            <CustomerNote as ::cryptbox::Seal>::ID,
        ];
        const RECORD_ID: &'static str = "id";
        const PLAINTEXT: &'static [&'static str] = &[];
        fn seal<K>(
            &self,
            binding: &Self::Scope,
            keys: &K,
        ) -> ::core::result::Result<SealedCustomer, ::cryptbox::Error>
        where
            K: ::cryptbox::EncryptionKeySource<Self::Keys>
                + ::cryptbox::BlindIndexKeySource<Self::Keys> + ?::core::marker::Sized,
        {
            let (email, email_lookup) = Self::seal_email(
                &self.email,
                binding,
                &self.id,
                keys,
            )?;
            let note = Self::seal_note(&self.note, binding, &self.id, keys)?;
            ::core::result::Result::Ok(SealedCustomer {
                id: ::core::clone::Clone::clone(&self.id),
                email,
                email_lookup,
                note,
            })
        }
        fn open<K>(
            sealed: SealedCustomer,
            binding: &Self::Scope,
            keys: &K,
        ) -> ::core::result::Result<Self, ::cryptbox::Error>
        where
            K: ::cryptbox::EncryptionKeySource<Self::Keys> + ?::core::marker::Sized,
        {
            let record_id = &sealed.id;
            let email = sealed
                .email
                .open(
                    ::cryptbox::__private::InRecord::<
                        <<CustomerEmail as ::cryptbox::Seal>::Scope as ::cryptbox::SealScope>::Parts,
                        _,
                    >(binding, record_id),
                    keys,
                )?;
            let note = sealed
                .note
                .open(
                    ::cryptbox::__private::InRecord::<
                        <<CustomerNote as ::cryptbox::Seal>::Scope as ::cryptbox::SealScope>::Parts,
                        _,
                    >(binding, record_id),
                    keys,
                )?;
            ::core::result::Result::Ok(Self { id: sealed.id, email, note })
        }
    }
    #[automatically_derived]
    impl ::cryptbox::IndexedBy<EmailLookup> for Customer {
        fn indexed_value(
            &self,
        ) -> &<<EmailLookup as ::cryptbox::BlindIndexSpec>::Seal as ::cryptbox::Seal>::Value {
            &self.email
        }
    }
};
