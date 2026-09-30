pub struct Customer {
    #[record_id]
    pub id: i64,
    pub created_at: i64,
    /// The primary contact address.
    #[seal(id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13", scope = cryptbox::Tenant)]
    pub email: String,
    #[seal(
        id = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38",
        scope = cryptbox::Tenant,
        padding = block(16),
        name = PrivateNote,
    )]
    note: String,
}
///The seal of `Customer::email`, which `#[derive(Record)]` declares.
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
        type Scope = ::cryptbox::Recorded<cryptbox::Tenant, i64>;
        type Keys = cryptbox::Tenant;
        type Indexes = ();
    }
};
///The seal of `Customer::note`, which `#[derive(Record)]` declares.
struct PrivateNote;
const _: () = {
    #[automatically_derived]
    impl ::cryptbox::Seal for PrivateNote {
        const ID: ::cryptbox::SealId = ::cryptbox::SealId::from_u128(
            0x0d7e3a95_4b1c_4e62_8f0a_9c5b2d7e1f38,
        );
        const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::block(16);
        type Value = String;
        type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
        type Scope = ::cryptbox::Recorded<cryptbox::Tenant, i64>;
        type Keys = cryptbox::Tenant;
        type Indexes = ();
    }
};
///The sealed form of [`Customer`], as it is stored.
pub struct SealedCustomer {
    pub id: i64,
    pub created_at: i64,
    /// The primary contact address.
    pub email: ::cryptbox::Sealed<CustomerEmail>,
    note: ::cryptbox::Sealed<PrivateNote>,
}
const _: () = {
    const _: () = if !::cryptbox::__private::writes_declared_indexes(
        <<CustomerEmail as ::cryptbox::Seal>::Indexes as ::cryptbox::IndexList<
            CustomerEmail,
        >>::IDS,
        &[],
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
        <<PrivateNote as ::cryptbox::Seal>::Indexes as ::cryptbox::IndexList<
            PrivateNote,
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
        ///Seals `email` alone under `binding` and the record ID `record`, for a partial update.
        pub fn seal_email<K>(
            value: &<CustomerEmail as ::cryptbox::Seal>::Value,
            binding: &<<CustomerEmail as ::cryptbox::Seal>::Scope as ::cryptbox::SealScope>::Parts,
            record: &i64,
            keys: &K,
        ) -> ::core::result::Result<::cryptbox::Sealed<CustomerEmail>, ::cryptbox::Error>
        where
            K: ::cryptbox::EncryptionKeySource<<CustomerEmail as ::cryptbox::Seal>::Keys>
                + ?::core::marker::Sized,
        {
            ::cryptbox::Sealed::<
                CustomerEmail,
            >::seal(value, ::cryptbox::__private::InRecord(binding, record), keys)
        }
        ///Seals `note` alone under `binding` and the record ID `record`, for a partial update.
        fn seal_note<K>(
            value: &<PrivateNote as ::cryptbox::Seal>::Value,
            binding: &<<PrivateNote as ::cryptbox::Seal>::Scope as ::cryptbox::SealScope>::Parts,
            record: &i64,
            keys: &K,
        ) -> ::core::result::Result<::cryptbox::Sealed<PrivateNote>, ::cryptbox::Error>
        where
            K: ::cryptbox::EncryptionKeySource<<PrivateNote as ::cryptbox::Seal>::Keys>
                + ?::core::marker::Sized,
        {
            ::cryptbox::Sealed::<
                PrivateNote,
            >::seal(value, ::cryptbox::__private::InRecord(binding, record), keys)
        }
    }
    #[automatically_derived]
    impl ::cryptbox::Record for Customer {
        type Sealed = SealedCustomer;
        type Scope = cryptbox::Tenant;
        type Keys = cryptbox::Tenant;
        const SEALS: &'static [::cryptbox::SealId] = &[
            <CustomerEmail as ::cryptbox::Seal>::ID,
            <PrivateNote as ::cryptbox::Seal>::ID,
        ];
        const RECORD_ID: &'static str = "id";
        const PLAINTEXT: &'static [&'static str] = &["created_at"];
        fn seal<K>(
            &self,
            binding: &Self::Scope,
            keys: &K,
        ) -> ::core::result::Result<SealedCustomer, ::cryptbox::Error>
        where
            K: ::cryptbox::EncryptionKeySource<Self::Keys>
                + ::cryptbox::BlindIndexKeySource<Self::Keys> + ?::core::marker::Sized,
        {
            let email = Self::seal_email(&self.email, binding, &self.id, keys)?;
            let note = Self::seal_note(&self.note, binding, &self.id, keys)?;
            ::core::result::Result::Ok(SealedCustomer {
                id: ::core::clone::Clone::clone(&self.id),
                created_at: ::core::clone::Clone::clone(&self.created_at),
                email,
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
                        <<PrivateNote as ::cryptbox::Seal>::Scope as ::cryptbox::SealScope>::Parts,
                        _,
                    >(binding, record_id),
                    keys,
                )?;
            ::core::result::Result::Ok(Self {
                id: sealed.id,
                created_at: sealed.created_at,
                email,
                note,
            })
        }
    }
};
fn main() {}
