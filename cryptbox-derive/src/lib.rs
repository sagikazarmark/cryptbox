//! Derive macros for [`cryptbox`](https://docs.rs/cryptbox).
//!
//! Enable them with `cryptbox`'s `derive` feature and use them through
//! `cryptbox`; do not depend on this crate directly. Each derive expands to
//! exactly the trait impls you would write by hand, inside `const _: () = { … };`
//! with absolute `::cryptbox::` paths. It adds no `Debug`, `Deref`, `From`, or
//! hidden items, so the manual impl stays a first-class alternative. The
//! generated items are `Record`'s stored form, the seals and blind-index
//! specs its fields declare, its index handles and partition structs, and
//! compile-time checks.
//!
//! Every derive takes `#[cryptbox(…)]`, on the item and, for `Record`, on its
//! fields, and accepts `crate = "path"` in its item-level attribute, for code
//! that reaches `cryptbox` under another path.

mod attr;
mod blind_index;
mod bound_id;
mod record;
mod seal;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

/// Derives `cryptbox::Seal`, for a marker or for a type that is its own value.
///
/// | `#[cryptbox(…)]` key | Required | Meaning |
/// | --- | --- | --- |
/// | `id = "…"` | yes | The seal ID, a hyphenated UUID string literal. |
/// | `value = Type` | on a unit struct | The value type a marker seals. A type with fields is its own value and rejects it. |
/// | `codec = Type` | on a type with fields, unless `transparent` | The codec. See below for its defaults. |
/// | `transparent` | no | Stores a type's single field alone. |
/// | `padding = …` | no | `none` (the default), `block(size)`, or `length(len)`. |
/// | `bound(Type, …)` | no | The bound ID types values are bound to (`Bound`), in argument order. Defaults to none. |
/// | `record = Type` | no | The type of the record ID values are bound to (`Record`). Defaults to none. |
/// | `indexes(Type, …)` | no | The seal's blind indexes (`Indexes`). Defaults to none. |
///
/// The ID is validated when the macro expands and is never derived from the
/// type's name: generate a fresh UUID for every seal. Padding parameters are
/// validated when the macro expands too.
///
/// The type's shape decides only whether it is its own value; its codec is
/// always stated or a built-in default, never inferred from the shape:
///
/// - A **unit struct** is a marker over a separate `value` type, which several
///   seals can share. Without `codec`, the value type's built-in default applies: only
///   `String`, `Vec<u8>`, and their `Secret` wrappers have one, and any other
///   value type reports that it has no default codec.
/// - **Any other type** is its own value (`Value = Self`). With `codec`, that codec
///   encodes the whole type. With `transparent`, the type must be a struct with
///   exactly one field, and the seal stores that field alone: with `codec` if
///   given, or else with the field type's built-in default codec. A transparent seal
///   stores exactly the bytes of a marker over the field's type with the same
///   ID and codec, so the two read each other's values.
///
/// Without `bound`, `record`, and `indexes`, values are bound to their seal ID
/// alone: `Bound = ()`, `Record = ()`, and no declared blind indexes.
///
/// ```
/// #[derive(cryptbox::Seal)]
/// #[cryptbox(
///     id = "0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64",
///     value = String,
///     padding = block(16),
/// )]
/// pub struct HomeAddress;
/// ```
///
/// expands to exactly the manual impl:
///
/// ```
/// # pub struct HomeAddress;
/// const _: () = {
///     #[automatically_derived]
///     impl ::cryptbox::Seal for HomeAddress {
///         const ID: ::cryptbox::SealId =
///             ::cryptbox::SealId::from_u128(0x0b6f3c2a_8e41_4d57_a9c3_5e1f2d7b8a64);
///         const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::block(16);
///         type Value = String;
///         type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
///         type Bound = ();
///         type Record = ();
///         type Indexes = ();
///     }
/// };
/// ```
///
/// A seal bound to a tenant and a record, with a blind index:
///
/// ```
/// # use cryptbox::BlindIndexError;
/// # use zeroize::Zeroizing;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
/// #     Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
/// # }
/// #[derive(cryptbox::Seal)]
/// #[cryptbox(
///     id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
///     value = String,
///     bound(cryptbox::TenantId),
///     record = i64,
///     indexes(EmailLookup),
/// )]
/// pub struct CustomerEmail;
///
/// #[derive(cryptbox::BlindIndexSpec)]
/// #[cryptbox(
///     id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
///     seal = CustomerEmail,
///     bits = 32,
///     query = str,
///     normalize = normalize_email,
///     normalizer = "email/1",
/// )]
/// pub struct EmailLookup;
/// ```
///
/// expands to exactly the manual impl:
///
/// ```
/// # pub struct CustomerEmail;
/// # pub struct EmailLookup;
/// # impl cryptbox::BlindIndexSpec for EmailLookup {
/// #     type Seal = CustomerEmail;
/// #     type Partition = (cryptbox::TenantId,);
/// #     const ID: cryptbox::IndexId = cryptbox::index_id!("2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53");
/// #     const BITS: u16 = 32;
/// #     const NORMALIZER: &'static str = "email/1";
/// #     type Query = str;
/// #     fn normalize_query(query: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, cryptbox::BlindIndexError> {
/// #         Ok(zeroize::Zeroizing::new(query.as_bytes().to_vec()))
/// #     }
/// #     fn normalize_value(value: &String) -> Result<zeroize::Zeroizing<Vec<u8>>, cryptbox::BlindIndexError> {
/// #         Self::normalize_query(value)
/// #     }
/// # }
/// const _: () = {
///     #[automatically_derived]
///     impl ::cryptbox::Seal for CustomerEmail {
///         const ID: ::cryptbox::SealId =
///             ::cryptbox::SealId::from_u128(0x6c3b1f0e_8a24_4d5b_9e71_2f4a6c8d0b13);
///         const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
///         type Value = String;
///         type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
///         type Bound = (cryptbox::TenantId,);
///         type Record = i64;
///         type Indexes = (EmailLookup,);
///     }
/// };
/// ```
///
/// A seal that is its own value, such as a whole response sealed as JSON:
///
/// ```
/// #[derive(serde::Serialize, serde::Deserialize, cryptbox::Seal)]
/// #[cryptbox(id = "5d2f8a61-3c4e-4b7a-9e10-6f8b2c4d1a93", codec = cryptbox::Json)]
/// pub struct ProfileResponse {
///     pub name: String,
///     pub email: String,
/// }
/// ```
///
/// sets `type Value = Self;` and `type Codec = cryptbox::Json;`, with the other
/// items as for a marker.
///
/// A transparent seal stores its single field:
///
/// ```
/// #[derive(cryptbox::Seal)]
/// #[cryptbox(id = "7a1c3e5f-9b2d-4f60-8a4c-1e3b5d7f9a2c", transparent)]
/// pub struct UserEmail(String);
/// ```
///
/// It is its own codec, since no crate-provided adapter can wrap or unwrap it
/// without `From` or `Deref`. The derive expands to exactly the manual impls,
/// with `Result`, `Vec`, and `Zeroizing` spelled as absolute paths in the real
/// expansion:
///
/// ```
/// # use zeroize::Zeroizing;
/// # pub struct UserEmail(String);
/// const _: () = {
///     #[automatically_derived]
///     impl ::cryptbox::Seal for UserEmail {
///         const ID: ::cryptbox::SealId =
///             ::cryptbox::SealId::from_u128(0x7a1c3e5f_9b2d_4f60_8a4c_1e3b5d7f9a2c);
///         const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
///         type Value = Self;
///         type Codec = Self;
///         type Bound = ();
///         type Record = ();
///         type Indexes = ();
///     }
///
///     #[automatically_derived]
///     impl ::cryptbox::Codec<Self> for UserEmail {
///         const ID: &'static str =
///             <<String as ::cryptbox::__private::DefaultCodec>::Codec as ::cryptbox::Codec<String>>::ID;
///
///         fn encode(value: &Self) -> Result<Zeroizing<Vec<u8>>, ::cryptbox::CodecError> {
///             <<String as ::cryptbox::__private::DefaultCodec>::Codec as ::cryptbox::Codec<String>>::encode(
///                 &value.0,
///             )
///         }
///
///         fn decode(bytes: &[u8]) -> Result<Self, ::cryptbox::CodecError> {
///             <<String as ::cryptbox::__private::DefaultCodec>::Codec as ::cryptbox::Codec<String>>::decode(
///                 bytes,
///             )
///             .map(Self)
///         }
///     }
/// };
/// ```
#[proc_macro_derive(Seal, attributes(cryptbox))]
pub fn derive_seal(input: TokenStream) -> TokenStream {
    derive(input, seal::expand)
}

/// Derives `cryptbox::BlindIndexSpec` for a blind-index marker type.
///
/// | `#[cryptbox(…)]` key | Required | Meaning |
/// | --- | --- | --- |
/// | `id = "…"` | yes | The index ID, a hyphenated UUID string literal. |
/// | `seal = Type` | yes | The seal whose values the index projects. |
/// | `partition(Type, …)` | no | The bound ID types that partition the index, which a query supplies: some of the seal's bound types. Defaults to all of them. |
/// | `bits = N` | yes | The retained index bits, from 1 to 256. |
/// | `query = Type` | yes | The lookup input, such as `str`. |
/// | `normalize = path` | yes | A `fn(&Query) -> Result<Zeroizing<Vec<u8>>, BlindIndexError>`. |
/// | `project = path` | no | A `fn(&Value) -> P` where `&P` coerces to `&Query`. |
/// | `normalizer = "…"` | yes | The name of the normalization rules, such as `"email/1"`; see `BlindIndexSpec::NORMALIZER`. |
///
/// One normalizer serves both lookups and stored values. Without `project`, it
/// receives the sealed value directly, so `&Value` must coerce to `&Query`,
/// as `&String` does to `&str`. With `project`, it receives the projection,
/// such as one part of a larger value; prefer projections that borrow, because
/// an owned projection is a plaintext copy the normalizer cannot erase. Write
/// the impl by hand when a projection can fail or needs its own normalization.
///
/// The `normalizer` name is never derived from the paths: renaming a function
/// leaves stored indexes intact, while changing its body does not rename it.
///
/// ```
/// use cryptbox::BlindIndexError;
/// use zeroize::Zeroizing;
///
/// #[derive(cryptbox::Seal)]
/// #[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
/// struct UserEmail;
///
/// fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
///     Ok(Zeroizing::new(email.trim().to_ascii_lowercase().into_bytes()))
/// }
///
/// #[derive(cryptbox::BlindIndexSpec)]
/// #[cryptbox(
///     id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
///     seal = UserEmail,
///     bits = 32,
///     query = str,
///     normalize = normalize_email,
///     normalizer = "email/1",
/// )]
/// struct EmailLookup;
/// ```
///
/// expands to exactly the manual impl. The real expansion spells `Result`, `Vec`,
/// and `zeroize::Zeroizing` as absolute paths, the last through `cryptbox`, and
/// without `partition` names the seal's bound list as `<UserEmail as
/// Seal>::Bound`, here `()`:
///
/// ```
/// # use cryptbox::BlindIndexError;
/// # use zeroize::Zeroizing;
/// # #[derive(cryptbox::Seal)]
/// # #[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
/// # struct UserEmail;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
/// #     Ok(Zeroizing::new(email.trim().to_ascii_lowercase().into_bytes()))
/// # }
/// # struct EmailLookup;
/// const _: () = {
///     #[automatically_derived]
///     impl ::cryptbox::BlindIndexSpec for EmailLookup {
///         type Seal = UserEmail;
///         type Partition = ();
///         const ID: ::cryptbox::IndexId =
///             ::cryptbox::IndexId::from_u128(0x2e4c7b1a_5d3f_4a86_9b20_7f1e6c8d4a53);
///         const BITS: u16 = 32;
///         const NORMALIZER: &'static str = "email/1";
///         type Query = str;
///
///         fn normalize_query(
///             query: &str,
///         ) -> Result<Zeroizing<Vec<u8>>, ::cryptbox::BlindIndexError> {
///             normalize_email(query)
///         }
///
///         fn normalize_value(
///             value: &<UserEmail as ::cryptbox::Seal>::Value,
///         ) -> Result<Zeroizing<Vec<u8>>, ::cryptbox::BlindIndexError> {
///             normalize_email(value)
///         }
///     }
/// };
/// ```
///
/// With `project = street`, where `fn street(address: &Address) -> &str`,
/// `normalize_value` calls `normalize_email(&street(value))` instead.
#[proc_macro_derive(BlindIndexSpec, attributes(cryptbox))]
pub fn derive_blind_index_spec(input: TokenStream) -> TokenStream {
    derive(input, blind_index::expand)
}

/// Derives `cryptbox::BoundId` and `cryptbox::PartType` for a newtype over one
/// ID, such as an org ID, which seals bind their values to.
///
/// | `#[cryptbox(…)]` key | Required | Meaning |
/// | --- | --- | --- |
/// | `kind = "<uuid>"` | yes | The kind of value, `BoundId::KIND_ID`: a fresh UUID, persistent schema. |
/// | `crate = "path"` | no | The path to `cryptbox`. |
///
/// The field's type is any `PartType`, such as `[u8; 16]`, `uuid::Uuid` with
/// `cryptbox`'s `uuid` feature, `i64`, or `Vec<u8>`; the newtype binds as it.
///
/// ```
/// #[derive(cryptbox::BoundId)]
/// #[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
/// struct OrgId([u8; 16]);
/// ```
///
/// expands to:
///
/// ```
/// # struct OrgId([u8; 16]);
/// impl cryptbox::PartType for OrgId {
///     const KIND: cryptbox::PartKind = <[u8; 16] as cryptbox::PartType>::KIND;
///
///     fn part_value(&self) -> cryptbox::PartValue<'_> {
///         <[u8; 16] as cryptbox::PartType>::part_value(&self.0)
///     }
///
///     fn from_part_value(value: cryptbox::PartValue<'_>) -> Result<Self, cryptbox::Error> {
///         <[u8; 16] as cryptbox::PartType>::from_part_value(value).map(Self)
///     }
/// }
///
/// impl cryptbox::BoundId for OrgId {
///     const KIND_ID: cryptbox::PartId =
///         cryptbox::PartId::from_u128(0x59881c28_3003_4047_847f_d7cc73b140e5);
/// }
/// ```
#[proc_macro_derive(BoundId, attributes(cryptbox))]
pub fn derive_bound_id(input: TokenStream) -> TokenStream {
    derive(input, bound_id::expand)
}

/// Derives `cryptbox::Record` for a row struct, and generates its stored form,
/// the seals its fields declare, and a handle for each blind index.
///
/// Every field has exactly one role, in `#[cryptbox(…)]`; a field without one
/// fails the build, so nothing is stored as it is by accident:
///
/// | Field role | Meaning |
/// | --- | --- |
/// | `record_id` | The record ID, exactly one field. Every sealed field is bound to it. |
/// | `bound` | A bound value, such as an org: a `BoundId` type, up to four fields. Every sealed field is bound to all of them. |
/// | `seal = "<uuid>"` | Encrypted, under the field's own seal with this seal ID. |
/// | `plaintext` | Stored as it is. |
///
/// A sealed field also takes `codec = Type`, `padding = …`, as for
/// `#[derive(Seal)]`, and `name = Name` to name its seal instead of the
/// record's name and the field's, such as `CustomerEmail`. An `Option<T>`
/// field seals `T` when it is present. Each
/// `blind_index(…)` on a sealed field declares a blind index it writes:
///
/// | `blind_index(…)` key | Required | Meaning |
/// | --- | --- | --- |
/// | `id = "…"` | yes | The index ID. |
/// | `bits = N` | yes | The retained index bits, from 1 to 256. |
/// | `normalize = path`, `normalizer = "…"` | yes | As for `#[derive(BlindIndexSpec)]`. |
/// | `query = Type`, `project = path` | no | As for `#[derive(BlindIndexSpec)]`; `query` defaults to `str`. |
/// | `across(field, …)` | no | The bound fields the index spans. It is partitioned by the others. |
/// | `column = name` | no | The stored form's index column. Defaults to the field's name and `_index`. |
///
/// On the record, `#[cryptbox(stored(…))]` names the stored form, with
/// `name = Name` (by default `Stored` and the record's name, such as
/// `StoredCustomer`), and forwards every other attribute to it, such as
/// `stored(derive(sqlx::FromRow), sqlx(rename_all = "snake_case"))`. On a
/// field, `stored(…)` forwards attributes to the stored form's field.
/// `crate = "path"` names the path to `cryptbox`.
///
/// The stored form has the record's fields in order, each sealed field as its
/// `Sealed<Seal>`, and each blind index in a `BlindIndex<Spec>` column after its
/// field. `Record::seal` clones the record ID, bound, and plaintext fields, so
/// they implement `Clone`.
///
/// ```
/// # use cryptbox::BlindIndexError;
/// # use zeroize::Zeroizing;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
/// #     Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
/// # }
/// #[derive(Clone, cryptbox::BoundId)]
/// #[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
/// pub struct OrgId([u8; 16]);
///
/// #[derive(cryptbox::Record)]
/// pub struct Customer {
///     #[cryptbox(record_id)]
///     pub id: i64,
///     #[cryptbox(bound)]
///     pub org: OrgId,
///     #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
///     #[cryptbox(blind_index(
///         id = "ab78afa9-7aaa-499c-8239-037b7e136130",
///         bits = 32,
///         normalize = normalize_email,
///         normalizer = "email/1",
///     ))]
///     pub email: String,
///     #[cryptbox(plaintext)]
///     pub created_at: i64,
/// }
/// ```
///
/// expands to exactly this hand-written code. The real expansion spells
/// `Result`, `Option`, `Clone`, `Sized`, and the codec as absolute paths, wraps
/// each impl in `const _: () = { … };`, forwards docs, and checks, at compile
/// time, that each bound field is a `BoundId` and the record ID a `PartType`:
///
/// ```
/// # use cryptbox::{
/// #     BlindIndex, BlindIndexError, BlindIndexSpec, EncryptionKeys, Error, Index, IndexId,
/// #     Padding, PartType, Record, RecordKeys, Seal, SealId, Sealed, Utf8,
/// # };
/// # use zeroize::Zeroizing;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
/// #     Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
/// # }
/// # #[derive(Clone, cryptbox::BoundId)]
/// # #[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
/// # pub struct OrgId([u8; 16]);
/// # pub struct Customer {
/// #     pub id: i64,
/// #     pub org: OrgId,
/// #     pub email: String,
/// #     pub created_at: i64,
/// # }
/// /// The seal of `Customer::email`, which `#[derive(Record)]` declares.
/// pub struct CustomerEmail;
///
/// impl Seal for CustomerEmail {
///     const ID: SealId = SealId::from_u128(0x2cef6a47_3e20_42dc_a319_56022cb4cf30);
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Bound = (OrgId,);
///     type Record = i64;
///     type Indexes = (CustomerEmailIndex,);
/// }
///
/// /// The `email_index` blind index of `Customer::email`.
/// pub struct CustomerEmailIndex;
///
/// impl BlindIndexSpec for CustomerEmailIndex {
///     type Seal = CustomerEmail;
///     type Partition = (OrgId,);
///     const ID: IndexId = IndexId::from_u128(0xab78afa9_7aaa_499c_8239_037b7e136130);
///     const BITS: u16 = 32;
///     const NORMALIZER: &'static str = "email/1";
///     type Query = str;
///
///     fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
///         normalize_email(query)
///     }
///
///     fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
///         normalize_email(value)
///     }
/// }
///
/// /// The stored form of [`Customer`].
/// pub struct StoredCustomer {
///     pub id: i64,
///     pub org: OrgId,
///     pub email: Sealed<CustomerEmail>,
///     /// The `email_index` blind index of `email`.
///     pub email_index: BlindIndex<CustomerEmailIndex>,
///     pub created_at: i64,
/// }
///
/// impl Record for Customer {
///     type Stored = StoredCustomer;
///
///     const SEALS: &'static [SealId] = &[<CustomerEmail as Seal>::ID];
///     const RECORD_ID: &'static str = "id";
///     const BOUND: &'static [&'static str] = &["org"];
///     const PLAINTEXT: &'static [&'static str] = &["created_at"];
///
///     fn seal<K>(&self, keys: &K) -> Result<StoredCustomer, Error>
///     where
///         K: RecordKeys + ?Sized,
///     {
///         let email = Sealed::<CustomerEmail>::seal(&self.email, (&self.org, &self.id), keys)?;
///         let email_index = CustomerEmailIndex::derive_with(
///             &self.email,
///             &self.org,
///             keys.record_blind_index_keyring()?,
///         )?;
///
///         Ok(StoredCustomer {
///             id: Clone::clone(&self.id),
///             org: Clone::clone(&self.org),
///             email,
///             email_index,
///             created_at: Clone::clone(&self.created_at),
///         })
///     }
///
///     fn open<K>(stored: StoredCustomer, keys: &K) -> Result<Self, Error>
///     where
///         K: EncryptionKeys + ?Sized,
///     {
///         let email = stored.email.open((&stored.org, &stored.id), keys)?;
///
///         Ok(Self {
///             id: stored.id,
///             org: stored.org,
///             email,
///             created_at: stored.created_at,
///         })
///     }
/// }
///
/// impl Customer {
///     /// The `email_index` blind index of `email`, searched within its partition.
///     pub const EMAIL_INDEX: Index<Customer, CustomerEmailIndex, OrgId> = Index::__new(
///         |partition| Vec::from([PartType::part_value(partition)]),
///         |row: &StoredCustomer, partition| {
///             PartType::part_value(&row.org) == PartType::part_value(partition)
///         },
///         |record: &Customer| -> Option<&String> { Some(&record.email) },
///     );
/// }
/// ```
///
/// An index partitioned by two or more bound values takes a generated struct
/// with a field per bound value, named after the spec and `Partition`, such as
/// `CustomerNoteIndexPartition`; one that spans every bound value takes `()`.
#[proc_macro_derive(Record, attributes(cryptbox))]
pub fn derive_record(input: TokenStream) -> TokenStream {
    derive(input, record::expand)
}

fn derive(
    input: TokenStream,
    expand: fn(&DeriveInput) -> syn::Result<proc_macro2::TokenStream>,
) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
