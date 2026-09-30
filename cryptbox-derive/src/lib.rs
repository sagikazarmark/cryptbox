//! Derive macros for [`cryptbox`](https://docs.rs/cryptbox).
//!
//! Enable them with `cryptbox`'s `derive` feature and use them through
//! `cryptbox`; do not depend on this crate directly. Each derive expands to
//! exactly the trait impls you would write by hand, inside `const _: () = { … };`
//! with absolute `::cryptbox::` paths. It adds no `Debug`, `Deref`, `From`, or
//! hidden items, so the manual impl stays a first-class alternative. The
//! generated items are `Record`'s sealed struct, the seals its fields declare,
//! per-field sealers, and compile-time index checks.
//!
//! `Seal`, `BlindIndexSpec`, and `BoundId` take `#[cryptbox(…)]`. `Record`
//! takes `#[record(…)]`, with `#[record_id]`, `#[seal…]`, and
//! `#[blind_index(…)]` on its fields. Every derive accepts `crate = "path"` in
//! its struct-level attribute, for code that reaches `cryptbox` under another
//! path.

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

/// Derives `cryptbox::Record` for a row struct, and generates its sealed struct
/// and the seals its fields declare.
///
/// | `#[record(…)]` key | Required | Meaning |
/// | --- | --- | --- |
/// | `sealed = Name` | no | The name of the generated sealed struct. Defaults to `Sealed` and the record's name, such as `SealedCustomer`. |
/// | `attr(…)` | no | Attributes for the sealed struct, such as `attr(derive(sqlx::FromRow))`. |
///
/// On the fields:
///
/// | Field attribute | Meaning |
/// | --- | --- |
/// | `#[record_id]` | The field that holds the record ID, exactly one. It is never encrypted. |
/// | `#[seal(id = "…", …)]` | Declares the field's own seal, with this seal ID. |
/// | `#[seal(F)]` | Sealed with the existing seal `F` instead. |
/// | `#[seal]` | Sealed as its own type, which must be a seal, such as a transparent one. |
/// | `#[blind_index(S as column, …)]` | With a seal: the blind indexes it writes, each in a `BlindIndex<S>` field named `column`. |
///
/// A field without `#[seal…]` is stored as it is. The schema manifest lists
/// such fields by name (`Manifest::record`), so a field that should have been
/// sealed shows up in a snapshot review. A field's own seal takes:
///
/// | `#[seal(…)]` key | Meaning |
/// | --- | --- |
/// | `id = "…"` | The seal ID. Required. |
/// | `bound(Type, …)` | The bound ID types. Defaults to none. |
/// | `codec = Type`, `padding = …` | The codec and padding, as for `#[derive(Seal)]`. |
/// | `name = Name` | Names the seal `Name` instead of the record's name and the field's, such as `CustomerEmail`. |
///
/// A field's own seal is a generated unit struct with the field's visibility,
/// the least at which the sealed struct can name it. Its value type is the
/// field's type, its blind indexes those the field writes, its bound ID types
/// those declared, and its record the record ID's type: every value is
/// bound to its field, its bound values, and its row, so a value moved to another
/// field, table, or row fails to open. Blind indexes over it name it with
/// `#[blind_index(seal = CustomerEmail, …)]`.
///
/// An existing seal binds the record only if it declares a record ID of the
/// record's kind. One seal on two fields fails the build, since
/// their values could be swapped within a row. The
/// seals of all sealed fields must share one bound list, the record's `Bound`,
/// and a field must write
/// exactly the blind indexes its seal declares in `indexes(…)`: a missing,
/// extra, or repeated one fails the build, so no field can be sealed without
/// writing its indexes.
///
/// The sealed struct copies the struct's visibility, and each field's
/// visibility and `#[doc]` and `#[sqlx(…)]` attributes; its index columns follow
/// the field they index. Struct-level `#[sqlx(…)]` attributes are forwarded too,
/// so the sealed struct can derive `sqlx::FromRow`. They are copied as written: one
/// that describes the plaintext type, such as `try_from`, does not fit a
/// `Sealed<F>` field. `Record::seal` clones the plaintext fields, so they must
/// implement `Clone`.
///
/// For each sealed field, the derive also generates `seal_<field>`, which seals
/// one new value with its blind indexes for a partial update of that column.
/// `Record::seal` calls it for every sealed field.
///
/// ```
/// # use cryptbox::BlindIndexError;
/// # use zeroize::Zeroizing;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
/// #     Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
/// # }
/// #[derive(Clone, cryptbox::Record)]
/// pub struct Customer {
///     #[record_id]
///     pub id: i64,
///     #[seal(
///         id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
///         bound(cryptbox::TenantId),
///     )]
///     #[blind_index(EmailLookup as email_lookup)]
///     pub email: String,
///     #[seal(id = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38", bound(cryptbox::TenantId))]
///     pub note: String,
///     pub created_at: i64,
/// }
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
/// expands to exactly this hand-written code. The real expansion spells
/// `Result`, `Clone`, `Sized`, and the codec as absolute paths, wraps each seal
/// impl in `const _: () = { … };`, forwards docs, and also asserts, at compile
/// time, that each field writes the blind indexes its seal declares:
///
/// ```
/// # use std::marker::PhantomData;
/// # use cryptbox::{
/// #     BlindIndex, BlindIndexSpec, BoundValues, EncryptionKeys, Error, Padding, PartValue,
/// #     Record, RecordKeys, Seal, SealId, Sealed, TenantId, Utf8,
/// #     __private::{InRecord, bound_values},
/// # };
/// # use zeroize::Zeroizing;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, cryptbox::BlindIndexError> {
/// #     Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
/// # }
/// # #[derive(cryptbox::BlindIndexSpec)]
/// # #[cryptbox(
/// #     id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
/// #     seal = CustomerEmail,
/// #     bits = 32,
/// #     query = str,
/// #     normalize = normalize_email,
/// #     normalizer = "email/1",
/// # )]
/// # pub struct EmailLookup;
/// # #[derive(Clone)]
/// # pub struct Customer {
/// #     pub id: i64,
/// #     pub email: String,
/// #     pub note: String,
/// #     pub created_at: i64,
/// # }
/// /// The seal of `Customer::email`, which `#[derive(Record)]` declares.
/// pub struct CustomerEmail;
///
/// impl Seal for CustomerEmail {
///     const ID: SealId = SealId::from_u128(0x6c3b1f0e_8a24_4d5b_9e71_2f4a6c8d0b13);
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Bound = (TenantId,);
///     type Record = i64;
///     type Indexes = (EmailLookup,);
/// }
///
/// /// The seal of `Customer::note`, which `#[derive(Record)]` declares.
/// pub struct CustomerNote;
///
/// impl Seal for CustomerNote {
///     const ID: SealId = SealId::from_u128(0x0d7e3a95_4b1c_4e62_8f0a_9c5b2d7e1f38);
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Bound = (TenantId,);
///     type Record = i64;
///     type Indexes = ();
/// }
///
/// /// The sealed form of [`Customer`], as it is stored.
/// pub struct SealedCustomer {
///     pub id: i64,
///     pub email: Sealed<CustomerEmail>,
///     /// The `EmailLookup` blind index of `email`.
///     pub email_lookup: BlindIndex<EmailLookup>,
///     pub note: Sealed<CustomerNote>,
///     pub created_at: i64,
/// }
///
/// const _: () = {
///     #[automatically_derived]
///     impl Customer {
///         /// Seals `email` alone under the bound values `binding` and the record ID
///         /// `record`, with the blind indexes it stores, for a partial update.
///         pub fn seal_email<K>(
///             value: &<CustomerEmail as Seal>::Value,
///             binding: &[PartValue<'_>],
///             record: &i64,
///             keys: &K,
///         ) -> Result<(Sealed<CustomerEmail>, BlindIndex<EmailLookup>), Error>
///         where
///             K: RecordKeys + ?Sized,
///         {
///             let prepared = Sealed::<CustomerEmail>::prepare(value, InRecord::<<Self as Record>::Bound, _>(PhantomData, binding, record), keys)?
///                 .with_index_with::<EmailLookup>(keys.record_blind_index_keyring()?)?;
///             let email_lookup = prepared.index::<EmailLookup>()?.to_blind_index();
///
///             Ok((prepared.into_sealed(), email_lookup))
///         }
///
///         /// Seals `note` alone under the bound values `binding` and the record ID
///         /// `record`, for a partial update.
///         pub fn seal_note<K>(
///             value: &<CustomerNote as Seal>::Value,
///             binding: &[PartValue<'_>],
///             record: &i64,
///             keys: &K,
///         ) -> Result<Sealed<CustomerNote>, Error>
///         where
///             K: EncryptionKeys + ?Sized,
///         {
///             Sealed::<CustomerNote>::seal(value, InRecord::<<Self as Record>::Bound, _>(PhantomData, binding, record), keys)
///         }
///     }
///
///     #[automatically_derived]
///     impl cryptbox::Record for Customer {
///         type Sealed = SealedCustomer;
///         type Bound = (TenantId,);
///
///         const SEALS: &'static [SealId] = &[<CustomerEmail as Seal>::ID, <CustomerNote as Seal>::ID];
///         const RECORD_ID: &'static str = "id";
///         const PLAINTEXT: &'static [&'static str] = &["created_at"];
///
///         fn seal<'cryptbox, K>(
///             &self,
///             binding: impl BoundValues<'cryptbox, Self::Bound>,
///             keys: &K,
///         ) -> Result<SealedCustomer, Error>
///         where
///             K: RecordKeys + ?Sized,
///         {
///             let binding = bound_values(binding);
///             let (email, email_lookup) = Self::seal_email(&self.email, &binding, &self.id, keys)?;
///             let note = Self::seal_note(&self.note, &binding, &self.id, keys)?;
///
///             Ok(SealedCustomer {
///                 id: Clone::clone(&self.id),
///                 email,
///                 email_lookup,
///                 note,
///                 created_at: Clone::clone(&self.created_at),
///             })
///         }
///
///         fn open<'cryptbox, K>(
///             sealed: SealedCustomer,
///             binding: impl BoundValues<'cryptbox, Self::Bound>,
///             keys: &K,
///         ) -> Result<Self, Error>
///         where
///             K: EncryptionKeys + ?Sized,
///         {
///             let binding = bound_values(binding);
///             let record_id = &sealed.id;
///             let email = sealed.email.open(
///                 InRecord::<<Self as Record>::Bound, _>(PhantomData, &binding, record_id),
///                 keys,
///             )?;
///             let note = sealed.note.open(
///                 InRecord::<<Self as Record>::Bound, _>(PhantomData, &binding, record_id),
///                 keys,
///             )?;
///
///             Ok(Self {
///                 id: sealed.id,
///                 email,
///                 note,
///                 created_at: sealed.created_at,
///             })
///         }
///     }
///
///     #[automatically_derived]
///     impl cryptbox::IndexedBy<EmailLookup> for Customer {
///         fn indexed_value(&self) -> &<<EmailLookup as BlindIndexSpec>::Seal as Seal>::Value {
///             &self.email
///         }
///     }
/// };
/// ```
///
/// The index check is `const _: () = assert!(writes_declared_indexes(<F::Indexes
/// as IndexList<F>>::IDS, &[S::ID, …]))` for each sealed field; a hand-written
/// impl upholds it by writing every declared index.
#[proc_macro_derive(Record, attributes(record, record_id, seal, blind_index, sqlx))]
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
