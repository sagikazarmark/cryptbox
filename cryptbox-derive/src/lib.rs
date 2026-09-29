//! Derive macros for [`cryptbox`](https://docs.rs/cryptbox).
//!
//! Enable them with `cryptbox`'s `derive` feature and use them through
//! `cryptbox`; do not depend on this crate directly. Each derive expands to
//! exactly the trait impls you would write by hand, inside `const _: () = { … };`
//! with absolute `::cryptbox::` paths. It adds no `Debug`, `Deref`, `From`, or
//! hidden items, so the manual impl stays a first-class alternative. The
//! generated items are the struct you name with `Binding`'s `index_args`, and
//! `Record`'s sealed struct, per-field sealers, and compile-time index checks.
//!
//! All derives share one `#[cryptbox(...)]` attribute namespace. Every derive
//! accepts `crate = "path"` for code that reaches `cryptbox` under another path.

mod attr;
mod binding;
mod blind_index;
mod record;
mod seal;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

/// Derives `cryptbox::Seal`, for a marker or for a type that is its own value.
///
/// | Key | Required | Meaning |
/// | --- | --- | --- |
/// | `id = "…"` | yes | The seal ID, a hyphenated UUID string literal. |
/// | `value = Type` | on a unit struct | The value type a marker seals. A type with fields is its own value and rejects it. |
/// | `codec = Type` | on a type with fields, unless `transparent` | The codec. See below for its defaults. |
/// | `transparent` | no | Stores a type's single field alone. |
/// | `padding = …` | no | `none` (the default), `block(size)`, or `length(len)`. |
/// | `binding = Type` | no | The binding scope. Defaults to `FieldOnly`. |
/// | `record` | no | Also binds every value to a record ID (`RECORD = true`). |
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
/// Without `binding`, `record`, and `indexes`, values are bound to their seal
/// ID alone: `Binding = FieldOnly`, no record, and no declared blind indexes.
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
///         const RECORD: bool = false;
///         type Value = String;
///         type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
///         type Binding = ::cryptbox::FieldOnly;
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
///     binding = cryptbox::Tenant,
///     record,
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
///         const RECORD: bool = true;
///         type Value = String;
///         type Codec = <String as ::cryptbox::__private::DefaultCodec>::Codec;
///         type Binding = cryptbox::Tenant;
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
///         const RECORD: bool = false;
///         type Value = Self;
///         type Codec = Self;
///         type Binding = ::cryptbox::FieldOnly;
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
/// | Key | Required | Meaning |
/// | --- | --- | --- |
/// | `id = "…"` | yes | The index ID, a hyphenated UUID string literal. |
/// | `seal = Type` | yes | The seal whose values the index projects. |
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
/// and `zeroize::Zeroizing` as absolute paths, the last through `cryptbox`:
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

/// Derives `cryptbox::Binding` for an owned scope struct.
///
/// Each named field is one part, declared on the field:
///
/// | Field key | Required | Meaning |
/// | --- | --- | --- |
/// | `part = "…"` | yes | The part ID, a hyphenated UUID string literal. |
/// | `keys` | no | The part scopes key custody and blind indexes. |
/// | `index` | no | The part scopes blind indexes only. |
///
/// A part without `keys` or `index` is bound only. A part holds a `[u8; 16]`
/// UUID, a `uuid::Uuid` with `cryptbox`'s `uuid` feature, an `i64`, or bytes
/// (`Vec<u8>`, `Box<[u8]>`, or `TenantId`), or any other type that implements
/// `PartType`, such as an application's own ID newtype. A record is never a
/// part: declare `record` on the seal.
///
/// | Struct key | Required | Meaning |
/// | --- | --- | --- |
/// | `index_args = Name` | with bound-only and blind-index parts together | Generates `Name`, the index-arguments struct of the `keys` and `index` parts. |
///
/// Without `index_args`, the index arguments are the binding itself when every
/// part scopes blind indexes, and `()` when none does. The generated struct keeps
/// each field's name, type, visibility, and docs, and derives `Clone`, `Debug`,
/// `Hash`, `PartialEq`, and `Eq`.
///
/// Part IDs are validated when the macro expands: none is nil, and none repeats.
/// Declare the fields in any order; the derive sorts the parts by part ID. Every
/// part ID, kind, and role is persistent schema.
///
/// ```
/// #[derive(Clone, Hash, PartialEq, Eq, cryptbox::Binding)]
/// #[cryptbox(index_args = OrgSearch)]
/// pub struct OrgWorkspace {
///     /// Bound only.
///     #[cryptbox(part = "c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48")]
///     pub workspace: Vec<u8>,
///     /// The key scope and shred unit.
///     #[cryptbox(part = "3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90", keys)]
///     pub org: [u8; 16],
/// }
/// ```
///
/// expands to exactly the manual impls and the named struct. The real expansion
/// spells the derived traits as absolute paths. `FromIndexValues` builds the
/// index arguments back from their part values, for adapters that carry
/// index arguments as text:
///
/// ```
/// # #[derive(Clone, Hash, PartialEq, Eq)]
/// # pub struct OrgWorkspace {
/// #     pub workspace: Vec<u8>,
/// #     pub org: [u8; 16],
/// # }
/// /// The index arguments of [`OrgWorkspace`]: its `keys` and `index` parts.
/// #[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// pub struct OrgSearch {
///     /// The key scope and shred unit.
///     pub org: [u8; 16],
/// }
///
/// const _: () = {
///     #[automatically_derived]
///     impl ::cryptbox::Binding for OrgWorkspace {
///         // Sorted by part ID.
///         const PARTS: &'static [::cryptbox::PartSpec] = &[
///             ::cryptbox::PartSpec::keys(
///                 ::cryptbox::PartId::from_u128(0x3a1f0c6e_58b2_4d0a_9e57_1c4b8f2d6a90),
///                 <[u8; 16] as ::cryptbox::PartType>::KIND,
///             ),
///             ::cryptbox::PartSpec::bound(
///                 ::cryptbox::PartId::from_u128(0xc7d24e19_0b8a_4f63_a1d5_6e9f3b720c48),
///                 <Vec<u8> as ::cryptbox::PartType>::KIND,
///             ),
///         ];
///         type IndexArgs = OrgSearch;
///
///         fn values(&self) -> ::cryptbox::PartValues<'_> {
///             ::cryptbox::PartValues::from([
///                 <[u8; 16] as ::cryptbox::PartType>::part_value(&self.org),
///                 <Vec<u8> as ::cryptbox::PartType>::part_value(&self.workspace),
///             ])
///         }
///
///         fn index_values(args: &OrgSearch) -> ::cryptbox::PartValues<'_> {
///             ::cryptbox::PartValues::from([
///                 <[u8; 16] as ::cryptbox::PartType>::part_value(&args.org),
///             ])
///         }
///     }
///
///     #[automatically_derived]
///     impl ::cryptbox::FromIndexValues for OrgWorkspace {
///         fn from_index_values(
///             values: &[::cryptbox::PartValue<'_>],
///         ) -> Result<OrgSearch, ::cryptbox::Error> {
///             match values {
///                 [value0] => Ok(OrgSearch {
///                     org: <[u8; 16] as ::cryptbox::PartType>::from_part_value(*value0)?,
///                 }),
///                 _ => Err(::cryptbox::Error::InvalidBinding),
///             }
///         }
///     }
/// };
/// ```
///
/// A seal names the binding with `#[cryptbox(binding = OrgWorkspace)]`.
#[proc_macro_derive(Binding, attributes(cryptbox))]
pub fn derive_binding(input: TokenStream) -> TokenStream {
    derive(input, binding::expand)
}

/// Derives `cryptbox::Record` for a row struct, and generates its sealed struct.
///
/// | Struct key | Required | Meaning |
/// | --- | --- | --- |
/// | `record = field` | yes | The field that holds the record ID. It is never encrypted. |
/// | `sealed = Name` | yes | The name of the generated sealed struct. |
/// | `attr(…)` | no | Attributes for the sealed struct, such as `attr(derive(sqlx::FromRow))`. |
///
/// Every field says how it is stored:
///
/// | Field key | Meaning |
/// | --- | --- |
/// | `seal = F` | Sealed with seal `F`: the sealed struct holds a `Sealed<F>`. |
/// | `index(S as column, …)` | With `seal`: the blind indexes it writes, each in a `BlindIndex<S>` field named `column`. |
/// | `plaintext` | Stored as it is. The record ID must be `plaintext`. |
///
/// An unannotated field fails the build. The seals of all sealed fields must
/// share one `Binding`, and each field whose seal declares `record` is also
/// bound to the record ID, which any `PartType` can hold. A field must write
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
/// # #[derive(cryptbox::Seal)]
/// # #[cryptbox(
/// #     id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
/// #     value = String,
/// #     binding = cryptbox::Tenant,
/// #     record,
/// #     indexes(EmailLookup),
/// # )]
/// # pub struct CustomerEmail;
/// # #[derive(cryptbox::Seal)]
/// # #[cryptbox(id = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38", value = String, binding = cryptbox::Tenant)]
/// # pub struct CustomerNote;
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
/// #[derive(Clone, cryptbox::Record)]
/// #[cryptbox(record = id, sealed = SealedCustomer)]
/// pub struct Customer {
///     #[cryptbox(plaintext)]
///     pub id: i64,
///     #[cryptbox(seal = CustomerEmail, index(EmailLookup as email_lookup))]
///     pub email: String,
///     #[cryptbox(seal = CustomerNote)]
///     pub note: String,
/// }
/// ```
///
/// expands to exactly this hand-written struct and impls. The real expansion
/// spells `Result`, `Clone`, and `Sized` as absolute paths, forwards docs, and
/// also asserts, at compile time, that each field writes the blind indexes its
/// seal declares:
///
/// ```
/// # use cryptbox::{
/// #     BlindIndex, BlindIndexKeySource, BlindIndexSpec, EncryptionKeySource, Error, Seal,
/// #     InRecord, RecordId, Sealed,
/// # };
/// # use zeroize::Zeroizing;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, cryptbox::BlindIndexError> {
/// #     Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
/// # }
/// # #[derive(cryptbox::Seal)]
/// # #[cryptbox(
/// #     id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
/// #     value = String,
/// #     binding = cryptbox::Tenant,
/// #     record,
/// #     indexes(EmailLookup),
/// # )]
/// # pub struct CustomerEmail;
/// # #[derive(cryptbox::Seal)]
/// # #[cryptbox(id = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38", value = String, binding = cryptbox::Tenant)]
/// # pub struct CustomerNote;
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
/// # }
/// /// The sealed form of [`Customer`], as it is stored.
/// pub struct SealedCustomer {
///     pub id: i64,
///     pub email: Sealed<CustomerEmail>,
///     /// The `EmailLookup` blind index of `email`.
///     pub email_lookup: BlindIndex<EmailLookup>,
///     pub note: Sealed<CustomerNote>,
/// }
///
/// const _: () = {
///     #[automatically_derived]
///     impl Customer {
///         /// Seals `email` alone under `binding` and the record ID `record`, with the
///         /// blind indexes it stores, for a partial update.
///         pub fn seal_email<K>(
///             value: &<CustomerEmail as Seal>::Value,
///             binding: &<CustomerEmail as Seal>::Binding,
///             record: &i64,
///             keys: &K,
///         ) -> Result<(Sealed<CustomerEmail>, BlindIndex<EmailLookup>), Error>
///         where
///             K: EncryptionKeySource + BlindIndexKeySource + ?Sized,
///         {
///             let prepared = Sealed::<CustomerEmail>::prepare(
///                 value,
///                 InRecord(binding, RecordId::of(record)),
///                 keys,
///             )?
///             .with_index_with::<EmailLookup>(keys)?;
///             let email_lookup = prepared.index::<EmailLookup>()?.to_blind_index();
///
///             Ok((prepared.into_sealed(), email_lookup))
///         }
///
///         /// Seals `note` alone under `binding` and the record ID `record`, for a
///         /// partial update.
///         pub fn seal_note<K>(
///             value: &<CustomerNote as Seal>::Value,
///             binding: &<CustomerNote as Seal>::Binding,
///             record: &i64,
///             keys: &K,
///         ) -> Result<Sealed<CustomerNote>, Error>
///         where
///             K: EncryptionKeySource + ?Sized,
///         {
///             Sealed::<CustomerNote>::seal(value, InRecord(binding, RecordId::of(record)), keys)
///         }
///     }
///
///     #[automatically_derived]
///     impl cryptbox::Record for Customer {
///         type Sealed = SealedCustomer;
///         type Binding = <CustomerEmail as Seal>::Binding;
///
///         fn seal<K>(&self, binding: &Self::Binding, keys: &K) -> Result<SealedCustomer, Error>
///         where
///             K: EncryptionKeySource + BlindIndexKeySource + ?Sized,
///         {
///             let (email, email_lookup) = Self::seal_email(&self.email, binding, &self.id, keys)?;
///             let note = Self::seal_note(&self.note, binding, &self.id, keys)?;
///
///             Ok(SealedCustomer {
///                 id: Clone::clone(&self.id),
///                 email,
///                 email_lookup,
///                 note,
///             })
///         }
///
///         fn open<K>(sealed: SealedCustomer, binding: &Self::Binding, keys: &K) -> Result<Self, Error>
///         where
///             K: EncryptionKeySource + ?Sized,
///         {
///             let record_id = RecordId::of(&sealed.id);
///             let email = sealed.email.open(
///                 InRecord::<<CustomerEmail as Seal>::Binding>(binding, record_id),
///                 keys,
///             )?;
///             let note = sealed.note.open(
///                 InRecord::<<CustomerNote as Seal>::Binding>(binding, record_id),
///                 keys,
///             )?;
///
///             Ok(Self { id: sealed.id, email, note })
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
#[proc_macro_derive(Record, attributes(cryptbox, sqlx))]
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
