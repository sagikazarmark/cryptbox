//! Derive macros for [`cryptbox`](https://docs.rs/cryptbox).
//!
//! Enable them with `cryptbox`'s `derive` feature and use them through
//! `cryptbox`; do not depend on this crate directly. Each derive expands to
//! exactly the trait impls you would write by hand, inside `const _: () = { … };`
//! with absolute `::cryptbox::` paths. It adds no `Debug`, `Deref`, `From`, or
//! hidden items, so the manual impl stays a first-class alternative. The one
//! generated item is the struct you name with `Binding`'s `index_args`.
//!
//! All derives share one `#[cryptbox(...)]` attribute namespace. Every derive
//! accepts `crate = "path"` for code that reaches `cryptbox` under another path.

mod attr;
mod binding;
mod blind_index;
mod field;
mod plaintext;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

/// Derives `cryptbox::Field` for a field marker type.
///
/// | Key | Required | Meaning |
/// | --- | --- | --- |
/// | `id = "…"` | yes | The field ID, a hyphenated UUID string literal. |
/// | `value = Type` | yes | The value type stored in the field. |
/// | `codec = Type` | no | The codec. Defaults to `<Value as Plaintext>::Codec`. |
/// | `padding = …` | no | `none` (the default), `block(size)`, or `length(len)`. |
/// | `binding = Type` | no | The binding scope. Defaults to `FieldOnly`. |
/// | `record` | no | Also binds every value to a record ID (`RECORD = true`). |
/// | `indexes(Type, …)` | no | The field's blind indexes (`Indexes`). Defaults to none. |
///
/// The ID is validated when the macro expands and is never derived from the
/// type's name: generate a fresh UUID for every logical field. A codec is never
/// inferred from a type's shape. Without `codec`, a value type that does not
/// implement `Plaintext` reports that it has no default codec. Padding
/// parameters are validated when the macro expands.
///
/// Without `binding`, `record`, and `indexes`, values are bound to their field
/// ID alone: `Binding = FieldOnly`, no record, and no declared blind indexes.
///
/// ```
/// #[derive(cryptbox::Field)]
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
///     impl ::cryptbox::Field for HomeAddress {
///         const ID: ::cryptbox::FieldId =
///             ::cryptbox::FieldId::from_u128(0x0b6f3c2a_8e41_4d57_a9c3_5e1f2d7b8a64);
///         const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::block(16);
///         const RECORD: bool = false;
///         type Value = String;
///         type Codec = <String as ::cryptbox::Plaintext>::Codec;
///         type Binding = ::cryptbox::FieldOnly;
///         type Indexes = ();
///     }
/// };
/// ```
///
/// A field bound to a tenant and a record, with a blind index:
///
/// ```
/// # use cryptbox::BlindIndexError;
/// # use zeroize::Zeroizing;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
/// #     Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
/// # }
/// #[derive(cryptbox::Field)]
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
///     field = CustomerEmail,
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
/// #     type Field = CustomerEmail;
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
///     impl ::cryptbox::Field for CustomerEmail {
///         const ID: ::cryptbox::FieldId =
///             ::cryptbox::FieldId::from_u128(0x6c3b1f0e_8a24_4d5b_9e71_2f4a6c8d0b13);
///         const PADDING: ::cryptbox::Padding = ::cryptbox::Padding::NONE;
///         const RECORD: bool = true;
///         type Value = String;
///         type Codec = <String as ::cryptbox::Plaintext>::Codec;
///         type Binding = cryptbox::Tenant;
///         type Indexes = (EmailLookup,);
///     }
/// };
/// ```
#[proc_macro_derive(Field, attributes(cryptbox))]
pub fn derive_field(input: TokenStream) -> TokenStream {
    derive(input, field::expand)
}

/// Derives `cryptbox::BlindIndexSpec` for a blind-index marker type.
///
/// | Key | Required | Meaning |
/// | --- | --- | --- |
/// | `id = "…"` | yes | The index ID, a hyphenated UUID string literal. |
/// | `field = Type` | yes | The field whose values the index projects. |
/// | `bits = N` | yes | The retained index bits, from 1 to 256. |
/// | `query = Type` | yes | The lookup input, such as `str`. |
/// | `normalize = path` | yes | A `fn(&Query) -> Result<Zeroizing<Vec<u8>>, BlindIndexError>`. |
/// | `project = path` | no | A `fn(&Value) -> P` where `&P` coerces to `&Query`. |
/// | `normalizer = "…"` | yes | The name of the normalization rules, such as `"email/1"`; see `BlindIndexSpec::NORMALIZER`. |
///
/// One normalizer serves both lookups and stored values. Without `project`, it
/// receives the field's value directly, so `&Value` must coerce to `&Query`,
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
/// #[derive(cryptbox::Field)]
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
///     field = UserEmail,
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
/// # #[derive(cryptbox::Field)]
/// # #[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]
/// # struct UserEmail;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
/// #     Ok(Zeroizing::new(email.trim().to_ascii_lowercase().into_bytes()))
/// # }
/// # struct EmailLookup;
/// const _: () = {
///     #[automatically_derived]
///     impl ::cryptbox::BlindIndexSpec for EmailLookup {
///         type Field = UserEmail;
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
///             value: &<UserEmail as ::cryptbox::Field>::Value,
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

/// Derives `cryptbox::Plaintext`, naming a value type's default codec.
///
/// | Key | Required | Meaning |
/// | --- | --- | --- |
/// | `codec = Type` | no | The default codec. Only a single-field tuple struct may omit it. |
///
/// The mapping is persistent schema: never change it for a type with stored
/// data.
///
/// ```
/// #[derive(serde::Serialize, serde::Deserialize, cryptbox::Plaintext)]
/// #[cryptbox(codec = cryptbox::Json)]
/// struct Address {
///     street: String,
/// }
/// ```
///
/// expands to exactly the manual impl:
///
/// ```
/// # #[derive(serde::Serialize, serde::Deserialize)]
/// # struct Address {
/// #     street: String,
/// # }
/// const _: () = {
///     #[automatically_derived]
///     impl ::cryptbox::Plaintext for Address {
///         type Codec = cryptbox::Json;
///     }
/// };
/// ```
///
/// Without `codec`, a single-field tuple struct is transparent: it is its own
/// codec, stores exactly the bytes its inner value's default codec stores, and
/// shares that codec's `ID`.
///
/// ```
/// #[derive(cryptbox::Plaintext)]
/// struct Email(String);
/// ```
///
/// expands to exactly the manual impls, with `Result`, `Vec`, and `Zeroizing` spelled
/// as absolute paths in the real expansion:
///
/// ```
/// # use zeroize::Zeroizing;
/// # struct Email(String);
/// const _: () = {
///     #[automatically_derived]
///     impl ::cryptbox::Plaintext for Email {
///         type Codec = Self;
///     }
///
///     #[automatically_derived]
///     impl ::cryptbox::Codec<Self> for Email {
///         const ID: &'static str =
///             <<String as ::cryptbox::Plaintext>::Codec as ::cryptbox::Codec<String>>::ID;
///
///         fn encode(value: &Self) -> Result<Zeroizing<Vec<u8>>, ::cryptbox::CodecError> {
///             <<String as ::cryptbox::Plaintext>::Codec as ::cryptbox::Codec<String>>::encode(
///                 &value.0,
///             )
///         }
///
///         fn decode(bytes: &[u8]) -> Result<Self, ::cryptbox::CodecError> {
///             <<String as ::cryptbox::Plaintext>::Codec as ::cryptbox::Codec<String>>::decode(
///                 bytes,
///             )
///             .map(Self)
///         }
///     }
/// };
/// ```
#[proc_macro_derive(Plaintext, attributes(cryptbox))]
pub fn derive_plaintext(input: TokenStream) -> TokenStream {
    derive(input, plaintext::expand)
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
/// (`Vec<u8>`, `Box<[u8]>`, or `TenantId`); see `PartType`. A record is never a
/// part: declare `record` on the field.
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
/// expands to exactly the manual impl and the named struct. The real expansion
/// spells the derived traits as absolute paths:
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
/// };
/// ```
///
/// A field names the binding with `#[cryptbox(binding = OrgWorkspace)]`.
#[proc_macro_derive(Binding, attributes(cryptbox))]
pub fn derive_binding(input: TokenStream) -> TokenStream {
    derive(input, binding::expand)
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
