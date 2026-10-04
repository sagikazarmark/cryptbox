//! Derive macros for [`cryptbox`](https://docs.rs/cryptbox).
//!
//! Enable them with `cryptbox`'s `derive` feature and use them through
//! `cryptbox`; do not depend on this crate directly. Each derive expands to
//! exactly the trait impls you would write by hand, inside `const _: () = { … };`
//! with absolute `::cryptbox::` paths. It adds no `Debug`, `Deref`, or `From`
//! impls, so a manual `Seal` or `BlindIndexSpec` impl stays a first-class
//! alternative; only the derive implements `Record`. The generated items are
//! `Record`'s stored form, the seals and blind-index specs its fields declare,
//! its index handles, and compile-time checks.
//!
//! Every derive takes `#[cryptbox(…)]`, on the item and, for `Record`, on its
//! fields. Generated code names `::cryptbox`, so depend on it under that name.

mod attr;
mod blind_index;
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
/// Every value is bound to its seal ID, and a value sealed in a context, such as
/// a record's field, to the context's value too. A record declares the seals of
/// its fields itself: see `#[derive(Record)]`. Blind indexes name their seal:
/// see `#[derive(BlindIndexSpec)]`.
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
/// without `From` or `Deref`. Decoding builds the type from its field directly,
/// so a constructor that validates the field does not run: name a `codec` that
/// validates, or seal the field's type with a marker and convert it yourself.
/// The derive expands to exactly the manual impls, with `Result`, `Vec`, and
/// `Zeroizing` spelled as absolute paths in the real expansion:
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
/// | `bits = N` | yes | The retained index bits, from 1 to 256. |
/// | `query = Type` | yes | The lookup input, such as `str`. |
/// | `normalize = path` | yes | A `fn(&Query) -> Result<Zeroizing<Vec<u8>>, BlindIndexError>`. |
/// | `normalizer = "…"` | yes | The name of the normalization rules, such as `"email/1"`; see `BlindIndexSpec::NORMALIZER`. |
///
/// One normalizer serves both lookups and stored values. It receives the sealed
/// value directly, so `&Value` must coerce to `&Query`, as `&String` does to
/// `&str`. Write the impl by hand to index part of a value, such as an email's
/// domain, or to normalize stored values differently from queries.
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
#[proc_macro_derive(BlindIndexSpec, attributes(cryptbox))]
pub fn derive_blind_index_spec(input: TokenStream) -> TokenStream {
    derive(input, blind_index::expand)
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
/// | `seal = "<uuid>"` | Encrypted, under the field's own seal with this seal ID. |
/// | `plaintext` | Stored as it is, such as an org: authorize on it like any other column. |
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
/// | `query = Type` | no | As for `#[derive(BlindIndexSpec)]`; defaults to `str`. |
///
/// On the record, `#[cryptbox(stored(…))]` names the stored form, with
/// `name = Name` (by default `Stored` and the record's name, such as
/// `StoredCustomer`), and forwards every other attribute to it, such as
/// `stored(derive(sqlx::FromRow), sqlx(rename_all = "snake_case"))`. On a
/// field, `stored(…)` forwards attributes to the stored form's field.
///
/// The stored form has the record's fields in order, each sealed field as its
/// `Sealed<Seal, InRecord<Id>>`, sealed under the record ID of type `Id`, and
/// each blind index in a `BlindIndex<Spec>` column after its field, named after
/// the field with `_index`, such as `email_index`.
/// `Record::seal` clones the record ID and plaintext fields, so they implement
/// `Clone`.
///
/// ```
/// # use cryptbox::BlindIndexError;
/// # use zeroize::Zeroizing;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
/// #     Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
/// # }
/// #[derive(cryptbox::Record)]
/// pub struct Customer {
///     #[cryptbox(record_id)]
///     pub id: i64,
///     #[cryptbox(plaintext)]
///     pub org: i64,
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
/// expands to exactly this code. Only the derive implements `Record`: it also
/// implements a hidden marker trait that seals it. The real expansion spells
/// `Result`, `Option`, `Clone`, `Sized`, and the codec as absolute paths, wraps
/// each impl in `const _: () = { … };`, forwards docs, and checks, at compile
/// time, that the record ID is a UUID, an `i64`, or bytes. The seals it declares
/// know nothing of the record: the record seals and opens their values in its
/// context, `cryptbox::InRecord`, under its record ID:
///
/// ```
/// # use cryptbox::{
/// #     BlindIndex, BlindIndexError, BlindIndexSpec, EncryptionKeys, Error, InRecord, Index,
/// #     IndexId, Padding, Record, RecordKeys, Seal, SealId, Sealed, Utf8,
/// # };
/// # use zeroize::Zeroizing;
/// # fn normalize_email(email: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
/// #     Ok(Zeroizing::new(email.to_ascii_lowercase().into_bytes()))
/// # }
/// # pub struct Customer {
/// #     pub id: i64,
/// #     pub org: i64,
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
/// }
///
/// /// The `email_index` blind index of `Customer::email`.
/// pub struct CustomerEmailIndex;
///
/// impl BlindIndexSpec for CustomerEmailIndex {
///     type Seal = CustomerEmail;
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
///     pub org: i64,
///     pub email: Sealed<CustomerEmail, InRecord<i64>>,
///     /// The `email_index` blind index of `email`.
///     pub email_index: BlindIndex<CustomerEmailIndex>,
///     pub created_at: i64,
/// }
///
/// impl Record for Customer {
///     type Stored = StoredCustomer;
///     type Context = InRecord<i64>;
///
///     const SEALS: &'static [SealId] = &[<CustomerEmail as Seal>::ID];
///     const RECORD_ID: &'static str = "id";
///     const PLAINTEXT: &'static [&'static str] = &["org", "created_at"];
///
///     fn seal<K>(&self, keys: &K) -> Result<StoredCustomer, Error>
///     where
///         K: RecordKeys + ?Sized,
///     {
///         let email =
///             Sealed::<CustomerEmail, InRecord<i64>>::seal_in(&self.email, &self.id, keys)?;
///         let email_index =
///             BlindIndex::<CustomerEmailIndex>::derive(&self.email, keys.record_blind_index_keyring()?)?;
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
///         let email = Sealed::open_in(&stored.email, &stored.id, keys)?;
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
///     /// The `email_index` blind index of `email`.
///     pub const EMAIL_INDEX: Index<Customer, CustomerEmailIndex> =
///         Index::__new(|record: &Customer| -> Option<&String> { Some(&record.email) });
/// }
///
/// // Not public API: seals `Record` to the derive.
/// impl cryptbox::__private::DerivedRecord for Customer {}
/// ```
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
