//! Strongly typed application-layer encryption for Rust values.
//!
//! [`Sealed<F>`] is a value of field `F` sealed for storage: encrypted and bound
//! to the field, the values of its declared [`Binding`] (such as a tenant), and
//! optionally a record. [`Sealed::open`] authenticates it under the same
//! binding and returns the plaintext value. Use `CryptBox` when an application
//! owns encryption policy and key management but wants storage adapters to
//! enforce ciphertext-at-rest.
//!
//! **Experimental; not production-ready.** See the [threat model] for assumptions,
//! limitations, and outstanding review work.
//!
//! # Type model
//!
//! - [`Sealed<F>`] contains stored encrypted bytes. Parsing checks structure;
//!   opening authenticates. Sealing borrows the source value.
//! - [`Field`] is a marker type for one logical encrypted field. It declares the
//!   field ID, value type, codec, [`Padding`], [`Binding`], whether values bind a
//!   record, and its blind indexes. Several fields can share one value type.
//! - [`Args<F>`](Args) are the binding values of one call: `()` for a
//!   [`FieldOnly`] field, or the field's binding, with a [`RecordId`] when the
//!   field binds a record.
//! - [`Plain<F>`] and [`Secret<T>`] contain plaintext. `Plain` is the automatic
//!   `SQLx` column, for [`FieldOnly`] fields without a record or blind indexes.
//! - [`Plaintext`] names a value type's default codec: [`Utf8`] for `String`
//!   and [`Raw`] for `Vec<u8>`, and the same for their [`Secret`] wrappers.
//! - [`EncryptionKeyring`] and [`BlindIndexKeyring`] hold a current key plus
//!   previous keys; [`Keys`] pairs them. Operations take keys directly through
//!   [`EncryptionKeySource`] and [`BlindIndexKeySource`]; choosing which
//!   keyring protects which field or scope is application code.
//! - [`Prepared`] borrows a source value and derives sealed value and indexes for
//!   an application-owned atomic write; it does not persist them.
//! - A [`BlindIndexSpec`] binds a blind index to one field. A [`BlindIndex`] is a
//!   candidate selector: use every [`BlindIndexSpec::probes_with`]
//!   result, open candidates, and compare normalized plaintext.
//!
#![doc = "<div>"]
#![doc = include_str!("../docs/diagrams/lifecycle.svg")]
#![doc = "</div>"]
//!
//! See the [ownership reference] for clones, temporary buffers,
//! `Secret`, and shared key lifetimes, and the [custom-field example] for public
//! codec, normalizer, and key source implementations.
//!
#![doc = concat!(
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md\n",
    "[custom-field example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_field/README.md",
)]
//!
//! Every operation takes its binding arguments and keys explicitly, and never
//! reads the global. For [`FieldOnly`] fields without a record,
//! [`Sealed::seal_global`] and [`Sealed::open_global`] read the keys installed
//! with [`keys::install`] and fail with [`Error::KeysNotInstalled`] before
//! installation. The automatic `SQLx` column `Plain<F, K>` reads its keys from
//! `K`, the installed keys ([`GlobalKeys`]) by default. [`Padding`] is a closed
//! set of const policies.
//!
//! The [documentation index] links integration and operational guides.
//!
//! # Quick start
//!
//! **Ephemeral keys, in-memory demonstration only.** The [first-field tutorial]
//! supplies a complete fresh-project manifest and execution instructions.
//!
#![doc = include_str!("../docs/snippets/first-field.md")]
//!
//! The field names UTF-8 encoding and no padding, and binds values to its field
//! ID alone ([`FieldOnly`]), so its binding arguments are `()`. `Sealed` contains
//! the encrypted envelope; `open` returns the plaintext value. `&keys` supplies
//! the keyring explicitly: no global installation is needed. Before durable
//! storage, settle the persistent schema below and load
//! stable key material and generation IDs across restarts; see the
//! [first-field tutorial]'s durable-key next step.
//!
#![doc = concat!(
    "[first-field tutorial]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/first-field.md",
)]
//!
// Markdown uses the first definition: qualify the shared page's relative links for rustdoc.
#![doc = concat!(
    "\n[stored-value walkthrough]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/stored_values/README.md\n",
    "[live-backend check instructions]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/documentation.md#live-postgresql\n",
    "[task index]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/README.md\n\n",
    include_str!("../docs/features.md"),
)]
//!
//! # Persistent schema
//!
//! Codec compatibility, field/index IDs, normalization, and index precision
//! are persistent schema. Stored bytes do not describe them; changing them
//! requires a migration plan. Padding is not schema: the envelope records it
//! (except in format 1, which is read with the current policy).
//! Guard them in CI with [`testing::assert_encoding`] fixtures, a
//! [`schema::Manifest`] snapshot, and [`assert_unique_ids!`]; see [schema rules].
//!
#![doc = concat!(
    "[schema rules]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/integration.md#persistent-schema",
)]
//!
//! # Workflows
//!
//! See the [documentation index] for runnable examples, `SQLx` integration, key
//! lifecycle, maintenance, and migration.
//!
#![doc = concat!(
    "[documentation index]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/README.md\n",
    "[threat model]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/security.md",
)]
//!
//! # Security boundaries
//!
//! Encryption protects selected stored values while keys remain separate. The
//! binding rejects substitution across fields and binding values, and across
//! records for a field that binds one. It does not prevent replay of an older
//! value of the same record. Sizes and access patterns remain visible; blind
//! indexes additionally leak equality/frequency. Verify every candidate against
//! decrypted plaintext. A compromised application can expose keys and
//! plaintext. See the [threat model].
//!
//! Load root keys from a cryptographically secure secret source. Encryption and
//! blind-index root keys must be generated independently, and a generation ID
//! must never be reused with different key material.
//!
//! `CryptBox` zeroizes key material and temporary plaintext buffers it owns,
//! including superseded allocations when serialization buffers grow. It cannot
//! promise to erase arbitrary application values or operating-system copies of
//! configuration.

#![forbid(unsafe_code)]

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

#[cfg(doctest)]
#[doc = include_str!("../docs/first-field.md")]
pub struct FirstFieldDoctests;

mod binding;
mod blind;
mod codec;
mod crypto;
mod error;
mod field;
mod id;
mod key;
pub mod keys;
#[cfg(feature = "migrate")]
pub mod migrate;
mod padding;
mod prepare;
pub mod schema;
#[cfg(feature = "serde")]
mod serde_impl;
#[cfg(feature = "sqlx-postgres")]
mod sqlx_postgres;
#[cfg(feature = "sqlx-sqlite")]
mod sqlx_sqlite;
pub mod testing;
mod value;

pub(crate) use binding::BindingDomain;
pub use binding::{
    Args, Binding, FieldOnly, KeyScope, PartKind, PartRole, PartSpec, PartType, PartValue,
    PartValues, RecordId, ShapeFingerprint, Tenant, TenantId,
};
pub use blind::{
    BlindIndex, BlindIndexInfo, BlindIndexRef, BlindIndexSpec, IndexList, inspect_blind_index,
};
#[cfg(feature = "json")]
pub use codec::Json;
#[cfg(feature = "postcard")]
pub use codec::Postcard;
pub use codec::{Codec, Plaintext, Raw, Utf8};
#[cfg(feature = "derive")]
pub use cryptbox_derive::{Binding, BlindIndexSpec, Field, Plaintext};
pub use crypto::{
    CiphertextInfo, EXPERIMENTAL_XCHACHA20_POLY1305, decrypt, encrypt, inspect_ciphertext,
    is_ciphertext, needs_reencryption, reencrypt,
};
pub use error::{BlindIndexError, CodecError, CodecErrorKind, Error};
pub use field::Field;
pub use id::{FieldId, IndexId, IndexKeyId, InvalidIdentifier, KeyId, PartId, SuiteId};
pub use key::{
    BlindIndexKey, BlindIndexKeySource, BlindIndexKeyring, EncryptionKey, EncryptionKeySource,
    EncryptionKeyring, GlobalKeys, KeyContext, Keys,
};
pub use padding::Padding;
pub use prepare::Prepared;
pub use value::{Plain, Sealed, Secret};

// Paths that derive-generated code names; not public API.
#[doc(hidden)]
pub mod __private {
    pub use zeroize::Zeroizing;

    pub use crate::schema::has_duplicate;
}
