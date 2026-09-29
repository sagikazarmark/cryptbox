//! Strongly typed application-layer encryption for Rust values.
//!
//! [`Sealed<F>`] is a value sealed with seal `F`: encrypted and bound
//! to the seal, the values of its declared [`Binding`] (such as a tenant), and
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
//! - [`Seal`] declares how values are sealed: its seal ID, value type, codec,
//!   [`Padding`], [`Binding`], whether values bind a record, and its blind
//!   indexes. A seal is a marker over a value type that several seals can share,
//!   or its own value, such as a whole response.
//! - [`Args<F>`](Args) are the binding values of one call: `()` for a
//!   [`FieldOnly`] seal, or the seal's binding, with a [`RecordId`] when the
//!   seal binds a record.
//! - [`Plain<F>`] and [`Secret<T>`] contain plaintext. `Plain` is the automatic
//!   `SQLx` column, for [`FieldOnly`] seals without a record or blind indexes.
//! - [`Plaintext`] names a value type's default codec: [`Utf8`] for `String`
//!   and [`Raw`] for `Vec<u8>`, and the same for their [`Secret`] wrappers.
//! - [`EncryptionKeyring`] and [`BlindIndexKeyring`] hold a current key plus
//!   previous keys; [`Keys`] pairs them. Operations take keys directly through
//!   [`EncryptionKeySource`] and [`BlindIndexKeySource`]; choosing which
//!   keyring protects which seal or scope is application code.
//! - [`Prepared`] borrows a source value and derives sealed value and indexes for
//!   an application-owned atomic write; it does not persist them.
//! - A [`Record`] seals and opens a whole row under one binding and its
//!   plaintext record ID, writing every blind index its seals declare;
//!   [`open_matching`] opens the candidate rows of a lookup and keeps the matches.
//! - A [`BlindIndexSpec`] binds a blind index to one seal. A [`BlindIndex`] is a
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
//! reads the global. For [`FieldOnly`] seals without a record,
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
//! ## One seal, one keyring
//!
//! **Ephemeral keys, in-memory demonstration only.** The [first-field tutorial]
//! supplies a complete fresh-project manifest and execution instructions.
//!
#![doc = include_str!("../docs/snippets/first-field.md")]
//!
//! The seal names UTF-8 encoding and no padding, and binds values to its seal
//! ID alone ([`FieldOnly`]), so its binding arguments are `()`. `Sealed` contains
//! the encrypted envelope; `open` returns the plaintext value. `&keys` supplies
//! the keyring explicitly: no global installation is needed. Before durable
//! storage, settle the persistent schema below and load
//! stable key material and generation IDs across restarts; see the
//! [first-field tutorial]'s durable-key next step.
//!
//! For a `FieldOnly` seal without a record or blind indexes, [`Plain<F, K>`](Plain)
//! is the automatic `SQLx` column: it seals on encode and opens on decode with the
//! keys of `K`, the keys [`keys::install`] made available by default, so ordinary
//! database conversion needs no explicit call. Everything bound is sealed
//! explicitly, because a column decoder sees neither the row nor its scope.
//!
//! ## Then bind values to a scope
//!
//! When values of different tenants must not be interchangeable, or their keys
//! must differ, the seal declares a [`Binding`] and every call passes its
//! values. Here one keyring serves each tenant, so one tenant's data can be
//! shredded on its own:
//!
#![doc = include_str!("../docs/snippets/tenant-field.md")]
//!
//! The seal declares `Binding = Tenant` and `RECORD = true`, so each call
//! passes `(&tenant, record)`; a missing or extra record fails the build. Bound
//! values come from an authorized source, such as the request's verified claims,
//! never from the stored row. The library passes the key source the seal and the
//! binding's [`KeyScope`], and choosing which keyring protects which scope is
//! application code: sealing with the wrong one succeeds silently, while opening
//! with it fails loudly. See the [binding guide], [choosing keyrings], and the
//! [shredding runbook].
//!
#![doc = concat!(
    "[first-field tutorial]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/first-field.md\n",
    "[binding guide]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/bindings.md\n",
    "[choosing keyrings]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/choosing-keyrings.md\n",
    "[shredding runbook]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/shredding.md",
)]
//!
// Markdown uses the first definition: qualify the shared page's relative links for rustdoc.
#![doc = concat!(
    "\n[stored-value walkthrough]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/stored_values/README.md\n",
    "[live-backend check instructions]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/documentation.md#live-postgresql\n",
    "[task index]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/README.md\n",
    "[Restate guide]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/restate.md\n\n",
    include_str!("../docs/features.md"),
)]
//!
//! # Persistent schema
//!
//! Codec compatibility, seal/index/part IDs, the binding declaration (part kinds and
//! roles, and whether the seal binds a record), normalization, and index
//! precision are persistent schema. Stored bytes do not describe them, beyond a
//! diagnostic fingerprint of the binding declaration; changing them requires a
//! migration plan. Padding is not schema: the envelope records it.
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
//! binding rejects substitution across seals and binding values, and across
//! records for a seal that binds one. It does not prevent replay of an older
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
mod bound;
mod codec;
mod crypto;
mod envelope;
mod error;
mod id;
mod key;
mod key_source;
pub mod keys;
#[cfg(feature = "migrate")]
pub mod migrate;
mod padding;
mod prepare;
mod record;
#[cfg(feature = "restate")]
pub mod restate;
pub mod schema;
mod seal;
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
    Args, Binding, FieldOnly, FromIndexValues, InRecord, KeyScope, PartKind, PartRole, PartSpec,
    PartType, PartValue, PartValues, RecordId, Tenant, TenantId,
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
pub use cryptbox_derive::{Binding, BlindIndexSpec, Plaintext, Record, Seal};
pub use envelope::{
    CiphertextInfo, EXPERIMENTAL_XCHACHA20_POLY1305, SuiteId, inspect_ciphertext, is_ciphertext,
};
pub use error::{BlindIndexError, CodecError, CodecErrorKind, Error};
pub use id::{IndexId, InvalidIdentifier, PartId, SealId};
pub use key::{
    BlindIndexKey, BlindIndexKeyring, EncryptionKey, EncryptionKeyring, IndexKeyId, KeyError,
    KeyId, Keys,
};
pub use key_source::{BlindIndexKeySource, ColumnKeys, EncryptionKeySource, GlobalKeys};
pub use padding::Padding;
pub use prepare::Prepared;
pub use record::{IndexedBy, Record, open_matching};
pub use seal::Seal;
pub use value::{Plain, Sealed, Secret};

// Paths that derive-generated code names; not public API.
#[doc(hidden)]
pub mod __private {
    pub use uuid;
    pub use zeroize::Zeroizing;

    pub use crate::schema::{has_duplicate, writes_declared_indexes};
}
