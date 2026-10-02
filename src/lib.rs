//! Strongly typed application-layer encryption for Rust values.
//!
//! [`Sealed<F>`] is a value sealed with seal `F`: encrypted and bound to the
//! seal, and, for a field of a [`Record`], to the record it is stored in.
//! [`Sealed::open`] authenticates it and returns the plaintext value. Use `CryptBox` when an application
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
//!   [`Padding`], and its blind indexes. A seal is a marker over a value type
//!   that several seals can share, or its own value, such as a whole response.
//! - [`Plain<F>`] and [`Secret<T>`] contain plaintext. `Plain` is the automatic
//!   `SQLx` column, for seals without blind indexes.
//! - A [`Codec`] encodes a seal's values. Only `String` and `Vec<u8>` and their
//!   [`Secret`] wrappers have a default ([`Utf8`] and [`Raw`]); every other value
//!   type names its codec.
//! - [`EncryptionKeyring`] and [`BlindIndexKeyring`] hold a current key plus
//!   previous keys; [`Keys`] pairs them. Operations take the keys to use
//!   ([`EncryptionKeys`], [`BlindIndexKeys`], [`RecordKeys`]); choosing which
//!   keyring protects which values is application code.
//! - [`Prepared`] borrows a source value and derives sealed value and indexes for
//!   an application-owned atomic write; it does not persist them.
//! - A [`Record`] is a row whose sealed fields are bound to its record ID; it
//!   seals and opens the whole row, and its [`Index`] handles derive probes and
//!   open the candidate rows of a lookup.
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
//! codec and normalizer implementations, with keys the application refreshes.
//!
#![doc = concat!(
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md\n",
    "[custom-field example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_field/README.md",
)]
//!
//! Every operation takes its keys explicitly, and never reads the global.
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
//! ID. `Sealed` contains
//! the encrypted envelope; `open` returns the plaintext value. `&keys` supplies
//! the keyring explicitly: no global installation is needed. Before durable
//! storage, settle the persistent schema below and load
//! stable key material and generation IDs across restarts; see the
//! [first-field tutorial]'s durable-key next step.
//!
//! For a seal without blind indexes, [`Plain<F, K>`](Plain)
//! is the automatic `SQLx` column: it seals on encode and opens on decode with the
//! keys of `K`, the keys [`keys::install`] made available by default, so ordinary
//! database conversion needs no explicit call. A record's fields are sealed by
//! the record, because a column decoder does not see the row.
//!
//! ## Then keep tenants apart with a keyring per tenant
//!
//! When tenants must be kept apart, each has its own keyring, so another
//! tenant's keys cannot open its values and one tenant's data can be shredded
//! on its own:
//!
#![doc = include_str!("../docs/snippets/tenant-field.md")]
//!
//! Each call takes the tenant's keyring: choosing which
//! keyring protects which values is application code: sealing with the wrong one succeeds silently, while opening
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
    "[task index]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/README.md\n\n",
    include_str!("../docs/features.md"),
)]
//!
//! # Persistent schema
//!
//! Codec compatibility, seal and index IDs, the binding declaration (whether a
//! record field's seal binds the record ID, and its kind), normalization, and index
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
//! binding rejects substitution across seals, and across records for a
//! record's fields; keys separate tenants. It does not prevent replay of an older
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
pub mod schema;
mod seal;
mod secret;
#[cfg(feature = "serde")]
mod serde_impl;
#[cfg(feature = "sqlx-postgres")]
mod sqlx_postgres;
#[cfg(feature = "sqlx-sqlite")]
mod sqlx_sqlite;
pub mod testing;
mod value;

pub(crate) use binding::BindingDomain;
pub use blind::{
    BlindIndex, BlindIndexInfo, BlindIndexRef, BlindIndexSpec, IndexId, IndexList,
    inspect_blind_index,
};
#[cfg(feature = "json")]
pub use codec::Json;
#[cfg(feature = "postcard")]
pub use codec::Postcard;
pub use codec::{Codec, Raw, Utf8};
#[cfg(feature = "derive")]
pub use cryptbox_derive::{BlindIndexSpec, Record, Seal};
pub use envelope::{
    CiphertextInfo, EXPERIMENTAL_XCHACHA20_POLY1305, SuiteId, inspect_ciphertext, is_ciphertext,
};
pub use error::{BlindIndexError, CodecError, CodecErrorKind, Error};
pub use id::InvalidIdentifier;
pub use key::{
    BlindIndexKey, BlindIndexKeyring, EncryptionKey, EncryptionKeyring, IndexKeyId, KeyError,
    KeyId, Keys,
};
pub use key_source::{BlindIndexKeys, ColumnKeys, EncryptionKeys, GlobalKeys, RecordKeys};
pub use padding::Padding;
pub use prepare::Prepared;
pub use record::{Index, Record};
pub use seal::{Seal, SealId};
pub use secret::Secret;
pub use value::{Plain, Sealed};

// Paths that derive-generated code names; not public API.
#[doc(hidden)]
pub mod __private {
    pub use uuid;
    pub use zeroize::Zeroizing;

    pub use crate::binding::{RecordKey, RecordKind};
    pub use crate::codec::DefaultCodec;
    pub use crate::record::{open_in_record, seal_in_record};
    pub use crate::schema::{has_duplicate, writes_declared_indexes};
}
