//! Strongly typed application-layer encryption for Rust values.
//!
//! [`Sealed<F>`] is a value sealed with seal `F`: encrypted and bound to the
//! seal, and, in a [`Context`] such as a [`Record`]'s field, to the record it is
//! stored in. [`Sealed::open`] authenticates it and returns the plaintext value.
//!
//! The stored format is stable: later releases read what this one writes. The
//! API may still change before 1.0, and the library has not been independently
//! audited. See the [threat model] for assumptions and limitations. The
//! [guide] covers integration, and [operations] covers key rotation, sweeps,
//! migration, and shredding.
//!
#![doc = concat!(
    "[threat model]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/security.md\n",
    "[guide]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/guide.md\n",
    "[operations]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/operations.md",
)]
//!
//! # Quick start
//!
//! ```rust
//! use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Seal, SealId, Sealed, Utf8};
//!
//! struct UserEmail;
//!
//! impl Seal for UserEmail {
//!     const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
//!     const PADDING: Padding = Padding::NONE;
//!     type Value = String;
//!     type Codec = Utf8;
//! }
//!
//! fn main() -> Result<(), cryptbox::Error> {
//!     // Demo only: this key is lost when the process exits.
//!     let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
//!     let sealed = Sealed::<UserEmail>::seal(&"mark@example.com".to_owned(), &keys)?;
//!     assert_eq!(sealed.open(&keys)?, "mark@example.com");
//!     Ok(())
//! }
//! ```
//!
//! With the `derive` feature, `#[derive(Seal)]` writes the impl, and
//! `#[derive(Record)]` seals the fields of a whole row; see the [README].
//!
//! Before durable storage, settle the persistent schema below and load stable
//! key material and generation IDs across restarts.
//!
//! When tenants must be kept apart, give each its own keyring, so another
//! tenant's keys cannot open its values and one tenant's data can be shredded on
//! its own. Sealing with the wrong keyring succeeds silently, while opening with
//! it fails loudly; see the [tenant example].
//!
#![doc = concat!(
    "[README]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/README.md\n",
    "[tenant example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/tenant_field.rs",
)]
//!
//! # Type model
//!
//! - [`Sealed<F>`] contains stored encrypted bytes. Parsing checks structure;
//!   opening authenticates. Sealing borrows the source value.
//! - [`Seal`] declares how values are sealed: its seal ID, value type, codec,
//!   and [`Padding`]. A seal is a marker over a value type that several seals
//!   can share, or its own value, such as a whole response.
//! - [`Secret<T>`] contains plaintext, redacted from `Debug`; read it with
//!   [`Secret::expose_secret`].
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
//!   candidate selector: use every [`BlindIndex::probes`]
//!   result, open candidates, and compare normalized plaintext.
//! - [`envelope`] holds the byte-level inspection API, for tools and
//!   migrations that look at stored bytes without a seal.
//!
//! Every operation takes its keys explicitly, and never reads a global. Only
//! the automatic `SQLx` column, `Plain<F>` (with an `sqlx-*` feature), reads
//! the keys installed with `keys::install`, because a column decoder receives
//! no keys.
//!
// Markdown uses the first definition: qualify the shared page's relative links for rustdoc.
#![doc = concat!(
    "\n[stored-value walkthrough]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/stored_values/README.md\n\n",
    include_str!("../docs/features.md"),
)]
//!
//! # Persistent schema
//!
//! Codec compatibility, seal and index IDs, a record ID's type, normalization,
//! and index precision are persistent schema. Stored bytes do not describe them,
//! beyond a diagnostic fingerprint of the kind of context a value is sealed under; changing them requires a
//! migration plan. Padding is not schema: the envelope records it.
//! Guard them in CI with [`testing::assert_encoding`] fixtures, a
//! [`schema::Manifest`] snapshot, and [`assert_unique_ids!`].
//!
//! # Security boundaries
//!
//! Encryption protects selected stored values while keys remain separate. The
//! seal context rejects substitution across seals, and across records for a
//! record's fields; keys separate tenants. It does not prevent replay of an older
//! value of the same record. Sizes and access patterns remain visible; blind
//! indexes additionally leak equality/frequency. Verify every candidate against
//! decrypted plaintext. A compromised application can expose keys and
//! plaintext.
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

mod blind;
mod bound;
mod codec;
mod crypto;
pub mod envelope;
mod error;
mod id;
mod key;
mod key_source;
#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
pub mod keys;
#[cfg(feature = "migrate")]
pub mod migrate;
mod padding;
mod prepare;
mod record;
pub mod schema;
mod seal;
mod seal_context;
mod secret;
#[cfg(feature = "serde")]
mod serde_impl;
#[cfg(feature = "sqlx-postgres")]
mod sqlx_postgres;
#[cfg(feature = "sqlx-sqlite")]
mod sqlx_sqlite;
pub mod testing;
mod value;

pub use blind::{BlindIndex, BlindIndexRef, BlindIndexSpec, IndexId};
#[cfg(feature = "json")]
pub use codec::Json;
pub use codec::{Codec, Raw, Utf8};
#[cfg(feature = "derive")]
pub use cryptbox_derive::{BlindIndexSpec, Record, Seal};
pub use error::{BlindIndexError, CodecError, CodecErrorKind, Error};
pub use id::InvalidIdentifier;
pub use key::{
    BlindIndexKey, BlindIndexKeyring, EncryptionKey, EncryptionKeyring, IndexKeyId, KeyError,
    KeyId, Keys,
};
pub use key_source::{BlindIndexKeys, EncryptionKeys, RecordKeys};
pub use padding::Padding;
pub use prepare::Prepared;
pub use record::{Index, Record};
pub use seal::{Seal, SealId};
pub use seal_context::{Context, ContextKind, InRecord};
pub use secret::Secret;
#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
pub use value::Plain;
pub use value::Sealed;

// Paths that derive-generated code names; not public API.
#[doc(hidden)]
pub mod __private {
    pub use uuid;
    pub use zeroize::Zeroizing;

    pub use crate::blind::valid_normalizer;
    pub use crate::codec::DefaultCodec;
    pub use crate::id::{is_nil, non_nil};
    pub use crate::schema::has_duplicate;
    pub use crate::seal_context::{RecordKey, RecordKind, RecordValue};
}
