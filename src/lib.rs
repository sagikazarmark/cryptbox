//! Strongly typed application-layer encryption for Rust values.
//!
//! [`Encrypted`] marks a plaintext application value that must be encrypted at
//! supported storage boundaries. It is not a ciphertext container: use
//! [`Encrypted::expose_secret`] deliberately whenever plaintext access is
//! required. Use `CryptBox` when an application owns encryption policy and key
//! management but wants storage adapters to enforce ciphertext-at-rest.
//!
//! **Experimental; not production-ready.** See the [threat model] for assumptions,
//! limitations, and outstanding review work. This checkout includes unreleased
//! stored-byte Serde support; the Features reference distinguishes it from 0.5.0.
//!
//! # Type model
//!
//! - [`Encrypted<T, Profile>`] and [`Secret<T>`] contain plaintext.
//! - [`Ciphertext<T, Profile>`] contains stored encrypted bytes. Parsing checks
//!   structure; decryption authenticates. Encryption borrows and retains the source.
//! - [`EncryptionProfile`] chooses codec, padding, binding, and key context.
//! - [`Prepared`] borrows a source value and derives ciphertext/indexes for an
//!   application-owned atomic write; it does not persist them.
//! - A [`BlindIndex`] is a candidate selector. Use every [`blind_index_probes`]
//!   result, decrypt candidates, and compare normalized plaintext.
//!
#![doc = "<div>"]
#![doc = include_str!("../docs/diagrams/lifecycle.svg")]
#![doc = "</div>"]
//!
//! See the [ownership explanation] for clones, temporary buffers,
//! `Secret`, and shared key lifetimes, and the [custom-profile recipe] for public
//! codec, normalizer, and synchronous provider implementations.
//!
//! [ownership explanation]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/concepts.md#plaintext-and-key-ownership
//! [custom-profile recipe]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/custom-profile.md
//!
//! [`Binding`] is sealed to [`Unbound`] and [`FieldBound`], both with unit context
//! `()`. Thus `&()` is not an opt-out from field binding and does not supply keys.
//! Row/tenant binding is future work. [`KeyContext`] selects providers for
//! context-less operations; explicit-provider methods take keys separately.
//! [`Padding`] is also sealed to built-in policies.
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
//! The macro selects UTF-8 encoding, field binding, no padding, and the default
//! key context. `Encrypted` contains plaintext; `Ciphertext` contains the encrypted
//! envelope. `&()` supplies no runtime binding data, while `&keys` supplies the
//! provider explicitly: no global installation is needed. Before durable storage,
//! settle the persistent schema below and load stable key material and generation
//! IDs across restarts; see the [first-field tutorial]'s durable-key next step.
//!
//! [first-field tutorial]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/first-field.md
//!
#![doc = include_str!("../docs/features.md")]
//!
//! # Persistent schema
//!
//! Codec compatibility, padding mode, binding, field/index IDs, normalization,
//! and index precision are persistent schema. Stored bytes do not describe all
//! of them; changing them requires a migration plan. See [schema rules].
//!
//! [schema rules]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/concepts.md#persistent-schema
//!
//! # Workflows
//!
//! See the [documentation index] for runnable examples, SQLx integration, key
//! lifecycle, maintenance, and migration. Repository links describe development;
//! select your dependency version on docs.rs for released API documentation.
//!
//! [documentation index]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/README.md
//! [threat model]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/security.md
//!
//! # Security boundaries
//!
//! Encryption protects selected stored values while keys remain separate. Field
//! binding rejects cross-field substitution, but does not bind rows or prevent
//! replay. Sizes and access patterns remain visible; blind indexes additionally
//! leak equality/frequency. Verify every candidate against decrypted plaintext.
//! A compromised application can expose keys and plaintext. See the [threat model].
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

mod binding;
mod blind;
mod codec;
mod crypto;
mod error;
mod id;
mod key;
#[cfg(feature = "migrate")]
pub mod migrate;
mod padding;
mod prepare;
mod profile;
#[cfg(feature = "serde")]
mod serde_impl;
#[cfg(feature = "sqlx-postgres")]
mod sqlx_postgres;
#[cfg(feature = "sqlx-sqlite")]
mod sqlx_sqlite;
mod value;

#[doc(hidden)]
pub use binding::BindingDomain;
pub use binding::{Binding, Field, FieldBound, Unbound};
pub use blind::{
    BlindIndex, BlindIndexInfo, BlindIndexMetadata, BlindIndexRef, BlindIndexSpec,
    blind_index_probes, derive_blind_index, inspect_blind_index, verify_blind_index_candidate,
};
#[cfg(feature = "json")]
pub use codec::Json;
#[cfg(feature = "postcard")]
pub use codec::Postcard;
pub use codec::{Codec, Raw, Utf8};
pub use crypto::{
    CiphertextInfo, EXPERIMENTAL_XCHACHA20_POLY1305, decrypt, encrypt, inspect_ciphertext,
    is_ciphertext, needs_reencryption, reencrypt,
};
pub use error::{BlindIndexError, CodecError, CodecErrorKind, Error, KeyProviderError};
pub use id::{FieldId, IndexId, IndexKeyId, InvalidIdentifier, KeyId, SuiteId};
pub use key::{
    BlindIndexKey, BlindIndexKeyProvider, EncryptionKey, EncryptionKeyProvider, GlobalKeyContext,
    GlobalProviders, KeyContext, LocalBlindIndexKeyring, LocalEncryptionKeyring,
};
pub use padding::{NoPadding, PadToBlock, PadToLength, Padding};
pub use prepare::Prepared;
pub use profile::EncryptionProfile;
pub use value::{Ciphertext, Encrypted, ProfileContext, Secret};
