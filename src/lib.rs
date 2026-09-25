//! Strongly typed application-layer encryption for Rust values.
//!
//! [`Encrypted`] marks a plaintext application value that must be encrypted at
//! supported storage boundaries. It is not a ciphertext container: use
//! [`Encrypted::expose_secret`] deliberately whenever plaintext access is
//! required. Use `CryptBox` when an application owns encryption policy and key
//! management but wants storage adapters to enforce ciphertext-at-rest.
//!
//! **Reference for this crate's API.** Ciphertext format 1, blind-index format 1,
//! and suite ID 1 are independent of the crate release (0.5.0) and the historical
//! “v0.1 design”. The formats and suite are experimental and **not production-ready**.
//! Independent vectors, composition review, operational-policy acceptance, and
//! target review remain outstanding; passing tests does not complete these gates.
//! This checkout still declares 0.5.0 but includes unreleased stored-byte Serde
//! support. The Features reference distinguishes it from the published release.
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
//! Encryption and preparation retain the original plaintext. Decryption borrows
//! ciphertext and returns a new plaintext-bearing value. `Prepared` owns stored
//! representations while borrowing its source; the application persists those
//! representations atomically. Dropping preparation does not erase the source.
//! See the development [ownership explanation] for clones, temporary buffers,
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
//! The [development task index] links the canonical glossary, suitability,
//! integration, rotation, and security-review paths. It describes development
//! documentation, not the frozen release archive linked under Workflows.
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
//! A profile's codec, presence or absence of padding, binding policy, stable
//! field and index IDs, blind-index normalization, and retained precision are
//! persistent schema decisions. They are not all self-described by stored
//! bytes. Changing one requires an explicit migration for existing ciphertext
//! or indexes. Parameters of an already-padded policy may change without a
//! migration because padding removal is parameter-independent.
//!
//! # Workflows
//!
//! The docs.rs source links below are explicitly the **0.5.0 release archive**. They
//! predate later documentation improvements. For current navigation and adoption
//! guidance use the [development task index] and [development security review].
//!
//! Complete runnable programs demonstrate [key rotation], a [re-encryption
//! sweep], a [legacy migration], a [plaintext migration], [blind-index lookup],
//! and [in-memory SQLite storage]. The [maintenance sweep guide] and the
//! [legacy migration guide] cover the operational patterns, and the
//! [wire-format guide] records the experimental envelope and index formats.
//!
//! [key rotation]: https://docs.rs/crate/cryptbox/0.5.0/source/examples/key_rotation.rs
//! [re-encryption sweep]: https://docs.rs/crate/cryptbox/0.5.0/source/examples/reencryption_sweep.rs
//! [legacy migration]: https://docs.rs/crate/cryptbox/0.5.0/source/examples/legacy_migration.rs
//! [plaintext migration]: https://docs.rs/crate/cryptbox/0.5.0/source/examples/plaintext_migration.rs
//! [blind-index lookup]: https://docs.rs/crate/cryptbox/0.5.0/source/examples/blind_indexes.rs
//! [in-memory SQLite storage]: https://docs.rs/crate/cryptbox/0.5.0/source/examples/sqlx_sqlite.rs
//! [maintenance sweep guide]: https://docs.rs/crate/cryptbox/0.5.0/source/docs/reencryption-sweep.md
//! [legacy migration guide]: https://docs.rs/crate/cryptbox/0.5.0/source/docs/legacy-migration.md
//! [wire-format guide]: https://docs.rs/crate/cryptbox/0.5.0/source/docs/wire-format.md
//! [stored-value walkthrough]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/stored-values.md
//! [development task index]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/README.md
//! [development security review]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/security.md#security-review-path
//!
//! # Security boundaries
//!
//! Field binding makes ciphertext authentication fail across fields and
//! domain-separates blind-index derivation; it does not authenticate stored index
//! bytes or prevent same-field cross-row substitution. Blind indexes intentionally
//! leak equality and
//! frequency; every hit is a candidate that must be decrypted and compared,
//! regardless of padding. Unpadded profiles reveal the exact encoded plaintext
//! length. A padding policy coarsens that leakage to a size bucket or hides it
//! entirely up to a fixed length.
//!
//! Authenticated encryption does not prevent replay or rollback of an older
//! valid ciphertext. Retaining historical keys keeps old ciphertext readable,
//! so rotation is neither revocation nor crypto-shredding.
//!
//! `CryptBox` does not protect plaintext from a compromised application process
//! while keys are live, or hide database query and access patterns. Treat logs,
//! tracing data, crash dumps, swap, and other plaintext-bearing artifacts as
//! sensitive.
//! For unsuitable use cases and outstanding review gates, follow the
//! [development security review].
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
