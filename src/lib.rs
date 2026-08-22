//! Strongly typed application-layer encryption for Rust values.
//!
//! [`Encrypted`] marks a plaintext application value that must be encrypted at
//! supported storage boundaries. It is not a ciphertext container: use
//! [`Encrypted::expose_secret`] deliberately whenever plaintext access is
//! required. Use `CryptBox` when an application owns encryption policy and key
//! management but wants storage adapters to enforce ciphertext-at-rest.
//!
//! The v0.1 wire formats and built-in XChaCha20-Poly1305 suite are experimental
//! and must not be treated as stable until the published test vectors and
//! cryptographic review are complete.
//!
//! # Quick start
//!
//! ```
//! use cryptbox::{
//!     Encrypted, EncryptionKey, EncryptionProfile, Field, FieldBound,
//!     GlobalKeyContext, LocalEncryptionKeyring, Utf8, field_id, key_id,
//! };
//!
//! struct UserEmail;
//! impl Field for UserEmail {
//!     const ID: cryptbox::FieldId =
//!         field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
//!     const NAME: &'static str = "user-email";
//! }
//! impl EncryptionProfile<String> for UserEmail {
//!     type Codec = Utf8;
//!     type Binding = FieldBound<Self>;
//!     type Keys = GlobalKeyContext;
//! }
//!
//! // Fixed key material is for this doctest only; load production keys securely.
//! let keys = LocalEncryptionKeyring::new(
//!     EncryptionKey::new(
//!         key_id!("b7f69f1d-4476-4dc3-9576-528f95691d50"),
//!         [0x42; 32],
//!     ),
//!     [],
//! )?;
//! let email = Encrypted::<_, UserEmail>::new("mark@example.com".to_owned());
//! let ciphertext = email.encrypt_with(&(), &keys)?;
//! assert_eq!(
//!     ciphertext.decrypt_with(&(), &keys)?.expose_secret(),
//!     "mark@example.com",
//! );
//! # Ok::<(), cryptbox::Error>(())
//! ```
//!
//! # Features
//!
//! No features are enabled by default, and all features are additive:
//!
//! - `json` adds the `Json` codec. Its serialized representation is part of
//!   the persistent schema.
//! - `migrate` adds the explicit `migrate` module for adopting `CryptBox` over
//!   plaintext or data encrypted by a previous solution: permissive reads, a
//!   legacy recovery handler, and a resumable sweep. Intended for a bounded
//!   migration window only; the default decoding path stays strict.
//! - `postcard` adds the `Postcard` codec. Its serialized representation is
//!   part of the persistent schema.
//! - `sqlx-postgres` adds `SQLx` 0.8 `BYTEA` storage for `PostgreSQL`.
//! - `sqlx-sqlite` adds `SQLx` 0.8 `BLOB` storage for `SQLite`.
//!
//! The `SQLx` adapters automatically encrypt and decrypt [`Encrypted`] only for
//! unit-context profiles, using [`EncryptionProfile::Keys`]. [`Ciphertext`] and
//! blind-index storage work with explicit-context profiles. These features do
//! not choose an async runtime or TLS implementation for the application.
//! `CryptBox` deliberately provides no blanket Serde implementation for
//! [`Encrypted`], because plaintext and ciphertext serialization must remain
//! explicit.
//!
//! This is a standard-library crate requiring Rust 1.85 or newer. Encryption
//! requires a target on which `getrandom` can obtain operating-system entropy.
//! The portable `RustCrypto` backends assume constant-time integer multiplication;
//! targets where multiplication is variable-time, including certain 32-bit
//! PowerPC CPUs and some non-ARM microcontrollers, are not supported for secret
//! operations. The complete production target review is not yet finished.
//!
//! # Persistent schema
//!
//! A profile's codec, binding policy, stable field and index IDs, blind-index
//! normalization, and retained precision are persistent schema decisions. They
//! are not all self-described by stored bytes. Changing one requires an
//! explicit migration for existing ciphertext or indexes.
//!
//! # Workflows
//!
//! Complete runnable programs demonstrate [key rotation], a [re-encryption
//! sweep], a [legacy migration], a [plaintext migration], [blind-index lookup],
//! and [in-memory SQLite storage]. The [maintenance sweep guide] and the
//! [legacy migration guide] cover the operational patterns, and the
//! [wire-format guide] records the experimental envelope and index formats.
//!
//! [key rotation]: https://docs.rs/crate/cryptbox/latest/source/examples/key_rotation.rs
//! [re-encryption sweep]: https://docs.rs/crate/cryptbox/latest/source/examples/reencryption_sweep.rs
//! [legacy migration]: https://docs.rs/crate/cryptbox/latest/source/examples/legacy_migration.rs
//! [plaintext migration]: https://docs.rs/crate/cryptbox/latest/source/examples/plaintext_migration.rs
//! [blind-index lookup]: https://docs.rs/crate/cryptbox/latest/source/examples/blind_indexes.rs
//! [in-memory SQLite storage]: https://docs.rs/crate/cryptbox/latest/source/examples/sqlx_sqlite.rs
//! [maintenance sweep guide]: https://docs.rs/crate/cryptbox/latest/source/docs/reencryption-sweep.md
//! [legacy migration guide]: https://docs.rs/crate/cryptbox/latest/source/docs/legacy-migration.md
//! [wire-format guide]: https://docs.rs/crate/cryptbox/latest/source/docs/wire-format.md
//!
//! # Security boundaries
//!
//! Field binding prevents cross-field substitution, but not same-field
//! cross-row substitution. Blind indexes intentionally leak equality and
//! frequency; every hit is a candidate that must be decrypted and compared.
//! Ciphertext also reveals the encoded plaintext length plus fixed envelope
//! overhead.
//!
//! Authenticated encryption does not prevent replay or rollback of an older
//! valid ciphertext. Retaining historical keys keeps old ciphertext readable,
//! so rotation is neither revocation nor crypto-shredding.
//!
//! `CryptBox` does not protect plaintext from a compromised application process
//! while keys are live, or hide database query and access patterns. Treat logs,
//! tracing data, crash dumps, swap, and other plaintext-bearing artifacts as
//! sensitive.
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
mod prepare;
mod profile;
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
pub use prepare::Prepared;
pub use profile::EncryptionProfile;
pub use value::{Ciphertext, Encrypted, ProfileContext, Secret};
