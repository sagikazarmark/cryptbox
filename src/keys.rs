//! The process-wide keys behind the implicit forms.
//!
//! Every operation has an explicit form that takes keys and never reads the
//! global: [`Encrypted::encrypt_with`](crate::Encrypted::encrypt_with),
//! [`Ciphertext::decrypt_with`](crate::Ciphertext::decrypt_with),
//! [`Encrypted::prepare_with`](crate::Encrypted::prepare_with),
//! [`Prepared::with_index_with`](crate::Prepared::with_index_with), and
//! [`BlindIndexSpec::probes_with`](crate::BlindIndexSpec::probes_with).
//! Each implicit form (`encrypt()`, `decrypt()`, `prepare()`, `with_index()`,
//! `probes()`) is exactly its explicit form called with [`installed()`], and the
//! automatic `SQLx` column `Encrypted<F>` reads the same keys through
//! [`GlobalKeys`](crate::GlobalKeys).
//!
//! [`install`] sets the keys once, from the binary's entry point. It never
//! replaces installed keys, and nothing resets them. Before installation, the
//! implicit forms return [`Error::KeysNotInstalled`]; there is no default.
//!
//! ```
//! use cryptbox::{EncryptionKey, Keys, LocalEncryptionKeyring, keys};
//!
//! # fn main() -> Result<(), cryptbox::Error> {
//! // Load durable key material here; a generated key is for demonstration only.
//! let encryption = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
//! keys::install(Keys::new(encryption))?;
//! # Ok(())
//! # }
//! ```
//!
//! Tests should pass keys explicitly. A test that needs the global installs it
//! in its own test binary, which is its own process, and sequences every
//! assertion that depends on installation. See the [testing guide].
//!
//! # Forbidding the global
//!
//! Teams that want every call to name its keys can forbid the global with
//! Clippy's `disallowed_methods` in `clippy.toml`. Disallowing [`install`] is
//! enough to keep the global empty, so any remaining implicit call fails with
//! [`Error::KeysNotInstalled`]; disallowing the implicit forms reports those
//! calls at lint time instead:
//!
//! ```toml
#![doc = include_str!("../docs/snippets/clippy-no-global-keys.toml")]
//! ```
//!
//! With the `migrate` feature, also disallow
//! `cryptbox::migrate::MaybeEncrypted::decrypt` and
//! `cryptbox::migrate::MaybeEncrypted::decrypt_legacy`. Clippy warns about paths
//! that do not exist, so add them only when the feature is enabled.
//!
//! The automatic `SQLx` column defaults to [`GlobalKeys`](crate::GlobalKeys);
//! name another [`KeyContext`](crate::KeyContext) as its second type parameter,
//! `Encrypted<F, K>`, to use application-owned keys instead.
//!
#![doc = concat!(
    "[testing guide]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/testing.md",
)]

use std::sync::OnceLock;

use crate::{Error, Keys};

static INSTALLED: OnceLock<Keys> = OnceLock::new();

/// The error returned when keys are already installed.
///
/// Installed keys are never replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("keys are already installed")]
pub struct AlreadyInstalled;

/// Installs the process-wide keys for the remainder of the process.
///
/// Call this once from the binary's entry point, not from library code or test
/// setup.
///
/// # Errors
///
/// Returns [`AlreadyInstalled`] when keys are already installed. The installed
/// keys are kept and `keys` is dropped.
pub fn install(keys: Keys) -> Result<(), AlreadyInstalled> {
    INSTALLED.set(keys).map_err(|_| AlreadyInstalled)
}

/// Returns the process-wide keys.
///
/// # Errors
///
/// Returns [`Error::KeysNotInstalled`] before [`install`] succeeds.
pub fn installed() -> Result<&'static Keys, Error> {
    INSTALLED.get().ok_or(Error::KeysNotInstalled)
}
