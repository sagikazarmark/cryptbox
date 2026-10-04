//! The process-wide keys behind the automatic `SQLx` column.
//!
//! Every operation takes its keys explicitly and never reads the global:
//! [`Sealed::seal`](crate::Sealed::seal), [`Sealed::open`](crate::Sealed::open),
//! [`BlindIndex::derive`](crate::BlindIndex::derive), and
//! [`BlindIndex::probes`](crate::BlindIndex::probes). Only the automatic `SQLx`
//! column, [`Plain<F>`](crate::Plain), reads the installed keys, because
//! `SQLx` encoding and decoding receive no context; [`installed()`] returns
//! them to code that passes them on.
//!
//! The process-wide keys serve only standalone values: a record, or a tenant's
//! value, is sealed and opened explicitly, with keys the
//! application chooses for that tenant.
//!
//! [`install`] sets the keys once, from the binary's entry point. It never
//! replaces installed keys, and nothing resets them. Before installation,
//! [`installed()`] and the automatic column return [`Error::KeysNotInstalled`];
//! there is no default.
//!
//! ```
//! use cryptbox::{EncryptionKey, EncryptionKeyring, Keys, keys};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load durable key material here; a generated key is for demonstration only.
//! let encryption = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
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
//! enough to keep the global empty, so an automatic column that reads it fails
//! with [`Error::KeysNotInstalled`]:
//!
//! ```toml
//! disallowed-methods = [
//!     { path = "cryptbox::keys::install", reason = "pass keys explicitly" },
//!     { path = "cryptbox::keys::installed", reason = "pass keys explicitly" },
//! ]
//! ```
//!
#![doc = concat!(
    "[testing guide]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/docs/guide.md#testing",
)]

use std::sync::OnceLock;

use crate::{Error, Keys};

static INSTALLED: OnceLock<Keys> = OnceLock::new();

/// The error returned when keys are already installed.
///
/// Installed keys are never replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("keys are already installed")]
#[non_exhaustive]
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
