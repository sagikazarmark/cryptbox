// The bound layer: envelope operations under a resolved binding, with a keyring
// the typed layer chose for it.
//
// The envelope sees only binding bytes, a fingerprint, and a keyring. This
// layer turns a `BindingDomain` into the envelope's context, so `Sealed` and the
// migration planner share one path for each operation. Keyrings arrive as
// closures, so a different binding declaration is reported before any key
// source is asked.

use zeroize::Zeroizing;

use crate::envelope::{self, Context};
use crate::{BindingDomain, EncryptionKeyring, Error, Padding};

fn envelope_context(domain: &BindingDomain) -> Context<'_> {
    Context::new(domain.as_bytes(), domain.fingerprint())
}

/// Pads and seals `plaintext` under `domain` with the current key of `keyring`.
pub(crate) fn seal(
    domain: &BindingDomain,
    padding: Padding,
    plaintext: &[u8],
    keyring: impl FnOnce() -> Result<EncryptionKeyring, Error>,
) -> Result<Vec<u8>, Error> {
    envelope::seal(envelope_context(domain), padding, plaintext, &keyring()?)
}

/// Authenticates and decrypts `ciphertext` under `domain`, removing recorded padding.
///
/// A different binding declaration is reported before `keyring` is asked for.
pub(crate) fn open(
    domain: &BindingDomain,
    ciphertext: &[u8],
    keyring: impl FnOnce() -> Result<EncryptionKeyring, Error>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let checked = envelope::check(envelope_context(domain), ciphertext)?;

    checked.open(&keyring()?)
}

/// Reports whether `ciphertext` differs from what `domain` and `padding`
/// currently write, without decrypting it.
pub(crate) fn needs_reseal(
    domain: &BindingDomain,
    padding: Padding,
    ciphertext: &[u8],
    keyring: impl FnOnce() -> Result<EncryptionKeyring, Error>,
) -> Result<bool, Error> {
    let checked = envelope::check(envelope_context(domain), ciphertext)?;

    Ok(checked.needs_reseal(padding, &keyring()?))
}

/// Opens `ciphertext` under `from` and seals its plaintext under `to` with
/// `padding`, returning the plaintext too for callers that derive from it.
///
/// This is the one place where plaintext passes from an open to a seal.
pub(crate) fn reseal(
    (from, from_keyring): (
        &BindingDomain,
        impl FnOnce() -> Result<EncryptionKeyring, Error>,
    ),
    (to, to_keyring): (
        &BindingDomain,
        impl FnOnce() -> Result<EncryptionKeyring, Error>,
    ),
    padding: Padding,
    ciphertext: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Error> {
    let plaintext = open(from, ciphertext, from_keyring)?;
    let ciphertext = seal(to, padding, &plaintext, to_keyring)?;

    Ok((plaintext, ciphertext))
}
