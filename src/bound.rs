// The bound layer: envelope operations under a seal's context, with a keyring
// the typed layer chose for it, so `Sealed`, records, and the migration planner
// share one path for each operation.

use zeroize::Zeroizing;

use crate::envelope;
use crate::{EncryptionKeyring, Error, Padding, seal_context::SealContext};

/// Pads and seals `plaintext` under `context` with the current key of `keyring`.
pub(crate) fn seal(
    context: &SealContext,
    padding: Padding,
    plaintext: &[u8],
    keyring: &EncryptionKeyring,
) -> Result<Vec<u8>, Error> {
    envelope::seal(context.envelope(), padding, plaintext, keyring)
}

/// Authenticates and decrypts `ciphertext` under `context`, removing recorded padding.
pub(crate) fn open(
    context: &SealContext,
    ciphertext: &[u8],
    keyring: &EncryptionKeyring,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let checked = envelope::check(context.envelope(), ciphertext)?;

    checked.open(keyring)
}

/// Reports whether `ciphertext`, sealed in a context whose fingerprint is
/// `fingerprint`, differs from what `padding` currently writes, without
/// decrypting it.
pub(crate) fn needs_reseal(
    fingerprint: [u8; 8],
    padding: Padding,
    ciphertext: &[u8],
    keyring: &EncryptionKeyring,
) -> Result<bool, Error> {
    // Checking compares only the fingerprint, which covers a context's kind and
    // never its value, so no context bytes are needed: nothing is decrypted.
    let checked = envelope::check(envelope::Context::new(&[], fingerprint), ciphertext)?;

    Ok(checked.needs_reseal(padding, keyring))
}

/// Opens `ciphertext` under `from` and seals its plaintext under `to` with
/// `padding`, returning the plaintext too for callers that derive from it.
///
/// This is the one place where plaintext passes from an open to a seal.
pub(crate) fn reseal(
    (from, from_keyring): (&SealContext, &EncryptionKeyring),
    (to, to_keyring): (&SealContext, &EncryptionKeyring),
    padding: Padding,
    ciphertext: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Error> {
    let plaintext = open(from, ciphertext, from_keyring)?;
    let ciphertext = seal(to, padding, &plaintext, to_keyring)?;

    Ok((plaintext, ciphertext))
}
