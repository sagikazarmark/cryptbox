// The bound layer: envelope operations under a resolved binding, with the
// keyring the key source chooses for it.
//
// The envelope sees only binding bytes, a fingerprint, and a keyring. This
// layer resolves them from a `BindingDomain` and an `EncryptionKeySource`,
// so `Sealed` and the migration planner share one path for each operation.

use zeroize::Zeroizing;

use crate::envelope::{self, Context};
use crate::{BindingDomain, EncryptionKeySource, EncryptionKeyring, Error, Padding};

/// Asks `keys` for the keyring of `domain`'s field and key scope.
pub(crate) fn keyring(
    domain: &BindingDomain,
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<EncryptionKeyring, Error> {
    keys.encryption_keyring(domain.seal_id(), domain.key_scope())
}

fn envelope_context(domain: &BindingDomain) -> Context<'_> {
    Context::new(domain.as_bytes(), domain.fingerprint())
}

/// Pads and seals `plaintext` under `domain` with the current key of its keyring.
pub(crate) fn seal(
    domain: &BindingDomain,
    padding: Padding,
    plaintext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Vec<u8>, Error> {
    envelope::seal(
        envelope_context(domain),
        padding,
        plaintext,
        &keyring(domain, keys)?,
    )
}

/// Authenticates and decrypts `ciphertext` under `domain`, removing recorded padding.
///
/// A different binding declaration is reported before the key source is asked for
/// a keyring.
pub(crate) fn open(
    domain: &BindingDomain,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let checked = envelope::check(envelope_context(domain), ciphertext)?;

    checked.open(&keyring(domain, keys)?)
}

/// Reports whether `ciphertext` differs from what `domain` and `padding`
/// currently write, without decrypting it.
pub(crate) fn needs_reseal(
    domain: &BindingDomain,
    padding: Padding,
    ciphertext: &[u8],
    keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<bool, Error> {
    let checked = envelope::check(envelope_context(domain), ciphertext)?;

    Ok(checked.needs_reseal(padding, &keyring(domain, keys)?))
}

/// Opens `ciphertext` under `from` and seals its plaintext under `to` with
/// `padding`, returning the plaintext too for callers that derive from it.
///
/// This is the one place where plaintext passes from an open to a seal.
pub(crate) fn reseal(
    (from, from_keys): (&BindingDomain, &(impl EncryptionKeySource + ?Sized)),
    (to, to_keys): (&BindingDomain, &(impl EncryptionKeySource + ?Sized)),
    padding: Padding,
    ciphertext: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Error> {
    let plaintext = open(from, ciphertext, from_keys)?;
    let ciphertext = seal(to, padding, &plaintext, to_keys)?;

    Ok((plaintext, ciphertext))
}
