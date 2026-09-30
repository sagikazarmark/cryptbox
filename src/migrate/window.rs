use crate::{
    Args, BindingDomain, BlindIndex, BlindIndexKeySource, BlindIndexSpec, Codec,
    EncryptionKeySource, Error, KeyScope, Seal, SealScope, Sealed,
    args::{PartsOf, Target, with_domain},
    blind::{IndexArgs, probes_in},
    bound, inspect_ciphertext,
};

/// Opens a value during a legacy-binding window, whichever binding declaration it is
/// sealed with.
///
/// A value whose header names the seal's current declaration is opened under `args`
/// with `keys`, as [`Sealed::open`] does. Any other value is opened under the
/// older seal scope `Old` with `old_keys`: each of `Old`'s parts takes its value
/// from the scope in `args` by part ID, and the record in `args` is bound when
/// `Old` binds one, as
/// [`RowPlanner::legacy_binding`](super::RowPlanner::legacy_binding) does. A
/// value moving out of a record needs its record ID, which the arguments of a
/// seal that binds none cannot carry: reseal such values with a sweep.
///
/// The header's binding fingerprint only chooses the declaration to try: either way the
/// value must authenticate under that declaration's binding.
///
/// # Errors
///
/// Returns [`Error::BindingMismatch`] for a value of neither declaration, and
/// [`Error::InvalidBinding`] when `Old` has a part that the current scope
/// lacks or holds with another kind, or binds a record `args` lacks. Also
/// returns any error of
/// [`Sealed::open`].
pub fn open_across<Old, F>(
    sealed: &Sealed<F>,
    args: impl Args<F>,
    keys: &(impl EncryptionKeySource + ?Sized),
    old_keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<F::Value, Error>
where
    Old: SealScope,
    F: Seal,
{
    let bytes = sealed.as_bytes();
    let stored = inspect_ciphertext(bytes)?.context_fingerprint();
    let plaintext = with_domain::<F, _, _>(args, |target, scope, record| {
        if stored == target.domain.fingerprint() {
            return bound::open(&target.domain, bytes, || target.keyring(F::ID, keys));
        }

        let old = BindingDomain::projected::<Old, PartsOf<F>>(F::ID.as_bytes(), scope, record)?;
        let old_scope = KeyScope::projected::<Old::Parts, PartsOf<F>>(scope)?;
        bound::open(&old, bytes, || {
            old_keys.encryption_keyring(F::ID, &old_scope)
        })
    })?;

    Ok(F::Codec::decode(&plaintext)?)
}

/// Derives the probes of a lookup during a legacy-binding window: those of
/// the seal's current index binding under `args` with `keys`, followed by
/// those of the older declaration `Old` with `old_keys`.
///
/// A row keeps the index it was written with until a sweep reseals it, so a
/// lookup must match both declarations until the window closes. `Old`'s `keys` and
/// `index` parts take their values from `args` by part ID. A declaration change that
/// keeps the [index binding] keeps the index bytes, and a probe both declarations
/// share is returned once.
///
/// Probes are candidates only: open each candidate row with [`open_across`] and
/// check it with [`BlindIndexSpec::verify_candidate`].
///
/// # Errors
///
/// Returns [`Error::InvalidBinding`] when `args` does not match the binding's
/// `keys` and `index` parts, or when `Old` has such a part that `args` lacks or
/// holds with another kind. Also returns an error for normalization failure or
/// unavailable keys.
///
#[doc = concat!(
    "[index binding]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/wire-format.md#index-binding",
)]
pub fn probes_across<Old, S>(
    query: &S::Query,
    args: &IndexArgs<S>,
    keys: &(impl BlindIndexKeySource + ?Sized),
    old_keys: &(impl BlindIndexKeySource + ?Sized),
) -> Result<Vec<BlindIndex<S>>, Error>
where
    S: BlindIndexSpec,
    Old: SealScope,
{
    let mut probes = S::probes_with(query, args, keys)?;
    let old = Target {
        domain: BindingDomain::index_projected::<Old, PartsOf<S::Seal>>(
            <S::Seal as Seal>::ID.as_bytes(),
            args,
        )?,
        key_scope: KeyScope::index_projected::<Old::Parts, PartsOf<S::Seal>>(args)?,
    };
    for probe in probes_in::<S>(query, &old, old_keys)? {
        if !probes.contains(&probe) {
            probes.push(probe);
        }
    }

    Ok(probes)
}
