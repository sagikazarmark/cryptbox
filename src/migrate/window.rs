use crate::{
    Args, Binding, BindingDomain, BlindIndex, BlindIndexKeySource, BlindIndexSpec, Codec,
    EncryptionKeySource, Error, Seal, Sealed,
    binding::{declaration_fingerprint, with_domain},
    blind::{IndexArgs, probes_in},
    bound, inspect_ciphertext,
};

/// Opens a value during a legacy-binding window, whichever binding declaration it is
/// sealed with.
///
/// A value whose header names the seal's current declaration is opened under `args`
/// with `keys`, as [`Sealed::open`] does. Any other value is opened under the
/// older declaration `Old` with `old_keys`: each of `Old`'s parts takes its value
/// from the binding in `args` by part ID, and the record in `args` is bound
/// when the header names `Old` with a record, as
/// [`RowPlanner::legacy_binding`](super::RowPlanner::legacy_binding) does.
///
/// The header's binding fingerprint only chooses the declaration to try: either way the
/// value must authenticate under that declaration's binding.
///
/// # Errors
///
/// Returns [`Error::BindingMismatch`] for a value of neither declaration, and
/// [`Error::InvalidBinding`] when `Old` has a part that the current binding
/// lacks or holds with another kind. Also returns any error of
/// [`Sealed::open`].
pub fn open_across<Old, F>(
    sealed: &Sealed<F>,
    args: impl Args<F>,
    keys: &(impl EncryptionKeySource + ?Sized),
    old_keys: &(impl EncryptionKeySource + ?Sized),
) -> Result<F::Value, Error>
where
    Old: Binding,
    F: Seal,
{
    let bytes = sealed.as_bytes();
    let stored = inspect_ciphertext(bytes)?.context_fingerprint();
    let plaintext = with_domain::<F, _, _>(args, |domain, binding, record| {
        if stored == domain.fingerprint() {
            return bound::open(&domain, bytes, keys);
        }

        let recorded = record.is_some() && stored == declaration_fingerprint::<Old>(true);
        let record = if recorded { record } else { None };
        let old = BindingDomain::projected::<Old, F::Binding>(F::ID, binding, record)?;
        bound::open(&old, bytes, old_keys)
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
    Old: Binding,
{
    let mut probes = S::probes_with(query, args, keys)?;
    let old = BindingDomain::index_projected::<Old, <S::Seal as Seal>::Binding>(
        <S::Seal as Seal>::ID,
        args,
    )?;
    for probe in probes_in::<S>(query, &old, old_keys)? {
        if !probes.contains(&probe) {
            probes.push(probe);
        }
    }

    Ok(probes)
}
