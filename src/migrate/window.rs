use crate::{
    Args, BindingDomain, BlindIndex, BlindIndexKeys, BlindIndexSpec, BoundList, BoundValues, Codec,
    EncryptionKeys, Error, RecordIdType, Seal, Sealed,
    args::with_domain,
    binding::{bound_values, project},
    blind::{index_domain, probes_in},
    bound, inspect_ciphertext,
};

/// Opens a value during a legacy-binding window, whichever binding declaration it is
/// sealed with.
///
/// A value whose header names the seal's current declaration is opened under `args`
/// with `keys`, as [`Sealed::open`] does. Any other value is opened under the
/// older declaration of bound list `Old` and record `OldRecord` with `old_keys`:
/// each of `Old`'s values is taken from the bound values in `args` by kind, and
/// the record in `args` is bound when `OldRecord` is one, as
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
/// [`Error::InvalidBinding`] when `Old` has a type the current bound list
/// lacks, or `OldRecord` binds a record `args` lacks. Also
/// returns any error of
/// [`Sealed::open`].
pub fn open_across<Old, OldRecord, F>(
    sealed: &Sealed<F>,
    args: impl Args<F>,
    keys: &(impl EncryptionKeys + ?Sized),
    old_keys: &(impl EncryptionKeys + ?Sized),
) -> Result<F::Value, Error>
where
    Old: BoundList,
    OldRecord: RecordIdType,
    F: Seal,
{
    let bytes = sealed.as_bytes();
    let stored = inspect_ciphertext(bytes)?.context_fingerprint();
    let plaintext = with_domain::<F, _, _>(args, |domain, values, record| {
        if stored == domain.fingerprint() {
            return bound::open(&domain, bytes, keys.encryption_keyring());
        }

        let old = BindingDomain::projected::<Old, OldRecord>(
            F::ID.as_bytes(),
            <F::Bound as BoundList>::PARTS,
            values,
            record,
        )?;
        bound::open(&old, bytes, old_keys.encryption_keyring())
    })?;

    Ok(F::Codec::decode(&plaintext)?)
}

/// Derives the probes of a lookup during a legacy-binding window: those of the
/// index's current partition under `partition` with `keys`, followed by those of
/// the older partition `Old` with `old_keys`.
///
/// A row keeps the index it was written with until a sweep reseals it, so a
/// lookup must match both until the window closes. `Old` is the partition the
/// index had before, such as `()`, a sub-list of its current one: its values are
/// taken from `partition` by kind. A change that keeps the
/// [index binding] keeps the index bytes, and a probe both share is returned
/// once.
///
/// Probes are candidates only: open each candidate row with [`open_across`] and
/// check it with [`BlindIndexSpec::verify_candidate`].
///
/// # Errors
///
/// Returns [`Error::InvalidBinding`] when `Old` has a type the current
/// partition lacks, or an error for normalization failure or unavailable keys.
///
#[doc = concat!(
    "[index binding]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/wire-format.md#index-binding",
)]
pub fn probes_across<'a, Old, S>(
    query: &S::Query,
    partition: impl BoundValues<'a, S::Partition>,
    keys: &(impl BlindIndexKeys + ?Sized),
    old_keys: &(impl BlindIndexKeys + ?Sized),
) -> Result<Vec<BlindIndex<S>>, Error>
where
    S: BlindIndexSpec,
    Old: BoundList,
{
    let partition = bound_values(partition);
    let mut probes = probes_in::<S>(query, &index_domain::<S>(&partition)?, keys)?;
    let old = project(Old::PARTS, <S::Partition as BoundList>::PARTS, &partition)?;
    let old = BindingDomain::index::<Old>(<S::Seal as Seal>::ID.as_bytes(), &old)?;
    for probe in probes_in::<S>(query, &old, old_keys)? {
        if !probes.contains(&probe) {
            probes.push(probe);
        }
    }

    Ok(probes)
}
