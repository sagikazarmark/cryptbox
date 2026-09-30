use crate::{
    Args, BindingDomain, BlindIndex, BlindIndexKeySource, BlindIndexSpec, Codec,
    EncryptionKeySource, Error, FromParts, KeyScope, Seal, SealScope, Sealed,
    args::{PartsOf, Target, with_domain},
    binding::project_view,
    blind::probes_in,
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

/// Derives the probes of a lookup during a legacy-binding window: those of the
/// index's current scope under `scope` with `keys`, followed by those of the
/// older index scope `Old` with `old_keys`.
///
/// A row keeps the index it was written with until a sweep reseals it, so a
/// lookup must match both until the window closes. `Old` is the index scope the
/// index had before, such as `()`, and a view of its current scope: its parts
/// take their values from `scope` by part ID. A change that keeps the
/// [index binding] keeps the index bytes, and a probe both share is returned
/// once.
///
/// Probes are candidates only: open each candidate row with [`open_across`] and
/// check it with [`BlindIndexSpec::verify_candidate`].
///
/// # Errors
///
/// Returns [`Error::InvalidBinding`] for an invalid index-scope value, or an
/// error for normalization failure or unavailable keys. An `Old` that is not a
/// view of the current index scope fails the build.
///
#[doc = concat!(
    "[index binding]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/wire-format.md#index-binding",
)]
pub fn probes_across<Old, S>(
    query: &S::Query,
    scope: &S::Scope,
    keys: &(impl BlindIndexKeySource + ?Sized),
    old_keys: &(impl BlindIndexKeySource + ?Sized),
) -> Result<Vec<BlindIndex<S>>, Error>
where
    S: BlindIndexSpec,
    Old: FromParts,
{
    let mut probes = S::probes_with(query, scope, keys)?;
    let old: Old = project_view(scope)?;
    let old = Target {
        domain: BindingDomain::index(<S::Seal as Seal>::ID.as_bytes(), &old)?,
        key_scope: KeyScope::of(&old)?,
    };
    for probe in probes_in::<S>(query, &old, old_keys)? {
        if !probes.contains(&probe) {
            probes.push(probe);
        }
    }

    Ok(probes)
}
