use crate::{
    Args, BindingDomain, Codec, EncryptionKeys, Error, OptionalRecordId, Seal, Sealed, bound,
    inspect_ciphertext,
};

/// Opens a value during a legacy-binding window, whichever binding declaration it is
/// sealed with.
///
/// A value whose header names the seal's current declaration is opened under `args`
/// with `keys`, as [`Sealed::open`] does. Any other value is opened under the
/// older declaration of record `OldRecord` with `old_keys`, binding the record
/// in `args` when `OldRecord` is one, as
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
/// [`Error::InvalidBinding`] when `OldRecord` binds a record `args` lacks. Also
/// returns any error of [`Sealed::open`].
pub fn open_across<OldRecord, F>(
    sealed: &Sealed<F>,
    args: impl Args<F>,
    keys: &(impl EncryptionKeys + ?Sized),
    old_keys: &(impl EncryptionKeys + ?Sized),
) -> Result<F::Value, Error>
where
    OldRecord: OptionalRecordId,
    F: Seal,
{
    let bytes = sealed.as_bytes();
    let stored = inspect_ciphertext(bytes)?.context_fingerprint();
    let plaintext = args.with_record(|record| {
        let current = BindingDomain::record::<F::Record>(F::ID.as_bytes(), record)?;
        if stored == current.fingerprint() {
            return bound::open(&current, bytes, keys.encryption_keyring());
        }

        let record = OldRecord::RECORD.and(record);
        let old = BindingDomain::record::<OldRecord>(F::ID.as_bytes(), record)?;
        bound::open(&old, bytes, old_keys.encryption_keyring())
    })?;

    Ok(F::Codec::decode(&plaintext)?)
}
