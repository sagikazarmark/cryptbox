//! The typed layer's binding arguments: what a seal's callers pass, and the
//! binding and key scope the typed layer resolves from them.

use crate::{
    BindingDomain, EncryptionKeySource, EncryptionKeyring, Error, KeyScope, PartKind, PartType,
    PartValue, Recorded, Scope, Seal, SealId, SealScope,
};

/// The declared parts of seal `F`'s scope, without its record.
pub(crate) type PartsOf<F> = <<F as Seal>::Scope as SealScope>::Parts;

/// The binding arguments of one sealing or opening call under seal `F`.
///
/// Every value is bound to its seal's [`Scope`] and, when its scope is
/// [`Recorded`], to a record. The arguments take one of these forms:
///
/// | The seal's scope | Arguments |
/// | --- | --- |
/// | the empty scope `()` | `()` |
/// | a scope `S` | `&S` |
/// | `Recorded<(), Id>` | `((), &Id)` |
/// | `Recorded<S, Id>` | `(&S, &Id)` |
///
/// Passing a scope of another type, a record to a seal that binds none, or no
/// record to a seal that binds one is a type error.
///
/// This trait is sealed: the forms above are the only implementations.
///
/// # Examples
///
/// ```
/// use cryptbox::{
///     EncryptionKey, EncryptionKeyring, Padding, Recorded, Seal, SealId, Sealed, Tenant,
///     TenantId, Utf8,
/// };
///
/// struct CustomerEmail;
///
/// impl Seal for CustomerEmail {
///     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Scope = Recorded<Tenant, i64>;
///     type Indexes = ();
/// }
///
/// let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let tenant = Tenant(TenantId::new(b"acme".to_vec())?);
///
/// let sealed = Sealed::<CustomerEmail>::seal(&"ada@example.com".into(), (&tenant, &42), &keys)?;
/// assert_eq!(sealed.open((&tenant, &42), &keys)?, "ada@example.com");
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// Forgetting the record of a record-bound seal is a type error:
///
/// ```compile_fail,E0277
/// # use cryptbox::{
/// #     EncryptionKey, EncryptionKeyring, Padding, Recorded, Seal, SealId, Sealed, Tenant,
/// #     TenantId, Utf8,
/// # };
/// # struct CustomerEmail;
/// # impl Seal for CustomerEmail {
/// #     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Scope = Recorded<Tenant, i64>;
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let tenant = Tenant(TenantId::new(b"acme".to_vec())?);
///
/// let sealed = Sealed::<CustomerEmail>::seal(&"ada@example.com".into(), &tenant, &keys)?;
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// So does binding a record to a seal that declares none:
///
/// ```compile_fail,E0277
/// # use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Seal, SealId, Sealed, Utf8};
/// # struct Nickname;
/// # impl Seal for Nickname {
/// #     const ID: SealId = cryptbox::seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Scope = ();
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let sealed = Sealed::<Nickname>::seal(&"ada".into(), ((), &7_i64), &keys)?;
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// And a scope of another type:
///
/// ```compile_fail,E0277
/// # use cryptbox::{
/// #     EncryptionKey, EncryptionKeyring, Padding, Seal, SealId, Sealed, Tenant, TenantId, Utf8,
/// # };
/// # struct Nickname;
/// # impl Seal for Nickname {
/// #     const ID: SealId = cryptbox::seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Scope = ();
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let tenant = Tenant(TenantId::new(b"acme".to_vec())?);
///
/// let sealed = Sealed::<Nickname>::seal(&"ada".into(), &tenant, &keys)?;
/// # Ok::<(), cryptbox::Error>(())
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` are not binding arguments of seal `{F}`",
    label = "not the arguments `{F}`'s scope takes",
    note = "pass `()` for the empty scope, `&scope`, or `(&scope, &record_id)` when the seal's scope is `Recorded`"
)]
pub trait Args<F: Seal>: sealed::Sealed<F> {}

impl<F, T: sealed::Sealed<F>> Args<F> for T where F: Seal {}

pub(crate) mod sealed {
    use super::PartsOf;
    use crate::{PartValue, Seal};

    pub trait Sealed<F: Seal> {
        /// Passes the scope and the record's part value to `f`.
        fn with_parts<R>(self, f: impl FnOnce(&PartsOf<F>, Option<PartValue<'_>>) -> R) -> R;
    }
}

impl<F: Seal<Scope = ()>> sealed::Sealed<F> for () {
    fn with_parts<R>(self, f: impl FnOnce(&(), Option<PartValue<'_>>) -> R) -> R {
        f(&(), None)
    }
}

impl<S: Scope, F: Seal<Scope = S>> sealed::Sealed<F> for &S {
    fn with_parts<R>(self, f: impl FnOnce(&S, Option<PartValue<'_>>) -> R) -> R {
        f(self, None)
    }
}

impl<S, Id, F> sealed::Sealed<F> for (&S, &Id)
where
    S: Scope,
    Id: PartType + ?Sized + 'static,
    F: Seal<Scope = Recorded<S, Id>>,
{
    fn with_parts<R>(self, f: impl FnOnce(&S, Option<PartValue<'_>>) -> R) -> R {
        f(self.0, Some(self.1.part_value()))
    }
}

impl<Id, F> sealed::Sealed<F> for ((), &Id)
where
    Id: PartType + ?Sized + 'static,
    F: Seal<Scope = Recorded<(), Id>>,
{
    fn with_parts<R>(self, f: impl FnOnce(&(), Option<PartValue<'_>>) -> R) -> R {
        f(&(), Some(self.1.part_value()))
    }
}

/// The binding arguments of a sealed field of a [`Record`](crate::Record): the
/// record's scope and ID, with the ID bound exactly when the field's seal scope
/// is [`Recorded`].
///
/// `#[derive(Record)]` passes it to every sealed field, whichever of their seals
/// bind the record. Not public API.
#[doc(hidden)]
#[derive(Debug)]
pub struct InRecord<'a, S, Id: ?Sized>(pub &'a S, pub &'a Id);

impl<F, Id> sealed::Sealed<F> for InRecord<'_, PartsOf<F>, Id>
where
    F: Seal,
    Id: PartType + ?Sized,
{
    fn with_parts<R>(self, f: impl FnOnce(&PartsOf<F>, Option<PartValue<'_>>) -> R) -> R {
        const { check_record_kind(<F::Scope as SealScope>::RECORD, Id::KIND) };

        let record = <F::Scope as SealScope>::RECORD.map(|_| self.1.part_value());
        f(self.0, record)
    }
}

// Panics become build errors in `const` context.
const fn check_record_kind(declared: Option<PartKind>, id: PartKind) {
    if let Some(declared) = declared {
        assert!(
            declared as u8 == id as u8,
            "this seal binds a record ID of another type than the record's"
        );
    }
}

/// A seal's binding, encoded, with the key scope its keyring is chosen by.
///
/// The binding layer never chooses keys: the typed layer asks a key source for
/// the keyring of `key_scope` and hands the keyring down with `domain`.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub(crate) domain: BindingDomain,
    pub(crate) key_scope: KeyScope,
}

impl Target {
    /// Asks `keys` for the keyring of seal `seal` in this target's key scope.
    pub(crate) fn keyring(
        &self,
        seal: SealId,
        keys: &(impl EncryptionKeySource + ?Sized),
    ) -> Result<EncryptionKeyring, Error> {
        keys.encryption_keyring(seal, &self.key_scope)
    }
}

/// Encodes the binding of seal `F` under `args`.
pub(crate) fn domain<F: Seal, A: Args<F>>(args: A) -> Result<Target, Error> {
    args.with_parts(|scope, record| {
        Ok(Target {
            domain: BindingDomain::of::<F::Scope>(F::ID.as_bytes(), scope, record)?,
            key_scope: KeyScope::of(scope)?,
        })
    })
}

/// Encodes the binding of seal `F` under `args`, as [`domain`] does, and
/// passes it to `f` with the scope and record it was encoded from.
#[cfg(feature = "migrate")]
pub(crate) fn with_domain<F: Seal, A: Args<F>, T>(
    args: A,
    f: impl FnOnce(Target, &PartsOf<F>, Option<PartValue<'_>>) -> Result<T, Error>,
) -> Result<T, Error> {
    args.with_parts(|scope, record| {
        let target = Target {
            domain: BindingDomain::of::<F::Scope>(F::ID.as_bytes(), scope, record)?,
            key_scope: KeyScope::of(scope)?,
        };
        f(target, scope, record)
    })
}

/// Encodes the binding of seal `F` under `args`, as [`domain`] does, together
/// with the blind-index domain of its `keys` and `index` parts, which shares its
/// key scope.
pub(crate) fn domains<F: Seal, A: Args<F>>(args: A) -> Result<(Target, Target), Error> {
    args.with_parts(|scope, record| {
        let key_scope = KeyScope::of(scope)?;
        Ok((
            Target {
                domain: BindingDomain::of::<F::Scope>(F::ID.as_bytes(), scope, record)?,
                key_scope: key_scope.clone(),
            },
            Target {
                domain: BindingDomain::index_of(F::ID.as_bytes(), scope)?,
                key_scope,
            },
        ))
    })
}
