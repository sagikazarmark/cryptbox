use super::{BindingDomain, RecordId};
use crate::{Error, Seal};

/// The binding arguments of one sealing or opening call under seal `F`.
///
/// Every value is bound to its seal's [`Scope`](crate::Scope) and, when
/// [`Seal::RECORD`] is set, to a record. The arguments take one of these forms:
///
/// | The seal declares | Arguments |
/// | --- | --- |
/// | the empty scope `()`, no record | `()` |
/// | the empty scope `()`, with a record | `RecordId` |
/// | any binding, no record | `&F::Scope` |
/// | any binding, with a record | `(&F::Scope, RecordId)` |
/// | any binding, in a record | [`InRecord(&F::Scope, RecordId)`](InRecord) |
///
/// Passing a binding of another type is a type error. Passing a record to a
/// seal that binds none, or omitting it for a seal that binds one, fails the
/// build when the call is first compiled. Like the [`Scope`](crate::Scope)
/// checks, it runs after monomorphization, so `cargo check` does not report it;
/// `cargo build` and `cargo test` do.
///
/// [`InRecord`] opts out of that check: it binds the record exactly when the
/// seal declares one. A [`Record`](crate::Record) uses it to pass its ID to
/// every sealed field, whichever of their seals bind it.
///
/// This trait is sealed: the forms above are the only implementations.
///
/// # Examples
///
/// ```
/// use cryptbox::{
///     EncryptionKey, Seal, SealId, EncryptionKeyring, Padding, RecordId, Sealed,
///     Tenant, TenantId, Utf8,
/// };
///
/// struct CustomerEmail;
///
/// impl Seal for CustomerEmail {
///     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = true;
///     type Value = String;
///     type Codec = Utf8;
///     type Scope = Tenant;
///     type Indexes = ();
/// }
///
/// let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let tenant = Tenant(TenantId::new(b"acme".to_vec())?);
/// let record = RecordId::from(42_i64);
///
/// let sealed = Sealed::<CustomerEmail>::seal(&"ada@example.com".into(), (&tenant, record), &keys)?;
/// assert_eq!(sealed.open((&tenant, record), &keys)?, "ada@example.com");
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// Forgetting the record of a record-bound seal fails the build:
///
/// ```compile_fail,E0080
/// # use cryptbox::{
/// #     EncryptionKey, Seal, SealId, EncryptionKeyring, Padding, Sealed, Tenant, TenantId,
/// #     Utf8,
/// # };
/// # struct CustomerEmail;
/// # impl Seal for CustomerEmail {
/// #     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = true;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Scope = Tenant;
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
/// ```compile_fail,E0080
/// # use cryptbox::{
/// #     EncryptionKey, Seal, SealId, EncryptionKeyring, Padding, RecordId,
/// #     Sealed, Utf8,
/// # };
/// # struct Nickname;
/// # impl Seal for Nickname {
/// #     const ID: SealId = cryptbox::seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = false;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Scope = ();
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let sealed = Sealed::<Nickname>::seal(&"ada".into(), RecordId::from(7_i64), &keys)?;
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// And a binding of another type is a type error:
///
/// ```compile_fail,E0277
/// # use cryptbox::{
/// #     EncryptionKey, Seal, SealId, EncryptionKeyring, Padding, Sealed, Tenant,
/// #     TenantId, Utf8,
/// # };
/// # struct Nickname;
/// # impl Seal for Nickname {
/// #     const ID: SealId = cryptbox::seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = false;
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
pub trait Args<F: Seal>: sealed::Sealed<F> {}

impl<F, T: sealed::Sealed<F>> Args<F> for T where F: Seal {}

pub(crate) mod sealed {
    use crate::{RecordId, Seal};

    pub trait Sealed<F: Seal> {
        /// Whether this form carries a record.
        const RECORD: bool;

        /// Passes the binding and record to `f`.
        fn with_parts<R>(self, f: impl FnOnce(&F::Scope, Option<RecordId<'_>>) -> R) -> R;
    }
}

impl<F: Seal<Scope = ()>> sealed::Sealed<F> for () {
    const RECORD: bool = false;

    fn with_parts<R>(self, f: impl FnOnce(&(), Option<RecordId<'_>>) -> R) -> R {
        f(&(), None)
    }
}

impl<F: Seal<Scope = ()>> sealed::Sealed<F> for RecordId<'_> {
    const RECORD: bool = true;

    fn with_parts<R>(self, f: impl FnOnce(&(), Option<RecordId<'_>>) -> R) -> R {
        f(&(), Some(self))
    }
}

impl<F: Seal> sealed::Sealed<F> for &F::Scope {
    const RECORD: bool = false;

    fn with_parts<R>(self, f: impl FnOnce(&F::Scope, Option<RecordId<'_>>) -> R) -> R {
        f(self, None)
    }
}

impl<F: Seal> sealed::Sealed<F> for (&F::Scope, RecordId<'_>) {
    const RECORD: bool = true;

    fn with_parts<R>(self, f: impl FnOnce(&F::Scope, Option<RecordId<'_>>) -> R) -> R {
        f(self.0, Some(self.1))
    }
}

/// The binding arguments of a sealed field of a [`Record`](crate::Record): the
/// record's binding and ID.
///
/// The record is bound exactly when the field's seal declares [`Seal::RECORD`], so
/// one record ID serves every field of a row, whether or not it binds one.
/// Unlike the other [`Args`] forms, a record passed to a seal that binds none
/// is not a build error: it is ignored. Pass `(&binding, record)` where the
/// record must be bound.
///
/// ```
/// use cryptbox::{
///     EncryptionKey, EncryptionKeyring, Seal, SealId, InRecord, Padding, RecordId, Sealed,
///     Tenant, TenantId, Utf8,
/// };
///
/// /// Bound to its tenant only.
/// struct CustomerNote;
///
/// impl Seal for CustomerNote {
///     const ID: SealId = cryptbox::seal_id!("0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Scope = Tenant;
///     type Indexes = ();
/// }
///
/// let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let tenant = Tenant(TenantId::new(b"acme".to_vec())?);
/// let record = RecordId::from(42_i64);
///
/// let sealed = Sealed::<CustomerNote>::seal(&"VIP".into(), InRecord(&tenant, record), &keys)?;
/// // The seal binds no record, so the value opens under the tenant alone.
/// assert_eq!(sealed.open(&tenant, &keys)?, "VIP");
/// # Ok::<(), cryptbox::Error>(())
/// ```
#[derive(Debug)]
pub struct InRecord<'a, B>(pub &'a B, pub RecordId<'a>);

// Derived impls would require `B: Copy`, but only the reference is copied.
impl<B> Clone for InRecord<'_, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B> Copy for InRecord<'_, B> {}

impl<F: Seal> sealed::Sealed<F> for InRecord<'_, F::Scope> {
    const RECORD: bool = F::RECORD;

    fn with_parts<R>(self, f: impl FnOnce(&F::Scope, Option<RecordId<'_>>) -> R) -> R {
        f(self.0, F::RECORD.then_some(self.1))
    }
}

// Panics become build errors in `const` context, naming the missing or extra record.
const fn check_record(seal: bool, args: bool) {
    assert!(
        !seal || args,
        "this seal binds a record: pass `(&binding, record)`, or a `RecordId` for a seal with the empty scope"
    );
    assert!(
        seal || !args,
        "this seal binds no record: pass its binding alone, or `()` for a seal with the empty scope"
    );
}

/// Encodes the binding of seal `F` under `args`, checking at build time that
/// `args` carries a record exactly when `F` binds one.
pub(crate) fn domain<F: Seal, A: Args<F>>(args: A) -> Result<BindingDomain, Error> {
    const { check_record(F::RECORD, <A as sealed::Sealed<F>>::RECORD) };

    args.with_parts(|binding, record| BindingDomain::of(F::ID, binding, record))
}

/// Encodes the binding of seal `F` under `args`, as [`domain`] does, and
/// passes it to `f` with the binding and record it was encoded from.
#[cfg(feature = "migrate")]
pub(crate) fn with_domain<F: Seal, A: Args<F>, T>(
    args: A,
    f: impl FnOnce(BindingDomain, &F::Scope, Option<RecordId<'_>>) -> Result<T, Error>,
) -> Result<T, Error> {
    const { check_record(F::RECORD, <A as sealed::Sealed<F>>::RECORD) };

    args.with_parts(|binding, record| {
        f(BindingDomain::of(F::ID, binding, record)?, binding, record)
    })
}

/// Encodes the binding of seal `F` under `args`, as [`domain`] does, together
/// with the blind-index domain of its `keys` and `index` parts.
pub(crate) fn domains<F: Seal, A: Args<F>>(
    args: A,
) -> Result<(BindingDomain, BindingDomain), Error> {
    const { check_record(F::RECORD, <A as sealed::Sealed<F>>::RECORD) };

    args.with_parts(|binding, record| {
        Ok((
            BindingDomain::of(F::ID, binding, record)?,
            BindingDomain::index_of(F::ID, binding)?,
        ))
    })
}
