//! The typed layer's binding arguments: what a seal's callers pass, and the
//! binding the typed layer resolves from them.

use crate::{BindingDomain, BoundId, Error, PartType, PartValue, Seal, binding::OwnedBinding};

/// The binding arguments of one sealing or opening call under seal `F`: the
/// values of its bound ID types, in the order of [`Seal::Bound`], then the
/// record ID when [`Seal::Record`] is one.
///
/// | `Bound` | `Record` | Arguments |
/// | --- | --- | --- |
/// | `()` | `()` | `()` |
/// | `(OrgId,)` | `()` | `&org` |
/// | `(OrgId, WorkspaceId)` | `()` | `(&org, &workspace)` |
/// | `()` | `i64` | `&id` |
/// | `(OrgId,)` | `i64` | `(&org, &id)` |
/// | `(OrgId, WorkspaceId)` | `i64` | `(&org, &workspace, &id)` |
///
/// A seal binds up to four bound ID types. A value of another type, values in
/// another order, a record to a seal that binds none, and no record to a seal
/// that binds one are type errors.
///
/// This trait is sealed: the forms above are the only implementations.
///
/// # Examples
///
/// ```
/// use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Seal, SealId, Sealed, TenantId, Utf8};
///
/// struct CustomerEmail;
///
/// impl Seal for CustomerEmail {
///     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Bound = (TenantId,);
///     type Record = i64;
///     type Indexes = ();
/// }
///
/// let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let tenant = TenantId::new("acme")?;
///
/// let sealed = Sealed::<CustomerEmail>::seal(&"ada@example.com".into(), (&tenant, &42), &keys)?;
/// assert_eq!(sealed.open((&tenant, &42), &keys)?, "ada@example.com");
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// Forgetting the record of a record-bound seal is a type error:
///
/// ```compile_fail,E0277
/// # use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Seal, SealId, Sealed, TenantId, Utf8};
/// # struct CustomerEmail;
/// # impl Seal for CustomerEmail {
/// #     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Bound = (TenantId,);
/// #     type Record = i64;
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let tenant = TenantId::new("acme")?;
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
/// #     type Bound = ();
/// #     type Record = ();
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let sealed = Sealed::<Nickname>::seal(&"ada".into(), &7_i64, &keys)?;
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// And a bound value of another type:
///
/// ```compile_fail,E0277
/// # use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Seal, SealId, Sealed, TenantId, Utf8};
/// # struct Nickname;
/// # impl Seal for Nickname {
/// #     const ID: SealId = cryptbox::seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Bound = ();
/// #     type Record = ();
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let tenant = TenantId::new("acme")?;
///
/// let sealed = Sealed::<Nickname>::seal(&"ada".into(), &tenant, &keys)?;
/// # Ok::<(), cryptbox::Error>(())
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` are not binding arguments of seal `{F}`",
    label = "not the arguments `{F}` binds",
    note = "pass the seal's bound values in the order of `Seal::Bound`, `()` for none, then \
            `&record_id` when `Seal::Record` is one: `&org`, `(&org, &workspace)`, `(&org, &id)`"
)]
pub trait Args<F: Seal>: sealed::Sealed<F> {}

impl<F: Seal, T: sealed::Sealed<F>> Args<F> for T {}

pub(crate) mod sealed {
    use crate::{PartValue, Seal};

    pub trait Sealed<F: Seal> {
        /// Passes the bound values, in list order, and the record's value to `f`.
        fn with_values<T>(self, f: impl FnOnce(&[PartValue<'_>], Option<PartValue<'_>>) -> T) -> T;
    }

    /// The argument forms of bound list `L` and record `R`.
    pub trait ArgsFor<L, R> {
        fn with_values<T>(self, f: impl FnOnce(&[PartValue<'_>], Option<PartValue<'_>>) -> T) -> T;
    }
}

impl<F: Seal, A: sealed::ArgsFor<F::Bound, F::Record>> sealed::Sealed<F> for A {
    fn with_values<T>(self, f: impl FnOnce(&[PartValue<'_>], Option<PartValue<'_>>) -> T) -> T {
        sealed::ArgsFor::with_values(self, f)
    }
}

impl sealed::ArgsFor<(), ()> for () {
    fn with_values<T>(self, f: impl FnOnce(&[PartValue<'_>], Option<PartValue<'_>>) -> T) -> T {
        f(&[], None)
    }
}

impl<R: PartType + 'static> sealed::ArgsFor<(), R> for &R {
    fn with_values<T>(self, f: impl FnOnce(&[PartValue<'_>], Option<PartValue<'_>>) -> T) -> T {
        f(&[], Some(self.part_value()))
    }
}

// One bound value is passed alone, not as a one-tuple.
impl<A: BoundId> sealed::ArgsFor<(A,), ()> for &A {
    fn with_values<T>(self, f: impl FnOnce(&[PartValue<'_>], Option<PartValue<'_>>) -> T) -> T {
        f(&[self.part_value()], None)
    }
}

// Bound values, then the record.
macro_rules! recorded_args {
    ($($ty:ident $value:ident),+) => {
        impl<R: PartType + 'static, $($ty: BoundId),+> sealed::ArgsFor<($($ty,)+), R>
            for ($(&$ty,)+ &R)
        {
            fn with_values<T>(
                self,
                f: impl FnOnce(&[PartValue<'_>], Option<PartValue<'_>>) -> T,
            ) -> T {
                let ($($value,)+ record) = self;
                f(&[$($value.part_value()),+], Some(record.part_value()))
            }
        }
    };
}

// Two or more bound values, without a record.
macro_rules! bound_args {
    ($($ty:ident $value:ident),+) => {
        impl<$($ty: BoundId),+> sealed::ArgsFor<($($ty,)+), ()> for ($(&$ty,)+) {
            fn with_values<T>(
                self,
                f: impl FnOnce(&[PartValue<'_>], Option<PartValue<'_>>) -> T,
            ) -> T {
                let ($($value,)+) = self;
                f(&[$($value.part_value()),+], None)
            }
        }
    };
}

recorded_args!(A a);
recorded_args!(A a, B b);
recorded_args!(A a, B b, C c);
recorded_args!(A a, B b, C c, D d);
bound_args!(A a, B b);
bound_args!(A a, B b, C c);
bound_args!(A a, B b, C c, D d);

/// Encodes the binding of seal `F` under `values` and `record`.
pub(crate) fn target<F: Seal>(
    values: &[PartValue<'_>],
    record: Option<PartValue<'_>>,
) -> Result<BindingDomain, Error> {
    BindingDomain::bound::<F::Bound, F::Record>(F::ID.as_bytes(), values, record)
}

/// Encodes the binding of seal `F` under `args`.
pub(crate) fn domain<F: Seal, A: Args<F>>(args: A) -> Result<BindingDomain, Error> {
    args.with_values(|values, record| target::<F>(values, record))
}

/// Encodes the binding of seal `F` under `args`, as [`domain`] does, and
/// passes it to `f` with the values and record it was encoded from.
#[cfg(feature = "migrate")]
pub(crate) fn with_domain<F: Seal, A: Args<F>, T>(
    args: A,
    f: impl FnOnce(BindingDomain, &[PartValue<'_>], Option<PartValue<'_>>) -> Result<T, Error>,
) -> Result<T, Error> {
    args.with_values(|values, record| f(target::<F>(values, record)?, values, record))
}

/// Encodes the binding of seal `F` under `args`, as [`domain`] does, and returns
/// its bound values too, from which each blind index projects its partition.
pub(crate) fn domain_and_values<F: Seal, A: Args<F>>(
    args: A,
) -> Result<(BindingDomain, OwnedBinding), Error> {
    args.with_values(|values, record| Ok((target::<F>(values, record)?, OwnedBinding::new(values))))
}
