use super::{BindingDomain, FieldOnly, RecordId};
use crate::{Error, Field};

/// The binding arguments of one seal or open of field `F`.
///
/// Every value is bound to its field's [`Binding`](crate::Binding) and, when
/// [`Field::RECORD`] is set, to a record. The arguments take one of these forms:
///
/// | Field | Arguments |
/// | --- | --- |
/// | [`FieldOnly`], no record | `()` |
/// | [`FieldOnly`], with a record | `RecordId` |
/// | any binding, no record | `&F::Binding` |
/// | any binding, with a record | `(&F::Binding, RecordId)` |
///
/// Passing a binding of another type is a type error. Passing a record to a
/// field that binds none, or omitting it for a field that binds one, fails the
/// build when the call is first compiled. Like the [`Binding`](crate::Binding)
/// checks, it runs after monomorphization, so `cargo check` does not report it;
/// `cargo build` and `cargo test` do.
///
/// This trait is sealed: the forms above are the only implementations.
///
/// # Examples
///
/// ```
/// use cryptbox::{
///     EncryptionKey, Field, FieldId, EncryptionKeyring, Padding, RecordId, Sealed,
///     Tenant, TenantId, Utf8,
/// };
///
/// struct CustomerEmail;
///
/// impl Field for CustomerEmail {
///     const ID: FieldId = cryptbox::field_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = true;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = Tenant;
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
/// Forgetting the record of a record-bound field fails the build:
///
/// ```compile_fail,E0080
/// # use cryptbox::{
/// #     EncryptionKey, Field, FieldId, EncryptionKeyring, Padding, Sealed, Tenant, TenantId,
/// #     Utf8,
/// # };
/// # struct CustomerEmail;
/// # impl Field for CustomerEmail {
/// #     const ID: FieldId = cryptbox::field_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = true;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Binding = Tenant;
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let tenant = Tenant(TenantId::new(b"acme".to_vec())?);
///
/// let sealed = Sealed::<CustomerEmail>::seal(&"ada@example.com".into(), &tenant, &keys)?;
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// So does binding a record to a field that declares none:
///
/// ```compile_fail,E0080
/// # use cryptbox::{
/// #     EncryptionKey, Field, FieldId, FieldOnly, EncryptionKeyring, Padding, RecordId,
/// #     Sealed, Utf8,
/// # };
/// # struct Nickname;
/// # impl Field for Nickname {
/// #     const ID: FieldId = cryptbox::field_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = false;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Binding = FieldOnly;
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
/// #     EncryptionKey, Field, FieldId, FieldOnly, EncryptionKeyring, Padding, Sealed, Tenant,
/// #     TenantId, Utf8,
/// # };
/// # struct Nickname;
/// # impl Field for Nickname {
/// #     const ID: FieldId = cryptbox::field_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = false;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Binding = FieldOnly;
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let tenant = Tenant(TenantId::new(b"acme".to_vec())?);
///
/// let sealed = Sealed::<Nickname>::seal(&"ada".into(), &tenant, &keys)?;
/// # Ok::<(), cryptbox::Error>(())
/// ```
pub trait Args<F: Field>: sealed::Sealed<F> {}

impl<F, T: sealed::Sealed<F>> Args<F> for T where F: Field {}

pub(crate) mod sealed {
    use crate::{Field, RecordId};

    pub trait Sealed<F: Field> {
        /// Whether this form carries a record.
        const RECORD: bool;

        /// Passes the binding and record to `f`.
        fn with_parts<R>(self, f: impl FnOnce(&F::Binding, Option<RecordId<'_>>) -> R) -> R;
    }
}

impl<F: Field<Binding = FieldOnly>> sealed::Sealed<F> for () {
    const RECORD: bool = false;

    fn with_parts<R>(self, f: impl FnOnce(&FieldOnly, Option<RecordId<'_>>) -> R) -> R {
        f(&FieldOnly, None)
    }
}

impl<F: Field<Binding = FieldOnly>> sealed::Sealed<F> for RecordId<'_> {
    const RECORD: bool = true;

    fn with_parts<R>(self, f: impl FnOnce(&FieldOnly, Option<RecordId<'_>>) -> R) -> R {
        f(&FieldOnly, Some(self))
    }
}

impl<F: Field> sealed::Sealed<F> for &F::Binding {
    const RECORD: bool = false;

    fn with_parts<R>(self, f: impl FnOnce(&F::Binding, Option<RecordId<'_>>) -> R) -> R {
        f(self, None)
    }
}

impl<F: Field> sealed::Sealed<F> for (&F::Binding, RecordId<'_>) {
    const RECORD: bool = true;

    fn with_parts<R>(self, f: impl FnOnce(&F::Binding, Option<RecordId<'_>>) -> R) -> R {
        f(self.0, Some(self.1))
    }
}

// Panics become build errors in `const` context, naming the missing or extra record.
const fn check_record(field: bool, args: bool) {
    assert!(
        !field || args,
        "this field binds a record: pass `(&binding, record)`, or a `RecordId` for a `FieldOnly` field"
    );
    assert!(
        field || !args,
        "this field binds no record: pass its binding alone, or `()` for a `FieldOnly` field"
    );
}

/// Encodes the binding of field `F` under `args`, checking at build time that
/// `args` carries a record exactly when `F` binds one.
pub(crate) fn domain<F: Field, A: Args<F>>(args: A) -> Result<BindingDomain, Error> {
    const { check_record(F::RECORD, <A as sealed::Sealed<F>>::RECORD) };

    args.with_parts(|binding, record| BindingDomain::of(F::ID, binding, record))
}

/// Encodes the binding of field `F` under `args`, as [`domain`] does, together
/// with the blind-index domain of its `keys` and `index` parts.
pub(crate) fn domains<F: Field, A: Args<F>>(
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
