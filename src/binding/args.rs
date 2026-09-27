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
/// | any binding, in a record | [`InRecord(&F::Binding, RecordId)`](InRecord) |
///
/// Passing a binding of another type is a type error. Passing a record to a
/// field that binds none, or omitting it for a field that binds one, fails the
/// build when the call is first compiled. Like the [`Binding`](crate::Binding)
/// checks, it runs after monomorphization, so `cargo check` does not report it;
/// `cargo build` and `cargo test` do.
///
/// [`InRecord`] opts out of that check: it binds the record exactly when the
/// field declares one. A [`Record`](crate::Record) uses it to pass its ID to
/// every field, whichever of them bind it.
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

/// The binding arguments of a field of a [`Record`](crate::Record): the
/// record's binding and ID.
///
/// The record is bound exactly when the field declares [`Field::RECORD`], so
/// one record ID serves every field of a row, whether or not it binds one.
/// Unlike the other [`Args`] forms, a record passed to a field that binds none
/// is not a build error: it is ignored. Pass `(&binding, record)` where the
/// record must be bound.
///
/// ```
/// use cryptbox::{
///     EncryptionKey, EncryptionKeyring, Field, FieldId, InRecord, Padding, RecordId, Sealed,
///     Tenant, TenantId, Utf8,
/// };
///
/// /// Bound to its tenant only.
/// struct CustomerNote;
///
/// impl Field for CustomerNote {
///     const ID: FieldId = cryptbox::field_id!("0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
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
/// let sealed = Sealed::<CustomerNote>::seal(&"VIP".into(), InRecord(&tenant, record), &keys)?;
/// // The field binds no record, so the value opens under the tenant alone.
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

impl<F: Field> sealed::Sealed<F> for InRecord<'_, F::Binding> {
    const RECORD: bool = F::RECORD;

    fn with_parts<R>(self, f: impl FnOnce(&F::Binding, Option<RecordId<'_>>) -> R) -> R {
        f(self.0, F::RECORD.then_some(self.1))
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
