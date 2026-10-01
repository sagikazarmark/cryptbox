//! The typed layer's binding arguments: what a seal's callers pass, and the
//! binding the typed layer resolves from them.

use crate::{BindingDomain, Error, RecordId, RecordIdType, Seal, binding::Repr};

/// The binding arguments of one sealing or opening call under seal `F`: `()`,
/// or `&id` when [`Seal::Record`] is a record ID type.
///
/// | `Record` | Arguments |
/// | --- | --- |
/// | `()` | `()` |
/// | `i64` | `&id` |
///
/// A record ID of another type, a record to a seal that binds none, and no
/// record to a seal that binds one are type errors.
///
/// This trait is sealed: the forms above are the only implementations.
///
/// # Examples
///
/// ```
/// use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Seal, SealId, Sealed, Utf8};
///
/// struct CustomerEmail;
///
/// impl Seal for CustomerEmail {
///     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Record = i64;
///     type Indexes = ();
/// }
///
/// let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
///
/// let sealed = Sealed::<CustomerEmail>::seal(&"ada@example.com".into(), &42, &keys)?;
/// assert_eq!(sealed.open(&42, &keys)?, "ada@example.com");
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// Forgetting the record of a record-bound seal is a type error:
///
/// ```compile_fail,E0277
/// # use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Seal, SealId, Sealed, Utf8};
/// # struct CustomerEmail;
/// # impl Seal for CustomerEmail {
/// #     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Record = i64;
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let sealed = Sealed::<CustomerEmail>::seal(&"ada@example.com".into(), (), &keys)?;
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
/// #     type Record = ();
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let sealed = Sealed::<Nickname>::seal(&"ada".into(), &7_i64, &keys)?;
/// # Ok::<(), cryptbox::Error>(())
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` are not binding arguments of seal `{F}`",
    label = "not the arguments `{F}` binds",
    note = "pass `()`, or `&record_id` when `Seal::Record` is a record ID type"
)]
pub trait Args<F: Seal>: sealed::Sealed<F> {}

impl<F: Seal, T: sealed::Sealed<F>> Args<F> for T {}

pub(crate) mod sealed {
    use crate::{RecordId, Seal};

    pub trait Sealed<F: Seal> {
        /// Passes the record's value, when the seal binds one, to `f`.
        fn with_record<T>(self, f: impl FnOnce(Option<RecordId<'_>>) -> T) -> T;
    }

    /// The argument form of record `R`.
    pub trait ArgsFor<R> {
        fn with_record<T>(self, f: impl FnOnce(Option<RecordId<'_>>) -> T) -> T;
    }
}

impl<F: Seal, A: sealed::ArgsFor<F::Record>> sealed::Sealed<F> for A {
    fn with_record<T>(self, f: impl FnOnce(Option<RecordId<'_>>) -> T) -> T {
        sealed::ArgsFor::with_record(self, f)
    }
}

impl sealed::ArgsFor<()> for () {
    fn with_record<T>(self, f: impl FnOnce(Option<RecordId<'_>>) -> T) -> T {
        f(None)
    }
}

impl<R: RecordIdType> sealed::ArgsFor<R> for &R {
    fn with_record<T>(self, f: impl FnOnce(Option<RecordId<'_>>) -> T) -> T {
        f(Some(self.repr().record_id()))
    }
}

/// Encodes the binding of seal `F` under `args`.
pub(crate) fn domain<F: Seal, A: Args<F>>(args: A) -> Result<BindingDomain, Error> {
    args.with_record(|record| BindingDomain::record::<F::Record>(F::ID.as_bytes(), record))
}
