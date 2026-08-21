use std::marker::PhantomData;

use crate::FieldId;

/// Supplies stable cryptographic context for an encrypted value.
pub trait Binding: private::Sealed + Sized + 'static {
    /// Runtime context required to construct the binding domain.
    type Context: ?Sized;

    #[doc(hidden)]
    fn domain(context: &Self::Context) -> BindingDomain;
}

/// Explicitly selects encryption without logical-field binding.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unbound;

impl private::Sealed for Unbound {}

impl Binding for Unbound {
    type Context = ();

    fn domain((): &Self::Context) -> BindingDomain {
        BindingDomain::unbound()
    }
}

/// Declares the stable identity of a logical encrypted field.
///
/// Generate a unique ID for each logical field, keep it stable across Rust and
/// database renames, and never reuse it for a different field. Changing the ID
/// makes existing field-bound ciphertext fail authentication.
pub trait Field: Sized + 'static {
    /// The stable identifier, independent of Rust and database names.
    const ID: FieldId;
}

/// Binds ciphertext and blind indexes to the [`Field::ID`] declared by `F`.
///
/// This prevents values from authenticating under another logical field, but
/// does not prevent substitution between rows of the same field.
#[derive(Clone, Copy, Debug, Default)]
pub struct FieldBound<F>(PhantomData<fn() -> F>);

impl<F: Field> private::Sealed for FieldBound<F> {}

impl<F: Field> Binding for FieldBound<F> {
    type Context = ();

    fn domain((): &Self::Context) -> BindingDomain {
        BindingDomain::field(F::ID)
    }
}

/// Canonical binding bytes passed to the cryptographic core.
///
/// This type is public only because it appears in the sealed [`Binding`]
/// trait. Applications cannot construct or inspect its representation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct BindingDomain {
    encoded: [u8; 17],
    len: usize,
}

impl BindingDomain {
    const fn unbound() -> Self {
        Self {
            encoded: [0_u8; 17],
            len: 1,
        }
    }

    fn field(id: FieldId) -> Self {
        let mut encoded = [0_u8; 17];
        encoded[0] = 1;
        encoded[1..].copy_from_slice(id.as_bytes());
        Self { encoded, len: 17 }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.encoded[..self.len]
    }

    pub(crate) fn from_binding<B: Binding>(context: &B::Context) -> Self {
        B::domain(context)
    }
}

mod private {
    pub trait Sealed {}
}
