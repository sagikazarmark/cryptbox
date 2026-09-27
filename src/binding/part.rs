use super::{PartKind, PartValue, TenantId};

/// A type a binding part can hold, with its fixed [`PartKind`].
///
/// `#[derive(Binding)]` reads each part's kind and value through this trait. A
/// hand-written [`Binding`](super::Binding) can use it too, or name the kinds and
/// values directly.
///
/// | Type | Kind |
/// | --- | --- |
/// | `[u8; 16]` | [`PartKind::Uuid`] |
/// | `uuid::Uuid`, with the `uuid` feature | [`PartKind::Uuid`] |
/// | `i64` | [`PartKind::I64`] |
/// | `Vec<u8>`, `Box<[u8]>`, [`TenantId`] | [`PartKind::Bytes`] |
///
/// Implement it for an application's own ID types, such as a newtype over a
/// UUID, so a scope struct can hold them directly. The kinds stay canonical
/// whatever the type: there is no text kind, so encode text as bytes.
///
/// ```
/// use cryptbox::{PartKind, PartType, PartValue};
///
/// /// An org ID, bound as a UUID part.
/// #[derive(Clone, Copy, Hash, PartialEq, Eq)]
/// struct OrgId([u8; 16]);
///
/// impl PartType for OrgId {
///     const KIND: PartKind = PartKind::Uuid;
///
///     fn part_value(&self) -> PartValue<'_> {
///         PartValue::Uuid(self.0)
///     }
/// }
/// ```
///
/// The kind and the bound bytes are persistent schema: an implementation must
/// not change them for a type with stored data.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a binding part type",
    label = "a part holds a UUID, an `i64`, or bytes",
    note = "use `[u8; 16]`, `i64`, `Vec<u8>`, `Box<[u8]>`, or `cryptbox::TenantId`, `uuid::Uuid` with the `uuid` feature, or implement `cryptbox::PartType`; encode text as bytes"
)]
pub trait PartType {
    /// The kind of every value of this type.
    const KIND: PartKind;

    /// Returns the value to bind, of kind [`KIND`](Self::KIND).
    ///
    /// A value of another kind fails every seal and open with
    /// [`Error::InvalidBinding`](crate::Error::InvalidBinding).
    fn part_value(&self) -> PartValue<'_>;
}

impl PartType for [u8; 16] {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Uuid(*self)
    }
}

#[cfg(feature = "uuid")]
impl PartType for uuid::Uuid {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Uuid(*self.as_bytes())
    }
}

impl PartType for i64 {
    const KIND: PartKind = PartKind::I64;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::I64(*self)
    }
}

impl PartType for Vec<u8> {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(self)
    }
}

impl PartType for Box<[u8]> {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(self)
    }
}

impl PartType for TenantId {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(self.as_bytes())
    }
}
