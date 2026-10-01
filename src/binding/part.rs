use super::{PartKind, PartValue};

/// A type a record ID can have, with its fixed [`PartKind`].
///
/// A seal whose [`Record`](crate::Seal::Record) is this type binds each value
/// to the record ID through this trait.
///
/// | Type | Kind |
/// | --- | --- |
/// | `[u8; 16]` | [`PartKind::Uuid`] |
/// | `uuid::Uuid`, with the `uuid` feature | [`PartKind::Uuid`] |
/// | `i64` | [`PartKind::I64`] |
/// | `Vec<u8>`, `Box<[u8]>` | [`PartKind::Bytes`] |
///
/// Implement it for an application's own ID types, such as a newtype over a
/// UUID. The kinds stay canonical whatever the type: there is no text kind, so
/// encode text as bytes.
///
/// ```
/// use cryptbox::{PartKind, PartType, PartValue};
///
/// /// A customer ID, bound as a UUID.
/// #[derive(Clone, Copy, Hash, PartialEq, Eq)]
/// struct CustomerId([u8; 16]);
///
/// impl PartType for CustomerId {
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
    message = "`{Self}` is not a record ID type",
    label = "a record ID is a UUID, an `i64`, or bytes",
    note = "use `[u8; 16]`, `i64`, `Vec<u8>`, `Box<[u8]>`, `uuid::Uuid` with the `uuid` feature, or implement `cryptbox::PartType`; encode text as bytes"
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
