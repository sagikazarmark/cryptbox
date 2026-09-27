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
/// There is no text kind: encode text as bytes. This trait is sealed, so every
/// part stays one of these canonical kinds.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a binding part type",
    label = "a part holds a UUID, an `i64`, or bytes",
    note = "use `[u8; 16]`, `i64`, `Vec<u8>`, `Box<[u8]>`, or `cryptbox::TenantId`, or `uuid::Uuid` with the `uuid` feature; encode text as bytes"
)]
pub trait PartType: sealed::Sealed {
    /// The kind of every value of this type.
    const KIND: PartKind;

    /// Returns the value to bind.
    fn part_value(&self) -> PartValue<'_>;
}

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for [u8; 16] {}

impl PartType for [u8; 16] {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Uuid(*self)
    }
}

#[cfg(feature = "uuid")]
impl sealed::Sealed for uuid::Uuid {}

#[cfg(feature = "uuid")]
impl PartType for uuid::Uuid {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Uuid(*self.as_bytes())
    }
}

impl sealed::Sealed for i64 {}

impl PartType for i64 {
    const KIND: PartKind = PartKind::I64;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::I64(*self)
    }
}

impl sealed::Sealed for Vec<u8> {}

impl PartType for Vec<u8> {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(self)
    }
}

impl sealed::Sealed for Box<[u8]> {}

impl PartType for Box<[u8]> {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(self)
    }
}

impl sealed::Sealed for TenantId {}

impl PartType for TenantId {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(self.as_bytes())
    }
}
