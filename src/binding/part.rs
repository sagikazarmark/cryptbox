use super::{PartKind, PartValue, TenantId};
use crate::Error;

/// A type a binding part can hold, with its fixed [`PartKind`].
///
/// `#[derive(Scope)]` reads each part's kind and value through this trait,
/// and builds a scope back from its part values with
/// [`from_part_value`](Self::from_part_value). A hand-written
/// [`Scope`](super::Scope) can use it too, or name the kinds and values
/// directly.
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
/// use cryptbox::{Error, PartKind, PartType, PartValue};
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
///
///     fn from_part_value(value: PartValue<'_>) -> Result<Self, Error> {
///         <[u8; 16]>::from_part_value(value).map(Self)
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
    /// [`Error::InvalidBinding`].
    fn part_value(&self) -> PartValue<'_>;

    /// Reads a value back from the part value it binds: the inverse of
    /// [`part_value`](Self::part_value).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBinding`] for a value of another kind, or one
    /// the type cannot hold, such as an empty [`TenantId`].
    fn from_part_value(value: PartValue<'_>) -> Result<Self, Error>
    where
        Self: Sized;
}

impl PartType for [u8; 16] {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Uuid(*self)
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, Error> {
        match value {
            PartValue::Uuid(uuid) => Ok(uuid),
            _ => Err(Error::InvalidBinding),
        }
    }
}

#[cfg(feature = "uuid")]
impl PartType for uuid::Uuid {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Uuid(*self.as_bytes())
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, Error> {
        <[u8; 16]>::from_part_value(value).map(Self::from_bytes)
    }
}

impl PartType for i64 {
    const KIND: PartKind = PartKind::I64;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::I64(*self)
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, Error> {
        match value {
            PartValue::I64(value) => Ok(value),
            _ => Err(Error::InvalidBinding),
        }
    }
}

impl PartType for Vec<u8> {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(self)
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, Error> {
        match value {
            PartValue::Bytes(bytes) => Ok(bytes.to_vec()),
            _ => Err(Error::InvalidBinding),
        }
    }
}

impl PartType for Box<[u8]> {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(self)
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, Error> {
        Vec::from_part_value(value).map(Vec::into_boxed_slice)
    }
}

impl PartType for TenantId {
    const KIND: PartKind = PartKind::Bytes;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::Bytes(self.as_bytes())
    }

    fn from_part_value(value: PartValue<'_>) -> Result<Self, Error> {
        Vec::from_part_value(value).and_then(Self::new)
    }
}
