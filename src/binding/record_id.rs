use super::{RecordId, RecordKind};

/// A type a record ID can have, such as an application's own ID newtype.
///
/// A seal whose [`Record`](crate::Seal::Record) is this type binds each value to
/// the ID of the record it is stored in, so a value copied to another row fails
/// to open. The type binds as the built-in type it names, [`Self::Repr`]:
///
/// | `Repr` | Binds as |
/// | --- | --- |
/// | `[u8; 16]`, `uuid::Uuid` with the `uuid` feature | a UUID |
/// | `i64` | a signed 64-bit integer |
/// | `Vec<u8>`, `Box<[u8]>` | opaque bytes |
///
/// Each built-in type is its own `Repr`. A newtype names the one it wraps:
///
/// ```
/// use cryptbox::RecordIdType;
///
/// /// A customer ID, bound as a UUID.
/// struct CustomerId([u8; 16]);
///
/// impl RecordIdType for CustomerId {
///     type Repr = [u8; 16];
///
///     fn repr(&self) -> &[u8; 16] {
///         &self.0
///     }
/// }
/// ```
///
/// The record ID's type is persistent schema: its kind is part of the binding
/// declaration, so changing it, such as from `i64` to a UUID, is a migration.
/// There is no text kind: encode text as bytes.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a record ID type",
    label = "a record ID is a UUID, an `i64`, or bytes",
    note = "use `[u8; 16]`, `i64`, `Vec<u8>`, `Box<[u8]>`, or `uuid::Uuid` with the `uuid` feature, or implement `cryptbox::RecordIdType` for your ID type"
)]
pub trait RecordIdType: 'static {
    /// The built-in type this one binds as.
    type Repr: Repr;

    /// Returns the value to bind.
    fn repr(&self) -> &Self::Repr;
}

/// A built-in type a record ID binds as. Not public API: its kind and encoding
/// are persistent schema, fixed by the crate.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a built-in record ID representation",
    label = "a record ID binds as `[u8; 16]`, `uuid::Uuid`, `i64`, `Vec<u8>`, or `Box<[u8]>`"
)]
pub trait Repr: 'static {
    #[doc(hidden)]
    const KIND: RecordKind;

    #[doc(hidden)]
    fn record_id(&self) -> RecordId<'_>;
}

impl Repr for [u8; 16] {
    const KIND: RecordKind = RecordKind::Uuid;

    fn record_id(&self) -> RecordId<'_> {
        RecordId::Uuid(*self)
    }
}

impl RecordIdType for [u8; 16] {
    type Repr = Self;

    fn repr(&self) -> &Self {
        self
    }
}

#[cfg(feature = "uuid")]
impl Repr for uuid::Uuid {
    const KIND: RecordKind = RecordKind::Uuid;

    fn record_id(&self) -> RecordId<'_> {
        RecordId::Uuid(*self.as_bytes())
    }
}

#[cfg(feature = "uuid")]
impl RecordIdType for uuid::Uuid {
    type Repr = Self;

    fn repr(&self) -> &Self {
        self
    }
}

impl Repr for i64 {
    const KIND: RecordKind = RecordKind::I64;

    fn record_id(&self) -> RecordId<'_> {
        RecordId::I64(*self)
    }
}

impl RecordIdType for i64 {
    type Repr = Self;

    fn repr(&self) -> &Self {
        self
    }
}

impl Repr for Vec<u8> {
    const KIND: RecordKind = RecordKind::Bytes;

    fn record_id(&self) -> RecordId<'_> {
        RecordId::Bytes(self)
    }
}

impl RecordIdType for Vec<u8> {
    type Repr = Self;

    fn repr(&self) -> &Self {
        self
    }
}

impl Repr for Box<[u8]> {
    const KIND: RecordKind = RecordKind::Bytes;

    fn record_id(&self) -> RecordId<'_> {
        RecordId::Bytes(self)
    }
}

impl RecordIdType for Box<[u8]> {
    type Repr = Self;

    fn repr(&self) -> &Self {
        self
    }
}

/// The record a seal binds its values to: `()` for none, or a
/// [`RecordIdType`].
///
/// It is the bound of [`Seal::Record`](crate::Seal::Record), and has no other
/// implementations.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a record ID type",
    label = "use `()` for no record, or a record ID type",
    note = "use `[u8; 16]`, `i64`, `Vec<u8>`, `Box<[u8]>`, or `uuid::Uuid` with the `uuid` feature, or implement `cryptbox::RecordIdType` for your ID type"
)]
pub trait OptionalRecordId: 'static {
    #[doc(hidden)]
    const RECORD: Option<RecordKind>;
}

impl OptionalRecordId for () {
    const RECORD: Option<RecordKind> = None;
}

impl<T: RecordIdType> OptionalRecordId for T {
    const RECORD: Option<RecordKind> = Some(<T::Repr as Repr>::KIND);
}
