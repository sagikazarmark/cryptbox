use super::{RecordKind, RecordValue};

/// A type a record ID can have: `[u8; 16]`, `uuid::Uuid` with the `uuid`
/// feature, `i64`, `Vec<u8>`, or `Box<[u8]>`. Not public API: `#[derive(Record)]`
/// names it for a record's `record_id` field.
///
/// The kind and encoding are persistent schema, fixed by the crate.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a record ID type",
    label = "a record ID is a UUID, an `i64`, or bytes",
    note = "use `[u8; 16]`, `i64`, `Vec<u8>`, `Box<[u8]>`, or `uuid::Uuid` with the `uuid` feature"
)]
pub trait RecordKey: 'static {
    #[doc(hidden)]
    const KIND: RecordKind;

    #[doc(hidden)]
    fn record_value(&self) -> RecordValue<'_>;
}

impl RecordKey for [u8; 16] {
    const KIND: RecordKind = RecordKind::Uuid;

    fn record_value(&self) -> RecordValue<'_> {
        RecordValue::Uuid(*self)
    }
}

#[cfg(feature = "uuid")]
impl RecordKey for uuid::Uuid {
    const KIND: RecordKind = RecordKind::Uuid;

    fn record_value(&self) -> RecordValue<'_> {
        RecordValue::Uuid(*self.as_bytes())
    }
}

impl RecordKey for i64 {
    const KIND: RecordKind = RecordKind::I64;

    fn record_value(&self) -> RecordValue<'_> {
        RecordValue::I64(*self)
    }
}

impl RecordKey for Vec<u8> {
    const KIND: RecordKind = RecordKind::Bytes;

    fn record_value(&self) -> RecordValue<'_> {
        RecordValue::Bytes(self)
    }
}

impl RecordKey for Box<[u8]> {
    const KIND: RecordKind = RecordKind::Bytes;

    fn record_value(&self) -> RecordValue<'_> {
        RecordValue::Bytes(self)
    }
}
