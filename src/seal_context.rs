//! The envelope context a seal's values are sealed under: the seal ID and, for
//! a field of a record, the record ID.
//!
//! The envelope mixes these bytes into key derivation and the AAD, and stores
//! their fingerprint in its header; see ../docs/wire-format.md#seal-context.

use sha2::{Digest, Sha256};

use crate::{Error, Seal, SealId, envelope::Context};

// A persistent domain separator, not a display string: stored headers carry
// fingerprints computed with it.
const FINGERPRINT_LABEL: &[u8] = b"cryptbox/binding-fingerprint/v1\0";

// The record ID's slot: persistent context bytes, a nil ID and role code 3.
const RECORD_SLOT: [u8; 16] = [0; 16];
const RECORD_ROLE: u8 = 3;

/// The canonical kind of a record ID. Not public API: kinds are persistent
/// schema, and there is no text kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecordKind {
    /// A 16-byte UUID.
    Uuid,
    /// A signed 64-bit integer.
    I64,
    /// Opaque bytes.
    Bytes,
}

impl RecordKind {
    // Kind codes are persistent context bytes.
    const fn code(self) -> u8 {
        match self {
            Self::Uuid => 1,
            Self::I64 => 2,
            Self::Bytes => 3,
        }
    }
}

/// The value of a record ID, tagged with its kind. Not public API.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecordValue<'a> {
    /// A 16-byte UUID.
    Uuid([u8; 16]),
    /// A signed 64-bit integer.
    I64(i64),
    /// Opaque bytes.
    Bytes(&'a [u8]),
}

impl RecordValue<'_> {
    const fn kind(&self) -> RecordKind {
        match self {
            Self::Uuid(_) => RecordKind::Uuid,
            Self::I64(_) => RecordKind::I64,
            Self::Bytes(_) => RecordKind::Bytes,
        }
    }
}

/// A type a record ID can have: `[u8; 16]`, `uuid::Uuid` with the `uuid`
/// feature, `i64`, `Vec<u8>`, or `Box<[u8]>`. Not public API: `#[derive(Record)]`
/// names it for a record's `record_id` field.
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

/// Whether `K` is the record ID type a seal with `record` binds.
pub(crate) const fn binds<K: RecordKey>(record: Option<RecordKind>) -> bool {
    match record {
        Some(kind) => kind as u8 == K::KIND as u8,
        None => false,
    }
}

/// The context fingerprint of a seal whose fields bind a record ID of kind
/// `record`, or none.
pub(crate) fn fingerprint(record: Option<RecordKind>) -> [u8; 8] {
    // Preserve this canonical order: stored headers carry the result.
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_LABEL);
    hasher.update(u16::from(record.is_some()).to_be_bytes());
    if let Some(kind) = record {
        hasher.update(RECORD_SLOT);
        hasher.update([kind.code(), RECORD_ROLE]);
    }

    let digest = hasher.finalize();
    let mut fingerprint = [0_u8; 8];
    fingerprint.copy_from_slice(&digest[..8]);

    fingerprint
}

/// The context a value of a seal is sealed under, and its fingerprint.
#[derive(Clone, Debug)]
pub(crate) struct SealContext {
    bytes: Vec<u8>,
    fingerprint: [u8; 8],
}

impl SealContext {
    /// The context of seal `id`, with the record ID `record` for a record's
    /// field: `seal_id ‖ count ‖ record?`.
    ///
    /// Returns [`Error::MessageTooLong`] for a record ID longer than `u32::MAX`
    /// bytes.
    pub(crate) fn new(id: &SealId, record: Option<RecordValue<'_>>) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&u16::from(record.is_some()).to_be_bytes());
        if let Some(record) = record {
            let i64_bytes;
            let value: &[u8] = match &record {
                RecordValue::Uuid(uuid) => uuid,
                RecordValue::I64(value) => {
                    i64_bytes = value.to_be_bytes();
                    &i64_bytes
                }
                RecordValue::Bytes(bytes) => bytes,
            };
            let len = u32::try_from(value.len()).map_err(|_| Error::MessageTooLong)?;

            bytes.extend_from_slice(&RECORD_SLOT);
            bytes.push(record.kind().code());
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(value);
        }

        Ok(Self {
            bytes,
            fingerprint: fingerprint(record.map(|record| record.kind())),
        })
    }

    /// The context of seal `id` alone, as a standalone seal's values and every
    /// blind index use it.
    pub(crate) fn seal_id(id: &SealId) -> Self {
        Self::new(id, None).expect("a context without a record always fits")
    }

    /// The context of standalone seal `F`. A record field's seal fails the
    /// build here.
    pub(crate) fn standalone<F: Seal>() -> Self {
        const {
            assert!(
                F::RECORD.is_none(),
                "a record field's seal is sealed and opened by its record: use `Record::seal` \
                 and `Record::open`"
            );
        };

        Self::seal_id(&F::ID)
    }

    /// The context of record field seal `F` in the record whose ID is `id`. A
    /// standalone seal, or an ID of another type than `F` binds, fails the build
    /// here.
    pub(crate) fn in_record<F: Seal, K: RecordKey>(id: &K) -> Result<Self, Error> {
        const {
            assert!(
                binds::<K>(F::RECORD),
                "the record ID is not of the type this record field's seal binds"
            );
        };

        Self::new(&F::ID, Some(id.record_value()))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The envelope's view of this context.
    pub(crate) fn envelope(&self) -> Context<'_> {
        Context::new(&self.bytes, self.fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal_id;

    const SEAL: SealId = seal_id!("12345678-1234-4234-8234-1234567890ab");

    fn hex_array(value: &str) -> [u8; 8] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    #[test]
    fn a_seal_id_alone_is_followed_by_an_empty_count() {
        let context = SealContext::seal_id(&SEAL);

        // docs/wire-format.md#seal-context
        assert_eq!(
            hex::encode(&context.bytes),
            "123456781234423482341234567890ab0000"
        );
        // Independently computed with shasum over the documented label and count.
        assert_eq!(context.fingerprint, hex_array("65640fc8333534b9"));
    }

    #[test]
    fn a_record_id_follows_the_seal_id() {
        let context = SealContext::new(&SEAL, Some(RecordValue::I64(1))).unwrap();

        assert_eq!(
            hex::encode(&context.bytes),
            concat!(
                "123456781234423482341234567890ab",
                "0001",
                "00000000000000000000000000000000",
                "02",
                "00000008",
                "0000000000000001",
            )
        );
        // Independently computed with shasum over the documented bytes.
        assert_eq!(context.fingerprint, hex_array("76081b730530f822"));
    }

    #[test]
    fn a_bytes_record_id_is_length_prefixed() {
        let context = SealContext::new(&SEAL, Some(RecordValue::Bytes(b"row-7"))).unwrap();

        assert_eq!(
            hex::encode(&context.bytes),
            concat!(
                "123456781234423482341234567890ab",
                "0001",
                "00000000000000000000000000000000",
                "03",
                "00000005",
                "726f772d37",
            )
        );
    }

    #[test]
    fn record_ids_of_different_kinds_never_collide() {
        let bytes = SealContext::new(&SEAL, Some(RecordValue::Bytes(&7_i64.to_be_bytes())));
        let number = SealContext::new(&SEAL, Some(RecordValue::I64(7)));

        assert_ne!(bytes.unwrap().bytes, number.unwrap().bytes);
        assert_ne!(
            fingerprint(Some(RecordKind::I64)),
            fingerprint(Some(RecordKind::Bytes))
        );
    }

    #[test]
    fn an_empty_record_id_differs_from_none() {
        assert_ne!(
            SealContext::seal_id(&SEAL).bytes,
            SealContext::new(&SEAL, Some(RecordValue::Bytes(b"")))
                .unwrap()
                .bytes,
        );
    }

    #[test]
    fn a_seal_binds_only_its_own_record_id_type() {
        assert!(binds::<i64>(Some(RecordKind::I64)));
        assert!(!binds::<i64>(Some(RecordKind::Uuid)));
        assert!(!binds::<i64>(None));
    }
}
