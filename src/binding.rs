use crate::Error;

mod encoding;
mod record_id;

pub(crate) use record_id::Repr;
pub use record_id::{OptionalRecordId, RecordIdType};

/// The binding fingerprint of a seal that binds record `R`, as the envelope
/// header carries it.
pub(crate) fn declaration_fingerprint<R: OptionalRecordId>() -> [u8; 8] {
    BindingDeclaration::new(R::RECORD).fingerprint()
}

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

/// The ID of the record a value is bound to, tagged with its kind.
///
/// The kind is part of the binding, so the same number as an `i64` and as bytes
/// binds different records. A migration reads it from each row; see
/// `migrate::RowPlanner::for_rows`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecordId<'a> {
    /// A UUID, such as a client-generated version 7 UUID.
    Uuid([u8; 16]),
    /// A signed 64-bit integer.
    I64(i64),
    /// Opaque bytes.
    Bytes(&'a [u8]),
}

impl<'a> RecordId<'a> {
    /// Creates a record ID from opaque bytes.
    #[must_use]
    pub const fn from_bytes(bytes: &'a [u8]) -> Self {
        Self::Bytes(bytes)
    }

    /// Creates a record ID from any [`RecordIdType`], such as an application's
    /// own ID newtype, with that type's kind and value.
    #[must_use]
    pub fn of<T: RecordIdType>(id: &'a T) -> Self {
        id.repr().record_id()
    }

    pub(crate) const fn kind(&self) -> RecordKind {
        match self {
            Self::Uuid(_) => RecordKind::Uuid,
            Self::I64(_) => RecordKind::I64,
            Self::Bytes(_) => RecordKind::Bytes,
        }
    }
}

impl From<[u8; 16]> for RecordId<'_> {
    fn from(uuid: [u8; 16]) -> Self {
        Self::Uuid(uuid)
    }
}

#[cfg(feature = "uuid")]
impl From<uuid::Uuid> for RecordId<'_> {
    fn from(uuid: uuid::Uuid) -> Self {
        Self::Uuid(*uuid.as_bytes())
    }
}

impl From<i64> for RecordId<'_> {
    fn from(value: i64) -> Self {
        Self::I64(value)
    }
}

/// One part of a binding's encoding: an ID and a value kind.
///
/// A record is bound as the one part, under the nil part ID. See
/// ../docs/wire-format.md#binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PartSpec {
    id: [u8; 16],
    kind: RecordKind,
}

impl PartSpec {
    const fn record(kind: RecordKind) -> Self {
        Self { id: [0; 16], kind }
    }
}

/// The persistent declaration of a binding: the record's kind, when it binds
/// one.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BindingDeclaration {
    record: Option<RecordKind>,
}

impl BindingDeclaration {
    pub(crate) const fn new(record: Option<RecordKind>) -> Self {
        Self { record }
    }

    /// Every part of the declaration: the record's, if it binds one.
    fn specs(self) -> Vec<PartSpec> {
        self.record.map(PartSpec::record).into_iter().collect()
    }

    /// Fingerprints the declaration.
    pub(crate) fn fingerprint(self) -> [u8; 8] {
        encoding::fingerprint(&self.specs())
    }
}

/// A binding resolved for the cryptographic core, or a blind index's.
///
/// The encoded bytes are the domain separator that encryption mixes into key
/// derivation and AAD, and that a blind index mixes into its MAC input. The
/// binding fingerprint is recorded in the envelope and checked by readers. The
/// domain starts with the 16 bytes of an identity, a seal ID, which it does not
/// interpret; choosing keys is the typed layer's.
#[derive(Clone, Debug)]
pub(crate) struct BindingDomain {
    encoded: Vec<u8>,
    fingerprint: [u8; 8],
}

impl BindingDomain {
    /// Encodes the binding of seal `id` under `declaration`, with its record's
    /// value if the declaration binds one.
    ///
    /// A record the declaration does not bind, a missing record, and a record
    /// of another kind are [`Error::InvalidBinding`].
    pub(crate) fn new(
        id: &[u8; 16],
        declaration: BindingDeclaration,
        record: Option<RecordId<'_>>,
    ) -> Result<Self, Error> {
        let record = match (declaration.record, record) {
            (Some(kind), Some(record)) if record.kind() == kind => {
                Some((PartSpec::record(kind), record))
            }
            (None, None) => None,
            _ => return Err(Error::InvalidBinding),
        };

        Ok(Self {
            encoded: encoding::encode(id, record.iter().map(|(spec, value)| (spec, value)))?,
            fingerprint: declaration.fingerprint(),
        })
    }

    /// Encodes the binding of seal `id`, which binds record `R`, with the
    /// record's value if `R` is one.
    pub(crate) fn record<R: OptionalRecordId>(
        id: &[u8; 16],
        record: Option<RecordId<'_>>,
    ) -> Result<Self, Error> {
        Self::new(id, BindingDeclaration::new(R::RECORD), record)
    }

    /// Encodes the blind-index domain of seal `id`: the seal ID alone, the
    /// empty binding, since a query cannot know a record.
    // See ../docs/wire-format.md#index-binding.
    pub(crate) fn index(id: &[u8; 16]) -> Self {
        Self {
            encoded: encoding::encode(id, std::iter::empty())
                .expect("the empty binding always encodes"),
            fingerprint: BindingDeclaration::new(None).fingerprint(),
        }
    }

    /// The binding fingerprint the envelope header carries.
    pub(crate) fn fingerprint(&self) -> [u8; 8] {
        self.fingerprint
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal_id;

    const SEAL: [u8; 16] = *seal_id!("12345678-1234-4234-8234-1234567890ab").as_bytes();

    fn domain(
        record: Option<RecordKind>,
        value: Option<RecordId<'_>>,
    ) -> Result<BindingDomain, Error> {
        BindingDomain::new(&SEAL, BindingDeclaration::new(record), value)
    }

    fn hex_array(value: &str) -> [u8; 8] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    #[test]
    fn the_empty_binding_is_the_seal_id_without_parts() {
        let domain = domain(None, None).unwrap();

        // docs/wire-format.md#binding
        assert_eq!(
            hex::encode(domain.as_bytes()),
            "123456781234423482341234567890ab0000"
        );
        // Independently computed with shasum over the documented empty declaration.
        assert_eq!(domain.fingerprint(), hex_array("65640fc8333534b9"));
        assert_eq!(BindingDomain::index(&SEAL).as_bytes(), domain.as_bytes());
    }

    #[test]
    fn a_record_is_one_part_under_the_nil_id() {
        let domain = domain(Some(RecordKind::I64), Some(RecordId::I64(1))).unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            concat!(
                "123456781234423482341234567890ab",
                "0001",
                "00000000000000000000000000000000",
                "02",
                "00000008",
                "0000000000000001",
            )
        );
        // Independently computed with shasum over the documented declaration bytes.
        assert_eq!(domain.fingerprint(), hex_array("76081b730530f822"));
    }

    #[test]
    fn a_bytes_record_is_length_prefixed() {
        let domain = domain(Some(RecordKind::Bytes), Some(RecordId::Bytes(b"row-7"))).unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
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
    fn records_of_different_kinds_never_collide() {
        let bytes = domain(
            Some(RecordKind::Bytes),
            Some(RecordId::Bytes(&7_i64.to_be_bytes())),
        );
        let number = domain(Some(RecordKind::I64), Some(RecordId::I64(7)));

        assert_ne!(bytes.unwrap().as_bytes(), number.unwrap().as_bytes());
        // The record's kind is declared.
        assert_ne!(
            BindingDeclaration::new(Some(RecordKind::I64)).fingerprint(),
            BindingDeclaration::new(Some(RecordKind::Bytes)).fingerprint(),
        );
    }

    #[test]
    fn an_empty_record_differs_from_no_record() {
        assert_ne!(
            domain(None, None).unwrap().as_bytes(),
            domain(Some(RecordKind::Bytes), Some(RecordId::Bytes(b"")))
                .unwrap()
                .as_bytes(),
        );
    }

    #[test]
    fn invalid_records_are_rejected() {
        let uuid = RecordId::Uuid([0x33; 16]);
        let cases = [
            ("missing record", domain(Some(RecordKind::Uuid), None)),
            (
                "record of another kind",
                domain(Some(RecordKind::I64), Some(uuid)),
            ),
            ("unexpected record", domain(None, Some(uuid))),
        ];

        for (case, result) in cases {
            assert_eq!(result.unwrap_err(), Error::InvalidBinding, "{case}");
        }
    }
}
