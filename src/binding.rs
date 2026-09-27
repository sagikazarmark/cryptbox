// Only tests reach the scoped-binding encoder until the public `Binding` API
// wires it to fields (#99).
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "scoped bindings are not yet public")
)]

use std::fmt;

use sha2::{Digest, Sha256};

use crate::{Error, FieldId};

// A persistent domain separator, not a display string. See ../docs/wire-format.md#shape-fingerprint.
const SHAPE_LABEL: &[u8] = b"cryptbox/binding-shape/v1\0";

/// The canonical kind of a part or record value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PartKind {
    Uuid,
    I64,
    Bytes,
}

impl PartKind {
    // Kind codes are persistent binding bytes. See ../docs/wire-format.md#scoped-binding.
    const fn code(self) -> u8 {
        match self {
            Self::Uuid => 1,
            Self::I64 => 2,
            Self::Bytes => 3,
        }
    }
}

/// What a part scopes beyond the ciphertext itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PartRole {
    /// Scopes key custody and blind indexes; the unit you shred.
    Keys,
    /// Scopes blind indexes only.
    Index,
    /// Bound into the ciphertext only.
    Bound,
}

impl PartRole {
    // Role codes are persistent fingerprint input. See ../docs/wire-format.md#shape-fingerprint.
    const fn code(self) -> u8 {
        match self {
            Self::Keys => 1,
            Self::Index => 2,
            Self::Bound => 3,
        }
    }
}

/// One declared part of a binding shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PartSpec {
    id: [u8; 16],
    kind: PartKind,
    role: PartRole,
}

impl PartSpec {
    pub(crate) const fn new(id: [u8; 16], kind: PartKind, role: PartRole) -> Self {
        Self { id, kind, role }
    }
}

/// A runtime part or record value.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PartValue<'a> {
    Uuid([u8; 16]),
    I64(i64),
    Bytes(&'a [u8]),
}

impl PartValue<'_> {
    fn kind(&self) -> PartKind {
        match self {
            Self::Uuid(_) => PartKind::Uuid,
            Self::I64(_) => PartKind::I64,
            Self::Bytes(_) => PartKind::Bytes,
        }
    }

    // Kind-tagged and length-prefixed, so no two values of any kinds share bytes.
    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), Error> {
        let i64_bytes;
        let bytes: &[u8] = match self {
            Self::Uuid(uuid) => uuid,
            Self::I64(value) => {
                i64_bytes = value.to_be_bytes();
                &i64_bytes
            }
            Self::Bytes(bytes) => bytes,
        };
        let len = u32::try_from(bytes.len()).map_err(|_| Error::InvalidBinding)?;

        output.push(self.kind().code());
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(bytes);

        Ok(())
    }
}

/// The persistent shape of a binding: its declared parts and whether it binds a record.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BindingShape<'a> {
    parts: &'a [PartSpec],
    record: bool,
}

impl<'a> BindingShape<'a> {
    pub(crate) const fn new(parts: &'a [PartSpec], record: bool) -> Self {
        Self { parts, record }
    }

    /// Checks the shape's own invariants: at least one part or a record, and
    /// unique, non-nil part IDs.
    ///
    /// Without parts or a record, the binding is field-only and uses tag `01`.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let mut ids: Vec<_> = self.parts.iter().map(|spec| spec.id).collect();
        ids.sort_unstable();
        let duplicate = ids.windows(2).any(|pair| pair[0] == pair[1]);

        if (ids.is_empty() && !self.record) || ids.contains(&[0; 16]) || duplicate {
            return Err(Error::InvalidBinding);
        }

        Ok(())
    }

    /// Fingerprints the shape; declaration order does not matter.
    pub(crate) fn fingerprint(&self) -> ShapeFingerprint {
        let mut parts = self.parts.to_vec();
        parts.sort_by_key(|spec| spec.id);
        // A count that does not fit is rejected when the binding is encoded.
        let count = u16::try_from(parts.len()).unwrap_or(u16::MAX);

        // Preserve this canonical order: stored headers carry the result.
        // See ../docs/wire-format.md#shape-fingerprint.
        let mut hasher = Sha256::new();
        hasher.update(SHAPE_LABEL);
        hasher.update([u8::from(self.record)]);
        hasher.update(count.to_be_bytes());
        for spec in parts {
            hasher.update(spec.id);
            hasher.update([spec.kind.code(), spec.role.code()]);
        }

        let digest = hasher.finalize();
        let mut fingerprint = [0_u8; 8];
        fingerprint.copy_from_slice(&digest[..8]);

        ShapeFingerprint(fingerprint)
    }
}

/// A 64-bit fingerprint of a binding's shape: its part IDs, kinds, and roles,
/// and whether it binds a record.
///
/// A scoped ciphertext header carries the fingerprint of the shape it was
/// sealed with. It is diagnostic only: a reader always takes the expected shape
/// from its own field, and reports [`Error::BindingMismatch`] when the stored
/// fingerprint disagrees. See the [wire format].
///
#[doc = concat!(
    "[wire format]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/wire-format.md#shape-fingerprint",
)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ShapeFingerprint([u8; 8]);

impl ShapeFingerprint {
    /// Creates a fingerprint from its stored 8-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Returns the stored 8-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Display for ShapeFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|byte| write!(formatter, "{byte:02x}"))
    }
}

impl fmt::Debug for ShapeFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ShapeFingerprint")
            .field(&format_args!("{self}"))
            .finish()
    }
}

/// Canonical binding bytes passed to the cryptographic core.
#[derive(Clone, Debug)]
pub(crate) struct BindingDomain {
    field: FieldId,
    encoded: Vec<u8>,
    fingerprint: Option<ShapeFingerprint>,
}

impl BindingDomain {
    // The tag and UUID bytes are persistent KDF/AAD inputs, independent of
    // Rust names. Tag `00` is reserved. See ../docs/wire-format.md#binding.
    const FIELD_TAG: u8 = 1;
    const SCOPED_TAG: u8 = 2;
    const NO_RECORD: u8 = 0;

    pub(crate) fn field(id: FieldId) -> Self {
        let mut encoded = Vec::with_capacity(17);
        encoded.push(Self::FIELD_TAG);
        encoded.extend_from_slice(id.as_bytes());

        Self {
            field: id,
            encoded,
            fingerprint: None,
        }
    }

    /// Encodes a field's declared parts, in any order, with their values.
    ///
    /// `values` follows the order of `shape`'s parts.
    pub(crate) fn scoped(
        id: FieldId,
        shape: BindingShape<'_>,
        values: &[PartValue<'_>],
        record: Option<PartValue<'_>>,
    ) -> Result<Self, Error> {
        shape.validate()?;
        if shape.parts.len() != values.len() || shape.record != record.is_some() {
            return Err(Error::InvalidBinding);
        }

        let mut parts: Vec<_> = shape.parts.iter().zip(values).collect();
        // Sorting makes the bytes independent of declaration order.
        // See ../docs/wire-format.md#scoped-binding.
        parts.sort_by_key(|(spec, _)| spec.id);
        let count = u16::try_from(parts.len()).map_err(|_| Error::InvalidBinding)?;

        for (spec, value) in &parts {
            let empty_keys = spec.role == PartRole::Keys && matches!(value, PartValue::Bytes([]));
            if spec.kind != value.kind() || empty_keys {
                return Err(Error::InvalidBinding);
            }
        }

        let mut encoded = Vec::new();
        encoded.push(Self::SCOPED_TAG);
        encoded.extend_from_slice(id.as_bytes());
        match record {
            Some(record) => record.encode_into(&mut encoded)?,
            None => encoded.push(Self::NO_RECORD),
        }
        encoded.extend_from_slice(&count.to_be_bytes());
        for (spec, value) in parts {
            encoded.extend_from_slice(&spec.id);
            value.encode_into(&mut encoded)?;
        }

        Ok(Self {
            field: id,
            encoded,
            fingerprint: Some(shape.fingerprint()),
        })
    }

    pub(crate) fn field_id(&self) -> FieldId {
        self.field
    }

    /// The shape fingerprint a scoped header carries; `None` for a field-only binding.
    pub(crate) fn fingerprint(&self) -> Option<ShapeFingerprint> {
        self.fingerprint
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_id;

    const FIELD: FieldId = field_id!("12345678-1234-4234-8234-1234567890ab");

    #[test]
    fn field_only_binding_keeps_tag_01() {
        assert_eq!(
            hex::encode(BindingDomain::field(FIELD).as_bytes()),
            "01123456781234423482341234567890ab"
        );
    }

    const TENANT: PartSpec = PartSpec::new([0x11; 16], PartKind::Uuid, PartRole::Keys);
    const SEQUENCE: PartSpec = PartSpec::new([0xaa; 16], PartKind::I64, PartRole::Bound);

    #[test]
    fn scoped_binding_sorts_and_frames_parts() {
        // Declared out of order: the encoding sorts parts by part ID.
        let domain = BindingDomain::scoped(
            FIELD,
            BindingShape::new(&[SEQUENCE, TENANT], false),
            &[PartValue::I64(-2), PartValue::Uuid([0x33; 16])],
            None,
        )
        .unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            concat!(
                "02",
                "123456781234423482341234567890ab",
                "00",
                "0002",
                "11111111111111111111111111111111",
                "01",
                "00000010",
                "33333333333333333333333333333333",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "02",
                "00000008",
                "fffffffffffffffe",
            )
        );
    }

    #[test]
    fn scoped_binding_tags_the_record_kind() {
        let domain = BindingDomain::scoped(
            FIELD,
            BindingShape::new(&[TENANT], true),
            &[PartValue::Uuid([0x33; 16])],
            Some(PartValue::Bytes(b"row-7")),
        )
        .unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            concat!(
                "02",
                "123456781234423482341234567890ab",
                "03",
                "00000005",
                "726f772d37",
                "0001",
                "11111111111111111111111111111111",
                "01",
                "00000010",
                "33333333333333333333333333333333",
            )
        );
    }

    const LEFT: PartSpec = PartSpec::new([0x21; 16], PartKind::Bytes, PartRole::Bound);
    const RIGHT: PartSpec = PartSpec::new([0x22; 16], PartKind::Bytes, PartRole::Bound);

    fn bytes_of(
        parts: &[PartSpec],
        values: &[PartValue<'_>],
        record: Option<PartValue<'_>>,
    ) -> Vec<u8> {
        BindingDomain::scoped(
            FIELD,
            BindingShape::new(parts, record.is_some()),
            values,
            record,
        )
        .unwrap()
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn part_boundaries_are_unambiguous() {
        assert_ne!(
            bytes_of(
                &[LEFT, RIGHT],
                &[PartValue::Bytes(b"ab"), PartValue::Bytes(b"c")],
                None
            ),
            bytes_of(
                &[LEFT, RIGHT],
                &[PartValue::Bytes(b"a"), PartValue::Bytes(b"bc")],
                None
            ),
        );
    }

    #[test]
    fn an_empty_record_differs_from_no_record() {
        assert_ne!(
            bytes_of(&[LEFT], &[PartValue::Bytes(b"x")], None),
            bytes_of(
                &[LEFT],
                &[PartValue::Bytes(b"x")],
                Some(PartValue::Bytes(b""))
            ),
        );
    }

    #[test]
    fn values_of_different_kinds_never_collide() {
        let as_bytes = PartSpec::new([0x21; 16], PartKind::Bytes, PartRole::Bound);
        let as_i64 = PartSpec::new([0x21; 16], PartKind::I64, PartRole::Bound);
        let as_uuid = PartSpec::new([0x21; 16], PartKind::Uuid, PartRole::Bound);

        assert_ne!(
            bytes_of(&[as_bytes], &[PartValue::Bytes(&7_i64.to_be_bytes())], None),
            bytes_of(&[as_i64], &[PartValue::I64(7)], None),
        );
        assert_ne!(
            bytes_of(&[as_bytes], &[PartValue::Bytes(&[0x33; 16])], None),
            bytes_of(&[as_uuid], &[PartValue::Uuid([0x33; 16])], None),
        );
        assert_ne!(
            bytes_of(
                &[LEFT],
                &[PartValue::Bytes(b"x")],
                Some(PartValue::Bytes(&7_i64.to_be_bytes()))
            ),
            bytes_of(&[LEFT], &[PartValue::Bytes(b"x")], Some(PartValue::I64(7))),
        );
    }

    fn scoped(
        parts: &[PartSpec],
        record: bool,
        values: &[PartValue<'_>],
        record_value: Option<PartValue<'_>>,
    ) -> Result<BindingDomain, Error> {
        BindingDomain::scoped(
            FIELD,
            BindingShape::new(parts, record),
            values,
            record_value,
        )
    }

    #[test]
    fn invalid_bindings_are_rejected() {
        let uuid = PartValue::Uuid([0x33; 16]);
        let nil = PartSpec::new([0; 16], PartKind::Uuid, PartRole::Bound);
        let empty_keys = PartSpec::new([0x21; 16], PartKind::Bytes, PartRole::Keys);
        let cases: [(&str, Result<BindingDomain, Error>); 9] = [
            ("no parts and no record", scoped(&[], false, &[], None)),
            (
                "duplicate part ID",
                scoped(&[TENANT, TENANT], false, &[uuid, uuid], None),
            ),
            ("nil part ID", scoped(&[nil], false, &[uuid], None)),
            ("missing value", scoped(&[TENANT], false, &[], None)),
            ("extra value", scoped(&[TENANT], false, &[uuid, uuid], None)),
            (
                "kind mismatch",
                scoped(&[TENANT], false, &[PartValue::I64(1)], None),
            ),
            (
                "empty keys value",
                scoped(&[empty_keys], false, &[PartValue::Bytes(b"")], None),
            ),
            ("missing record", scoped(&[TENANT], true, &[uuid], None)),
            (
                "unexpected record",
                scoped(&[TENANT], false, &[uuid], Some(uuid)),
            ),
        ];

        for (case, result) in cases {
            assert_eq!(result.unwrap_err(), Error::InvalidBinding, "{case}");
        }
    }

    #[test]
    fn shape_fingerprint_is_truncated_sha256_of_the_sorted_shape() {
        // Independently computed with shasum over the documented shape bytes.
        assert_eq!(
            BindingShape::new(&[SEQUENCE, TENANT], false).fingerprint(),
            ShapeFingerprint::from_bytes(hex_array("f93e3f05d673ab72")),
        );
        assert_eq!(
            BindingShape::new(&[TENANT], true).fingerprint(),
            ShapeFingerprint::from_bytes(hex_array("f99c70ac24ad8a9a")),
        );
    }

    #[test]
    fn shape_fingerprint_ignores_declaration_order_but_not_roles() {
        let fingerprint = BindingShape::new(&[SEQUENCE, TENANT], false).fingerprint();
        let index_tenant = PartSpec::new([0x11; 16], PartKind::Uuid, PartRole::Index);

        assert_eq!(
            BindingShape::new(&[TENANT, SEQUENCE], false).fingerprint(),
            fingerprint
        );
        assert_ne!(
            BindingShape::new(&[SEQUENCE, index_tenant], false).fingerprint(),
            fingerprint
        );
        assert_ne!(
            BindingShape::new(&[SEQUENCE, TENANT], true).fingerprint(),
            fingerprint
        );
    }

    #[test]
    fn scoped_domain_carries_its_shape_fingerprint() {
        let shape = BindingShape::new(&[TENANT], false);
        let domain = scoped(&[TENANT], false, &[PartValue::Uuid([0x33; 16])], None).unwrap();

        assert_eq!(domain.fingerprint(), Some(shape.fingerprint()));
        assert_eq!(BindingDomain::field(FIELD).fingerprint(), None);
    }

    fn hex_array(value: &str) -> [u8; 8] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    #[test]
    fn a_record_alone_is_a_scoped_binding() {
        let domain = scoped(&[], true, &[], Some(PartValue::I64(1))).unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            "02123456781234423482341234567890ab02000000080000000000000001 0000".replace(' ', "")
        );
    }
}
