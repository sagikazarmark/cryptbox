use std::{fmt, hash::Hash};

use sha2::{Digest, Sha256};

use crate::{Error, FieldId, PartId};

mod args;
mod part;
mod presets;
mod scope;

pub use args::Args;
pub(crate) use args::{domain, domains};
pub use part::PartType;
pub use presets::{FieldOnly, Tenant, TenantId};
pub use scope::KeyScope;

// A persistent domain separator, not a display string. See ../docs/wire-format.md#shape-fingerprint.
const SHAPE_LABEL: &[u8] = b"cryptbox/binding-shape/v1\0";

/// The declared scope a field's values are bound to, such as a tenant, or an
/// org plus a workspace.
///
/// A binding is data only. [`PARTS`](Self::PARTS) declares the shape: each
/// part's ID, value kind, and [role](PartRole). [`values`](Self::values)
/// supplies the runtime values in the same order. `CryptBox` frames and
/// validates them; implementations never write bytes. The shape is persistent
/// schema: changing a part ID, kind, or role is a migration. See [ADR-0005] and
/// the [wire format].
///
/// A record ID is not a part. Whether a field binds a record is declared on the
/// field, and the record is always bound only: it never scopes keys or blind
/// indexes, since a record-scoped index could not be searched.
///
/// # Checks
///
/// `PARTS` must be sorted by part ID in ascending byte order, without
/// duplicates or nil IDs. A violation fails the build when the binding is first
/// used. The check runs after monomorphization, so `cargo check` does not
/// report it; `cargo build` and `cargo test` do. A record can never be
/// declared as a `keys` or `index` part, because it is not a part at all.
///
/// Supplied values are checked at each call: [`Error::InvalidBinding`] reports
/// a missing or extra value, a value of the wrong kind, or an empty `keys`
/// value.
///
/// # Shredding
///
/// Destroying root keys makes every value sealed under them unreadable. The
/// unit you can shred is the finest [`keys`](PartRole::Keys) part whose root keys
/// are stored independently: if every org has its own root keys, one org can be
/// shredded; its workspaces, bound only, cannot be shredded on their own.
///
/// # Examples
///
/// ```
/// use cryptbox::{Binding, KeyScope, PartKind, PartSpec, PartValue, PartValues};
///
/// /// An org scopes keys and blind indexes; a workspace is only bound.
/// #[derive(Clone, Hash, PartialEq, Eq)]
/// struct OrgWorkspace {
///     org: [u8; 16],
///     workspace: [u8; 16],
/// }
///
/// /// The parts a blind-index query knows: the org.
/// #[derive(Clone, Hash, PartialEq, Eq)]
/// struct OrgSearch {
///     org: [u8; 16],
/// }
///
/// impl Binding for OrgWorkspace {
///     // Sorted by part ID.
///     const PARTS: &'static [PartSpec] = &[
///         PartSpec::keys(cryptbox::part_id!("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90"), PartKind::Uuid),
///         PartSpec::bound(cryptbox::part_id!("c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48"), PartKind::Uuid),
///     ];
///     type IndexArgs = OrgSearch;
///
///     fn values(&self) -> PartValues<'_> {
///         PartValues::from([PartValue::Uuid(self.org), PartValue::Uuid(self.workspace)])
///     }
///
///     fn index_values(args: &OrgSearch) -> PartValues<'_> {
///         PartValues::from([PartValue::Uuid(args.org)])
///     }
/// }
///
/// let scope = OrgWorkspace { org: [1; 16], workspace: [2; 16] };
/// let search = OrgSearch { org: [1; 16] };
///
/// assert_eq!(KeyScope::of(&scope)?, KeyScope::of_index::<OrgWorkspace>(&search)?);
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// With the `derive` feature, `#[derive(Binding)]` writes exactly this impl, and
/// generates `OrgSearch`, from `#[cryptbox(index_args = OrgSearch)]` on the
/// struct, `#[cryptbox(part = "3a1f0c6e-…", keys)]` on `org`, and
/// `#[cryptbox(part = "c7d24e19-…")]` on `workspace`. It sorts the parts and
/// checks their IDs when it expands; [`PartType`] maps each field's type to
/// its kind.
///
/// Unsorted parts fail the build:
///
/// ```compile_fail,E0080
/// use cryptbox::{Binding, KeyScope, PartKind, PartSpec, PartValue, PartValues};
///
/// #[derive(Clone, Hash, PartialEq, Eq)]
/// struct Unsorted;
///
/// impl Binding for Unsorted {
///     const PARTS: &'static [PartSpec] = &[
///         PartSpec::keys(cryptbox::part_id!("c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48"), PartKind::I64),
///         PartSpec::bound(cryptbox::part_id!("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90"), PartKind::I64),
///     ];
///     type IndexArgs = ();
///
///     fn values(&self) -> PartValues<'_> {
///         PartValues::from([PartValue::I64(1), PartValue::I64(2)])
///     }
///
///     fn index_values((): &()) -> PartValues<'_> {
///         PartValues::from([PartValue::I64(1)])
///     }
/// }
///
/// let _ = KeyScope::of(&Unsorted);
/// ```
///
/// So do duplicate part IDs:
///
/// ```compile_fail,E0080
/// use cryptbox::{Binding, KeyScope, PartKind, PartSpec, PartValue, PartValues};
///
/// #[derive(Clone, Hash, PartialEq, Eq)]
/// struct Duplicate;
///
/// impl Binding for Duplicate {
///     const PARTS: &'static [PartSpec] = &[
///         PartSpec::keys(cryptbox::part_id!("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90"), PartKind::I64),
///         PartSpec::bound(cryptbox::part_id!("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90"), PartKind::I64),
///     ];
///     type IndexArgs = ();
///
///     fn values(&self) -> PartValues<'_> {
///         PartValues::from([PartValue::I64(1), PartValue::I64(2)])
///     }
///
///     fn index_values((): &()) -> PartValues<'_> {
///         PartValues::from([PartValue::I64(1)])
///     }
/// }
///
/// let _ = KeyScope::of(&Duplicate);
/// ```
///
#[doc = concat!(
    "[ADR-0005]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/adr/0005-runtime-binding-is-the-core.md\n",
    "[wire format]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/wire-format.md#scoped-binding",
)]
pub trait Binding: Clone + Hash + Eq + Send + Sync + 'static {
    /// The declared parts, sorted by part ID.
    const PARTS: &'static [PartSpec];

    /// The query-time arguments of a blind index: the values of the
    /// [`keys`](PartRole::Keys) and [`index`](PartRole::Index) parts.
    ///
    /// A query knows its scope but has no record, so it cannot supply a whole
    /// binding.
    type IndexArgs: Clone + Hash + Eq + Send + Sync + 'static;

    /// Returns one value for each of [`PARTS`](Self::PARTS), in the same order.
    fn values(&self) -> PartValues<'_>;

    /// Returns one value for each `keys` and `index` part, in
    /// [`PARTS`](Self::PARTS) order.
    ///
    /// These must equal the values [`values`](Self::values) returns for the same
    /// parts: a sealed value's prepared indexes take their scope from its
    /// binding, and probes take theirs from these arguments.
    fn index_values(args: &Self::IndexArgs) -> PartValues<'_>;
}

// Rejects shapes whose bytes or fingerprint would depend on declaration order,
// or that could not be encoded. Panics become build errors in `const` context.
pub(crate) const fn check_parts(parts: &[PartSpec]) {
    let mut index = 0;
    while index < parts.len() {
        let id = u128::from_be_bytes(parts[index].id);
        assert!(id != 0, "binding part IDs must not be nil");
        if index > 0 {
            assert!(
                u128::from_be_bytes(parts[index - 1].id) < id,
                "binding PARTS must be sorted by part ID without duplicates"
            );
        }
        index += 1;
    }
}

/// Checks that `values` holds exactly one value per spec, in order, of the
/// spec's kind, and that no `keys` value is empty.
fn check_values<'s>(
    specs: impl IntoIterator<Item = &'s PartSpec>,
    values: &[PartValue<'_>],
) -> Result<(), Error> {
    let mut values = values.iter();
    for spec in specs {
        let value = values.next().ok_or(Error::InvalidBinding)?;
        let empty_keys = spec.role == PartRole::Keys && matches!(value, PartValue::Bytes([]));
        if spec.kind != value.kind() || empty_keys {
            return Err(Error::InvalidBinding);
        }
    }

    match values.next() {
        Some(_) => Err(Error::InvalidBinding),
        None => Ok(()),
    }
}

/// The canonical kind of a part or record value.
///
/// Kinds are fixed: there is no text kind. Encode text as bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PartKind {
    /// A 16-byte UUID.
    Uuid,
    /// A signed 64-bit integer.
    I64,
    /// Opaque bytes.
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
///
/// Every part is bound into the ciphertext. The role is persistent schema:
/// changing it changes index derivation and key custody.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PartRole {
    /// Scopes key custody and blind indexes, and is the unit you shred.
    ///
    /// A `keys` value can't be empty, and must be known before rows are read.
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

    const fn scopes_index(self) -> bool {
        matches!(self, Self::Keys | Self::Index)
    }
}

/// One declared part of a binding shape: its ID, value kind, and role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartSpec {
    id: [u8; 16],
    kind: PartKind,
    role: PartRole,
}

impl PartSpec {
    pub(crate) const fn new(id: [u8; 16], kind: PartKind, role: PartRole) -> Self {
        Self { id, kind, role }
    }

    /// Declares a part that scopes key custody and blind indexes.
    #[must_use]
    pub const fn keys(id: PartId, kind: PartKind) -> Self {
        Self::new(*id.as_bytes(), kind, PartRole::Keys)
    }

    /// Declares a part that scopes blind indexes only.
    #[must_use]
    pub const fn index(id: PartId, kind: PartKind) -> Self {
        Self::new(*id.as_bytes(), kind, PartRole::Index)
    }

    /// Declares a part that is only bound into the ciphertext.
    #[must_use]
    pub const fn bound(id: PartId, kind: PartKind) -> Self {
        Self::new(*id.as_bytes(), kind, PartRole::Bound)
    }

    /// Returns the part ID.
    #[must_use]
    pub const fn id(&self) -> PartId {
        PartId::from_bytes(self.id)
    }

    /// Returns the value kind.
    #[must_use]
    pub const fn kind(&self) -> PartKind {
        self.kind
    }

    /// Returns the role.
    #[must_use]
    pub const fn role(&self) -> PartRole {
        self.role
    }
}

/// A runtime part value.
#[derive(Clone, Copy, Debug)]
pub enum PartValue<'a> {
    /// A 16-byte UUID.
    Uuid([u8; 16]),
    /// A signed 64-bit integer.
    I64(i64),
    /// Opaque bytes.
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

/// The values of a binding's parts, in declared order.
#[derive(Clone, Debug, Default)]
pub struct PartValues<'a>(Vec<PartValue<'a>>);

impl PartValues<'_> {
    /// Returns no values, for a binding without parts.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }
}

impl<'a, const N: usize> From<[PartValue<'a>; N]> for PartValues<'a> {
    fn from(values: [PartValue<'a>; N]) -> Self {
        Self(values.into())
    }
}

impl<'a> FromIterator<PartValue<'a>> for PartValues<'a> {
    fn from_iter<I: IntoIterator<Item = PartValue<'a>>>(values: I) -> Self {
        Self(values.into_iter().collect())
    }
}

/// The ID of the record a value is bound to, tagged with its kind.
///
/// A record is always bound only: it never scopes keys or blind indexes. The
/// kind is part of the binding, so the same number as an `i64` and as bytes
/// binds different records.
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

impl<'a> RecordId<'a> {
    // Records share the part value encoding, kind codes included.
    const fn part_value(self) -> PartValue<'a> {
        match self {
            Self::Uuid(uuid) => PartValue::Uuid(uuid),
            Self::I64(value) => PartValue::I64(value),
            Self::Bytes(bytes) => PartValue::Bytes(bytes),
        }
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
    key_scope: KeyScope,
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
            key_scope: KeyScope::empty(),
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
        if shape.record != record.is_some() {
            return Err(Error::InvalidBinding);
        }
        check_values(shape.parts, values)?;

        let mut parts: Vec<_> = shape.parts.iter().zip(values).collect();
        // Sorting makes the bytes independent of declaration order.
        // See ../docs/wire-format.md#scoped-binding.
        parts.sort_by_key(|(spec, _)| spec.id);
        let count = u16::try_from(parts.len()).map_err(|_| Error::InvalidBinding)?;
        let key_scope = KeyScope::keys_of(parts.iter().copied());

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
            key_scope,
        })
    }

    /// Encodes `binding` for field `id`: field-only when it has no parts and
    /// no record, scoped otherwise.
    pub(crate) fn of<B: Binding>(
        id: FieldId,
        binding: &B,
        record: Option<RecordId<'_>>,
    ) -> Result<Self, Error> {
        const { check_parts(B::PARTS) };

        let values = binding.values();
        if B::PARTS.is_empty() && record.is_none() {
            return if values.0.is_empty() {
                Ok(Self::field(id))
            } else {
                Err(Error::InvalidBinding)
            };
        }

        Self::scoped(
            id,
            BindingShape::new(B::PARTS, record.is_some()),
            &values.0,
            record.map(RecordId::part_value),
        )
    }

    /// Encodes the blind-index domain of field `id` under a query's arguments.
    ///
    /// The domain is the binding restricted to its `keys` and `index` parts,
    /// without a record: field-only when the binding has no such parts.
    // See ../docs/wire-format.md#index-binding.
    pub(crate) fn index<B: Binding>(id: FieldId, args: &B::IndexArgs) -> Result<Self, Error> {
        const { check_parts(B::PARTS) };

        let specs: Vec<_> = B::PARTS
            .iter()
            .copied()
            .filter(|spec| spec.role.scopes_index())
            .collect();

        Self::index_parts(id, &specs, &B::index_values(args).0)
    }

    /// Encodes the blind-index domain of field `id` under a whole binding: the
    /// same domain as [`Self::index`] under the binding's `keys` and `index`
    /// values.
    pub(crate) fn index_of<B: Binding>(id: FieldId, binding: &B) -> Result<Self, Error> {
        const { check_parts(B::PARTS) };

        let values = binding.values();
        check_values(B::PARTS, &values.0)?;
        let (specs, values): (Vec<_>, Vec<_>) = B::PARTS
            .iter()
            .copied()
            .zip(values.0)
            .filter(|(spec, _)| spec.role.scopes_index())
            .unzip();

        Self::index_parts(id, &specs, &values)
    }

    fn index_parts(
        id: FieldId,
        specs: &[PartSpec],
        values: &[PartValue<'_>],
    ) -> Result<Self, Error> {
        if specs.is_empty() {
            return if values.is_empty() {
                Ok(Self::field(id))
            } else {
                Err(Error::InvalidBinding)
            };
        }

        Self::scoped(id, BindingShape::new(specs, false), values, None)
    }

    pub(crate) fn field_id(&self) -> FieldId {
        self.field
    }

    /// The shape fingerprint a scoped header carries; `None` for a field-only binding.
    pub(crate) fn fingerprint(&self) -> Option<ShapeFingerprint> {
        self.fingerprint
    }

    /// The `keys` parts of the binding, passed to key sources.
    pub(crate) const fn key_scope(&self) -> &KeyScope {
        &self.key_scope
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{field_id, part_id};

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

    /// An org is the key scope; a workspace is only bound.
    #[derive(Clone, Hash, PartialEq, Eq)]
    struct OrgWorkspace {
        org: [u8; 16],
        workspace: Vec<u8>,
    }

    #[derive(Clone, Hash, PartialEq, Eq)]
    struct OrgSearch {
        org: [u8; 16],
    }

    impl Binding for OrgWorkspace {
        const PARTS: &'static [PartSpec] = &[
            PartSpec::keys(
                part_id!("11111111-1111-1111-1111-111111111111"),
                PartKind::Uuid,
            ),
            PartSpec::bound(
                part_id!("22222222-2222-2222-2222-222222222222"),
                PartKind::Bytes,
            ),
        ];
        type IndexArgs = OrgSearch;

        fn values(&self) -> PartValues<'_> {
            PartValues::from([PartValue::Uuid(self.org), PartValue::Bytes(&self.workspace)])
        }

        fn index_values(args: &OrgSearch) -> PartValues<'_> {
            PartValues::from([PartValue::Uuid(args.org)])
        }
    }

    fn ws1() -> OrgWorkspace {
        OrgWorkspace {
            org: [0x33; 16],
            workspace: b"ws-1".to_vec(),
        }
    }

    #[test]
    fn a_two_part_scope_encodes_the_documented_vector() {
        // docs/wire-format.md#provisional-scoped-vectors
        let domain = BindingDomain::of(FIELD, &ws1(), None).unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            "02123456781234423482341234567890ab0000021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31"
        );
        assert_eq!(
            domain.fingerprint(),
            Some(ShapeFingerprint::from_bytes(hex_array("cda083fe6eae1bf1")))
        );
    }

    #[test]
    fn a_two_part_scope_binds_the_record_last_documented_vector() {
        let domain = BindingDomain::of(FIELD, &ws1(), Some(RecordId::from(7_i64))).unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            "02123456781234423482341234567890ab0200000008000000000000000700021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31"
        );
    }

    const LOW: [u8; 16] = [0x11; 16];
    const HIGH: [u8; 16] = [0x22; 16];

    fn part(id: [u8; 16], role: PartRole) -> PartSpec {
        PartSpec::new(id, PartKind::I64, role)
    }

    #[test]
    fn sorted_unique_parts_pass() {
        check_parts(&[]);
        check_parts(&[part(LOW, PartRole::Keys), part(HIGH, PartRole::Bound)]);
    }

    #[test]
    #[should_panic(expected = "sorted by part ID without duplicates")]
    fn unsorted_parts_fail() {
        check_parts(&[part(HIGH, PartRole::Keys), part(LOW, PartRole::Bound)]);
    }

    #[test]
    #[should_panic(expected = "sorted by part ID without duplicates")]
    fn duplicate_parts_fail() {
        check_parts(&[part(LOW, PartRole::Keys), part(LOW, PartRole::Index)]);
    }

    #[test]
    #[should_panic(expected = "must not be nil")]
    fn nil_parts_fail() {
        check_parts(&[part([0; 16], PartRole::Bound)]);
    }
}
