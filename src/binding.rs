use std::hash::Hash;
use std::marker::PhantomData;

use crate::Error;
use crate::id::identifier;

mod encoding;
mod part;
mod presets;

pub use part::PartType;
pub use presets::{Tenant, TenantId};

identifier!(
    PartId,
    "A stable binding-part identifier, independent of Rust names."
);

/// The declared scope a seal's values are bound to, such as a tenant, or an
/// org plus a workspace.
///
/// A scope is data only. [`PARTS`](Self::PARTS) is its declaration: each
/// part's ID and value kind. [`values`](Self::values) supplies the runtime
/// values in the same order. `CryptBox` frames and validates them;
/// implementations never write bytes. The declaration is persistent schema:
/// changing a part ID or kind is a migration. See [ADR-0005], [ADR-0009], and
/// the [wire format].
///
/// Parts have no roles. A scope can be a **view** of another: a scope whose
/// parts are a subset of the other's, matched by part ID and kind, and built
/// from its values with [`FromParts`]. Views say what else a part scopes: a
/// seal's [keys view](crate::Seal::Keys) holds the parts key custody follows,
/// and a blind index's [index scope](crate::BlindIndexSpec::Scope) the parts a
/// query supplies. A part in no view is bound only.
///
/// A record ID is not a part. A seal binds one with the seal scope
/// [`Recorded`], and the record is always bound only: it is in no view, since
/// a record-scoped index could not be searched.
///
/// # Checks
///
/// `PARTS` must be sorted by part ID in ascending byte order, without
/// duplicates or nil IDs. A violation fails the build when the scope is first
/// used. The check runs after monomorphization, so `cargo check` does not
/// report it; `cargo build` and `cargo test` do.
///
/// Supplied values are checked at each call: [`Error::InvalidBinding`] reports
/// a missing or extra value, a value of the wrong kind, or an empty value of a
/// part in the seal's keys view.
///
/// # Shredding
///
/// Destroying root keys makes every value sealed under them unreadable. The
/// unit you can shred is the finest part of the keys view whose root keys are
/// stored independently: if every org has its own root keys, one org can be
/// shredded; its workspaces, bound only, cannot be shredded on their own.
///
/// # Examples
///
/// ```
/// use cryptbox::{FromParts, PartKind, PartSpec, PartValue, PartValues, Scope};
///
/// /// An org scopes keys; a workspace is only bound.
/// #[derive(Clone, Hash, PartialEq, Eq)]
/// struct OrgWorkspace {
///     org: [u8; 16],
///     workspace: [u8; 16],
/// }
///
/// impl Scope for OrgWorkspace {
///     // Sorted by part ID.
///     const PARTS: &'static [PartSpec] = &[
///         PartSpec::new(cryptbox::part_id!("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90"), PartKind::Uuid),
///         PartSpec::new(cryptbox::part_id!("c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48"), PartKind::Uuid),
///     ];
///
///     fn values(&self) -> PartValues<'_> {
///         PartValues::from([PartValue::Uuid(self.org), PartValue::Uuid(self.workspace)])
///     }
/// }
///
/// impl FromParts for OrgWorkspace {
///     fn from_parts(values: &[PartValue<'_>]) -> Result<Self, cryptbox::Error> {
///         match values {
///             [PartValue::Uuid(org), PartValue::Uuid(workspace)] => Ok(Self {
///                 org: *org,
///                 workspace: *workspace,
///             }),
///             _ => Err(cryptbox::Error::InvalidBinding),
///         }
///     }
/// }
///
/// let scope = OrgWorkspace { org: [1; 16], workspace: [2; 16] };
///
/// // A scope is built back from its values, as its views are.
/// assert!(OrgWorkspace::from_parts(scope.values().as_slice())? == scope);
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// With the `derive` feature, `#[derive(Scope)]` writes exactly these impls from
/// `#[cryptbox(part = "3a1f0c6e-…")]` on `org` and
/// `#[cryptbox(part = "c7d24e19-…")]` on `workspace`. It sorts the parts and
/// checks their IDs when it expands; [`PartType`] maps each field's type to its
/// kind.
///
/// Unsorted parts fail the build:
///
/// ```compile_fail,E0080
/// use cryptbox::{PartKind, PartSpec, PartValue, PartValues, Scope};
/// # use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Raw, Seal, SealId, Sealed};
///
/// #[derive(Clone, Hash, PartialEq, Eq)]
/// struct Unsorted;
///
/// impl Scope for Unsorted {
///     const PARTS: &'static [PartSpec] = &[
///         PartSpec::new(cryptbox::part_id!("c7d24e19-0b8a-4f63-a1d5-6e9f3b720c48"), PartKind::I64),
///         PartSpec::new(cryptbox::part_id!("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90"), PartKind::I64),
///     ];
///
///     fn values(&self) -> PartValues<'_> {
///         PartValues::from([PartValue::I64(1), PartValue::I64(2)])
///     }
/// }
/// # struct Bytes;
/// # impl Seal for Bytes {
/// #     const ID: SealId = SealId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
/// #     type Scope = Unsorted;
/// #     type Keys = ();
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
///
/// // `Bytes` is a seal whose scope is `Unsorted`.
/// let _ = Sealed::<Bytes>::seal(&Vec::new(), &Unsorted, &keys);
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// So do duplicate part IDs:
///
/// ```compile_fail,E0080
/// use cryptbox::{PartKind, PartSpec, PartValue, PartValues, Scope};
/// # use cryptbox::{EncryptionKey, EncryptionKeyring, Padding, Raw, Seal, SealId, Sealed};
///
/// #[derive(Clone, Hash, PartialEq, Eq)]
/// struct Duplicate;
///
/// impl Scope for Duplicate {
///     const PARTS: &'static [PartSpec] = &[
///         PartSpec::new(cryptbox::part_id!("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90"), PartKind::I64),
///         PartSpec::new(cryptbox::part_id!("3a1f0c6e-58b2-4d0a-9e57-1c4b8f2d6a90"), PartKind::I64),
///     ];
///
///     fn values(&self) -> PartValues<'_> {
///         PartValues::from([PartValue::I64(1), PartValue::I64(2)])
///     }
/// }
/// # struct Bytes;
/// # impl Seal for Bytes {
/// #     const ID: SealId = SealId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
/// #     type Scope = Duplicate;
/// #     type Keys = ();
/// #     type Indexes = ();
/// # }
/// # let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
///
/// // `Bytes` is a seal whose scope is `Duplicate`.
/// let _ = Sealed::<Bytes>::seal(&Vec::new(), &Duplicate, &keys);
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
#[doc = concat!(
    "[ADR-0005]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/adr/0005-runtime-binding-is-the-core.md\n",
    "[ADR-0009]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/adr/0009-scopes-have-views.md\n",
    "[wire format]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/wire-format.md#binding",
)]
pub trait Scope: Clone + Hash + Eq + Send + Sync + 'static {
    /// The declared parts, sorted by part ID.
    const PARTS: &'static [PartSpec];

    /// Returns one value for each of [`PARTS`](Self::PARTS), in the same order.
    fn values(&self) -> PartValues<'_>;
}

/// A [`Scope`] that can be built back from its part values.
///
/// This is the inverse of [`Scope::values`]: given one value per part of
/// [`PARTS`](Scope::PARTS), in order, it returns the scope that supplies them.
/// It is how a **view** is built: a scope whose parts are a subset of another
/// scope's, matched by part ID and kind, takes its values from that scope's
/// values by part ID. `#[derive(Scope)]` implements it; a hand-written scope can
/// read each value with [`PartType::from_part_value`].
///
/// ```
/// use cryptbox::{FromParts, PartValue, Tenant, TenantId};
///
/// let acme = Tenant(TenantId::new("acme")?);
///
/// assert_eq!(Tenant::from_parts(&[PartValue::Bytes(b"acme")])?, acme);
/// assert!(Tenant::from_parts(&[]).is_err());
/// # Ok::<(), cryptbox::Error>(())
/// ```
pub trait FromParts: Scope {
    /// Builds the scope from one value per part, in `PARTS` order.
    ///
    /// Building then reading back with [`Scope::values`] must return the same
    /// values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBinding`] for a missing or extra value, or a value
    /// its part's type cannot hold, such as one of another kind.
    fn from_parts(values: &[PartValue<'_>]) -> Result<Self, Error>;
}

// Whether every part of `view` is a part of `scope`, with the same ID and kind.
const fn is_view(view: &[PartSpec], scope: &[PartSpec]) -> bool {
    let mut index = 0;
    while index < view.len() {
        let mut found = false;
        let mut candidate = 0;
        while candidate < scope.len() {
            if u128::from_be_bytes(view[index].id) == u128::from_be_bytes(scope[candidate].id)
                && view[index].kind as u8 == scope[candidate].kind as u8
            {
                found = true;
            }
            candidate += 1;
        }
        if !found {
            return false;
        }
        index += 1;
    }

    true
}

// Panics become build errors in `const` context.
pub(crate) const fn check_view(view: &[PartSpec], scope: &[PartSpec]) {
    assert!(
        is_view(view, scope),
        "a view's parts must be parts of its scope, with the same part IDs and kinds"
    );
}

// Panics become build errors in `const` context.
pub(crate) const fn check_keys_view(keys: &[PartSpec], scope: &[PartSpec]) {
    assert!(
        is_view(keys, scope),
        "a seal's keys view must be a view of its scope: its parts must be parts of the \
         scope, with the same part IDs and kinds"
    );
}

// Panics become build errors in `const` context. A query selects index keys
// by the keys view projected from its index scope, so the index scope must hold
// every part of the keys view.
pub(crate) const fn check_index_scope(index: &[PartSpec], scope: &[PartSpec], keys: &[PartSpec]) {
    assert!(
        is_view(index, scope),
        "a blind index's scope must be a view of its seal's scope: its parts must be parts \
         of the seal's scope, with the same part IDs and kinds"
    );
    assert!(
        is_view(keys, index),
        "a blind index's scope must include every part of its seal's keys view"
    );
}

/// Builds the view `V` of `scope`, taking each of its parts' values from
/// `scope`'s by part ID.
///
/// A `V` that is not a view of `S` fails the build when the projection is first
/// used; like the [`Scope`] checks, it runs after monomorphization.
pub(crate) fn project_view<V: FromParts, S: Scope>(scope: &S) -> Result<V, Error> {
    const {
        check_parts(V::PARTS);
        check_parts(S::PARTS);
        check_view(V::PARTS, S::PARTS);
    };

    let values = scope.values();
    check_values(S::PARTS, &[], &values.0)?;
    let projected = project(V::PARTS, &S::PARTS.iter().zip(&values.0))?;

    V::from_parts(&projected)
}

/// What a seal's values are bound to beyond its seal ID: a [`Scope`], or a scope
/// and a record, [`Recorded<S, Id>`](Recorded).
///
/// Every [`Scope`] is a seal scope that binds no record. A seal names its seal
/// scope as [`Seal::Scope`](crate::Seal::Scope), and its [binding
/// arguments](crate::Args) follow from it.
pub trait SealScope: 'static {
    /// The declared parts, without the record.
    type Parts: Scope;

    /// The kind of the record ID a value is bound to, or `None` without one.
    const RECORD: Option<PartKind>;
}

impl<S: Scope> SealScope for S {
    type Parts = S;
    const RECORD: Option<PartKind> = None;
}

/// Scope `S` together with a record whose ID has type `Id`.
///
/// A seal whose scope is `Recorded<S, Id>` binds every value to the ID of the
/// record it is stored in, as well as to `S`: a value copied to another row of
/// the same table fails to open. The record is bound as one more part, which is
/// always bound only: it never scopes keys or blind indexes, since a query cannot
/// know it. Its kind is `Id`'s [`PartType::KIND`], so changing the ID's type is
/// a declaration change. Record IDs are generated by the client, such as version
/// 7 UUIDs, before the value is sealed, and are never reused.
///
/// A `Recorded` value is never constructed: the binding arguments carry the scope
/// and the record ID, as `(&scope, &id)`, or `((), &id)` for the empty scope. A
/// [`Record`](crate::Record) passes each row's ID to the seals of its fields.
///
/// ```
/// use cryptbox::{
///     EncryptionKey, EncryptionKeyring, Padding, Recorded, Seal, SealId, Sealed, Tenant,
///     TenantId, Utf8,
/// };
///
/// struct CustomerEmail;
///
/// impl Seal for CustomerEmail {
///     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Scope = Recorded<Tenant, i64>;
///     type Keys = Tenant;
///     type Indexes = ();
/// }
///
/// let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
/// let acme = Tenant(TenantId::new(b"acme".to_vec())?);
///
/// let sealed = Sealed::<CustomerEmail>::seal(&"ada@example.com".into(), (&acme, &42), &keys)?;
/// assert_eq!(sealed.open((&acme, &42), &keys)?, "ada@example.com");
/// assert!(sealed.open((&acme, &43), &keys).is_err());
/// # Ok::<(), cryptbox::Error>(())
/// ```
pub struct Recorded<S, Id: ?Sized>(PhantomData<S>, PhantomData<Id>);

impl<S: Scope, Id: PartType + ?Sized + 'static> SealScope for Recorded<S, Id> {
    type Parts = S;
    const RECORD: Option<PartKind> = Some(Id::KIND);
}

// Rejects declarations whose bytes or fingerprint would depend on part order,
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
/// spec's kind, and that no value of a part in the keys view `keys` is empty.
pub(crate) fn check_values<'s>(
    specs: impl IntoIterator<Item = &'s PartSpec>,
    keys: &[PartSpec],
    values: &[PartValue<'_>],
) -> Result<(), Error> {
    let mut values = values.iter();
    for spec in specs {
        let value = values.next().ok_or(Error::InvalidBinding)?;
        let empty_keys = matches!(value, PartValue::Bytes([])) && is_keys_part(spec, keys);
        if spec.kind != value.kind() || empty_keys {
            return Err(Error::InvalidBinding);
        }
    }

    match values.next() {
        Some(_) => Err(Error::InvalidBinding),
        None => Ok(()),
    }
}

/// Whether `spec` is a part of the keys view `keys`.
pub(super) fn is_keys_part(spec: &PartSpec, keys: &[PartSpec]) -> bool {
    keys.iter().any(|key| key.id == spec.id)
}

/// Takes the value of each of `specs` from `parts` by part ID; a missing part or
/// another kind is [`Error::InvalidBinding`].
fn project<'v>(
    specs: &[PartSpec],
    parts: &(impl Iterator<Item = (&'v PartSpec, &'v PartValue<'v>)> + Clone),
) -> Result<Vec<PartValue<'v>>, Error> {
    specs
        .iter()
        .map(|spec| {
            parts
                .clone()
                .find(|(part, _)| part.id == spec.id && part.kind == spec.kind)
                .map(|(_, value)| *value)
                .ok_or(Error::InvalidBinding)
        })
        .collect()
}

/// The binding fingerprint of seal scope `S` with keys view `K`, as the
/// envelope header carries it.
pub(crate) fn declaration_fingerprint<S: SealScope, K: Scope>() -> [u8; 8] {
    BindingDeclaration::of::<S, K>().fingerprint()
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

/// One declared part of a scope: its ID and value kind.
///
/// A part has no role: whether it scopes key custody or a blind index is up to
/// the views that include it, a seal's [keys view](crate::Seal::Keys) and a
/// blind index's [index scope](crate::BlindIndexSpec::Scope).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartSpec {
    id: [u8; 16],
    kind: PartKind,
}

impl PartSpec {
    /// Declares a part with ID `id` and values of kind `kind`.
    #[must_use]
    pub const fn new(id: PartId, kind: PartKind) -> Self {
        Self::from_bytes(*id.as_bytes(), kind)
    }

    pub(crate) const fn from_bytes(id: [u8; 16], kind: PartKind) -> Self {
        Self { id, kind }
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
    pub(crate) fn kind(&self) -> PartKind {
        match self {
            Self::Uuid(_) => PartKind::Uuid,
            Self::I64(_) => PartKind::I64,
            Self::Bytes(_) => PartKind::Bytes,
        }
    }
}

/// The values of a binding's parts, in declared order.
#[derive(Clone, Debug, Default)]
pub struct PartValues<'a>(Vec<PartValue<'a>>);

impl<'a> PartValues<'a> {
    /// Returns no values, for a binding without parts.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Returns the values, in declared order.
    #[must_use]
    pub fn as_slice(&self) -> &[PartValue<'a>] {
        &self.0
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

    /// Creates a record ID from any [`PartType`], such as an application's own
    /// ID newtype, with that type's kind and value.
    #[must_use]
    pub fn of<T: PartType + ?Sized>(id: &'a T) -> Self {
        match id.part_value() {
            PartValue::Uuid(uuid) => Self::Uuid(uuid),
            PartValue::I64(value) => Self::I64(value),
            PartValue::Bytes(bytes) => Self::Bytes(bytes),
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

#[cfg(feature = "migrate")]
impl<'a> RecordId<'a> {
    // Records share the part value encoding, kind codes included.
    pub(crate) const fn part_value(self) -> PartValue<'a> {
        match self {
            Self::Uuid(uuid) => PartValue::Uuid(uuid),
            Self::I64(value) => PartValue::I64(value),
            Self::Bytes(bytes) => PartValue::Bytes(bytes),
        }
    }
}

// The part a record is bound as: the nil part ID, which no declared part may
// use, so it always sorts first. See ../docs/wire-format.md#binding.
const fn record_part(kind: PartKind) -> PartSpec {
    PartSpec::from_bytes([0; 16], kind)
}

/// The persistent declaration of a binding: its declared parts, the parts of
/// its keys view, and, when it binds a record, the record's kind.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BindingDeclaration<'a> {
    parts: &'a [PartSpec],
    keys: &'a [PartSpec],
    record: Option<PartKind>,
}

impl<'a> BindingDeclaration<'a> {
    pub(crate) const fn new(
        parts: &'a [PartSpec],
        keys: &'a [PartSpec],
        record: Option<PartKind>,
    ) -> Self {
        Self {
            parts,
            keys,
            record,
        }
    }

    /// The declaration of seal scope `S` with keys view `K`.
    pub(crate) const fn of<S: SealScope, K: Scope>() -> Self {
        Self::new(<S::Parts as Scope>::PARTS, K::PARTS, S::RECORD)
    }

    /// Checks the declaration's own invariants: unique, non-nil part IDs.
    ///
    /// Without parts or a record, the declaration is empty: the seal is
    /// unscoped.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let mut ids: Vec<_> = self.parts.iter().map(|spec| spec.id).collect();
        ids.sort_unstable();
        let duplicate = ids.windows(2).any(|pair| pair[0] == pair[1]);

        if ids.contains(&[0; 16]) || duplicate {
            return Err(Error::InvalidBinding);
        }

        Ok(())
    }

    /// Every part of the declaration, the record's included.
    fn specs(&self) -> Vec<PartSpec> {
        self.record
            .map(record_part)
            .into_iter()
            .chain(self.parts.iter().copied())
            .collect()
    }

    /// Fingerprints the declaration; part order does not matter.
    pub(crate) fn fingerprint(&self) -> [u8; 8] {
        encoding::fingerprint(&self.specs(), self.keys)
    }
}

/// A binding resolved for the cryptographic core, or its blind-index restriction.
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
    /// Encodes a seal's declared parts, in any order, with their values, and
    /// its record if the declaration binds one.
    ///
    /// Without parts or a record, the declaration is empty and the seal is
    /// unscoped.
    ///
    /// `values` follows the order of `declaration`'s parts.
    pub(crate) fn scoped(
        id: &[u8; 16],
        declaration: BindingDeclaration<'_>,
        values: &[PartValue<'_>],
        record: Option<PartValue<'_>>,
    ) -> Result<Self, Error> {
        declaration.validate()?;
        check_values(declaration.parts, declaration.keys, values)?;
        let record = match (declaration.record, record) {
            (Some(kind), Some(record)) if record.kind() == kind => {
                Some((record_part(kind), record))
            }
            (None, None) => None,
            _ => return Err(Error::InvalidBinding),
        };

        let parts: Vec<_> = record
            .iter()
            .map(|(spec, value)| (spec, value))
            .chain(declaration.parts.iter().zip(values))
            .collect();
        Ok(Self {
            encoded: encoding::encode(id, parts)?,
            fingerprint: declaration.fingerprint(),
        })
    }

    /// Encodes the binding of seal `id`, whose seal scope is `S` and keys view
    /// `K`, under the declared parts' values and the record if `S` binds one.
    pub(crate) fn of<S: SealScope, K: Scope>(
        id: &[u8; 16],
        scope: &S::Parts,
        record: Option<PartValue<'_>>,
    ) -> Result<Self, Error> {
        const { check_parts(<S::Parts as Scope>::PARTS) };

        let values = scope.values();
        Self::scoped(id, BindingDeclaration::of::<S, K>(), &values.0, record)
    }

    /// Encodes the blind-index domain of seal `id` under an index scope: every
    /// part of `scope`, without a record, or the empty binding without parts.
    /// `keys` are the parts of the seal's keys view, whose values can't be empty.
    // See ../docs/wire-format.md#index-binding.
    pub(crate) fn index<I: Scope>(
        id: &[u8; 16],
        scope: &I,
        keys: &[PartSpec],
    ) -> Result<Self, Error> {
        const { check_parts(I::PARTS) };

        let values = scope.values();
        Self::scoped(
            id,
            BindingDeclaration::new(I::PARTS, keys, None),
            &values.0,
            None,
        )
    }

    /// Encodes the binding of seal `id` under the older declaration `Old` with
    /// keys view `OldKeys`, taking each of `Old`'s parts from `scope` by part
    /// ID, and binding `record` when `Old` binds one.
    ///
    /// A part of `Old` that `scope` lacks, or holds with another kind, and a
    /// record `Old` binds but `record` lacks, are [`Error::InvalidBinding`].
    #[cfg(feature = "migrate")]
    pub(crate) fn projected<Old: SealScope, OldKeys: Scope, B: Scope>(
        id: &[u8; 16],
        scope: &B,
        record: Option<PartValue<'_>>,
    ) -> Result<Self, Error> {
        const { check_parts(<Old::Parts as Scope>::PARTS) };
        const { check_parts(B::PARTS) };

        let values = scope.values();
        check_values(B::PARTS, &[], &values.0)?;
        let values = project(
            <Old::Parts as Scope>::PARTS,
            &B::PARTS.iter().zip(&values.0),
        )?;
        let record = if Old::RECORD.is_some() { record } else { None };

        Self::scoped(
            id,
            BindingDeclaration::of::<Old, OldKeys>(),
            &values,
            record,
        )
    }

    /// The binding fingerprint the envelope header carries.
    pub(crate) fn fingerprint(&self) -> [u8; 8] {
        self.fingerprint
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

/// Creates a [`PartId`](crate::PartId) from a UUID literal.
#[macro_export]
macro_rules! part_id {
    ($value:literal) => {{
        const ID: $crate::PartId =
            $crate::PartId::from_bytes($crate::__private::uuid::uuid!($value).into_bytes());
        ID
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal_id;

    const SEAL: [u8; 16] = *seal_id!("12345678-1234-4234-8234-1234567890ab").as_bytes();

    #[test]
    fn the_empty_binding_is_the_seal_id_without_parts() {
        let domain = scoped(&[], None, &[], None).unwrap();

        // docs/wire-format.md#binding
        assert_eq!(
            hex::encode(domain.as_bytes()),
            "123456781234423482341234567890ab0000"
        );
    }

    const TENANT: PartSpec = PartSpec::from_bytes([0x11; 16], PartKind::Uuid);
    const SEQUENCE: PartSpec = PartSpec::from_bytes([0xaa; 16], PartKind::I64);

    #[test]
    fn scoped_binding_sorts_and_frames_parts() {
        // Declared out of order: the encoding sorts parts by part ID.
        let domain = BindingDomain::scoped(
            &SEAL,
            BindingDeclaration::new(&[SEQUENCE, TENANT], &[TENANT], None),
            &[PartValue::I64(-2), PartValue::Uuid([0x33; 16])],
            None,
        )
        .unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            concat!(
                "123456781234423482341234567890ab",
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
    fn a_record_is_a_part_with_the_nil_id_that_sorts_first() {
        let domain = BindingDomain::scoped(
            &SEAL,
            BindingDeclaration::new(&[TENANT], &[TENANT], Some(PartKind::Bytes)),
            &[PartValue::Uuid([0x33; 16])],
            Some(PartValue::Bytes(b"row-7")),
        )
        .unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            concat!(
                "123456781234423482341234567890ab",
                "0002",
                "00000000000000000000000000000000",
                "03",
                "00000005",
                "726f772d37",
                "11111111111111111111111111111111",
                "01",
                "00000010",
                "33333333333333333333333333333333",
            )
        );
    }

    const LEFT: PartSpec = PartSpec::from_bytes([0x21; 16], PartKind::Bytes);
    const RIGHT: PartSpec = PartSpec::from_bytes([0x22; 16], PartKind::Bytes);

    fn bytes_of(
        parts: &[PartSpec],
        values: &[PartValue<'_>],
        record: Option<PartValue<'_>>,
    ) -> Vec<u8> {
        BindingDomain::scoped(
            &SEAL,
            BindingDeclaration::new(parts, &[], record.map(|record| record.kind())),
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
        let as_bytes = PartSpec::from_bytes([0x21; 16], PartKind::Bytes);
        let as_i64 = PartSpec::from_bytes([0x21; 16], PartKind::I64);
        let as_uuid = PartSpec::from_bytes([0x21; 16], PartKind::Uuid);

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
        record: Option<PartKind>,
        values: &[PartValue<'_>],
        record_value: Option<PartValue<'_>>,
    ) -> Result<BindingDomain, Error> {
        BindingDomain::scoped(
            &SEAL,
            BindingDeclaration::new(parts, parts, record),
            values,
            record_value,
        )
    }

    #[test]
    fn invalid_bindings_are_rejected() {
        let uuid = PartValue::Uuid([0x33; 16]);
        let nil = PartSpec::from_bytes([0; 16], PartKind::Uuid);
        let empty_keys = PartSpec::from_bytes([0x21; 16], PartKind::Bytes);
        let cases: [(&str, Result<BindingDomain, Error>); 10] = [
            ("value without a part", scoped(&[], None, &[uuid], None)),
            (
                "duplicate part ID",
                scoped(&[TENANT, TENANT], None, &[uuid, uuid], None),
            ),
            ("nil part ID", scoped(&[nil], None, &[uuid], None)),
            ("missing value", scoped(&[TENANT], None, &[], None)),
            ("extra value", scoped(&[TENANT], None, &[uuid, uuid], None)),
            (
                "kind mismatch",
                scoped(&[TENANT], None, &[PartValue::I64(1)], None),
            ),
            (
                "empty keys value",
                scoped(&[empty_keys], None, &[PartValue::Bytes(b"")], None),
            ),
            (
                "missing record",
                scoped(&[TENANT], Some(PartKind::Uuid), &[uuid], None),
            ),
            (
                "record of another kind",
                scoped(&[TENANT], Some(PartKind::I64), &[uuid], Some(uuid)),
            ),
            (
                "unexpected record",
                scoped(&[TENANT], None, &[uuid], Some(uuid)),
            ),
        ];

        for (case, result) in cases {
            assert_eq!(result.unwrap_err(), Error::InvalidBinding, "{case}");
        }
    }

    #[test]
    fn declaration_fingerprint_is_truncated_sha256_of_the_sorted_parts() {
        // Independently computed with shasum over the documented declaration bytes.
        assert_eq!(
            BindingDeclaration::new(&[SEQUENCE, TENANT], &[TENANT], None).fingerprint(),
            hex_array("b226c39c1cdd11d0"),
        );
        assert_eq!(
            BindingDeclaration::new(&[TENANT], &[TENANT], Some(PartKind::I64)).fingerprint(),
            hex_array("a1c8a14a6c349e76"),
        );
    }

    #[test]
    fn declaration_fingerprint_ignores_part_order_but_not_the_keys_view() {
        let fingerprint =
            BindingDeclaration::new(&[SEQUENCE, TENANT], &[TENANT], None).fingerprint();

        assert_eq!(
            BindingDeclaration::new(&[TENANT, SEQUENCE], &[TENANT], None).fingerprint(),
            fingerprint
        );
        assert_ne!(
            BindingDeclaration::new(&[SEQUENCE, TENANT], &[], None).fingerprint(),
            fingerprint
        );
        assert_ne!(
            BindingDeclaration::new(&[SEQUENCE, TENANT], &[TENANT], Some(PartKind::I64))
                .fingerprint(),
            fingerprint
        );
        // The record's kind is declared, like any part's.
        assert_ne!(
            BindingDeclaration::new(&[], &[], Some(PartKind::I64)).fingerprint(),
            BindingDeclaration::new(&[], &[], Some(PartKind::Bytes)).fingerprint(),
        );
    }

    #[test]
    fn every_domain_carries_its_declaration_fingerprint() {
        let declaration = BindingDeclaration::new(&[TENANT], &[TENANT], None);
        let domain = scoped(&[TENANT], None, &[PartValue::Uuid([0x33; 16])], None).unwrap();

        assert_eq!(domain.fingerprint(), declaration.fingerprint());
        // Independently computed with shasum over the documented empty declaration.
        assert_eq!(
            scoped(&[], None, &[], None).unwrap().fingerprint(),
            hex_array("65640fc8333534b9")
        );
    }

    fn hex_array(value: &str) -> [u8; 8] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    #[test]
    fn a_record_alone_binds_the_record_without_parts() {
        let domain = scoped(&[], Some(PartKind::I64), &[], Some(PartValue::I64(1))).unwrap();

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

    /// An org scopes keys; a workspace is only bound.
    #[derive(Clone, Hash, PartialEq, Eq)]
    struct OrgWorkspace {
        org: [u8; 16],
        workspace: Vec<u8>,
    }

    impl Scope for OrgWorkspace {
        const PARTS: &'static [PartSpec] = &[
            PartSpec::new(
                part_id!("11111111-1111-1111-1111-111111111111"),
                PartKind::Uuid,
            ),
            PartSpec::new(
                part_id!("22222222-2222-2222-2222-222222222222"),
                PartKind::Bytes,
            ),
        ];
        fn values(&self) -> PartValues<'_> {
            PartValues::from([PartValue::Uuid(self.org), PartValue::Bytes(&self.workspace)])
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
        let domain = BindingDomain::of::<OrgWorkspace, Org>(&SEAL, &ws1(), None).unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            "123456781234423482341234567890ab00021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31"
        );
        assert_eq!(domain.fingerprint(), hex_array("3c607e5f83c2ec23"));
    }

    #[test]
    fn a_two_part_scope_binds_the_record_first_documented_vector() {
        let domain = BindingDomain::of::<Recorded<OrgWorkspace, i64>, Org>(
            &SEAL,
            &ws1(),
            Some(PartValue::I64(7)),
        )
        .unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            "123456781234423482341234567890ab0003000000000000000000000000000000000200000008000000000000000711111111111111111111111111111111010000001033333333333333333333333333333333222222222222222222222222222222220300000004 77732d31".replace(' ', "")
        );
        assert_eq!(domain.fingerprint(), hex_array("5d608899e74caec9"));
    }

    const LOW: [u8; 16] = [0x11; 16];
    const HIGH: [u8; 16] = [0x22; 16];

    fn part(id: [u8; 16]) -> PartSpec {
        PartSpec::from_bytes(id, PartKind::I64)
    }

    #[test]
    fn sorted_unique_parts_pass() {
        check_parts(&[]);
        check_parts(&[part(LOW), part(HIGH)]);
    }

    #[test]
    #[should_panic(expected = "sorted by part ID without duplicates")]
    fn unsorted_parts_fail() {
        check_parts(&[part(HIGH), part(LOW)]);
    }

    #[test]
    #[should_panic(expected = "sorted by part ID without duplicates")]
    fn duplicate_parts_fail() {
        check_parts(&[part(LOW), part(LOW)]);
    }

    #[test]
    #[should_panic(expected = "must not be nil")]
    fn nil_parts_fail() {
        check_parts(&[part([0; 16])]);
    }

    /// The org of an [`OrgWorkspace`]: a view of it.
    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    struct Org {
        org: [u8; 16],
    }

    impl Scope for Org {
        const PARTS: &'static [PartSpec] = &[PartSpec::new(
            part_id!("11111111-1111-1111-1111-111111111111"),
            PartKind::Uuid,
        )];
        fn values(&self) -> PartValues<'_> {
            PartValues::from([PartValue::Uuid(self.org)])
        }
    }

    impl FromParts for Org {
        fn from_parts(values: &[PartValue<'_>]) -> Result<Self, Error> {
            match values {
                [PartValue::Uuid(org)] => Ok(Self { org: *org }),
                _ => Err(Error::InvalidBinding),
            }
        }
    }

    #[test]
    fn a_view_takes_its_parts_values_from_the_scope_by_part_id() {
        assert_eq!(
            project_view::<Org, OrgWorkspace>(&ws1()).unwrap(),
            Org { org: [0x33; 16] }
        );
        assert_eq!(project_view::<(), OrgWorkspace>(&ws1()).unwrap(), ());
    }

    #[test]
    fn a_view_matches_parts_by_id_and_kind() {
        let org = part(LOW);
        let org_as_bytes = PartSpec::from_bytes(LOW, PartKind::Bytes);
        let workspace = part(HIGH);

        assert!(is_view(&[], &[org, workspace]));
        assert!(is_view(&[org], &[org, workspace]));
        assert!(is_view(&[org, workspace], &[org, workspace]));
        assert!(!is_view(&[org], &[workspace]));
        assert!(!is_view(&[org_as_bytes], &[org, workspace]));
    }
}
