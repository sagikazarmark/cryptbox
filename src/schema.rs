//! A reviewable listing of persistent schema for CI snapshot tests.

use std::{
    any::{TypeId, type_name},
    fmt,
};

use crate::{
    Binding, BlindIndexSpec, Codec, IndexId, Padding, PartKind, PartRole, PartSpec, Seal, SealId,
    binding::declaration_fingerprint,
};

/// Lists fields and blind indexes with their persistent schema.
///
/// Register every field and index explicitly, render the manifest with
/// [`Display`](fmt::Display), and compare the result with a committed
/// snapshot in a test. A change to persistent schema then shows up as a
/// snapshot diff for review. Assert that [`Self::duplicates`] is empty as well.
///
/// Each field lists:
///
/// - its field ID, codec ID, and padding;
/// - `record`: whether it binds a record;
/// - `binding`: the [binding fingerprint](crate::CiphertextInfo::context_fingerprint),
///   in hex, that its headers carry, followed by each part's ID, kind, and role in part-ID
///   order;
/// - `shred unit`: the finest unit that destroying root keys can shred, if the
///   application stores root keys per [key scope](crate::KeyScope): the
///   [`keys`](crate::PartRole::Keys) parts, joined by `+`, or `keyring` when
///   there are none and only the whole keyring can be. The library cannot see
///   how keys are stored, so a coarser choice, such as one keyring for every
///   tenant, shreds only that coarser unit; say so in the custody label;
/// - `custody`: the label given with [`Self::custody`], if any.
///
/// Each index lists its index ID, field ID, bits, and normalizer name.
///
/// The output names IDs, never Rust types, so it is the same on every
/// toolchain and survives renaming or moving a marker. The value type is not
/// listed: the codec ID stands for its stored bytes, and golden-bytes fixtures
/// ([`assert_encoding`](crate::testing::assert_encoding)) pin them.
///
/// # Examples
///
/// ```
/// use cryptbox::{Seal, SealId, Padding, Tenant, Utf8, schema::Manifest};
///
/// struct Nickname;
///
/// impl Seal for Nickname {
///     const ID: SealId = cryptbox::seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
///     const PADDING: Padding = Padding::block(16);
///     const RECORD: bool = true;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = Tenant;
///     type Indexes = ();
/// }
///
/// let manifest = Manifest::new()
///     .seal::<Nickname>()
///     .custody::<Nickname>("general KMS, one key per tenant");
///
/// assert!(manifest.duplicates().is_empty());
/// assert_eq!(manifest.to_string(), "\
/// seal 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
///   codec: utf8
///   padding: block(16)
///   record: yes
///   binding: a28551bd5fbddbb1
///     part 1e8306bf-3135-4570-831c-6732f92550e9 bytes keys
///   shred unit: 1e8306bf-3135-4570-831c-6732f92550e9
///   custody: general KMS, one key per tenant
/// ");
/// ```
#[derive(Debug, Default)]
pub struct Manifest {
    seals: Vec<SealEntry>,
    indexes: Vec<IndexEntry>,
}

#[derive(Debug)]
struct IndexEntry {
    marker: TypeId,
    name: &'static str,
    id: IndexId,
    seal: SealId,
    bits: u16,
    normalizer: &'static str,
}

#[derive(Debug)]
struct SealEntry {
    marker: TypeId,
    name: &'static str,
    id: SealId,
    codec: &'static str,
    padding: Padding,
    record: bool,
    parts: &'static [PartSpec],
    fingerprint: [u8; 8],
    custody: Option<String>,
}

impl Manifest {
    /// Creates an empty manifest.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers seal `F`.
    ///
    /// Registering it again changes nothing.
    #[must_use]
    pub fn seal<F: Seal>(mut self) -> Self {
        self.seal_entry::<F>();
        self
    }

    /// Labels which keys protect field `F`, registering it if needed.
    ///
    /// The library cannot see which keyring an application passes for a field,
    /// so the manifest records custody declaratively: the label appears in the
    /// snapshot for reviewers and auditors, and a later label replaces an
    /// earlier one. Name the key custody, such as `"payments KMS, per org"`,
    /// never key material. Line breaks are escaped to keep the label on one
    /// line. Test that the application passes those keys with
    /// [`assert_sealed_under`](crate::testing::assert_sealed_under).
    #[must_use]
    pub fn custody<F: Seal>(mut self, label: impl Into<String>) -> Self {
        self.seal_entry::<F>().custody = Some(label.into());
        self
    }

    fn seal_entry<F: Seal>(&mut self) -> &mut SealEntry {
        let marker = TypeId::of::<F>();
        let position = self
            .seals
            .iter()
            .position(|seal| seal.marker == marker)
            .unwrap_or_else(|| {
                self.seals.push(SealEntry {
                    marker,
                    name: type_name::<F>(),
                    id: F::ID,
                    codec: <F::Codec as Codec<F::Value>>::ID,
                    padding: F::PADDING,
                    record: F::RECORD,
                    parts: <F::Binding as Binding>::PARTS,
                    fingerprint: declaration_fingerprint::<F::Binding>(F::RECORD),
                    custody: None,
                });
                self.seals.len() - 1
            });

        &mut self.seals[position]
    }

    /// Registers blind index `I`.
    ///
    /// Register its seal separately with [`Self::seal`]. Registering it again
    /// changes nothing.
    #[must_use]
    pub fn index<I: BlindIndexSpec>(mut self) -> Self {
        let marker = TypeId::of::<I>();
        if self.indexes.iter().all(|index| index.marker != marker) {
            self.indexes.push(IndexEntry {
                marker,
                name: type_name::<I>(),
                id: I::ID,
                seal: <I::Seal as Seal>::ID,
                bits: I::BITS,
                normalizer: I::NORMALIZER,
            });
        }
        self
    }

    /// Returns every field or index ID that more than one registered marker declares.
    ///
    /// Markers that share a field ID are one logical field and can read each
    /// other's ciphertext. That is occasionally deliberate, but usually a copied
    /// ID, so assert that this is empty in a test. Each duplicate names the
    /// markers by [`std::any::type_name`] to help find the copy; the manifest's
    /// own output lists only the ID.
    #[must_use]
    pub fn duplicates(&self) -> Vec<Duplicate> {
        let seals = shared_ids(self.seals.iter().map(|seal| (seal.id, seal.name)))
            .map(|(id, markers)| Duplicate::Seal { id, markers });
        let indexes = shared_ids(self.indexes.iter().map(|index| (index.id, index.name)))
            .map(|(id, markers)| Duplicate::Index { id, markers });

        seals.chain(indexes).collect()
    }
}

/// An ID that more than one registered marker declares.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Duplicate {
    /// Several field markers declare one field ID.
    Seal {
        /// The shared ID.
        id: SealId,
        /// The markers' type names, in registration order.
        markers: Vec<&'static str>,
    },
    /// Several blind-index markers declare one index ID.
    Index {
        /// The shared ID.
        id: IndexId,
        /// The markers' type names, in registration order.
        markers: Vec<&'static str>,
    },
}

impl fmt::Display for Duplicate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seal { id, markers } => {
                write!(formatter, "duplicate seal ID {id}: {}", markers.join(", "))
            }
            Self::Index { id, markers } => {
                write!(formatter, "duplicate index ID {id}: {}", markers.join(", "))
            }
        }
    }
}

/// Groups marker names by ID, in order of first appearance, keeping only shared IDs.
fn shared_ids<Id: PartialEq>(
    entries: impl Iterator<Item = (Id, &'static str)>,
) -> impl Iterator<Item = (Id, Vec<&'static str>)> {
    let mut groups: Vec<(Id, Vec<&'static str>)> = Vec::new();

    for (id, marker) in entries {
        match groups.iter_mut().find(|(group, _)| *group == id) {
            Some((_, markers)) => markers.push(marker),
            None => groups.push((id, vec![marker])),
        }
    }

    groups.into_iter().filter(|(_, markers)| markers.len() > 1)
}

impl fmt::Display for Manifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for seal in &self.seals {
            writeln!(formatter, "seal {}", seal.id)?;
            writeln!(formatter, "  codec: {}", seal.codec)?;
            writeln!(formatter, "  padding: {}", seal.padding)?;
            writeln!(formatter, "  record: {}", yes_no(seal.record))?;
            writeln!(formatter, "  binding: {}", hex::encode(seal.fingerprint))?;
            for part in seal.parts {
                writeln!(
                    formatter,
                    "    part {} {} {}",
                    part.id(),
                    kind_name(part.kind()),
                    role_name(part.role()),
                )?;
            }
            write!(formatter, "  shred unit: ")?;
            let mut keys = seal
                .parts
                .iter()
                .filter(|part| part.role() == PartRole::Keys);
            match keys.next() {
                // Without `keys` parts, only the whole keyring can be destroyed.
                None => writeln!(formatter, "keyring")?,
                Some(first) => {
                    write!(formatter, "{}", first.id())?;
                    for part in keys {
                        write!(formatter, " + {}", part.id())?;
                    }
                    writeln!(formatter)?;
                }
            }
            if let Some(custody) = &seal.custody {
                write!(formatter, "  custody: ")?;
                for character in custody.chars() {
                    if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
                        write!(formatter, "{}", character.escape_debug())?;
                    } else {
                        write!(formatter, "{character}")?;
                    }
                }
                writeln!(formatter)?;
            }
        }

        for index in &self.indexes {
            writeln!(formatter, "index {}", index.id)?;
            writeln!(formatter, "  seal: {}", index.seal)?;
            writeln!(formatter, "  bits: {}", index.bits)?;
            writeln!(formatter, "  normalizer: {}", index.normalizer)?;
        }

        // Type names are not stable across compilers, so the snapshot names IDs only.
        for duplicate in self.duplicates() {
            match duplicate {
                Duplicate::Seal { id, .. } => writeln!(formatter, "duplicate seal ID {id}")?,
                Duplicate::Index { id, .. } => writeln!(formatter, "duplicate index ID {id}")?,
            }
        }

        Ok(())
    }
}

// Manifest spellings are snapshot text: keep them stable.
const fn yes_no(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

const fn kind_name(kind: PartKind) -> &'static str {
    match kind {
        PartKind::Uuid => "uuid",
        PartKind::I64 => "i64",
        PartKind::Bytes => "bytes",
    }
}

const fn role_name(role: PartRole) -> &'static str {
    match role {
        PartRole::Keys => "keys",
        PartRole::Index => "index",
        PartRole::Bound => "bound",
    }
}

/// Fails compilation when two of the listed markers declare the same ID.
///
/// List field markers to check their field IDs, or `indexes:` followed by
/// blind-index markers to check their index IDs. The check is a constant
/// assertion, so it works with manual impls and derives alike and needs no test
/// to run. Markers that deliberately share a field ID are one logical field;
/// leave one of them out.
///
/// ```
/// use cryptbox::{Seal, SealId, FieldOnly, Padding, Utf8};
///
/// struct HomeAddress;
///
/// impl Seal for HomeAddress {
///     const ID: SealId = cryptbox::seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = ();
/// }
///
/// struct BillingAddress;
///
/// impl Seal for BillingAddress {
///     const ID: SealId = cryptbox::seal_id!("7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = ();
/// }
///
/// cryptbox::assert_unique_ids!(HomeAddress, BillingAddress);
/// ```
///
/// A copied ID fails to compile:
///
/// ```compile_fail,E0080
/// # use cryptbox::{Seal, SealId, FieldOnly, Padding, Utf8};
/// # struct HomeAddress;
/// # impl Seal for HomeAddress {
/// #     const ID: SealId = cryptbox::seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = false;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Binding = FieldOnly;
/// #     type Indexes = ();
/// # }
/// struct BillingAddress;
///
/// impl Seal for BillingAddress {
///     const ID: SealId = cryptbox::seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
///     const PADDING: Padding = Padding::NONE;
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = ();
/// }
///
/// cryptbox::assert_unique_ids!(HomeAddress, BillingAddress);
/// ```
///
/// So does a copied index ID:
///
/// ```compile_fail,E0080
/// # use cryptbox::{BlindIndexError, BlindIndexSpec, Seal, SealId, FieldOnly, IndexId, Padding, Raw};
/// # use zeroize::Zeroizing;
/// # struct Bytes;
/// # impl Seal for Bytes {
/// #     const ID: SealId = SealId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = false;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
/// #     type Binding = FieldOnly;
/// #     type Indexes = ();
/// # }
/// struct Exact;
///
/// impl BlindIndexSpec for Exact {
///     type Seal = Bytes;
///     const ID: IndexId = IndexId::from_bytes([2; 16]);
///     const BITS: u16 = 32;
///     const NORMALIZER: &'static str = "exact/1";
///     type Query = [u8];
/// #   fn normalize_query(q: &[u8]) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> { Ok(Zeroizing::new(q.to_vec())) }
/// #   fn normalize_value(v: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> { Ok(Zeroizing::new(v.clone())) }
/// }
///
/// struct Prefix;
///
/// impl BlindIndexSpec for Prefix {
///     type Seal = Bytes;
///     const ID: IndexId = IndexId::from_bytes([2; 16]);
///     const BITS: u16 = 16;
///     const NORMALIZER: &'static str = "prefix/1";
///     type Query = [u8];
/// #   fn normalize_query(q: &[u8]) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> { Ok(Zeroizing::new(q.to_vec())) }
/// #   fn normalize_value(v: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> { Ok(Zeroizing::new(v.clone())) }
/// }
///
/// cryptbox::assert_unique_ids!(indexes: Exact, Prefix);
/// ```
#[macro_export]
macro_rules! assert_unique_ids {
    (indexes: $($index:ty),+ $(,)?) => {
        const _: () = ::core::assert!(
            !$crate::__private::has_duplicate(&[
                $(*<$index as $crate::BlindIndexSpec>::ID.as_bytes()),+
            ]),
            ::core::concat!("duplicate index ID among ", ::core::stringify!($($index),+)),
        );
    };
    ($($seal:ty),+ $(,)?) => {
        const _: () = ::core::assert!(
            !$crate::__private::has_duplicate(&[
                $(*<$seal as $crate::Seal>::ID.as_bytes()),+
            ]),
            ::core::concat!("duplicate seal ID among ", ::core::stringify!($($seal),+)),
        );
    };
}

/// Reports whether any two of `ids` are equal, at compile time.
#[doc(hidden)]
#[must_use]
pub const fn has_duplicate(ids: &[[u8; 16]]) -> bool {
    let mut first = 0;
    while first < ids.len() {
        let mut second = first + 1;
        while second < ids.len() {
            if equal(&ids[first], &ids[second]) {
                return true;
            }
            second += 1;
        }
        first += 1;
    }

    false
}

/// Reports whether `written` holds exactly the index IDs of `declared`, each
/// once and in any order, at compile time.
///
/// `#[derive(Record)]` checks each field's written indexes against its
/// [`Seal::Indexes`](crate::Seal::Indexes) with it.
#[doc(hidden)]
#[must_use]
pub const fn writes_declared_indexes(
    declared: &[crate::IndexId],
    written: &[crate::IndexId],
) -> bool {
    if written.len() != declared.len() {
        return false;
    }

    let mut index = 0;
    while index < written.len() {
        if !contains(declared, &written[index])
            || contains(written.split_at(index).0, &written[index])
        {
            return false;
        }
        index += 1;
    }

    true
}

const fn contains(ids: &[crate::IndexId], id: &crate::IndexId) -> bool {
    let mut index = 0;
    while index < ids.len() {
        if equal(ids[index].as_bytes(), id.as_bytes()) {
            return true;
        }
        index += 1;
    }

    false
}

const fn equal(left: &[u8; 16], right: &[u8; 16]) -> bool {
    let mut index = 0;
    while index < 16 {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }

    true
}
