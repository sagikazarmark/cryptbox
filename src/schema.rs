//! A reviewable listing of persistent schema for CI snapshot tests.

use std::{
    any::{TypeId, type_name},
    fmt,
};

use crate::{
    BlindIndexSpec, Codec, ContextKind, IndexId, Padding, Record, Seal, SealId,
    seal_context::{self, RecordKind},
};

/// Lists seals and blind indexes with their persistent schema.
///
/// Register every seal and index explicitly, render the manifest with
/// [`Display`](fmt::Display), and compare the result with a committed
/// snapshot in a test. A change to persistent schema then shows up as a
/// snapshot diff for review. Assert that [`Self::duplicates`] is empty as well.
///
/// Each seal lists its seal ID, codec ID, and padding, and the
/// [context fingerprint](crate::envelope::CiphertextInfo::context_fingerprint) of each
/// context [`Self::sealed`] registers it in: a seal knows nothing of where its
/// values are stored, so the manifest lists what the application registers.
///
/// Each index lists its index ID, seal ID, bits, and normalizer name.
///
/// Each record lists the seal IDs of its sealed fields, the field that holds
/// its record ID, the record ID's kind, its context fingerprint, and its
/// plaintext fields. A field stored as it is has no ID, so
/// the manifest names it, and a field that should have been sealed shows up in
/// the snapshot.
///
/// The output names IDs, never Rust types, so it is the same on every
/// toolchain and survives renaming or moving a marker; a record's field names
/// are the one exception. The value type is not
/// listed: the codec ID stands for its stored bytes, and golden-bytes fixtures
/// ([`assert_encoding`](crate::testing::assert_encoding)) pin them.
///
/// # Examples
///
/// ```
/// use cryptbox::{Padding, Seal, SealId, Utf8, schema::Manifest};
///
/// struct Nickname;
///
/// impl Seal for Nickname {
///     const ID: SealId = cryptbox::seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
///     const PADDING: Padding = Padding::block(16);
///     type Value = String;
///     type Codec = Utf8;
/// }
///
/// // Nicknames are stored as standalone values, `Sealed<Nickname>`.
/// let manifest = Manifest::new().sealed::<Nickname, ()>();
///
/// assert!(manifest.duplicates().is_empty());
/// assert_eq!(manifest.to_string(), "\
/// seal 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01
///   codec: utf8
///   padding: block(16)
///   context: 502de8fcfb838c80
/// ");
/// ```
#[derive(Debug, Default)]
pub struct Manifest {
    seals: Vec<SealEntry>,
    indexes: Vec<IndexEntry>,
    records: Vec<RecordEntry>,
    contexts: Vec<ContextEntry>,
}

/// A context a seal ID is registered in: by `sealed`, which names the seal's
/// marker, or by a record, which names only its seals' IDs.
#[derive(Debug, PartialEq)]
struct ContextEntry {
    seal: SealId,
    marker: Option<TypeId>,
    record_kind: Option<RecordKind>,
}

#[derive(Debug)]
struct RecordEntry {
    marker: TypeId,
    name: &'static str,
    seals: &'static [SealId],
    record_id: &'static str,
    record_kind: Option<RecordKind>,
    plaintext: &'static [&'static str],
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
}

impl Manifest {
    /// Creates an empty manifest.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers seal `F`: its seal ID, codec, and padding.
    ///
    /// Registering it again changes nothing. Register the context its values
    /// are stored in with [`Self::sealed`], or with [`Self::record`] for a
    /// record's.
    #[must_use]
    pub fn seal<F: Seal>(mut self) -> Self {
        let marker = TypeId::of::<F>();
        if self.seals.iter().all(|seal| seal.marker != marker) {
            self.seals.push(SealEntry {
                marker,
                name: type_name::<F>(),
                id: F::ID,
                codec: <F::Codec as Codec<F::Value>>::ID,
                padding: F::PADDING,
            });
        }
        self
    }

    /// Registers seal `F` and the context `C` its values are stored in, as
    /// [`Sealed<F, C>`](crate::Sealed): `()` for standalone values.
    ///
    /// The seal lists the context's fingerprint, and [`Self::duplicates`]
    /// reports a seal registered in several kinds of context, such as a record
    /// field's seal also stored standalone. Registering it again changes
    /// nothing.
    #[must_use]
    pub fn sealed<F: Seal, C: ContextKind>(mut self) -> Self {
        let context = ContextEntry {
            seal: F::ID,
            marker: Some(TypeId::of::<F>()),
            record_kind: C::RECORD,
        };
        if !self.contexts.contains(&context) {
            self.contexts.push(context);
        }
        self.seal::<F>()
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

    /// Registers record `R`: its sealed fields' seal IDs, the name of its record
    /// ID field, its context, and the names of its plaintext fields.
    ///
    /// Its seals are registered in its context, [`Record::Context`]; register
    /// the seals themselves with [`Self::seal`]. Registering it again changes
    /// nothing.
    #[must_use]
    pub fn record<R: Record + 'static>(mut self) -> Self {
        let marker = TypeId::of::<R>();
        if self.records.iter().all(|record| record.marker != marker) {
            let record_kind = <R::Context as ContextKind>::RECORD;
            self.records.push(RecordEntry {
                marker,
                name: type_name::<R>(),
                seals: R::SEALS,
                record_id: R::RECORD_ID,
                record_kind,
                plaintext: R::PLAINTEXT,
            });
            self.contexts
                .extend(R::SEALS.iter().map(|seal| ContextEntry {
                    seal: *seal,
                    marker: None,
                    record_kind,
                }));
        }
        self
    }

    /// Returns every seal or index ID that more than one registered marker
    /// declares, every seal ID registered in more than one kind of context, and
    /// every seal ID that more than one registered record field declares.
    ///
    /// Markers that share a seal ID are one seal and can read each
    /// other's ciphertext. That is occasionally deliberate, but usually a copied
    /// ID, so assert that this is empty in a test. Each duplicate names the
    /// markers by [`std::any::type_name`] to help find the copy; the manifest's
    /// own output lists only the ID.
    ///
    /// A seal stored in several kinds of context, such as a record field's seal
    /// also stored standalone, has values that open only in the context they
    /// were sealed in, and that share its blind indexes. That is usually a
    /// mistake.
    ///
    /// Record fields that share a seal ID, in one record or in several with the
    /// same kind of record ID, share a context: their stored values can be
    /// swapped undetected. `#[derive(Record)]` rejects a seal ID repeated within
    /// one record.
    #[must_use]
    pub fn duplicates(&self) -> Vec<Duplicate> {
        let seals = shared_ids(self.seals.iter().map(|seal| (seal.id, seal.name)))
            .map(|(id, markers)| Duplicate::Seal { id, markers });
        let indexes = shared_ids(self.indexes.iter().map(|index| (index.id, index.name)))
            .map(|(id, markers)| Duplicate::Index { id, markers });
        let contexts = self
            .shared_contexts()
            .map(|(id, contexts)| Duplicate::Context {
                id,
                contexts: contexts
                    .into_iter()
                    .map(seal_context::fingerprint)
                    .collect(),
            });

        let fields = shared_ids(
            self.records
                .iter()
                .flat_map(|record| record.seals.iter().map(|seal| (*seal, record.name))),
        )
        .map(|(id, records)| Duplicate::RecordField { id, records });

        seals.chain(indexes).chain(contexts).chain(fields).collect()
    }

    /// Groups the kinds of context of each seal ID, in order of first
    /// appearance, keeping only seal IDs in more than one.
    fn shared_contexts(&self) -> impl Iterator<Item = (SealId, Vec<Option<RecordKind>>)> {
        let mut groups: Vec<(SealId, Vec<Option<RecordKind>>)> = Vec::new();

        for context in &self.contexts {
            let kind = context.record_kind;
            match groups.iter_mut().find(|(id, _)| *id == context.seal) {
                Some((_, kinds)) => {
                    if !kinds.contains(&kind) {
                        kinds.push(kind);
                    }
                }
                None => groups.push((context.seal, vec![kind])),
            }
        }

        groups
            .into_iter()
            .filter(|(_, contexts)| contexts.len() > 1)
    }
}

/// An ID that more than one registered marker declares.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Duplicate {
    /// Several seal types declare one seal ID.
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
    /// One seal ID is registered in several kinds of context.
    Context {
        /// The seal ID.
        id: SealId,
        /// The contexts' fingerprints, in registration order.
        contexts: Vec<[u8; 8]>,
    },
    /// Several record fields declare one seal ID, so their values can be
    /// swapped between them.
    RecordField {
        /// The shared seal ID.
        id: SealId,
        /// The records' type names, once per field, in registration order.
        records: Vec<&'static str>,
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
            Self::Context { id, contexts } => {
                let contexts: Vec<String> = contexts.iter().map(hex::encode).collect();
                write!(
                    formatter,
                    "seal ID {id} in several contexts: {}",
                    contexts.join(", ")
                )
            }
            Self::RecordField { id, records } => write!(
                formatter,
                "seal ID {id} in several record fields: {}",
                records.join(", ")
            ),
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
            let contexts = self
                .contexts
                .iter()
                .filter(|context| context.marker == Some(seal.marker));
            for context in contexts {
                writeln!(
                    formatter,
                    "  context: {}",
                    hex::encode(seal_context::fingerprint(context.record_kind))
                )?;
            }
        }

        for index in &self.indexes {
            writeln!(formatter, "index {}", index.id)?;
            writeln!(formatter, "  seal: {}", index.seal)?;
            writeln!(formatter, "  bits: {}", index.bits)?;
            writeln!(formatter, "  normalizer: {}", index.normalizer)?;
        }

        for record in &self.records {
            writeln!(formatter, "record")?;
            write!(formatter, "  seals:")?;
            for (position, seal) in record.seals.iter().enumerate() {
                let separator = if position == 0 { " " } else { ", " };
                write!(formatter, "{separator}{seal}")?;
            }
            writeln!(formatter)?;
            writeln!(formatter, "  record id: {}", record.record_id)?;
            writeln!(
                formatter,
                "  record kind: {}",
                record.record_kind.map_or("none", kind_name)
            )?;
            writeln!(
                formatter,
                "  context: {}",
                hex::encode(seal_context::fingerprint(record.record_kind))
            )?;
            match record.plaintext {
                [] => writeln!(formatter, "  plaintext: none")?,
                fields => writeln!(formatter, "  plaintext: {}", fields.join(", "))?,
            }
        }

        // Type names are not stable across compilers, so the snapshot names IDs only.
        for duplicate in self.duplicates() {
            match duplicate {
                Duplicate::Seal { id, .. } => writeln!(formatter, "duplicate seal ID {id}")?,
                Duplicate::Index { id, .. } => writeln!(formatter, "duplicate index ID {id}")?,
                Duplicate::Context { id, .. } => {
                    writeln!(formatter, "seal ID {id} in several contexts")?;
                }
                Duplicate::RecordField { id, .. } => {
                    writeln!(formatter, "seal ID {id} in several record fields")?;
                }
            }
        }

        Ok(())
    }
}

// Manifest spellings are snapshot text: keep them stable.
const fn kind_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Uuid => "uuid",
        RecordKind::I64 => "i64",
        RecordKind::Bytes => "bytes",
    }
}

/// Fails compilation when two of the listed types declare the same ID, when one
/// declares the nil UUID, or when a blind index's normalizer name is not
/// versioned, such as `"email/1"`.
///
/// List seals to check their seal IDs, or `indexes:` followed by
/// blind-index markers to check their index IDs and normalizer names. The
/// derives check the same rules when they expand. The check is a constant
/// assertion, so it works with manual impls and derives alike and needs no test
/// to run. Markers that deliberately share a seal ID are one seal;
/// leave one of them out.
///
/// ```
/// use cryptbox::{Seal, SealId, Padding, Utf8};
///
/// struct HomeAddress;
///
/// impl Seal for HomeAddress {
///     const ID: SealId = cryptbox::seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
/// }
///
/// struct BillingAddress;
///
/// impl Seal for BillingAddress {
///     const ID: SealId = cryptbox::seal_id!("7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
/// }
///
/// cryptbox::assert_unique_ids!(HomeAddress, BillingAddress);
/// ```
///
/// A copied ID fails to compile:
///
/// ```compile_fail,E0080
/// # use cryptbox::{Seal, SealId, Padding, Utf8};
/// # struct HomeAddress;
/// # impl Seal for HomeAddress {
/// #     const ID: SealId = cryptbox::seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// # }
/// struct BillingAddress;
///
/// impl Seal for BillingAddress {
///     const ID: SealId = cryptbox::seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
/// }
///
/// cryptbox::assert_unique_ids!(HomeAddress, BillingAddress);
/// ```
///
/// So does a copied index ID:
///
/// ```compile_fail,E0080
/// # use cryptbox::{BlindIndexError, BlindIndexSpec, Seal, SealId, IndexId, Padding, Raw};
/// # use zeroize::Zeroizing;
/// # struct Bytes;
/// # impl Seal for Bytes {
/// #     const ID: SealId = SealId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
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
///
/// And so does a normalizer name without a version:
///
/// ```compile_fail,E0080
/// # use cryptbox::{BlindIndexError, BlindIndexSpec, Seal, SealId, IndexId, Padding, Raw};
/// # use zeroize::Zeroizing;
/// # struct Bytes;
/// # impl Seal for Bytes {
/// #     const ID: SealId = SealId::from_bytes([1; 16]);
/// #     const PADDING: Padding = Padding::NONE;
/// #     type Value = Vec<u8>;
/// #     type Codec = Raw;
/// # }
/// struct Exact;
///
/// impl BlindIndexSpec for Exact {
///     type Seal = Bytes;
///     const ID: IndexId = IndexId::from_bytes([2; 16]);
///     const BITS: u16 = 32;
///     const NORMALIZER: &'static str = "exact";
///     type Query = [u8];
/// #   fn normalize_query(q: &[u8]) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> { Ok(Zeroizing::new(q.to_vec())) }
/// #   fn normalize_value(v: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> { Ok(Zeroizing::new(v.clone())) }
/// }
///
/// cryptbox::assert_unique_ids!(indexes: Exact);
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
        $(
            const _: () = ::core::assert!(
                !$crate::__private::is_nil(<$index as $crate::BlindIndexSpec>::ID.as_bytes()),
                ::core::concat!("the ID of ", ::core::stringify!($index), " is the nil UUID"),
            );
            const _: () = ::core::assert!(
                $crate::__private::valid_normalizer(<$index as $crate::BlindIndexSpec>::NORMALIZER),
                ::core::concat!(
                    "the normalizer of ",
                    ::core::stringify!($index),
                    " is not a versioned name, such as \"email/1\"",
                ),
            );
        )+
    };
    ($($seal:ty),+ $(,)?) => {
        const _: () = ::core::assert!(
            !$crate::__private::has_duplicate(&[
                $(*<$seal as $crate::Seal>::ID.as_bytes()),+
            ]),
            ::core::concat!("duplicate seal ID among ", ::core::stringify!($($seal),+)),
        );
        $(
            const _: () = ::core::assert!(
                !$crate::__private::is_nil(<$seal as $crate::Seal>::ID.as_bytes()),
                ::core::concat!("the ID of ", ::core::stringify!($seal), " is the nil UUID"),
            );
        )+
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
