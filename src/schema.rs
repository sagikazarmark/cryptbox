//! A reviewable listing of persistent schema for CI snapshot tests.

use std::{any::type_name, fmt};

use crate::{BlindIndexSpec, Codec, Field, FieldId, IndexId, Padding};

/// Lists fields and blind indexes with their persistent schema.
///
/// Register every field and index explicitly, render the manifest with
/// [`Display`](fmt::Display), and compare the result with a committed
/// snapshot in a test. A change to a field's ID, value type, codec ID, or
/// padding, or to an index's ID, field, bits, or normalizer, then shows up as a
/// snapshot diff for review. Assert that [`Self::duplicates`] is empty as well.
///
/// Markers and value types are named by [`std::any::type_name`]. Its output
/// includes module paths and may change between compiler versions; review
/// such a diff and update the snapshot.
///
/// # Examples
///
/// ```
/// use cryptbox::{Field, FieldId, FieldOnly, Padding, Utf8, schema::Manifest};
///
/// struct Nickname;
///
/// impl Field for Nickname {
///     const ID: FieldId = cryptbox::field_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
///     const PADDING: Padding = Padding::block(16);
///     const RECORD: bool = false;
///     type Value = String;
///     type Codec = Utf8;
///     type Binding = FieldOnly;
///     type Indexes = ();
/// }
///
/// let manifest = Manifest::new().field::<Nickname>();
///
/// assert!(manifest.duplicates().is_empty());
///
/// // field 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01 my_app::Nickname
/// //   value: alloc::string::String
/// //   codec: utf8
/// //   padding: block(16)
/// let snapshot = manifest.to_string();
/// assert!(snapshot.starts_with("field 5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01 "));
/// assert!(snapshot.ends_with("::Nickname
///   value: alloc::string::String
///   codec: utf8
///   padding: block(16)
/// "));
/// ```
#[derive(Debug, Default)]
pub struct Manifest {
    fields: Vec<FieldEntry>,
    indexes: Vec<IndexEntry>,
}

#[derive(Debug)]
struct IndexEntry {
    id: IndexId,
    marker: &'static str,
    field: FieldId,
    bits: u16,
    normalizer: &'static str,
}

#[derive(Debug)]
struct FieldEntry {
    id: FieldId,
    marker: &'static str,
    value: &'static str,
    codec: &'static str,
    padding: Padding,
}

impl Manifest {
    /// Creates an empty manifest.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers field `F`.
    #[must_use]
    pub fn field<F: Field>(mut self) -> Self {
        self.fields.push(FieldEntry {
            id: F::ID,
            marker: type_name::<F>(),
            value: type_name::<F::Value>(),
            codec: <F::Codec as Codec<F::Value>>::ID,
            padding: F::PADDING,
        });
        self
    }

    /// Registers blind index `I`.
    ///
    /// Register its field separately with [`Self::field`].
    #[must_use]
    pub fn index<I: BlindIndexSpec>(mut self) -> Self {
        self.indexes.push(IndexEntry {
            id: I::ID,
            marker: type_name::<I>(),
            field: <I::Field as Field>::ID,
            bits: I::BITS,
            normalizer: I::NORMALIZER,
        });
        self
    }

    /// Returns every field or index ID that more than one registered marker declares.
    ///
    /// Markers that share a field ID are one logical field and can read each
    /// other's ciphertext. That is occasionally deliberate, but usually a copied
    /// ID, so assert that this is empty in a test.
    #[must_use]
    pub fn duplicates(&self) -> Vec<Duplicate> {
        let fields = shared_ids(self.fields.iter().map(|field| (field.id, field.marker)))
            .map(|(id, markers)| Duplicate::Field { id, markers });
        let indexes = shared_ids(self.indexes.iter().map(|index| (index.id, index.marker)))
            .map(|(id, markers)| Duplicate::Index { id, markers });

        fields.chain(indexes).collect()
    }
}

/// An ID that more than one registered marker declares.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Duplicate {
    /// Several field markers declare one field ID.
    Field {
        /// The shared ID.
        id: FieldId,
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
            Self::Field { id, markers } => {
                write!(formatter, "duplicate field ID {id}: {}", markers.join(", "))
            }
            Self::Index { id, markers } => {
                write!(formatter, "duplicate index ID {id}: {}", markers.join(", "))
            }
        }
    }
}

/// Groups distinct markers by ID, in order of first appearance, keeping only shared IDs.
fn shared_ids<Id: PartialEq>(
    entries: impl Iterator<Item = (Id, &'static str)>,
) -> impl Iterator<Item = (Id, Vec<&'static str>)> {
    let mut groups: Vec<(Id, Vec<&'static str>)> = Vec::new();

    for (id, marker) in entries {
        match groups.iter_mut().find(|(group, _)| *group == id) {
            Some((_, markers)) if !markers.contains(&marker) => markers.push(marker),
            Some(_) => {}
            None => groups.push((id, vec![marker])),
        }
    }

    groups.into_iter().filter(|(_, markers)| markers.len() > 1)
}

impl fmt::Display for Manifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for field in &self.fields {
            writeln!(formatter, "field {} {}", field.id, field.marker)?;
            writeln!(formatter, "  value: {}", field.value)?;
            writeln!(formatter, "  codec: {}", field.codec)?;
            writeln!(formatter, "  padding: {}", field.padding)?;
        }

        for index in &self.indexes {
            writeln!(formatter, "index {} {}", index.id, index.marker)?;
            writeln!(formatter, "  field: {}", index.field)?;
            writeln!(formatter, "  bits: {}", index.bits)?;
            writeln!(formatter, "  normalizer: {}", index.normalizer)?;
        }

        for duplicate in self.duplicates() {
            writeln!(formatter, "{duplicate}")?;
        }

        Ok(())
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
/// use cryptbox::{Field, FieldId, FieldOnly, Padding, Utf8};
///
/// struct HomeAddress;
///
/// impl Field for HomeAddress {
///     const ID: FieldId = cryptbox::field_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
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
/// impl Field for BillingAddress {
///     const ID: FieldId = cryptbox::field_id!("7d1f0c52-3b8e-4a6f-9c21-6e4b8d0a9f13");
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
/// # use cryptbox::{Field, FieldId, FieldOnly, Padding, Utf8};
/// # struct HomeAddress;
/// # impl Field for HomeAddress {
/// #     const ID: FieldId = cryptbox::field_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
/// #     const PADDING: Padding = Padding::NONE;
/// #     const RECORD: bool = false;
/// #     type Value = String;
/// #     type Codec = Utf8;
/// #     type Binding = FieldOnly;
/// #     type Indexes = ();
/// # }
/// struct BillingAddress;
///
/// impl Field for BillingAddress {
///     const ID: FieldId = cryptbox::field_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
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
/// # use cryptbox::{BlindIndexError, BlindIndexSpec, Field, FieldId, FieldOnly, IndexId, Padding, Raw};
/// # use zeroize::Zeroizing;
/// # struct Bytes;
/// # impl Field for Bytes {
/// #     const ID: FieldId = FieldId::from_bytes([1; 16]);
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
///     type Field = Bytes;
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
///     type Field = Bytes;
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
    ($($field:ty),+ $(,)?) => {
        const _: () = ::core::assert!(
            !$crate::__private::has_duplicate(&[
                $(*<$field as $crate::Field>::ID.as_bytes()),+
            ]),
            ::core::concat!("duplicate field ID among ", ::core::stringify!($($field),+)),
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
