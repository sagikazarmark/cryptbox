use std::fmt;

use crate::{
    BlindIndex, BlindIndexKeySource, BlindIndexSpec, Codec, EncryptionKeySource, Error, Field,
    FieldOnly, IndexKeyId, Sealed,
    binding::domain,
    blind::{current_key_id, derive_value},
    crypto::needs_reencryption_bound,
    inspect_blind_index,
};

use super::{LegacyFormat, legacy};

/// The classification of one stored row against the current key generations.
///
/// Malformed rows are not a state: classification returns an error for them.
/// Classification inspects unauthenticated structure and generation metadata,
/// not authenticated readability, decoded-value validity, or index consistency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RowState {
    /// The envelope and every blind index structurally parse and name current generations.
    /// Ciphertext is not decrypted and indexes are not recomputed.
    Current,
    /// The envelope or at least one blind index names a historical generation.
    Stale,
    /// The stored bytes are legacy data rather than a `CryptBox` envelope.
    #[doc(alias = "Plaintext")]
    Legacy,
}

/// Replacement bytes for one row.
///
/// Apply with optimistic concurrency: the update predicate must compare every
/// column byte that was originally read.
pub struct RowWrite {
    ciphertext: Vec<u8>,
    indexes: Vec<Vec<u8>>,
}

impl RowWrite {
    /// Returns the replacement envelope bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the replacement blind-index bytes in registration order.
    ///
    /// Columns that were already current keep their original bytes verbatim.
    #[must_use]
    pub fn indexes(&self) -> &[Vec<u8>] {
        &self.indexes
    }
}

impl fmt::Debug for RowWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RowWrite([REDACTED])")
    }
}

/// The planned action for one stored row.
#[derive(Debug)]
pub struct RowOutcome {
    state: RowState,
    write: Option<RowWrite>,
}

impl RowOutcome {
    /// Returns the row's classification.
    #[must_use]
    pub const fn state(&self) -> RowState {
        self.state
    }

    /// Returns the replacement bytes, absent for a current row.
    #[must_use]
    pub fn write(&self) -> Option<&RowWrite> {
        self.write.as_ref()
    }

    /// Consumes the outcome and returns the replacement bytes.
    #[must_use]
    pub fn into_write(self) -> Option<RowWrite> {
        self.write
    }
}

type IndexDeriver<F> = fn(&<F as Field>::Value, &dyn BlindIndexKeySource) -> Result<Vec<u8>, Error>;

type CurrentIndexKey = fn(&dyn BlindIndexKeySource) -> Result<IndexKeyId, Error>;

fn derive_index_bytes<F, Spec>(
    value: &F::Value,
    keys: &dyn BlindIndexKeySource,
) -> Result<Vec<u8>, Error>
where
    F: Field,
    Spec: BlindIndexSpec<Field = F>,
{
    derive_value::<Spec>(value, keys).map(BlindIndex::into_bytes)
}

fn current_index_key_id<Spec: BlindIndexSpec>(
    keys: &dyn BlindIndexKeySource,
) -> Result<IndexKeyId, Error> {
    current_key_id::<Spec>(keys)
}

// Reads the unauthenticated header only, without copying the envelope.
fn is_stale_envelope<F: Field<Binding = FieldOnly>>(
    ciphertext: &[u8],
    keys: &dyn EncryptionKeySource,
) -> Result<bool, Error> {
    needs_reencryption_bound(&domain::<F, ()>(())?, F::PADDING, ciphertext, keys)
}

struct IndexColumn<'a, F>
where
    F: Field,
{
    derive: IndexDeriver<F>,
    current_key: CurrentIndexKey,
    keys: &'a dyn BlindIndexKeySource,
}

/// Plans the rewrite of one encrypted column and its blind-index columns.
///
/// The planner is pure and synchronous: it performs no storage IO, so its
/// classification and rewrite logic is testable without a database. It
/// implements the per-row rules of the maintenance sweep guide: current rows
/// are skipped without generating fresh nonces, stale envelopes are
/// re-encrypted, stale blind indexes are re-derived from the authoritative
/// (decrypted) ciphertext, and recovered legacy data is encrypted with every
/// registered index derived alongside.
/// Current rows are skipped without authentication or decoding, and current
/// index bytes are retained without checking consistency. Use a separate
/// authenticated-read and index-recomputation pass when those checks are required.
///
/// The planner serves [`FieldOnly`] fields without a record.
pub struct RowPlanner<'a, F>
where
    F: Field,
{
    keys: &'a dyn EncryptionKeySource,
    legacy: Option<&'a dyn LegacyFormat>,
    indexes: Vec<IndexColumn<'a, F>>,
}

impl<'a, F> RowPlanner<'a, F>
where
    F: Field<Binding = FieldOnly>,
{
    /// Creates a planner for field `F` and an encryption key source.
    pub fn new(keys: &'a dyn EncryptionKeySource) -> Self {
        Self {
            keys,
            legacy: None,
            indexes: Vec::new(),
        }
    }

    /// Configures the handler used to recover non-envelope stored values.
    ///
    /// Without a handler, non-envelope bytes are treated as plaintext and
    /// decoded directly through the field's codec.
    #[must_use]
    pub fn with_legacy(mut self, legacy: &'a dyn LegacyFormat) -> Self {
        self.legacy = Some(legacy);
        self
    }

    /// Registers the next blind-index column.
    ///
    /// Columns are positional: registration order must match the order in
    /// which stored index bytes are later passed to [`Self::classify_row`] and
    /// [`Self::plan_row`].
    ///
    /// The index must be declared over this field. Registering another field's
    /// index is a type error:
    ///
    /// ```compile_fail,E0271
    /// use cryptbox::{
    ///     BlindIndexError, BlindIndexSpec, Field, FieldId, FieldOnly, IndexId,
    ///     BlindIndexKeyring, EncryptionKeyring, Padding, Utf8, migrate::RowPlanner,
    /// };
    /// use zeroize::Zeroizing;
    ///
    /// struct UserEmail;
    ///
    /// impl Field for UserEmail {
    ///     const ID: FieldId = FieldId::from_bytes([1; 16]);
    ///     const PADDING: Padding = Padding::NONE;
    ///     const RECORD: bool = false;
    ///     type Value = String;
    ///     type Codec = Utf8;
    ///     type Binding = FieldOnly;
    ///     type Indexes = ();
    /// }
    ///
    /// struct InviteEmail;
    ///
    /// impl Field for InviteEmail {
    ///     const ID: FieldId = FieldId::from_bytes([2; 16]);
    ///     const PADDING: Padding = Padding::NONE;
    ///     const RECORD: bool = false;
    ///     type Value = String;
    ///     type Codec = Utf8;
    ///     type Binding = FieldOnly;
    ///     type Indexes = ();
    /// }
    ///
    /// struct InviteEmailLookup;
    ///
    /// impl BlindIndexSpec for InviteEmailLookup {
    ///     type Field = InviteEmail;
    ///     const ID: IndexId = IndexId::from_bytes([3; 16]);
    ///     const BITS: u16 = 32;
    ///     const NORMALIZER: &'static str = "exact/1";
    ///     type Query = str;
    ///
    ///     fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    ///         Ok(Zeroizing::new(query.as_bytes().to_vec()))
    ///     }
    ///
    ///     fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
    ///         Self::normalize_query(value)
    ///     }
    /// }
    ///
    /// fn planner<'a>(
    ///     keys: &'a EncryptionKeyring,
    ///     index_keys: &'a BlindIndexKeyring,
    /// ) -> RowPlanner<'a, UserEmail> {
    ///     RowPlanner::<UserEmail>::new(keys).with_index_with::<InviteEmailLookup>(index_keys)
    /// }
    /// ```
    #[must_use]
    pub fn with_index_with<Spec>(mut self, keys: &'a dyn BlindIndexKeySource) -> Self
    where
        Spec: BlindIndexSpec<Field = F>,
    {
        self.indexes.push(IndexColumn {
            derive: derive_index_bytes::<F, Spec>,
            current_key: current_index_key_id::<Spec>,
            keys,
        });

        self
    }

    /// Classifies one stored row without producing writes or consuming nonces.
    ///
    /// Checks structure and compares unauthenticated generation IDs. It does not
    /// decrypt, decode, recover legacy data, or recompute indexes. Index parsing
    /// checks the stored format, not agreement with the registered specification's
    /// precision or logical ID. Classification may stop at the first legacy or
    /// stale component, so later columns need not have been inspected.
    /// [`RowState::Current`] does not establish authenticated readability.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed envelopes or blind indexes, an index
    /// column arity mismatch, or unavailable keys.
    pub fn classify_row(&self, ciphertext: &[u8], indexes: &[&[u8]]) -> Result<RowState, Error> {
        self.check_arity(indexes)?;

        match crate::inspect_ciphertext(ciphertext) {
            Ok(_) => {}
            Err(Error::NotCiphertext) => return Ok(RowState::Legacy),
            Err(error) => return Err(error),
        }

        if is_stale_envelope::<F>(ciphertext, self.keys)? {
            return Ok(RowState::Stale);
        }

        for (column, bytes) in self.indexes.iter().zip(indexes) {
            if column.is_stale(bytes)? {
                return Ok(RowState::Stale);
            }
        }

        Ok(RowState::Current)
    }

    /// Classifies one stored row and builds its replacement bytes when needed.
    ///
    /// Current rows are returned without decryption. Current index columns keep
    /// their bytes even when another component is rewritten. Re-encryption alone
    /// authenticates and checks padding but does not decode with the codec;
    /// stale-index derivation also decrypts and decodes the value.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::classify_row`],
    /// and additionally when decryption, codec decoding, encryption, or index
    /// derivation fails while building the replacement.
    pub fn plan_row(&self, ciphertext: &[u8], indexes: &[&[u8]]) -> Result<RowOutcome, Error> {
        self.check_arity(indexes)?;

        match crate::inspect_ciphertext(ciphertext) {
            Ok(_) => {}
            Err(Error::NotCiphertext) => return self.plan_legacy_row(ciphertext),
            Err(error) => return Err(error),
        }

        let envelope_is_stale = is_stale_envelope::<F>(ciphertext, self.keys)?;
        let mut stale_columns = Vec::with_capacity(self.indexes.len());
        for (column, bytes) in self.indexes.iter().zip(indexes) {
            stale_columns.push(column.is_stale(bytes)?);
        }

        if !envelope_is_stale && !stale_columns.contains(&true) {
            return Ok(RowOutcome {
                state: RowState::Current,
                write: None,
            });
        }

        let parsed = Sealed::<F>::from_validated_bytes(ciphertext.to_vec());
        let rewritten = if envelope_is_stale {
            parsed.reseal((), self.keys)?
        } else {
            parsed
        };

        let indexes = if stale_columns.contains(&true) {
            // The ciphertext is authoritative: stale indexes are re-derived
            // from decrypted plaintext, never trusted index metadata.
            let value = rewritten.open((), self.keys)?;
            let mut replacements = Vec::with_capacity(self.indexes.len());
            for ((column, bytes), stale) in self.indexes.iter().zip(indexes).zip(&stale_columns) {
                replacements.push(if *stale {
                    (column.derive)(&value, column.keys)?
                } else {
                    bytes.to_vec()
                });
            }

            replacements
        } else {
            indexes.iter().map(|bytes| bytes.to_vec()).collect()
        };

        Ok(RowOutcome {
            state: RowState::Stale,
            write: Some(RowWrite {
                ciphertext: rewritten.into_bytes(),
                indexes,
            }),
        })
    }

    fn plan_legacy_row(&self, bytes: &[u8]) -> Result<RowOutcome, Error> {
        let plaintext = legacy::recover(bytes, self.legacy)?;
        let value = F::Codec::decode(&plaintext)?;
        let sealed = Sealed::<F>::seal(&value, (), self.keys)?;
        let mut indexes = Vec::with_capacity(self.indexes.len());
        for column in &self.indexes {
            indexes.push((column.derive)(&value, column.keys)?);
        }

        Ok(RowOutcome {
            state: RowState::Legacy,
            write: Some(RowWrite {
                ciphertext: sealed.into_bytes(),
                indexes,
            }),
        })
    }

    fn check_arity(&self, indexes: &[&[u8]]) -> Result<(), Error> {
        if indexes.len() == self.indexes.len() {
            Ok(())
        } else {
            Err(Error::IndexColumnMismatch {
                expected: self.indexes.len(),
                actual: indexes.len(),
            })
        }
    }
}

impl<F> IndexColumn<'_, F>
where
    F: Field,
{
    fn is_stale(&self, bytes: &[u8]) -> Result<bool, Error> {
        Ok(inspect_blind_index(bytes)?.index_key_id() != (self.current_key)(self.keys)?)
    }
}

impl<F> fmt::Debug for RowPlanner<'_, F>
where
    F: Field,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RowPlanner")
            .field("legacy", &self.legacy.is_some())
            .field("indexes", &self.indexes.len())
            .finish_non_exhaustive()
    }
}
