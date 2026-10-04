use std::fmt;

use zeroize::Zeroizing;

use crate::{
    BlindIndex, BlindIndexKeyring, BlindIndexSpec, Codec, EncryptionKeyring, Error, Seal,
    blind::{derive_value, index_context},
    bound,
    envelope::{inspect_blind_index, inspect_ciphertext},
    seal_context::{RecordIdType, RecordValue, SealContext},
};

use super::{LegacyFormat, legacy};

/// The classification of one stored row against the current key generations
/// and seal context.
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

    const fn unchanged(state: RowState) -> Self {
        Self { state, write: None }
    }
}

type RecordIdFn<'a, R> = Box<dyn Fn(&R) -> Result<Option<RecordValue>, Error> + Send + Sync + 'a>;

type IndexDeriver<F> =
    fn(&<F as Seal>::Value, &SealContext, &BlindIndexKeyring) -> Result<Vec<u8>, Error>;

fn derive_index_bytes<Spec: BlindIndexSpec>(
    value: &<Spec::Seal as Seal>::Value,
    context: &SealContext,
    keys: &BlindIndexKeyring,
) -> Result<Vec<u8>, Error> {
    derive_value::<Spec>(value, context, keys).map(BlindIndex::into_bytes)
}

struct IndexColumn<'a, F>
where
    F: Seal,
{
    context: SealContext,
    deriver: IndexDeriver<F>,
    keys: &'a BlindIndexKeyring,
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
/// # Records
///
/// Each row of a record field's seal is sealed under its record ID, which a
/// closure reads from `R`, the row's columns ([`Self::for_rows`]). A planner
/// seals with one keyring: when the application keeps values under separate
/// keys, such as one keyring per org, run one sweep per keyring over the rows
/// those keys protect. [`Self::new`] serves standalone values, whose rows
/// need no columns.
///
/// A seal does not know whether it is a record field's, so a planner of the
/// wrong kind builds: [`Self::new`] over a record's field, or
/// [`Self::for_rows`] with a record ID of another kind. Every row then reports
/// [`Error::ContextMismatch`], which a verification pass counts as a malformed
/// row, not as a misconfigured pass. Check a pass on a few known-good rows
/// before trusting its counts.
pub struct RowPlanner<'a, F, R = ()>
where
    F: Seal,
{
    keys: &'a EncryptionKeyring,
    record_id: RecordIdFn<'a, R>,
    legacy: Option<&'a dyn LegacyFormat>,
    indexes: Vec<IndexColumn<'a, F>>,
}

impl<'a, F, R> RowPlanner<'a, F, R>
where
    F: Seal,
{
    /// Creates a planner for standalone values of seal `F`, as
    /// [`Sealed<F>`](crate::Sealed) holds them, and their encryption keyring.
    ///
    /// A record field's values are sealed under each row's record ID: use
    /// [`Self::for_rows`]. A standalone planner reports them as
    /// [`Error::ContextMismatch`].
    #[must_use]
    pub fn new(keys: &'a EncryptionKeyring) -> Self {
        Self::with_record_id(keys, Box::new(|_| Ok(None)))
    }

    /// Creates a planner for rows of seal `F` that `keys` protects, each bound
    /// to the record ID `record_id` reads from its columns: a reference to a
    /// UUID or an `i64`, such as `|row| Ok(&row.id)`.
    ///
    /// Use it for a record field's values, as
    /// [`Sealed<F, InRecord<Id>>`](crate::InRecord) holds them; the record ID's
    /// type `Id` must be the field's, or every row reports
    /// [`Error::ContextMismatch`]. An error from `record_id` is returned as it
    /// is, and stops a sweep or verification pass.
    pub fn for_rows<Id: RecordIdType>(
        keys: &'a EncryptionKeyring,
        record_id: impl for<'r> Fn(&'r R) -> Result<&'r Id, Error> + Send + Sync + 'a,
    ) -> Self {
        Self::with_record_id(
            keys,
            Box::new(move |row| record_id(row).map(|id| Some(id.record_value()))),
        )
    }

    fn with_record_id(keys: &'a EncryptionKeyring, record_id: RecordIdFn<'a, R>) -> Self {
        Self {
            keys,
            record_id,
            legacy: None,
            indexes: Vec::new(),
        }
    }

    /// Configures the handler used to recover non-envelope stored values.
    ///
    /// Without a handler, non-envelope bytes are treated as plaintext and
    /// decoded directly through the seal's codec.
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
    /// The index must be declared over this seal. Registering another seal's
    /// index is a type error:
    ///
    /// ```compile_fail,E0271
    /// use cryptbox::{
    ///     BlindIndexError, BlindIndexSpec, Seal, SealId, IndexId,
    ///     BlindIndexKeyring, EncryptionKeyring, Padding, Utf8, migrate::RowPlanner,
    /// };
    /// use zeroize::Zeroizing;
    ///
    /// struct UserEmail;
    ///
    /// impl Seal for UserEmail {
    ///     const ID: SealId = SealId::from_bytes([1; 16]);
    ///     const PADDING: Padding = Padding::NONE;
    ///     type Value = String;
    ///     type Codec = Utf8;
    /// }
    ///
    /// struct InviteEmail;
    ///
    /// impl Seal for InviteEmail {
    ///     const ID: SealId = SealId::from_bytes([2; 16]);
    ///     const PADDING: Padding = Padding::NONE;
    ///     type Value = String;
    ///     type Codec = Utf8;
    /// }
    ///
    /// struct InviteEmailLookup;
    ///
    /// impl BlindIndexSpec for InviteEmailLookup {
    ///     type Seal = InviteEmail;
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
    ///     RowPlanner::<UserEmail>::new(keys).with_index::<InviteEmailLookup>(index_keys)
    /// }
    /// ```
    #[must_use]
    pub fn with_index<Spec>(mut self, keys: &'a BlindIndexKeyring) -> Self
    where
        Spec: BlindIndexSpec<Seal = F>,
    {
        self.indexes.push(IndexColumn {
            context: index_context::<Spec>(),
            deriver: derive_index_bytes::<Spec>,
            keys,
        });

        self
    }

    /// Classifies one stored row without producing writes or consuming nonces.
    ///
    /// `row` holds the columns the row's record ID is read from.
    /// Checks the row's structure, and compares unauthenticated
    /// context fingerprints and generation IDs. It does not decrypt, decode,
    /// recover legacy data, or recompute indexes. Index parsing
    /// checks the stored format, not agreement with the registered specification's
    /// precision or logical ID. Classification may stop at the first legacy or
    /// stale component, so later columns need not have been inspected.
    /// [`RowState::Current`] does not establish authenticated readability.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed envelopes or blind indexes, an envelope
    /// of another kind of context, an index column arity mismatch, or
    /// unavailable keys.
    pub fn classify_row(
        &self,
        row: &R,
        ciphertext: &[u8],
        indexes: &[&[u8]],
    ) -> Result<RowState, Error> {
        self.check_arity(indexes)?;
        let record = (self.record_id)(row)?;
        let context = SealContext::new(&F::ID, record);

        match inspect_ciphertext(ciphertext) {
            Ok(_) => {}
            Err(Error::NotCiphertext) => return Ok(RowState::Legacy),
            Err(error) => return Err(error),
        }

        if bound::needs_reseal(
            context.envelope().fingerprint(),
            F::PADDING,
            ciphertext,
            self.keys,
        )? {
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
    /// Current rows are returned without decryption. Current
    /// index columns keep their bytes even when another component is
    /// rewritten. Re-encryption alone authenticates and checks padding but does
    /// not decode with the codec; stale-index derivation also decrypts and
    /// decodes the value.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::classify_row`],
    /// and additionally when decryption, codec decoding, encryption, or index
    /// derivation fails while building the replacement.
    pub fn plan_row(
        &self,
        row: &R,
        ciphertext: &[u8],
        indexes: &[&[u8]],
    ) -> Result<RowOutcome, Error> {
        self.check_arity(indexes)?;
        let record = (self.record_id)(row)?;
        let context = SealContext::new(&F::ID, record);

        match inspect_ciphertext(ciphertext) {
            Ok(_) => {}
            Err(Error::NotCiphertext) => return self.plan_legacy_row(&context, ciphertext),
            Err(error) => return Err(error),
        }

        let envelope_is_stale = bound::needs_reseal(
            context.envelope().fingerprint(),
            F::PADDING,
            ciphertext,
            self.keys,
        )?;
        let mut stale_columns = Vec::with_capacity(self.indexes.len());
        for (column, bytes) in self.indexes.iter().zip(indexes) {
            stale_columns.push(column.is_stale(bytes)?);
        }
        let indexes_are_stale = stale_columns.contains(&true);

        if !envelope_is_stale && !indexes_are_stale {
            return Ok(RowOutcome::unchanged(RowState::Current));
        }

        let current = (&context, self.keys);
        let (plaintext, ciphertext) = if envelope_is_stale {
            bound::reseal(current, current, F::PADDING, ciphertext)?
        } else {
            (
                bound::open(&context, ciphertext, self.keys)?,
                ciphertext.to_vec(),
            )
        };

        let indexes = if indexes_are_stale {
            // The ciphertext is authoritative: stale indexes are re-derived
            // from decrypted plaintext, never trusted index metadata.
            let value = F::Codec::decode(&plaintext)?;
            let mut replacements = Vec::with_capacity(self.indexes.len());
            for ((column, bytes), stale) in self.indexes.iter().zip(indexes).zip(&stale_columns) {
                replacements.push(if *stale {
                    column.derive(&value)?
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
                ciphertext,
                indexes,
            }),
        })
    }

    fn plan_legacy_row(&self, context: &SealContext, bytes: &[u8]) -> Result<RowOutcome, Error> {
        let plaintext = legacy::recover(bytes, self.legacy)?;
        let value = F::Codec::decode(&plaintext)?;
        let plaintext: Zeroizing<Vec<u8>> = F::Codec::encode(&value)?;
        let ciphertext = bound::seal(context, F::PADDING, &plaintext, self.keys)?;

        Ok(RowOutcome {
            state: RowState::Legacy,
            write: Some(RowWrite {
                ciphertext,
                indexes: self.derive_indexes(&value)?,
            }),
        })
    }

    fn derive_indexes(&self, value: &F::Value) -> Result<Vec<Vec<u8>>, Error> {
        self.indexes
            .iter()
            .map(|column| column.derive(value))
            .collect()
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
    F: Seal,
{
    fn is_stale(&self, bytes: &[u8]) -> Result<bool, Error> {
        Ok(inspect_blind_index(bytes)?.index_key_id() != self.keys.current().id())
    }

    fn derive(&self, value: &F::Value) -> Result<Vec<u8>, Error> {
        (self.deriver)(value, &self.context, self.keys)
    }
}

impl<F, R> fmt::Debug for RowPlanner<'_, F, R>
where
    F: Seal,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RowPlanner")
            .field("legacy", &self.legacy.is_some())
            .field("indexes", &self.indexes.len())
            .finish_non_exhaustive()
    }
}
