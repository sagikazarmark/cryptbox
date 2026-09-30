use std::{fmt, marker::PhantomData};

use zeroize::Zeroizing;

use crate::{
    BindingDomain, BlindIndex, BlindIndexKeyring, BlindIndexSpec, BoundList, BoundValues, Codec,
    EncryptionKeyring, Error, PartValue, RecordId, RecordIdType, Seal,
    binding::{OwnedBinding, bound_values, declaration_fingerprint},
    blind::{derive_value, projected_domain},
    bound, inspect_blind_index, inspect_ciphertext,
};

use super::{LegacyFormat, legacy};

/// The classification of one stored row against the current key generations
/// and binding declaration.
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
    /// The envelope's header names an older binding declaration registered with
    /// [`RowPlanner::legacy_binding`].
    ///
    /// Only the unauthenticated binding fingerprint is compared.
    LegacyBinding,
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

/// The binding arguments of one stored row, which a [`RowPlanner`]'s row
/// closure builds from the row's columns.
///
/// It holds the row's bound values, of the seal's bound list `L`, and, for a
/// seal that binds a [record](Seal::Record), its record ID. A record omitted for a seal
/// that binds one, or passed to a seal that binds none while no
/// [legacy-binding window](RowPlanner::legacy_binding) binds one either, fails
/// planning with [`Error::InvalidBinding`].
#[derive(Clone, Debug)]
pub struct RowArgs<'r, L> {
    bound: OwnedBinding,
    record: Option<RecordId<'r>>,
    list: PhantomData<fn() -> L>,
}

impl<'r, L: BoundList> RowArgs<'r, L> {
    /// Creates the arguments of a row bound to the values `bound` without a
    /// record. The values are copied, so they may be built from the row's
    /// columns in place, such as `&TenantId::new(row.tenant.clone())?`.
    pub fn new<'v>(bound: impl BoundValues<'v, L>) -> Self {
        Self {
            bound: OwnedBinding::new(&bound_values(bound)),
            record: None,
            list: PhantomData,
        }
    }

    /// Binds the row's record ID too.
    #[must_use]
    pub fn with_record(self, record: RecordId<'r>) -> Self {
        Self {
            record: Some(record),
            ..self
        }
    }
}

type RowArgsFn<'a, F, R> =
    Box<dyn for<'r> Fn(&'r R) -> Result<RowArgs<'r, <F as Seal>::Bound>, Error> + 'a>;

type IndexDeriver<F> =
    fn(&<F as Seal>::Value, &BindingDomain, &BlindIndexKeyring) -> Result<Vec<u8>, Error>;

type IndexDomainFn = fn(&[PartValue<'_>]) -> Result<BindingDomain, Error>;

type LegacyDomain = fn(&[PartValue<'_>], Option<PartValue<'_>>) -> Result<BindingDomain, Error>;

fn derive_index_bytes<Spec: BlindIndexSpec>(
    value: &<Spec::Seal as Seal>::Value,
    domain: &BindingDomain,
    keys: &BlindIndexKeyring,
) -> Result<Vec<u8>, Error> {
    derive_value::<Spec>(value, domain, keys).map(BlindIndex::into_bytes)
}

struct IndexColumn<'a, F>
where
    F: Seal,
{
    /// Projects the column's partition from a row's bound values and encodes it.
    domain: IndexDomainFn,
    deriver: IndexDeriver<F>,
    keys: &'a BlindIndexKeyring,
}

/// An older binding declaration whose rows the planner reseals, and its keys.
struct LegacyDeclaration<'a> {
    /// The declaration's binding fingerprint.
    fingerprint: [u8; 8],
    /// Whether the declaration binds a record.
    recorded: bool,
    domain: LegacyDomain,
    keys: &'a EncryptionKeyring,
}

/// The binding of one row under the planner's seal.
struct RowBinding {
    domain: BindingDomain,
    /// One index domain per registered index column, in order.
    index_domains: Vec<BindingDomain>,
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
/// # Bindings
///
/// Each row is sealed under its own binding arguments, which a row closure
/// builds from `R`, the row's columns ([`Self::for_rows`]). A planner seals
/// with one keyring: when the application keeps values under separate keys,
/// such as one keyring per org, run one sweep per keyring over the rows those
/// keys protect. [`Self::new`] serves a seal without bound values or a record, whose
/// rows need no columns.
///
/// To change a seal's binding declaration, register the declaration it had before with
/// [`Self::legacy_binding`]: rows whose header still names that declaration are
/// opened under it and resealed under the current one.
pub struct RowPlanner<'a, F, R = ()>
where
    F: Seal,
{
    keys: &'a EncryptionKeyring,
    row_args: RowArgsFn<'a, F, R>,
    legacy: Option<&'a dyn LegacyFormat>,
    legacy_declarations: Vec<LegacyDeclaration<'a>>,
    indexes: Vec<IndexColumn<'a, F>>,
}

impl<'a, F, R> RowPlanner<'a, F, R>
where
    F: Seal<Bound = (), Record = ()>,
{
    /// Creates a planner for a seal `F` without bound values or a record, and its
    /// encryption keyring.
    ///
    /// Any other seal is a type error; use [`Self::for_rows`].
    #[must_use]
    pub fn new(keys: &'a EncryptionKeyring) -> Self {
        Self::for_rows(keys, |_| Ok(RowArgs::new(())))
    }
}

impl<'a, F, R> RowPlanner<'a, F, R>
where
    F: Seal,
{
    /// Creates a planner for rows of seal `F` that `keys` protects.
    ///
    /// `row_args` builds each row's binding arguments from its columns. An
    /// error from `row_args` is returned as it is, and stops a sweep or
    /// verification pass.
    pub fn for_rows(
        keys: &'a EncryptionKeyring,
        row_args: impl for<'r> Fn(&'r R) -> Result<RowArgs<'r, F::Bound>, Error> + 'a,
    ) -> Self {
        Self {
            keys,
            row_args: Box::new(row_args),
            legacy: None,
            legacy_declarations: Vec::new(),
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

    /// Opens a legacy-binding window: rows sealed with the older binding
    /// declaration of bound list `Old` and record `OldRecord` are opened under it
    /// with `keys` and resealed under the seal's current binding.
    ///
    /// `Old` is the bound list the seal had before, such as `()` or
    /// `(TenantId,)`, and `OldRecord` its record, such as `()` or `i64`. `Old`
    /// takes each value from the row's current bound values, by kind, and when
    /// `OldRecord` is one, the row's record ID: rows moving out of a record
    /// still pass it. `keys` is the keyring those rows were sealed with. The
    /// window covers moving from no bound values to any, adding bound values,
    /// and moving into or out of a record, but not removing a bound value or
    /// changing its kind. A type of `Old` that the current bound list lacks, and
    /// a record `OldRecord` binds that the row lacks, fail planning with
    /// [`Error::InvalidBinding`].
    ///
    /// Such rows are classified as [`RowState::LegacyBinding`] by their header's
    /// binding fingerprint, and every blind index is derived again under the
    /// current binding. Close the window once a verification pass counts none.
    #[must_use]
    pub fn legacy_binding<Old: BoundList, OldRecord: RecordIdType>(
        mut self,
        keys: &'a EncryptionKeyring,
    ) -> Self {
        self.legacy_declarations.push(LegacyDeclaration {
            fingerprint: declaration_fingerprint::<Old, OldRecord>(),
            recorded: <OldRecord as RecordIdType>::RECORD.is_some(),
            domain: |values, record| {
                BindingDomain::projected::<Old, OldRecord>(
                    F::ID.as_bytes(),
                    <F::Bound as BoundList>::PARTS,
                    values,
                    record,
                )
            },
            keys,
        });

        self
    }

    /// Opens a legacy window for the declaration of seal `L`, such as the legacy
    /// seal `#[derive(Record)]` declares for a field's `legacy(…)`: rows sealed
    /// with it are opened under `L`'s seal ID and binding declaration with `keys`,
    /// and resealed under the current seal.
    ///
    /// It is [`Self::legacy_binding`] for a legacy declaration that may name
    /// another seal ID. Rows are found by their header's binding fingerprint, so a
    /// declaration that differs only in its seal ID is not detected: its rows are
    /// classified as the current declaration's.
    #[must_use]
    pub fn legacy_seal<L: Seal<Value = F::Value>>(mut self, keys: &'a EncryptionKeyring) -> Self {
        self.legacy_declarations.push(LegacyDeclaration {
            fingerprint: declaration_fingerprint::<L::Bound, L::Record>(),
            recorded: <L::Record as RecordIdType>::RECORD.is_some(),
            domain: |values, record| {
                BindingDomain::projected::<L::Bound, L::Record>(
                    L::ID.as_bytes(),
                    <F::Bound as BoundList>::PARTS,
                    values,
                    record,
                )
            },
            keys,
        });

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
    ///     type Bound = ();
    ///     type Record = ();
    ///     type Indexes = ();
    /// }
    ///
    /// struct InviteEmail;
    ///
    /// impl Seal for InviteEmail {
    ///     const ID: SealId = SealId::from_bytes([2; 16]);
    ///     const PADDING: Padding = Padding::NONE;
    ///     type Value = String;
    ///     type Codec = Utf8;
    ///     type Bound = ();
    ///     type Record = ();
    ///     type Indexes = ();
    /// }
    ///
    /// struct InviteEmailLookup;
    ///
    /// impl BlindIndexSpec for InviteEmailLookup {
    ///     type Seal = InviteEmail;
    ///     type Partition = ();
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
    pub fn with_index_with<Spec>(mut self, keys: &'a BlindIndexKeyring) -> Self
    where
        Spec: BlindIndexSpec<Seal = F>,
    {
        self.indexes.push(IndexColumn {
            domain: projected_domain::<Spec>,
            deriver: derive_index_bytes::<Spec>,
            keys,
        });

        self
    }

    /// Classifies one stored row without producing writes or consuming nonces.
    ///
    /// `row` holds the columns the row's binding arguments are built from.
    /// Checks the row's structure, and compares unauthenticated
    /// binding fingerprints and generation IDs. It does not decrypt, decode,
    /// recover legacy data, or recompute indexes. Index parsing
    /// checks the stored format, not agreement with the registered specification's
    /// precision or logical ID. Classification may stop at the first legacy or
    /// stale component, so later columns need not have been inspected.
    /// [`RowState::Current`] does not establish authenticated readability.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed envelopes or blind indexes, an envelope
    /// of an unregistered binding declaration, an index column arity mismatch,
    /// invalid binding arguments, or unavailable keys.
    pub fn classify_row(
        &self,
        row: &R,
        ciphertext: &[u8],
        indexes: &[&[u8]],
    ) -> Result<RowState, Error> {
        self.check_arity(indexes)?;
        let args = (self.row_args)(row)?;
        let binding = self.bind(&args)?;

        match inspect_ciphertext(ciphertext) {
            Ok(info)
                if self
                    .legacy_declaration(&binding, info.context_fingerprint())
                    .is_some() =>
            {
                return Ok(RowState::LegacyBinding);
            }
            Ok(_) => {}
            Err(Error::NotCiphertext) => return Ok(RowState::Legacy),
            Err(error) => return Err(error),
        }

        if bound::needs_reseal(&binding.domain, F::PADDING, ciphertext, self.keys)? {
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
    /// decodes the value. A row of a legacy binding declaration is opened under that
    /// declaration and every index is derived again.
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
        let args = (self.row_args)(row)?;
        let binding = self.bind(&args)?;

        match inspect_ciphertext(ciphertext) {
            Ok(info) => {
                if let Some(legacy) = self.legacy_declaration(&binding, info.context_fingerprint())
                {
                    return self.plan_legacy_binding_row(legacy, &args, &binding, ciphertext);
                }
            }
            Err(Error::NotCiphertext) => return self.plan_legacy_row(&binding, ciphertext),
            Err(error) => return Err(error),
        }

        let envelope_is_stale =
            bound::needs_reseal(&binding.domain, F::PADDING, ciphertext, self.keys)?;
        let mut stale_columns = Vec::with_capacity(self.indexes.len());
        for (column, bytes) in self.indexes.iter().zip(indexes) {
            stale_columns.push(column.is_stale(bytes)?);
        }
        let indexes_are_stale = stale_columns.contains(&true);

        if !envelope_is_stale && !indexes_are_stale {
            return Ok(RowOutcome::unchanged(RowState::Current));
        }

        let current = (&binding.domain, self.keys);
        let (plaintext, ciphertext) = if envelope_is_stale {
            bound::reseal(current, current, F::PADDING, ciphertext)?
        } else {
            (
                bound::open(&binding.domain, ciphertext, self.keys)?,
                ciphertext.to_vec(),
            )
        };

        let indexes = if indexes_are_stale {
            // The ciphertext is authoritative: stale indexes are re-derived
            // from decrypted plaintext, never trusted index metadata.
            let value = F::Codec::decode(&plaintext)?;
            let mut replacements = Vec::with_capacity(self.indexes.len());
            let columns = self.indexes.iter().zip(&binding.index_domains);
            for (((column, domain), bytes), stale) in columns.zip(indexes).zip(&stale_columns) {
                replacements.push(if *stale {
                    column.derive(&value, domain)?
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

    /// Encodes the row's binding.
    fn bind(&self, args: &RowArgs<'_, F::Bound>) -> Result<RowBinding, Error> {
        let recorded = <F::Record as RecordIdType>::RECORD.is_some();
        let legacy_recorded = self
            .legacy_declarations
            .iter()
            .any(|legacy| legacy.recorded);
        if args.record.is_some() && !recorded && !legacy_recorded {
            return Err(Error::InvalidBinding);
        }

        let record = if recorded { args.record } else { None };
        let domain = BindingDomain::bound::<F::Bound, F::Record>(
            F::ID.as_bytes(),
            &args.bound.values(),
            record.map(RecordId::part_value),
        )?;
        Ok(RowBinding {
            index_domains: self
                .indexes
                .iter()
                .map(|column| (column.domain)(&args.bound.values()))
                .collect::<Result<_, _>>()?,
            domain,
        })
    }

    /// Returns the registered legacy declaration an envelope's header names,
    /// unless it names the current declaration.
    fn legacy_declaration(
        &self,
        binding: &RowBinding,
        stored: [u8; 8],
    ) -> Option<&LegacyDeclaration<'a>> {
        if stored == binding.domain.fingerprint() {
            return None;
        }

        self.legacy_declarations
            .iter()
            .find(|legacy| legacy.fingerprint == stored)
    }

    fn plan_legacy_binding_row(
        &self,
        legacy: &LegacyDeclaration<'a>,
        args: &RowArgs<'_, F::Bound>,
        binding: &RowBinding,
        ciphertext: &[u8],
    ) -> Result<RowOutcome, Error> {
        let old = (legacy.domain)(&args.bound.values(), args.record.map(RecordId::part_value))?;
        let (plaintext, ciphertext) = bound::reseal(
            (&old, legacy.keys),
            (&binding.domain, self.keys),
            F::PADDING,
            ciphertext,
        )?;
        // The index binding may have changed with the declaration, so every index
        // is derived again.
        let indexes = if self.indexes.is_empty() {
            Vec::new()
        } else {
            self.derive_indexes(&F::Codec::decode(&plaintext)?, binding)?
        };

        Ok(RowOutcome {
            state: RowState::LegacyBinding,
            write: Some(RowWrite {
                ciphertext,
                indexes,
            }),
        })
    }

    fn plan_legacy_row(&self, binding: &RowBinding, bytes: &[u8]) -> Result<RowOutcome, Error> {
        let plaintext = legacy::recover(bytes, self.legacy)?;
        let value = F::Codec::decode(&plaintext)?;
        let plaintext: Zeroizing<Vec<u8>> = F::Codec::encode(&value)?;
        let ciphertext = bound::seal(&binding.domain, F::PADDING, &plaintext, self.keys)?;

        Ok(RowOutcome {
            state: RowState::Legacy,
            write: Some(RowWrite {
                ciphertext,
                indexes: self.derive_indexes(&value, binding)?,
            }),
        })
    }

    fn derive_indexes(
        &self,
        value: &F::Value,
        binding: &RowBinding,
    ) -> Result<Vec<Vec<u8>>, Error> {
        self.indexes
            .iter()
            .zip(&binding.index_domains)
            .map(|(column, domain)| column.derive(value, domain))
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

    fn derive(&self, value: &F::Value, domain: &BindingDomain) -> Result<Vec<u8>, Error> {
        (self.deriver)(value, domain, self.keys)
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
            .field("legacy_declarations", &self.legacy_declarations.len())
            .field("indexes", &self.indexes.len())
            .finish_non_exhaustive()
    }
}
