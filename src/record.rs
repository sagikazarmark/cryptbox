use std::{fmt, marker::PhantomData};

use crate::{
    Args, BlindIndex, BlindIndexKeys, BlindIndexSpec, EncryptionKeys, Error, PartValue, RecordKeys,
    Seal, SealId, Sealed,
    binding::declaration_fingerprint,
    blind::{index_domain, probes_in},
    inspect_ciphertext,
};

/// A row whose sealed fields are bound to their seals, to the row's bound
/// values, and to its record ID, all of which the row stores.
///
/// A record pairs a plaintext struct with its stored form, [`Self::Stored`]:
/// the record ID, bound values, and plaintext fields as they are, each sealed
/// field as its [`Sealed`](crate::Sealed) value, and a
/// [`BlindIndex`] column per blind index. [`Self::seal`] encrypts every sealed
/// field and derives its indexes; [`Self::open`] authenticates and opens them.
///
/// The record ID and bound values, such as an org, are read from the stored row
/// and authenticated by opening: a row whose org column was changed, or whose
/// sealed value was copied from another row, fails to open. They say where the
/// row belongs; authorize on the opened record's bound values, or check them
/// before opening with [`Self::open_expecting`].
///
/// With the `derive` feature, `#[derive(Record)]` generates the stored form,
/// this impl, a seal for each sealed field, a blind-index spec and an
/// [`Index`] handle for each blind index, and the partition struct of each
/// index partitioned by two or more bound values.
pub trait Record: Sized {
    /// The stored form: the record ID, bound values, and plaintext fields as
    /// they are, the sealed fields, and a column per blind index.
    type Stored;

    /// The seal ID of each sealed field, in field order.
    ///
    /// The [schema manifest](crate::schema::Manifest::record) names the record
    /// by them.
    const SEALS: &'static [SealId];

    /// The name of the field that holds the record ID.
    const RECORD_ID: &'static str;

    /// The names of the bound fields, in field order.
    const BOUND: &'static [&'static str];

    /// The names of the fields stored as they are, in field order.
    ///
    /// Field names are the Rust names the [schema
    /// manifest](crate::schema::Manifest::record) lists, so a field that should
    /// have been sealed shows up in its snapshot.
    const PLAINTEXT: &'static [&'static str];

    /// The names of the sealed fields whose legacy declaration is still
    /// opened, named by `legacy(…)`, in field order.
    ///
    /// The [schema manifest](crate::schema::Manifest::record) lists them, so
    /// closing a window shows up in its snapshot.
    const LEGACY: &'static [&'static str] = &[];

    /// Encrypts every sealed field under the record's bound values and ID, and
    /// derives its blind indexes.
    ///
    /// A record without blind indexes takes an
    /// [`EncryptionKeyring`](crate::EncryptionKeyring); one with blind indexes
    /// takes [`Keys`](crate::Keys) with a blind-index keyring.
    ///
    /// # Errors
    ///
    /// Returns any error of sealing a field or deriving one of its indexes, such
    /// as [`Error::BlindIndexKeysNotConfigured`] for keys without a blind-index
    /// keyring.
    fn seal<K>(&self, keys: &K) -> Result<Self::Stored, Error>
    where
        K: RecordKeys + ?Sized;

    /// Opens the sealed fields of `stored` under its bound values and ID.
    ///
    /// Stored blind indexes are neither read nor checked.
    ///
    /// # Errors
    ///
    /// Returns any error of opening a field, such as
    /// [`Error::AuthenticationFailed`] for a value of another record or bound
    /// value.
    fn open<K>(stored: Self::Stored, keys: &K) -> Result<Self, Error>
    where
        K: EncryptionKeys + ?Sized;

    /// Opens `stored` only if `expect` accepts it, checked before anything is
    /// decrypted: compare its record ID or bound values with those the caller
    /// asked for or may read.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedRecord`] when `expect` rejects the row, or any
    /// error of [`Self::open`].
    fn open_expecting<K>(
        stored: Self::Stored,
        keys: &K,
        expect: impl FnOnce(&Self::Stored) -> bool,
    ) -> Result<Self, Error>
    where
        K: EncryptionKeys + ?Sized,
    {
        if !expect(&stored) {
            return Err(Error::UnexpectedRecord);
        }

        Self::open(stored, keys)
    }
}

/// The part values of a partition, in its spec's order.
type PartitionValues<P> = for<'p> fn(&'p P) -> Vec<PartValue<'p>>;

/// A blind index of record `R`, spec `S`, searched within partition `P`: the
/// bound values that partition it, which a query supplies.
///
/// `#[derive(Record)]` declares one as a const named after the index column,
/// such as `Customer::EMAIL_INDEX`. `P` is the bound ID type of an index
/// partitioned by one bound value, a generated struct with a field per bound
/// value for two or more, or `()` for an index that spans them all.
pub struct Index<R: Record, S: BlindIndexSpec, P> {
    partition: PartitionValues<P>,
    in_partition: fn(&R::Stored, &P) -> bool,
    value: fn(&R) -> Option<&<S::Seal as Seal>::Value>,
    marker: PhantomData<fn() -> (R, S)>,
}

impl<R: Record, S: BlindIndexSpec, P> Index<R, S, P> {
    /// Creates the handle of an index. Not public API: `#[derive(Record)]`
    /// declares handles.
    #[doc(hidden)]
    pub const fn __new(
        partition: PartitionValues<P>,
        in_partition: fn(&R::Stored, &P) -> bool,
        value: fn(&R) -> Option<&<S::Seal as Seal>::Value>,
    ) -> Self {
        Self {
            partition,
            in_partition,
            value,
            marker: PhantomData,
        }
    }

    /// Derives the probes for `query` in `partition`, one per readable index
    /// key; select the rows whose index column holds any of them.
    ///
    /// # Errors
    ///
    /// Returns an error for normalization failure, a partition value of
    /// another kind than its type declares, or keys without a blind-index
    /// keyring.
    pub fn probes(
        &self,
        query: &S::Query,
        partition: &P,
        keys: &(impl BlindIndexKeys + ?Sized),
    ) -> Result<Vec<BlindIndex<S>>, Error> {
        probes_in::<S>(
            query,
            &index_domain::<S>(&(self.partition)(partition))?,
            keys,
        )
    }

    /// Opens the candidate rows of a lookup in `partition` and keeps the
    /// matches, with one result per row kept, in the order of `rows`.
    ///
    /// A truncated index selects false candidates too, so each row is opened
    /// and its value compared with `query` by
    /// [`BlindIndexSpec::verify_candidate`]; rows that do not match are dropped.
    /// A row outside `partition` is reported as [`Error::OutsidePartition`]
    /// without being decrypted, and a row that fails to open as its error: never
    /// as a non-match. The bound values the index spans, such as a workspace
    /// under an org-wide search, are read from each row and authenticated:
    /// authorize on them.
    ///
    /// # Errors
    ///
    /// Returns an error when `query` cannot be normalized.
    pub fn open_matching(
        &self,
        query: &S::Query,
        partition: &P,
        rows: impl IntoIterator<Item = R::Stored>,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Vec<Result<R, Error>>, Error> {
        S::normalize_query(query)?;
        let mut results = Vec::new();

        for row in rows {
            if !(self.in_partition)(&row, partition) {
                results.push(Err(Error::OutsidePartition));
                continue;
            }
            let record = match R::open(row, keys) {
                Ok(record) => record,
                Err(error) => {
                    results.push(Err(error));
                    continue;
                }
            };
            match (self.value)(&record).map(|value| S::verify_candidate(query, value)) {
                None | Some(Ok(false)) => {}
                Some(Ok(true)) => results.push(Ok(record)),
                Some(Err(error)) => results.push(Err(error)),
            }
        }

        Ok(results)
    }
}

impl<R: Record, S: BlindIndexSpec, P> Clone for Index<R, S, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R: Record, S: BlindIndexSpec, P> Copy for Index<R, S, P> {}

impl<R: Record, S: BlindIndexSpec, P> fmt::Debug for Index<R, S, P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Index")
            .field("id", &S::ID)
            .finish_non_exhaustive()
    }
}

/// Opens a record field that may still be sealed with its legacy declaration,
/// `L`: the declaration it had before, named by `legacy(…)`. Not public API:
/// `#[derive(Record)]` calls it.
///
/// The header's binding fingerprint chooses the declaration to try; either way
/// the value must authenticate under it. When only the seal ID changed, the
/// declarations share a fingerprint, so a value that fails to authenticate
/// under the current seal is tried under the legacy one.
///
/// # Errors
///
/// Returns [`Error::BindingMismatch`] for a value of neither declaration, or any
/// error of opening it.
#[doc(hidden)]
pub fn open_legacy<F, L>(
    sealed: &Sealed<F>,
    args: impl Args<F>,
    legacy: impl Args<L>,
    keys: &(impl EncryptionKeys + ?Sized),
) -> Result<F::Value, Error>
where
    F: Seal,
    L: Seal<Value = F::Value>,
{
    let stored = inspect_ciphertext(sealed.as_bytes())?.context_fingerprint();
    let current = declaration_fingerprint::<F::Bound, F::Record>();
    let old = declaration_fingerprint::<L::Bound, L::Record>();

    if stored == current {
        match sealed.open(args, keys) {
            Err(Error::AuthenticationFailed) if old == current && L::ID != F::ID => {}
            opened => return opened,
        }
    } else if stored != old {
        return Err(Error::BindingMismatch);
    }

    Sealed::<L>::from_bytes(sealed.as_bytes().to_vec())?.open(legacy, keys)
}
