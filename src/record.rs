use std::{fmt, marker::PhantomData};

use crate::{
    BlindIndex, BlindIndexKeys, BlindIndexSpec, EncryptionKeys, Error, RecordKeys, Seal, SealId,
    Sealed,
    blind::{index_context, probes_in},
    seal_context::{RecordKey, SealContext},
};

/// A row whose sealed fields are bound to their seals and to its record ID,
/// which the row stores.
///
/// A record pairs a plaintext struct with its stored form, [`Self::Stored`]:
/// the record ID and plaintext fields as they are, each sealed
/// field as its [`Sealed`](crate::Sealed) value, and a
/// [`BlindIndex`] column per blind index. [`Self::seal`] encrypts every sealed
/// field and derives its indexes; [`Self::open`] authenticates and opens them.
///
/// The record ID is read from the stored row and authenticated by opening: a
/// sealed value copied from another row or field fails to open. Plaintext
/// columns, such as an org, are not authenticated: authorize on them like any
/// other column, before decrypting with [`Self::open_expecting`] or after. With
/// a keyring per org, another org's row fails to open with
/// [`Error::UnknownEncryptionKey`].
///
/// With the `derive` feature, `#[derive(Record)]` generates the stored form,
/// this impl, a seal for each sealed field, a blind-index spec and an
/// [`Index`] handle for each blind index.
pub trait Record: Sized {
    /// The stored form: the record ID and plaintext fields as they are, the
    /// sealed fields, and a column per blind index.
    type Stored;

    /// The seal ID of each sealed field, in field order.
    ///
    /// The [schema manifest](crate::schema::Manifest::record) names the record
    /// by them.
    const SEALS: &'static [SealId];

    /// The name of the field that holds the record ID.
    const RECORD_ID: &'static str;

    /// The names of the fields stored as they are, in field order.
    ///
    /// Field names are the Rust names the [schema
    /// manifest](crate::schema::Manifest::record) lists, so a field that should
    /// have been sealed shows up in its snapshot.
    const PLAINTEXT: &'static [&'static str];

    /// Encrypts every sealed field under the record ID, and derives its blind
    /// indexes.
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

    /// Opens the sealed fields of `stored` under its record ID.
    ///
    /// Stored blind indexes are neither read nor checked.
    ///
    /// # Errors
    ///
    /// Returns any error of opening a field, such as
    /// [`Error::AuthenticationFailed`] for a value of another record.
    fn open<K>(stored: Self::Stored, keys: &K) -> Result<Self, Error>
    where
        K: EncryptionKeys + ?Sized;

    /// Opens `stored` only if `expect` accepts it, checked before anything is
    /// decrypted: compare its record ID or plaintext columns, such as an org,
    /// with those the caller asked for or may read.
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

/// A blind index of record `R` and spec `S`.
///
/// `#[derive(Record)]` declares one as a const named after the index column,
/// such as `Customer::EMAIL_INDEX`. An index is derived under its seal alone:
/// equal values in different tenants derive equal indexes under shared keys, and
/// unrelated ones under a blind-index keyring per tenant.
pub struct Index<R: Record, S: BlindIndexSpec> {
    value: fn(&R) -> Option<&<S::Seal as Seal>::Value>,
    marker: PhantomData<fn() -> (R, S)>,
}

impl<R: Record, S: BlindIndexSpec> Index<R, S> {
    /// Creates the handle of an index. Not public API: `#[derive(Record)]`
    /// declares handles.
    #[doc(hidden)]
    pub const fn __new(value: fn(&R) -> Option<&<S::Seal as Seal>::Value>) -> Self {
        Self {
            value,
            marker: PhantomData,
        }
    }

    /// Derives the probes for `query`, one per readable index key; select the
    /// rows whose index column holds any of them, within what the caller may
    /// read, such as `WHERE org = ?`.
    ///
    /// # Errors
    ///
    /// Returns an error for normalization failure, or keys without a
    /// blind-index keyring.
    pub fn probes(
        &self,
        query: &S::Query,
        keys: &(impl BlindIndexKeys + ?Sized),
    ) -> Result<Vec<BlindIndex<S>>, Error> {
        probes_in::<S>(query, &index_context::<S>(), keys)
    }

    /// Opens the candidate rows of a lookup and keeps the matches, with one
    /// result per row kept, in the order of `rows`.
    ///
    /// A truncated index selects false candidates too, so each row is opened
    /// and its value compared with `query` by
    /// [`BlindIndexSpec::verify_candidate`]; rows that do not match are dropped.
    /// A row that fails to open is reported as its error, never as a non-match.
    /// Plaintext columns, such as an org, are not authenticated: select within
    /// what the caller may read, and authorize on each hit.
    ///
    /// # Errors
    ///
    /// Returns an error when `query` cannot be normalized.
    pub fn open_matching(
        &self,
        query: &S::Query,
        rows: impl IntoIterator<Item = R::Stored>,
        keys: &(impl EncryptionKeys + ?Sized),
    ) -> Result<Vec<Result<R, Error>>, Error> {
        S::normalize_query(query)?;
        let mut results = Vec::new();

        for row in rows {
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

impl<R: Record, S: BlindIndexSpec> Clone for Index<R, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R: Record, S: BlindIndexSpec> Copy for Index<R, S> {}

impl<R: Record, S: BlindIndexSpec> fmt::Debug for Index<R, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Index")
            .field("id", &S::ID)
            .finish_non_exhaustive()
    }
}

/// Seals a record field's `value` under its seal `F` and the record ID `id`.
/// Not public API: `#[derive(Record)]` calls it.
///
/// # Errors
///
/// Returns any error of sealing.
#[doc(hidden)]
pub fn seal_in_record<F: Seal>(
    value: &F::Value,
    id: &impl RecordKey,
    keys: &(impl EncryptionKeys + ?Sized),
) -> Result<Sealed<F>, Error> {
    Sealed::seal_in(value, &SealContext::in_record::<F, _>(id)?, keys)
}

/// Opens a record field's value under its seal `F` and the record ID `id`. Not
/// public API: `#[derive(Record)]` calls it.
///
/// # Errors
///
/// Returns any error of opening, such as [`Error::AuthenticationFailed`] for a
/// value of another record.
#[doc(hidden)]
pub fn open_in_record<F: Seal>(
    sealed: &Sealed<F>,
    id: &impl RecordKey,
    keys: &(impl EncryptionKeys + ?Sized),
) -> Result<F::Value, Error> {
    sealed.open_in(&SealContext::in_record::<F, _>(id)?, keys)
}
