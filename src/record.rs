use crate::{
    BlindIndexKeySource, BlindIndexSpec, EncryptionKeySource, Error, FromParts, Scope, Seal,
};

/// A row of plaintext values sealed and opened together under one binding.
///
/// A record pairs a plaintext struct with its sealed storage form,
/// [`Self::Sealed`]. [`Self::seal`] encrypts every sealed field and writes
/// each field's blind indexes; [`Self::open`] authenticates and opens them.
/// Plaintext fields, such as the record ID, are copied as they are.
///
/// Every sealed field shares the record's [`Scope`] and its
/// [keys view](Self::Keys), so one key source serves the whole record, and each
/// field whose seal scope is [`Recorded`](crate::Recorded) is also bound to the
/// record's ID. The
/// record ID is never encrypted, so it can be read before the row is opened. The
/// binding must come from an authorized source, never from the stored row.
///
/// [`Self::open`] takes the record ID from the row itself. A value copied from
/// another record fails authentication, but a whole row returned in place of
/// another opens as the record it is. When you asked for one record, compare
/// the opened ID with the one you asked for.
///
/// With the `derive` feature, `#[derive(Record)]` generates the sealed struct,
/// this impl, per-field sealers for partial updates, and the seals its fields
/// declare with `#[cryptbox(id = "…")]`, each bound to its field, scope, and row;
/// and it checks that each field writes exactly the blind indexes its seal
/// declares. See its documentation for the expansion, which a hand-written impl
/// can follow.
pub trait Record: Sized {
    /// The storage form: the plaintext fields, the sealed values, and their
    /// blind indexes.
    type Sealed;

    /// The binding every sealed field of the record shares.
    type Scope: Scope;

    /// The keys view every sealed field's seal shares, [`Seal::Keys`], by which
    /// the key source is asked.
    type Keys: FromParts;

    /// Encrypts every sealed field under `binding` and the record's ID, and
    /// derives its blind indexes.
    ///
    /// # Errors
    ///
    /// Returns any error of sealing a field or deriving one of its indexes.
    fn seal<K>(&self, binding: &Self::Scope, keys: &K) -> Result<Self::Sealed, Error>
    where
        K: EncryptionKeySource<Self::Keys> + BlindIndexKeySource<Self::Keys> + ?Sized;

    /// Opens the sealed fields of `sealed` under `binding` and the record's
    /// ID.
    ///
    /// Stored blind indexes are neither read nor checked.
    ///
    /// # Errors
    ///
    /// Returns any error of opening a field, such as
    /// [`Error::AuthenticationFailed`] for a value of another record or binding.
    fn open<K>(sealed: Self::Sealed, binding: &Self::Scope, keys: &K) -> Result<Self, Error>
    where
        K: EncryptionKeySource<Self::Keys> + ?Sized;
}

/// A [`Record`] that stores blind index `S` of one of its fields.
///
/// [`open_matching`] reads the indexed field's value through it to verify
/// candidates. `#[derive(Record)]` implements it for each index a field writes.
pub trait IndexedBy<S: BlindIndexSpec>: Record {
    /// Returns the value of the field `S` indexes.
    fn indexed_value(&self) -> &<S::Seal as Seal>::Value;
}

/// Opens the candidate rows of a blind-index lookup and keeps the matches.
///
/// `rows` are the rows a store selected with the probes of `S`
/// ([`BlindIndexSpec::probes_with`]). A truncated index selects false
/// candidates too, so each row is opened under `binding` and its indexed value
/// compared with `query` by [`BlindIndexSpec::verify_candidate`]; rows that do
/// not match are dropped. Matches keep the order of `rows`.
///
/// # Errors
///
/// Returns the first error of opening a row, such as
/// [`Error::AuthenticationFailed`] for a row of another binding, or of
/// normalizing `query` or a value. A row that fails to open is never treated
/// as a non-match.
pub fn open_matching<R, S>(
    rows: impl IntoIterator<Item = R::Sealed>,
    query: &S::Query,
    binding: &R::Scope,
    keys: &(impl EncryptionKeySource<R::Keys> + ?Sized),
) -> Result<Vec<R>, Error>
where
    R: IndexedBy<S>,
    S: BlindIndexSpec,
{
    let mut matches = Vec::new();

    for row in rows {
        let record = R::open(row, binding, keys)?;
        if S::verify_candidate(query, record.indexed_value())? {
            matches.push(record);
        }
    }

    Ok(matches)
}
