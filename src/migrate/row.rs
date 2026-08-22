use std::fmt;

use crate::{
    BlindIndex, BlindIndexKeyProvider, BlindIndexSpec, Ciphertext, Codec, Encrypted,
    EncryptionKeyProvider, EncryptionProfile, Error, derive_blind_index, inspect_blind_index,
    needs_reencryption, value::ProfileContext,
};

use super::{LegacyFormat, legacy};

/// The classification of one stored row against the current key generations.
///
/// Malformed rows are not a state: classification returns an error for them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RowState {
    /// The envelope and every blind index use the current generations.
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

type IndexDeriver<T, Profile> =
    fn(&T, &ProfileContext<T, Profile>, &dyn BlindIndexKeyProvider) -> Result<Vec<u8>, Error>;

fn derive_index_bytes<T, Profile, Spec>(
    value: &T,
    context: &ProfileContext<T, Profile>,
    keys: &dyn BlindIndexKeyProvider,
) -> Result<Vec<u8>, Error>
where
    Profile: EncryptionProfile<T>,
    Spec: BlindIndexSpec<T>,
{
    derive_blind_index::<Spec, T, Profile::Binding>(value, context, keys)
        .map(BlindIndex::into_bytes)
}

struct IndexColumn<'a, T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    derive: IndexDeriver<T, Profile>,
    keys: &'a dyn BlindIndexKeyProvider,
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
pub struct RowPlanner<'a, T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    context: &'a ProfileContext<T, Profile>,
    keys: &'a dyn EncryptionKeyProvider,
    legacy: Option<&'a dyn LegacyFormat>,
    indexes: Vec<IndexColumn<'a, T, Profile>>,
}

impl<'a, T, Profile> RowPlanner<'a, T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    /// Creates a planner for the profile's binding context and key provider.
    pub fn new(
        context: &'a ProfileContext<T, Profile>,
        keys: &'a dyn EncryptionKeyProvider,
    ) -> Self {
        Self {
            context,
            keys,
            legacy: None,
            indexes: Vec::new(),
        }
    }

    /// Configures the handler used to recover non-envelope stored values.
    ///
    /// Without a handler, non-envelope bytes are treated as plaintext and
    /// decoded directly through the profile's codec.
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
    #[must_use]
    pub fn with_index_with<Spec>(mut self, keys: &'a dyn BlindIndexKeyProvider) -> Self
    where
        Spec: BlindIndexSpec<T>,
    {
        self.indexes.push(IndexColumn {
            derive: derive_index_bytes::<T, Profile, Spec>,
            keys,
        });

        self
    }

    /// Classifies one stored row without producing writes or consuming nonces.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed envelopes or blind indexes, an index
    /// column arity mismatch, or an unavailable key provider.
    pub fn classify_row(&self, ciphertext: &[u8], indexes: &[&[u8]]) -> Result<RowState, Error> {
        self.check_arity(indexes)?;

        match crate::inspect_ciphertext(ciphertext) {
            Ok(_) => {}
            Err(Error::NotCiphertext) => return Ok(RowState::Legacy),
            Err(error) => return Err(error),
        }

        if needs_reencryption(ciphertext, self.keys)? {
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

        let envelope_is_stale = needs_reencryption(ciphertext, self.keys)?;
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

        let parsed = Ciphertext::<T, Profile>::from_validated_bytes(ciphertext.to_vec());
        let rewritten = if envelope_is_stale {
            parsed.reencrypt_with(self.context, self.keys)?
        } else {
            parsed
        };

        let indexes = if stale_columns.contains(&true) {
            // The ciphertext is authoritative: stale indexes are re-derived
            // from decrypted plaintext, never trusted index metadata.
            let value = rewritten.decrypt_with(self.context, self.keys)?;
            let mut replacements = Vec::with_capacity(self.indexes.len());
            for ((column, bytes), stale) in self.indexes.iter().zip(indexes).zip(&stale_columns) {
                replacements.push(if *stale {
                    (column.derive)(value.expose_secret(), self.context, column.keys)?
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
        let value = Encrypted::<T, Profile>::new(<Profile::Codec as Codec<T>>::decode(&plaintext)?);
        let ciphertext = value.encrypt_with(self.context, self.keys)?;
        let mut indexes = Vec::with_capacity(self.indexes.len());
        for column in &self.indexes {
            indexes.push((column.derive)(
                value.expose_secret(),
                self.context,
                column.keys,
            )?);
        }

        Ok(RowOutcome {
            state: RowState::Legacy,
            write: Some(RowWrite {
                ciphertext: ciphertext.into_bytes(),
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

impl<T, Profile> IndexColumn<'_, T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    fn is_stale(&self, bytes: &[u8]) -> Result<bool, Error> {
        Ok(inspect_blind_index(bytes)?.index_key_id() != self.keys.current_key()?.id())
    }
}

impl<T, Profile> fmt::Debug for RowPlanner<'_, T, Profile>
where
    Profile: EncryptionProfile<T>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RowPlanner")
            .field("legacy", &self.legacy.is_some())
            .field("indexes", &self.indexes.len())
            .finish_non_exhaustive()
    }
}
