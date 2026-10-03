use sqlx::{Row, SqliteConnection, error::UnexpectedNullError, sqlite::SqliteRow};

use super::{
    RowWrite, SweepRow, SweepStore,
    table::{ParamStyle, SweepSql, SweepTable},
};

/// A [`SweepStore`] over one `SQLite` table with an integer cursor column.
///
/// Available with both `migrate` and `sqlx-sqlite` features.
///
/// Checkpoints are stored in the progress table configured on the
/// [`SweepTable`]; call [`Self::ensure_progress_table`] once before the first
/// sweep. Applications with a different cursor shape implement [`SweepStore`]
/// directly.
pub struct SqliteSweepStore<'a> {
    connection: &'a mut SqliteConnection,
    sql: SweepSql,
}

impl<'a> SqliteSweepStore<'a> {
    /// Creates a store over a connection and table description.
    #[must_use]
    pub fn new(connection: &'a mut SqliteConnection, table: &SweepTable) -> Self {
        Self {
            connection,
            sql: table.sql(ParamStyle::Question),
        }
    }

    /// Creates the checkpoint progress table when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns the underlying database error.
    pub async fn ensure_progress_table(&mut self) -> Result<(), sqlx::Error> {
        sqlx::query(&self.sql.create_progress)
            .execute(&mut *self.connection)
            .await?;

        Ok(())
    }
}

impl SweepStore for SqliteSweepStore<'_> {
    type Cursor = i64;
    type Columns = ();
    type Error = sqlx::Error;

    async fn load_checkpoint(&mut self) -> Result<Option<i64>, sqlx::Error> {
        sqlx::query_scalar(&self.sql.load_checkpoint)
            .bind(self.sql.migration_name.as_str())
            .fetch_optional(&mut *self.connection)
            .await
    }

    async fn save_checkpoint(&mut self, cursor: &i64) -> Result<(), sqlx::Error> {
        sqlx::query(&self.sql.save_checkpoint)
            .bind(self.sql.migration_name.as_str())
            .bind(*cursor)
            .execute(&mut *self.connection)
            .await?;

        Ok(())
    }

    async fn load_batch(
        &mut self,
        after: Option<&i64>,
        limit: usize,
    ) -> Result<Vec<SweepRow<i64>>, sqlx::Error> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let query = match after {
            Some(after) => sqlx::query(&self.sql.select_after).bind(*after).bind(limit),
            None => sqlx::query(&self.sql.select_first).bind(limit),
        };
        let rows = query.fetch_all(&mut *self.connection).await?;

        let mut batch = Vec::with_capacity(rows.len());
        for row in rows {
            let cursor: i64 = row.try_get(0)?;
            let ciphertext = bytes(&row, 1)?;
            let mut indexes = Vec::with_capacity(self.sql.index_count);
            for position in 0..self.sql.index_count {
                indexes.push(bytes(&row, 2 + position)?);
            }

            batch.push(SweepRow {
                cursor,
                columns: (),
                ciphertext,
                indexes,
            });
        }

        Ok(batch)
    }

    async fn update(
        &mut self,
        row: &SweepRow<i64>,
        replacement: &RowWrite,
    ) -> Result<bool, sqlx::Error> {
        let mut query = sqlx::query(&self.sql.update).bind(replacement.ciphertext().to_vec());
        for bytes in replacement.indexes() {
            query = query.bind(bytes.clone());
        }
        query = query.bind(row.cursor).bind(row.ciphertext.clone());
        for bytes in &row.indexes {
            query = query.bind(bytes.clone());
        }

        let result = query.execute(&mut *self.connection).await?;

        Ok(result.rows_affected() == 1)
    }
}

/// Reads a swept column's bytes, rejecting NULL.
///
/// `SQLite` decodes NULL as empty bytes, which the guarded update could never
/// match, so the row would be skipped as a conflict.
fn bytes(row: &SqliteRow, index: usize) -> Result<Vec<u8>, sqlx::Error> {
    row.try_get::<Option<Vec<u8>>, _>(index)?
        .ok_or_else(|| sqlx::Error::ColumnDecode {
            index: index.to_string(),
            source: Box::new(UnexpectedNullError),
        })
}
