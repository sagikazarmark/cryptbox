use sqlx::{Row, SqliteConnection};

use super::{
    RowWrite, SweepRow, SweepStore,
    table::{ParamStyle, SweepSql, SweepTable},
};

/// A [`SweepStore`] over one `SQLite` table with an integer cursor column.
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
            let ciphertext: Vec<u8> = row.try_get(1)?;
            let mut indexes = Vec::with_capacity(self.sql.index_count);
            for position in 0..self.sql.index_count {
                indexes.push(row.try_get::<Vec<u8>, _>(2 + position)?);
            }

            batch.push(SweepRow {
                cursor,
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
