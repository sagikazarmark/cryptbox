/// Identifies the table, cursor, and columns a `SQLx` sweep operates on.
///
/// Identifiers are operator configuration: they are interpolated into SQL
/// after double-quote escaping, while every value goes through bind
/// parameters. Never derive identifiers from untrusted input.
#[derive(Clone, Debug)]
pub struct SweepTable {
    table: String,
    cursor_column: String,
    ciphertext_column: String,
    index_columns: Vec<String>,
    progress_table: String,
    migration_name: String,
}

impl SweepTable {
    /// Describes a table by its cursor and encrypted columns.
    ///
    /// The progress table defaults to `cryptbox_migration_progress` and the
    /// migration name to `table.ciphertext_column`.
    #[must_use]
    pub fn new(table: &str, cursor_column: &str, ciphertext_column: &str) -> Self {
        Self {
            table: table.to_owned(),
            cursor_column: cursor_column.to_owned(),
            ciphertext_column: ciphertext_column.to_owned(),
            index_columns: Vec::new(),
            progress_table: "cryptbox_migration_progress".to_owned(),
            migration_name: format!("{table}.{ciphertext_column}"),
        }
    }

    /// Registers the next blind-index column.
    ///
    /// Order must match the [`RowPlanner::with_index_with`] registration
    /// order.
    ///
    /// [`RowPlanner::with_index_with`]: super::RowPlanner::with_index_with
    #[must_use]
    pub fn with_index_column(mut self, column: &str) -> Self {
        self.index_columns.push(column.to_owned());

        self
    }

    /// Overrides the progress table and this sweep's durable checkpoint name.
    #[must_use]
    pub fn with_progress(mut self, table: &str, migration_name: &str) -> Self {
        table.clone_into(&mut self.progress_table);
        migration_name.clone_into(&mut self.migration_name);

        self
    }

    pub(crate) fn sql(&self, style: ParamStyle) -> SweepSql {
        let table = quote_identifier(&self.table);
        let cursor = quote_identifier(&self.cursor_column);
        let progress = quote_identifier(&self.progress_table);
        let mut columns = vec![quote_identifier(&self.ciphertext_column)];
        columns.extend(
            self.index_columns
                .iter()
                .map(|column| quote_identifier(column)),
        );
        let select_list = format!("{cursor}, {}", columns.join(", "));

        let mut params = style.params();
        let select_first = format!(
            "SELECT {select_list} FROM {table} ORDER BY {cursor} LIMIT {}",
            params.next(),
        );

        let mut params = style.params();
        let select_after = format!(
            "SELECT {select_list} FROM {table} WHERE {cursor} > {} ORDER BY {cursor} LIMIT {}",
            params.next(),
            params.next(),
        );

        let mut params = style.params();
        let assignments: Vec<String> = columns
            .iter()
            .map(|column| format!("{column} = {}", params.next()))
            .collect();
        let mut predicates = vec![format!("{cursor} = {}", params.next())];
        predicates.extend(
            columns
                .iter()
                .map(|column| format!("{column} = {}", params.next())),
        );
        let update = format!(
            "UPDATE {table} SET {} WHERE {}",
            assignments.join(", "),
            predicates.join(" AND "),
        );

        let mut params = style.params();
        let load_checkpoint = format!(
            "SELECT last_id FROM {progress} WHERE name = {}",
            params.next()
        );

        let mut params = style.params();
        let save_checkpoint = format!(
            "INSERT INTO {progress} (name, last_id) VALUES ({}, {}) \
             ON CONFLICT (name) DO UPDATE SET last_id = EXCLUDED.last_id",
            params.next(),
            params.next(),
        );

        let create_progress = format!(
            "CREATE TABLE IF NOT EXISTS {progress} (name TEXT PRIMARY KEY, last_id BIGINT NOT NULL)",
        );

        SweepSql {
            select_first,
            select_after,
            update,
            load_checkpoint,
            save_checkpoint,
            create_progress,
            migration_name: self.migration_name.clone(),
            index_count: self.index_columns.len(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ParamStyle {
    /// SQLite-style `?` placeholders.
    Question,
    /// PostgreSQL-style `$n` placeholders.
    Dollar,
}

impl ParamStyle {
    const fn params(self) -> Params {
        Params {
            style: self,
            count: 0,
        }
    }
}

struct Params {
    style: ParamStyle,
    count: usize,
}

impl Params {
    fn next(&mut self) -> String {
        self.count += 1;
        match self.style {
            ParamStyle::Question => "?".to_owned(),
            ParamStyle::Dollar => format!("${}", self.count),
        }
    }
}

pub(crate) struct SweepSql {
    pub(crate) select_first: String,
    pub(crate) select_after: String,
    pub(crate) update: String,
    pub(crate) load_checkpoint: String,
    pub(crate) save_checkpoint: String,
    pub(crate) create_progress: String,
    pub(crate) migration_name: String,
    pub(crate) index_count: usize,
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::{ParamStyle, SweepTable};

    fn table() -> SweepTable {
        SweepTable::new("users", "id", "email_ciphertext").with_index_column("email_bidx")
    }

    #[test]
    fn builds_question_style_sql() {
        let sql = table().sql(ParamStyle::Question);

        assert_eq!(
            sql.select_after,
            "SELECT \"id\", \"email_ciphertext\", \"email_bidx\" FROM \"users\" \
             WHERE \"id\" > ? ORDER BY \"id\" LIMIT ?",
        );
        assert_eq!(
            sql.update,
            "UPDATE \"users\" SET \"email_ciphertext\" = ?, \"email_bidx\" = ? \
             WHERE \"id\" = ? AND \"email_ciphertext\" = ? AND \"email_bidx\" = ?",
        );
        assert_eq!(sql.migration_name, "users.email_ciphertext");
        assert_eq!(sql.index_count, 1);
    }

    #[test]
    fn builds_dollar_style_sql() {
        let sql = table().sql(ParamStyle::Dollar);

        assert_eq!(
            sql.select_after,
            "SELECT \"id\", \"email_ciphertext\", \"email_bidx\" FROM \"users\" \
             WHERE \"id\" > $1 ORDER BY \"id\" LIMIT $2",
        );
        assert_eq!(
            sql.update,
            "UPDATE \"users\" SET \"email_ciphertext\" = $1, \"email_bidx\" = $2 \
             WHERE \"id\" = $3 AND \"email_ciphertext\" = $4 AND \"email_bidx\" = $5",
        );
        assert_eq!(
            sql.save_checkpoint,
            "INSERT INTO \"cryptbox_migration_progress\" (name, last_id) VALUES ($1, $2) \
             ON CONFLICT (name) DO UPDATE SET last_id = EXCLUDED.last_id",
        );
    }

    #[test]
    fn escapes_identifier_quotes() {
        let sql = SweepTable::new("odd\"table", "id", "ct").sql(ParamStyle::Question);

        assert!(sql.select_first.contains("\"odd\"\"table\""));
    }
}
