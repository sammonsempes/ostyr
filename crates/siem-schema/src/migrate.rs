use crate::column::Column;
use crate::create::check_unique;
use crate::error::SchemaError;
use crate::identifier::quote_identifier;


fn check_kept(old_column: &Column, newer: &[Column]) -> Result<(), SchemaError> {
    match newer.iter().find(|candidate| candidate.name == old_column.name) {
        None => Err(SchemaError::RemovedColumn(old_column.name.clone())),
        Some(found) if found.column_type != old_column.column_type => Err(SchemaError::ChangedColumn(old_column.name.clone())),
        Some(_) => Ok(()),
    }
}


/// Renders one `ALTER TABLE` adding the new columns; empty when nothing was added; removal and retyping are refused.
pub fn render_migration(table: &str, old: &[Column], newer: &[Column]) -> Result<String, SchemaError> {
    let table_name = quote_identifier(table)?;
    check_unique(old)?;
    check_unique(newer)?;
    old.iter().try_for_each(|old_column| check_kept(old_column, newer))?;
    let additions = newer
        .iter()
        .filter(|column| !old.iter().any(|existing| existing.name == column.name))
        .map(|column| quote_identifier(&column.name).map(|name| format!("ADD COLUMN {name} {}", column.column_type)))
        .collect::<Result<Vec<_>, _>>()?;
    if additions.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("ALTER TABLE {table_name} {}\n", additions.join(", ")))
    }
}
