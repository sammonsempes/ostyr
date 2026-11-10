use crate::column::Column;
use crate::create::check_unique;
use crate::error::SchemaError;
use crate::identifier::quote_identifier;
use crate::ttl::{has_move, render_ttl, TtlSettings};


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


/// Renders `ALTER TABLE … MODIFY TTL` when the TTL changed; empty otherwise; removing a cold move or changing the storage policy is refused.
pub fn render_ttl_migration(table: &str, old: &TtlSettings, newer: &TtlSettings) -> Result<String, SchemaError> {
    let table_name = quote_identifier(table)?;
    let old_expression = render_ttl(old)?;
    let new_expression = render_ttl(newer)?;
    if old.storage_policy != newer.storage_policy {
        Err(SchemaError::ChangedStoragePolicy)
    } else if has_move(old) && !has_move(newer) {
        Err(SchemaError::RemovedMove)
    } else if old_expression == new_expression {
        Ok(String::new())
    } else {
        Ok(format!("ALTER TABLE {table_name} MODIFY TTL {new_expression}\n"))
    }
}
