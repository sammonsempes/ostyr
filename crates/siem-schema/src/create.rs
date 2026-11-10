use crate::column::Column;
use crate::error::SchemaError;
use crate::identifier::{quote_identifier, validate_identifier};
use crate::schema::{TENANT_COLUMN, TENANT_TIER_COLUMN, TIMESTAMP_COLUMN};
use crate::ttl::{render_ttl, TtlSettings};


fn has_column(columns: &[Column], name: &str) -> bool {
    columns.iter().any(|column| column.name == name)
}


/// Refuses a column list with a repeated name.
pub fn check_unique(columns: &[Column]) -> Result<(), SchemaError> {
    columns.iter().enumerate().try_for_each(|(index, column)| {
        if columns.iter().skip(index + 1).any(|other| other.name == column.name) {
            Err(SchemaError::DuplicateColumn(column.name.clone()))
        } else {
            Ok(())
        }
    })
}


/// Renders one indented column line.
pub fn render_column(column: &Column) -> Result<String, SchemaError> {
    quote_identifier(&column.name).map(|name| format!("    {name} {}", column.column_type))
}


fn check_required(columns: &[Column], required: &str) -> Result<(), SchemaError> {
    if has_column(columns, required) {
        Ok(())
    } else {
        Err(SchemaError::MissingColumn(required.to_string()))
    }
}


fn render_settings(ttl: &TtlSettings) -> Result<String, SchemaError> {
    match &ttl.storage_policy {
        Some(policy) => validate_identifier(policy).map(|name| format!("SETTINGS storage_policy = '{name}'\n")),
        None => Ok(String::new()),
    }
}


/// Renders the `CREATE TABLE` statement of the events table.
pub fn render_create_table(table: &str, columns: &[Column], ttl: &TtlSettings) -> Result<String, SchemaError> {
    let table_name = quote_identifier(table)?;
    [TIMESTAMP_COLUMN, TENANT_COLUMN, TENANT_TIER_COLUMN]
        .iter()
        .try_for_each(|required| check_required(columns, required))?;
    check_unique(columns)?;
    let lines = columns.iter().map(render_column).collect::<Result<Vec<_>, _>>()?;
    let timestamp = quote_identifier(TIMESTAMP_COLUMN)?;
    let tenant = quote_identifier(TENANT_COLUMN)?;
    let expression = render_ttl(ttl)?;
    let settings = render_settings(ttl)?;
    Ok(format!(
        "CREATE TABLE {table_name}\n(\n{}\n)\nENGINE = MergeTree\nPARTITION BY toDate({timestamp})\nORDER BY ({tenant}, {timestamp})\nTTL {expression}\n{settings}",
        lines.join(",\n")
    ))
}
