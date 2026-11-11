use crate::column::{Column, ColumnType};


pub const TIMESTAMP_COLUMN: &str = "@timestamp";


pub const TENANT_COLUMN: &str = "tenant";


pub const TENANT_TIER_COLUMN: &str = "tenant_tier";


const DEFAULT_COLUMNS: [(&str, ColumnType); 43] = [
    (TIMESTAMP_COLUMN, ColumnType::Timestamp),
    (TENANT_COLUMN, ColumnType::LowCardinalityText),
    (TENANT_TIER_COLUMN, ColumnType::LowCardinalityText),
    ("ecs.version", ColumnType::LowCardinalityText),
    ("event.id", ColumnType::Text),
    ("event.kind", ColumnType::LowCardinalityText),
    ("event.category", ColumnType::ArrayLowCardinalityText),
    ("event.type", ColumnType::ArrayLowCardinalityText),
    ("event.action", ColumnType::LowCardinalityText),
    ("event.outcome", ColumnType::LowCardinalityText),
    ("event.dataset", ColumnType::LowCardinalityText),
    ("event.module", ColumnType::LowCardinalityText),
    ("event.severity", ColumnType::UInt32),
    ("event.sequence", ColumnType::UInt64),
    ("message", ColumnType::Text),
    ("host.name", ColumnType::Text),
    ("host.id", ColumnType::Text),
    ("host.ip", ColumnType::ArrayText),
    ("host.os.type", ColumnType::LowCardinalityText),
    ("user.name", ColumnType::Text),
    ("user.id", ColumnType::Text),
    ("user.domain", ColumnType::Text),
    ("source.ip", ColumnType::Text),
    ("source.port", ColumnType::UInt16),
    ("source.domain", ColumnType::Text),
    ("destination.ip", ColumnType::Text),
    ("destination.port", ColumnType::UInt16),
    ("destination.domain", ColumnType::Text),
    ("network.transport", ColumnType::LowCardinalityText),
    ("network.direction", ColumnType::LowCardinalityText),
    ("process.pid", ColumnType::UInt32),
    ("process.name", ColumnType::Text),
    ("process.executable", ColumnType::Text),
    ("process.command_line", ColumnType::Text),
    ("process.args", ColumnType::ArrayText),
    ("process.working_directory", ColumnType::Text),
    ("process.parent.pid", ColumnType::UInt32),
    ("process.parent.executable", ColumnType::Text),
    ("process.parent.command_line", ColumnType::Text),
    ("file.path", ColumnType::Text),
    ("file.size", ColumnType::UInt64),
    ("event.code", ColumnType::LowCardinalityText),
    ("event.provider", ColumnType::LowCardinalityText),
];


/// The ECS columns produced by `ecs-normalise` and read by `sigma-sql`, plus the tenant columns.
pub fn default_columns() -> Vec<Column> {
    DEFAULT_COLUMNS
        .iter()
        .map(|(name, column_type)| Column {
            name: (*name).to_string(),
            column_type: *column_type,
        })
        .collect()
}
