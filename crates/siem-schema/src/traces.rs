use crate::column::{Column, ColumnType};
use crate::create::render_column;
use crate::error::SchemaError;
use crate::identifier::{quote_identifier, validate_identifier};
use crate::schema::TENANT_COLUMN;


pub const TRACES_TABLE: &str = "trace_spans";


pub const DEFAULT_TRACE_DAYS: u32 = 7;


pub const MAX_TRACE_DAYS: u32 = 30;


pub const TRACE_STORAGE_POLICY: &str = "default";


pub const TRACE_ID_COLUMN: &str = "trace_id";


pub const SERVICE_COLUMN: &str = "service_name";


pub const START_COLUMN: &str = "start";


const TRACE_ID_INDEX: &str = "trace_id_bloom";


const BLOOM_FALSE_POSITIVE_RATE: &str = "0.01";


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracesRetention {
    pub days: u32,
    pub storage_policy: String,
}


impl Default for TracesRetention {
    fn default() -> Self {
        TracesRetention {
            days: DEFAULT_TRACE_DAYS,
            storage_policy: TRACE_STORAGE_POLICY.to_string(),
        }
    }
}


/// Refuses a retention of 0 days, above `MAX_TRACE_DAYS`, or a storage policy that is not a plain identifier.
pub fn check_trace_retention(settings: &TracesRetention) -> Result<(), SchemaError> {
    if (1..=MAX_TRACE_DAYS).contains(&settings.days) {
        validate_identifier(&settings.storage_policy).map(|_| ())
    } else {
        Err(SchemaError::InvalidTraceDays(settings.days, MAX_TRACE_DAYS))
    }
}


fn column(name: &str, column_type: ColumnType) -> Column {
    Column {
        name: name.to_string(),
        column_type,
    }
}


fn span_columns() -> Vec<Column> {
    vec![
        column(TENANT_COLUMN, ColumnType::LowCardinalityText),
        column(TRACE_ID_COLUMN, ColumnType::Id16),
        column("span_id", ColumnType::Id8),
        column("parent_span_id", ColumnType::Id8),
        column(SERVICE_COLUMN, ColumnType::LowCardinalityText),
        column("name", ColumnType::Text),
        column("kind", ColumnType::LowCardinalityText),
        column(START_COLUMN, ColumnType::TimestampNanos),
        column("duration_nanos", ColumnType::UInt64),
        column("status_code", ColumnType::LowCardinalityText),
        column("status_message", ColumnType::Text),
        column("attributes", ColumnType::TextMap),
        column("event_count", ColumnType::UInt32),
        column("link_count", ColumnType::UInt32),
    ]
}


/// Renders the `trace_spans` table; every query on it filters on `tenant` first.
pub fn render_traces_ddl(settings: &TracesRetention) -> Result<String, SchemaError> {
    check_trace_retention(settings)?;
    let name = quote_identifier(TRACES_TABLE)?;
    let lines = span_columns().iter().map(render_column).collect::<Result<Vec<_>, _>>()?;
    let start = quote_identifier(START_COLUMN)?;
    let tenant = quote_identifier(TENANT_COLUMN)?;
    let service = quote_identifier(SERVICE_COLUMN)?;
    let trace_id = quote_identifier(TRACE_ID_COLUMN)?;
    let index = quote_identifier(TRACE_ID_INDEX)?;
    let policy = validate_identifier(&settings.storage_policy)?;
    let days = settings.days;
    Ok(format!(
        "CREATE TABLE {name}\n(\n{},\n    INDEX {index} {trace_id} TYPE bloom_filter({BLOOM_FALSE_POSITIVE_RATE}) GRANULARITY 1\n)\nENGINE = MergeTree\nPARTITION BY toYYYYMMDD({start})\nORDER BY ({tenant}, {service}, {start})\nTTL toDateTime({start}) + toIntervalDay({days})\nSETTINGS storage_policy = '{policy}'\n",
        lines.join(",\n")
    ))
}
