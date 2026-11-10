use crate::column::{Column, ColumnType};
use crate::create::render_column;
use crate::error::SchemaError;
use crate::identifier::{quote_identifier, validate_identifier};
use crate::schema::{TENANT_COLUMN, TIMESTAMP_COLUMN};
use crate::ttl::check_days;


pub const RAW_TABLE: &str = "metric_samples";


pub const BUCKET_COLUMN: &str = "bucket";


pub const DEFAULT_RAW_DAYS: u32 = 7;


pub const DEFAULT_MINUTE_DAYS: u32 = 30;


pub const DEFAULT_HOUR_DAYS: u32 = 180;


pub const DEFAULT_DAY_DAYS: u32 = 1825;


pub const MAX_RAW_DAYS: u32 = 14;


pub const DEFAULT_STORAGE_POLICY: &str = "default";


pub const SECONDS_PER_MINUTE: u64 = 60;


pub const SECONDS_PER_HOUR: u64 = 3600;


pub const SECONDS_PER_DAY: u64 = 86400;


pub const RAW_RESOLUTION_SECONDS: u64 = 1;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsTable {
    Raw,
    Minute,
    Hour,
    Day,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRetention {
    pub days: u32,
    pub storage_policy: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsRetention {
    pub raw: TableRetention,
    pub minute: TableRetention,
    pub hour: TableRetention,
    pub day: TableRetention,
}


const TABLES_FINEST_FIRST: [MetricsTable; 4] = [MetricsTable::Raw, MetricsTable::Minute, MetricsTable::Hour, MetricsTable::Day];


fn default_retention(days: u32) -> TableRetention {
    TableRetention {
        days,
        storage_policy: DEFAULT_STORAGE_POLICY.to_string(),
    }
}


impl Default for MetricsRetention {
    fn default() -> Self {
        MetricsRetention {
            raw: default_retention(DEFAULT_RAW_DAYS),
            minute: default_retention(DEFAULT_MINUTE_DAYS),
            hour: default_retention(DEFAULT_HOUR_DAYS),
            day: default_retention(DEFAULT_DAY_DAYS),
        }
    }
}


/// Name of the table; its materialised view adds the suffix `_mv`.
pub fn table_name(table: MetricsTable) -> &'static str {
    match table {
        MetricsTable::Raw => RAW_TABLE,
        MetricsTable::Minute => "metric_rollup_1m",
        MetricsTable::Hour => "metric_rollup_1h",
        MetricsTable::Day => "metric_rollup_1d",
    }
}


/// Time resolution of the table in seconds.
pub fn resolution_seconds(table: MetricsTable) -> u64 {
    match table {
        MetricsTable::Raw => RAW_RESOLUTION_SECONDS,
        MetricsTable::Minute => SECONDS_PER_MINUTE,
        MetricsTable::Hour => SECONDS_PER_HOUR,
        MetricsTable::Day => SECONDS_PER_DAY,
    }
}


/// SQL interval of the table resolution.
pub fn interval_sql(table: MetricsTable) -> &'static str {
    match table {
        MetricsTable::Raw => "INTERVAL 1 SECOND",
        MetricsTable::Minute => "INTERVAL 1 MINUTE",
        MetricsTable::Hour => "INTERVAL 1 HOUR",
        MetricsTable::Day => "INTERVAL 1 DAY",
    }
}


fn engine(table: MetricsTable) -> &'static str {
    match table {
        MetricsTable::Raw => "MergeTree",
        MetricsTable::Minute | MetricsTable::Hour | MetricsTable::Day => "AggregatingMergeTree",
    }
}


/// Retention and storage policy of the table.
pub fn table_retention(settings: &MetricsRetention, table: MetricsTable) -> &TableRetention {
    match table {
        MetricsTable::Raw => &settings.raw,
        MetricsTable::Minute => &settings.minute,
        MetricsTable::Hour => &settings.hour,
        MetricsTable::Day => &settings.day,
    }
}


fn check_order(settings: &MetricsRetention, fine: MetricsTable, coarse: MetricsTable) -> Result<(), SchemaError> {
    let fine_days = table_retention(settings, fine).days;
    let coarse_days = table_retention(settings, coarse).days;
    if coarse_days < fine_days {
        Err(SchemaError::RetentionOrder {
            fine: table_name(fine).to_string(),
            fine_days,
            coarse: table_name(coarse).to_string(),
            coarse_days,
        })
    } else {
        Ok(())
    }
}


fn check_table(settings: &MetricsRetention, table: MetricsTable) -> Result<(), SchemaError> {
    let retention = table_retention(settings, table);
    check_days(retention.days)?;
    validate_identifier(&retention.storage_policy).map(|_| ())
}


/// Refuses a retention out of range, a raw table kept too long or a rollup kept shorter than the finer table.
pub fn check_retention(settings: &MetricsRetention) -> Result<(), SchemaError> {
    TABLES_FINEST_FIRST.iter().try_for_each(|table| check_table(settings, *table))?;
    if settings.raw.days > MAX_RAW_DAYS {
        Err(SchemaError::RawRetentionTooLong(settings.raw.days, MAX_RAW_DAYS))
    } else {
        check_order(settings, MetricsTable::Raw, MetricsTable::Minute)?;
        check_order(settings, MetricsTable::Minute, MetricsTable::Hour)?;
        check_order(settings, MetricsTable::Hour, MetricsTable::Day)
    }
}


/// Finest table whose resolution is not finer than the step and whose retention covers the range (both in seconds).
pub fn pick_table(settings: &MetricsRetention, range_seconds: u64, step_seconds: u64) -> Result<MetricsTable, SchemaError> {
    check_retention(settings)?;
    TABLES_FINEST_FIRST
        .iter()
        .find(|table| {
            let retained = u64::from(table_retention(settings, **table).days) * SECONDS_PER_DAY;
            resolution_seconds(**table) <= step_seconds && range_seconds <= retained
        })
        .copied()
        .ok_or(SchemaError::NoMetricsTable(range_seconds, step_seconds))
}


fn column(name: &str, column_type: ColumnType) -> Column {
    Column {
        name: name.to_string(),
        column_type,
    }
}


fn key_columns() -> Vec<Column> {
    vec![
        column(TENANT_COLUMN, ColumnType::LowCardinalityText),
        column("metric", ColumnType::LowCardinalityText),
        column("unit", ColumnType::LowCardinalityText),
        column("kind", ColumnType::MetricKind),
        column("labels", ColumnType::LabelMap),
    ]
}


fn raw_columns() -> Vec<Column> {
    let time_and_value = vec![column(TIMESTAMP_COLUMN, ColumnType::Timestamp), column("value", ColumnType::Float64)];
    [key_columns(), time_and_value].concat()
}


fn rollup_columns() -> Vec<Column> {
    let aggregates = vec![
        column(BUCKET_COLUMN, ColumnType::Timestamp),
        column("value_min", ColumnType::MinFloat64),
        column("value_max", ColumnType::MaxFloat64),
        column("value_sum", ColumnType::SumFloat64),
        column("value_count", ColumnType::SumUInt64),
        column("value_last", ColumnType::LastFloat64),
    ];
    [key_columns(), aggregates].concat()
}


fn render_table(table: MetricsTable, columns: &[Column], time_column: &str, settings: &MetricsRetention) -> Result<String, SchemaError> {
    let name = quote_identifier(table_name(table))?;
    let lines = columns.iter().map(render_column).collect::<Result<Vec<_>, _>>()?;
    let time = quote_identifier(time_column)?;
    let tenant = quote_identifier(TENANT_COLUMN)?;
    let retention = table_retention(settings, table);
    let policy = validate_identifier(&retention.storage_policy)?;
    Ok(format!(
        "CREATE TABLE {name}\n(\n{}\n)\nENGINE = {}\nPARTITION BY toYYYYMM({time})\nORDER BY ({tenant}, `metric`, `unit`, `kind`, `labels`, {time})\nTTL toDateTime({time}) + toIntervalDay({})\nSETTINGS storage_policy = '{policy}'\n",
        lines.join(",\n"),
        engine(table),
        retention.days
    ))
}


fn render_view(table: MetricsTable) -> Result<String, SchemaError> {
    let target = quote_identifier(table_name(table))?;
    let view = quote_identifier(&format!("{}_mv", table_name(table)))?;
    let source = quote_identifier(RAW_TABLE)?;
    let timestamp = quote_identifier(TIMESTAMP_COLUMN)?;
    let bucket = quote_identifier(BUCKET_COLUMN)?;
    let interval = interval_sql(table);
    Ok(format!(
        "CREATE MATERIALIZED VIEW {view} TO {target} AS\nSELECT `tenant`, `metric`, `unit`, `kind`, `labels`,\n    toStartOfInterval({timestamp}, {interval}) AS {bucket},\n    min(`value`) AS `value_min`,\n    max(`value`) AS `value_max`,\n    sum(`value`) AS `value_sum`,\n    count() AS `value_count`,\n    anyLast(`value`) AS `value_last`\nFROM {source}\nGROUP BY `tenant`, `metric`, `unit`, `kind`, `labels`, {bucket}\n"
    ))
}


fn render_any_table(table: MetricsTable, settings: &MetricsRetention) -> Result<String, SchemaError> {
    match table {
        MetricsTable::Raw => render_table(table, &raw_columns(), TIMESTAMP_COLUMN, settings),
        MetricsTable::Minute | MetricsTable::Hour | MetricsTable::Day => render_table(table, &rollup_columns(), BUCKET_COLUMN, settings),
    }
}


/// Renders the raw table, the three rollup tables, then the three materialised views that fill them.
pub fn render_metrics_ddl(settings: &MetricsRetention) -> Result<Vec<String>, SchemaError> {
    check_retention(settings)?;
    let tables = TABLES_FINEST_FIRST.iter().map(|table| render_any_table(*table, settings));
    let views = TABLES_FINEST_FIRST.iter().skip(1).map(|table| render_view(*table));
    tables.chain(views).collect()
}
