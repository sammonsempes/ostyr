use std::fmt;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Text,
    LowCardinalityText,
    ArrayText,
    ArrayLowCardinalityText,
    Timestamp,
    UInt16,
    UInt32,
    UInt64,
    Float64,
    MetricKind,
    LabelMap,
    MinFloat64,
    MaxFloat64,
    SumFloat64,
    SumUInt64,
    LastFloat64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub column_type: ColumnType,
}


impl fmt::Display for ColumnType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sql = match self {
            ColumnType::Text => "String",
            ColumnType::LowCardinalityText => "LowCardinality(String)",
            ColumnType::ArrayText => "Array(String)",
            ColumnType::ArrayLowCardinalityText => "Array(LowCardinality(String))",
            ColumnType::Timestamp => "DateTime64(3, 'UTC')",
            ColumnType::UInt16 => "UInt16",
            ColumnType::UInt32 => "UInt32",
            ColumnType::UInt64 => "UInt64",
            ColumnType::Float64 => "Float64",
            ColumnType::MetricKind => "Enum8('gauge' = 1, 'counter' = 2, 'histogram' = 3)",
            ColumnType::LabelMap => "Map(LowCardinality(String), String)",
            ColumnType::MinFloat64 => "SimpleAggregateFunction(min, Float64)",
            ColumnType::MaxFloat64 => "SimpleAggregateFunction(max, Float64)",
            ColumnType::SumFloat64 => "SimpleAggregateFunction(sum, Float64)",
            ColumnType::SumUInt64 => "SimpleAggregateFunction(sum, UInt64)",
            ColumnType::LastFloat64 => "SimpleAggregateFunction(anyLast, Float64)",
        };
        formatter.write_str(sql)
    }
}
