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
        };
        formatter.write_str(sql)
    }
}
