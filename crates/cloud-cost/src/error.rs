use core_config::error::ConfigError;
use core_pg::error::PgError;
use thiserror::Error;


/// No variant carries text taken from an export row.
#[derive(Debug, Error)]
pub enum CostError {
    #[error("tenant refused: {0}")]
    Tenant(#[from] PgError),
    #[error("cannot read the export: {0}")]
    Read(#[from] csv::Error),
    #[error("required column `{column}` is missing")]
    MissingColumn { column: &'static str },
    #[error("export larger than {limit} bytes")]
    TooLarge { limit: u64 },
    #[error("export has more than {limit} rows")]
    TooManyRows { limit: u64 },
    #[error("an amount total does not fit a decimal")]
    Overflow,
    #[error("budget file refused: {0}")]
    Budgets(#[from] ConfigError),
    #[error("more than {limit} budgets")]
    TooManyBudgets { limit: usize },
    #[error("budget number {index} refused: invalid {field}")]
    InvalidBudget { index: usize, field: &'static str },
    #[error("budget `{budget}` is in another currency than the export")]
    CurrencyMismatch { budget: String },
    #[error("the month must be written YYYY-MM")]
    BadMonth,
}
