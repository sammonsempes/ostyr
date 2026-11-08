use crate::error::SchemaError;
use crate::identifier::{quote_identifier, validate_identifier};
use crate::schema::{TENANT_TIER_COLUMN, TIMESTAMP_COLUMN};


pub const MAX_RETENTION_DAYS: u32 = 3650;


pub const MAX_TIERS: usize = 16;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierRetention {
    pub tier: String,
    pub hot_days: u32,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlSettings {
    pub default_days: u32,
    pub tiers: Vec<TierRetention>,
}


/// Checks a retention in days.
pub fn check_days(days: u32) -> Result<u32, SchemaError> {
    if (1..=MAX_RETENTION_DAYS).contains(&days) {
        Ok(days)
    } else {
        Err(SchemaError::InvalidDays(days, MAX_RETENTION_DAYS))
    }
}


fn tier_branch(tier: &TierRetention) -> Result<String, SchemaError> {
    let name = validate_identifier(&tier.tier)?;
    let days = check_days(tier.hot_days)?;
    Ok(format!("`{TENANT_TIER_COLUMN}` = '{name}', toIntervalDay({days})"))
}


/// Renders the TTL expression: rows are deleted after the retention of their tenant tier.
pub fn render_ttl(settings: &TtlSettings) -> Result<String, SchemaError> {
    let default_days = check_days(settings.default_days)?;
    let timestamp = quote_identifier(TIMESTAMP_COLUMN)?;
    if settings.tiers.len() > MAX_TIERS {
        Err(SchemaError::TooManyTiers(settings.tiers.len(), MAX_TIERS))
    } else if settings.tiers.is_empty() {
        Ok(format!("toDateTime({timestamp}) + toIntervalDay({default_days})"))
    } else {
        let branches = settings.tiers.iter().map(tier_branch).collect::<Result<Vec<_>, _>>()?;
        Ok(format!(
            "toDateTime({timestamp}) + multiIf({}, toIntervalDay({default_days}))",
            branches.join(", ")
        ))
    }
}
