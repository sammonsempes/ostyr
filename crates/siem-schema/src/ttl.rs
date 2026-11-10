use crate::error::SchemaError;
use crate::identifier::{quote_identifier, validate_identifier};
use crate::schema::{TENANT_TIER_COLUMN, TIMESTAMP_COLUMN};


pub const MAX_RETENTION_DAYS: u32 = 3650;


pub const MAX_TIERS: usize = 16;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierRetention {
    pub tier: String,
    pub hot_days: u32,
    pub move_after_days: Option<u32>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlSettings {
    pub default_days: u32,
    pub default_move_after_days: Option<u32>,
    pub tiers: Vec<TierRetention>,
    pub storage_policy: Option<String>,
    pub cold_volume: Option<String>,
}


/// Checks a retention in days.
pub fn check_days(days: u32) -> Result<u32, SchemaError> {
    if (1..=MAX_RETENTION_DAYS).contains(&days) {
        Ok(days)
    } else {
        Err(SchemaError::InvalidDays(days, MAX_RETENTION_DAYS))
    }
}


fn retention_days(tier: &TierRetention) -> Result<u32, SchemaError> {
    check_days(tier.hot_days)
}


fn tier_branch(tier: &TierRetention, days_of: fn(&TierRetention) -> Result<u32, SchemaError>) -> Result<String, SchemaError> {
    let name = validate_identifier(&tier.tier)?;
    let days = days_of(tier)?;
    Ok(format!("`{TENANT_TIER_COLUMN}` = '{name}', toIntervalDay({days})"))
}


fn check_move(move_days: u32, retention_days: u32) -> Result<u32, SchemaError> {
    check_days(move_days)?;
    if move_days < retention_days {
        Ok(move_days)
    } else {
        Err(SchemaError::MoveNotBeforeRetention(move_days, retention_days))
    }
}


fn move_days(tier: &TierRetention) -> Result<u32, SchemaError> {
    match tier.move_after_days {
        Some(move_days) => check_move(move_days, tier.hot_days),
        None => check_days(tier.hot_days),
    }
}


fn interval_expression(timestamp: &str, default_days: u32, branches: &[String]) -> String {
    if branches.is_empty() {
        format!("toDateTime({timestamp}) + toIntervalDay({default_days})")
    } else {
        format!(
            "toDateTime({timestamp}) + multiIf({}, toIntervalDay({default_days}))",
            branches.join(", ")
        )
    }
}


/// True when any tier or the default moves parts to the cold volume.
pub fn has_move(settings: &TtlSettings) -> bool {
    settings.default_move_after_days.is_some() || settings.tiers.iter().any(|tier| tier.move_after_days.is_some())
}


fn render_move(settings: &TtlSettings, timestamp: &str, default_days: u32) -> Result<Option<String>, SchemaError> {
    if has_move(settings) {
        let volume = settings.cold_volume.as_deref().ok_or(SchemaError::MissingColdVolume)?;
        let volume_name = validate_identifier(volume)?;
        let default_move = match settings.default_move_after_days {
            Some(move_days) => check_move(move_days, default_days)?,
            None => default_days,
        };
        let branches = settings
            .tiers
            .iter()
            .map(|tier| tier_branch(tier, move_days))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(format!(
            "{} TO VOLUME '{volume_name}'",
            interval_expression(timestamp, default_move, &branches)
        )))
    } else {
        Ok(None)
    }
}


/// Renders the TTL expression: parts move to the cold volume when configured, rows are deleted after the retention of their tenant tier.
pub fn render_ttl(settings: &TtlSettings) -> Result<String, SchemaError> {
    let default_days = check_days(settings.default_days)?;
    let timestamp = quote_identifier(TIMESTAMP_COLUMN)?;
    if settings.tiers.len() > MAX_TIERS {
        Err(SchemaError::TooManyTiers(settings.tiers.len(), MAX_TIERS))
    } else {
        let branches = settings
            .tiers
            .iter()
            .map(|tier| tier_branch(tier, retention_days))
            .collect::<Result<Vec<_>, _>>()?;
        let delete = interval_expression(&timestamp, default_days, &branches);
        match render_move(settings, &timestamp, default_days)? {
            Some(moved) => Ok(format!("{moved}, {delete} DELETE")),
            None => Ok(delete),
        }
    }
}
