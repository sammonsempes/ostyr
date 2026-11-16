use crate::error::RiskError;
use crate::model::Weights;
use core_config::load::load_file;
use std::path::Path;


pub const MAX_SEVERITY_POINTS: u32 = 10_000;


pub const MAX_PER_MILLION: u32 = 1_000_000;


pub const MAX_BONUS_PERMILLE: u32 = 10_000;


pub const MAX_FULL_SCORE_POINTS: u32 = 1_000_000;


/// Range-checks every value; the error names the key, never the value.
pub fn check_weights(weights: &Weights) -> Result<(), RiskError> {
    let severity = &weights.severity_points;
    let checks = [
        ("severity_points.low", severity.low, 0, MAX_SEVERITY_POINTS),
        ("severity_points.medium", severity.medium, 0, MAX_SEVERITY_POINTS),
        ("severity_points.high", severity.high, 0, MAX_SEVERITY_POINTS),
        ("severity_points.critical", severity.critical, 0, MAX_SEVERITY_POINTS),
        ("rare_threshold_per_million", weights.rare_threshold_per_million, 0, MAX_PER_MILLION),
        ("entity_rare_bonus_permille", weights.entity_rare_bonus_permille, 0, MAX_BONUS_PERMILLE),
        ("fleet_rare_bonus_permille", weights.fleet_rare_bonus_permille, 0, MAX_BONUS_PERMILLE),
        ("full_score_points", weights.full_score_points, 1, MAX_FULL_SCORE_POINTS),
    ];
    checks.iter().try_for_each(|&(key, value, min, max)| {
        if (min..=max).contains(&value) {
            Ok(())
        } else {
            Err(RiskError::OutOfRange { key })
        }
    })
}


pub fn load_weights(path: &Path) -> Result<Weights, RiskError> {
    let weights: Weights = load_file(path)?;
    check_weights(&weights)?;
    Ok(weights)
}
