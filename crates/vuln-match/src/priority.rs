//! Deterministic finding priority.

use crate::model::{Criticality, ScoredFinding};


const CVSS_MIN: f64 = 0.0;


const CVSS_MAX: f64 = 10.0;


const EPSS_MIN: f64 = 0.0;


const EPSS_MAX: f64 = 1.0;


const CVSS_POINTS_PER_UNIT: f64 = 10.0;


const CVSS_WEIGHT: u32 = 10;


const EPSS_POINTS: f64 = 1000.0;


const KEV_BONUS: u32 = 10_000;


const WEIGHT_MEDIUM: u32 = 2;


const WEIGHT_HIGH: u32 = 3;


const WEIGHT_CRITICAL: u32 = 4;


/// Priority is `(cvss * 100 + epss * 1000) * criticality weight (1 to 4)`, plus 10000 for a KEV entry; inputs are clamped, NaN counts as 0.
pub fn priority_of(scored: &ScoredFinding) -> u32 {
    let cvss_points = (scored.cvss.clamp(CVSS_MIN, CVSS_MAX) * CVSS_POINTS_PER_UNIT).round() as u32;
    let epss_points = (scored.epss.clamp(EPSS_MIN, EPSS_MAX) * EPSS_POINTS).round() as u32;
    let weight = match scored.criticality {
        Criticality::Low => 1,
        Criticality::Medium => WEIGHT_MEDIUM,
        Criticality::High => WEIGHT_HIGH,
        Criticality::Critical => WEIGHT_CRITICAL,
    };
    let kev_bonus = if scored.kev { KEV_BONUS } else { 0 };
    (cvss_points * CVSS_WEIGHT + epss_points) * weight + kev_bonus
}


/// Highest priority first; ties are ordered by the finding itself, so equal input gives equal output.
pub fn rank(mut findings: Vec<ScoredFinding>) -> Vec<ScoredFinding> {
    findings.sort_by(|left, right| priority_of(right).cmp(&priority_of(left)).then_with(|| left.finding.cmp(&right.finding)));
    findings
}
