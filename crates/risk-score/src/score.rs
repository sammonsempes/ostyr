use crate::error::RiskError;
use crate::model::{Contribution, EntityRef, Score, Severity, Weights};
use ecs_normalise::suricata::is_unsafe;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};


pub const MAX_CONTRIBUTIONS: usize = 100_000;


pub const MAX_ENTITIES: usize = 10_000;


pub const MAX_ENTITY_ID_BYTES: usize = 256;


pub const DECAY_DAYS: i64 = 7;


pub const SECONDS_PER_DAY: i64 = 86_400;


pub const FUTURE_SKEW_SECONDS: i64 = 300;


pub const PERMILLE: u128 = 1_000;


pub const PER_MILLION: u32 = 1_000_000;


pub const MAX_SCORE: u128 = 100;


#[derive(Default)]
pub struct Tally {
    pub milli_points: u128,
    pub used: usize,
    pub dropped: usize,
}


pub fn severity_points(severity: Severity, weights: &Weights) -> u32 {
    match severity {
        Severity::Low => weights.severity_points.low,
        Severity::Medium => weights.severity_points.medium,
        Severity::High => weights.severity_points.high,
        Severity::Critical => weights.severity_points.critical,
    }
}


pub fn rarity_permille(contribution: &Contribution, weights: &Weights) -> u128 {
    let entity_bonus = if contribution.entity_rate <= weights.rare_threshold_per_million {
        weights.entity_rare_bonus_permille
    } else {
        0
    };
    let fleet_bonus = if contribution.fleet_rate <= weights.rare_threshold_per_million {
        weights.fleet_rare_bonus_permille
    } else {
        0
    };
    PERMILLE + u128::from(entity_bonus) + u128::from(fleet_bonus)
}


/// Milli-points: severity points x rarity x (1 - false positive rate) x linear decay over 7 days; `None` when dropped (too old or future-dated).
pub fn entity_points(contribution: &Contribution, weights: &Weights, now: i64) -> Option<u128> {
    let age = now.saturating_sub(contribution.observed_at);
    let decay_seconds = DECAY_DAYS * SECONDS_PER_DAY;
    let remaining = decay_seconds.saturating_sub(age.max(0));
    (age >= -FUTURE_SKEW_SECONDS && remaining > 0).then(|| {
        let reliability = u128::from(PER_MILLION.saturating_sub(contribution.false_positive_rate));
        let severity = u128::from(severity_points(contribution.severity, weights));
        let weighted = severity * rarity_permille(contribution, weights) * reliability * u128::from(remaining.unsigned_abs());
        weighted / (u128::from(PER_MILLION) * u128::from(decay_seconds.unsigned_abs()))
    })
}


pub fn check_contribution(contribution: &Contribution) -> Result<(), RiskError> {
    let id = &contribution.entity.id;
    let bad_id = id.is_empty() || id.len() > MAX_ENTITY_ID_BYTES || id.chars().any(is_unsafe);
    let bad_rate = contribution.false_positive_rate > PER_MILLION;
    match (bad_id, bad_rate) {
        (true, _) => Err(RiskError::BadEntityId { max: MAX_ENTITY_ID_BYTES }),
        (false, true) => Err(RiskError::RateOutOfRange),
        (false, false) => Ok(()),
    }
}


/// Typed refusal before any scoring work: contribution count, entity ids, rates, distinct entity count.
pub fn check_bounds(contributions: &[Contribution]) -> Result<(), RiskError> {
    let count_ok = if contributions.len() > MAX_CONTRIBUTIONS {
        Err(RiskError::TooManyContributions { max: MAX_CONTRIBUTIONS })
    } else {
        Ok(())
    };
    count_ok?;
    contributions.iter().try_for_each(check_contribution)?;
    let entities: BTreeSet<&EntityRef> = contributions.iter().map(|contribution| &contribution.entity).collect();
    if entities.len() > MAX_ENTITIES {
        Err(RiskError::TooManyEntities { max: MAX_ENTITIES })
    } else {
        Ok(())
    }
}


/// Sum per entity, normalised by a linear clamp: `full_score_points` points give 100; ordered by descending score, then by entity.
pub fn score_entities(contributions: &[Contribution], weights: &Weights, now: i64) -> Result<Vec<Score>, RiskError> {
    check_bounds(contributions)?;
    let mut tallies: BTreeMap<&EntityRef, Tally> = BTreeMap::new();
    for contribution in contributions {
        let tally = tallies.entry(&contribution.entity).or_default();
        match entity_points(contribution, weights, now) {
            Some(points) => {
                tally.milli_points += points;
                tally.used += 1;
            }
            None => tally.dropped += 1,
        }
    }
    let full_scale = u128::from(weights.full_score_points) * PERMILLE;
    let mut scores: Vec<Score> = tallies
        .into_iter()
        .map(|(entity, tally)| Score {
            entity: entity.clone(),
            value: (tally.milli_points.saturating_mul(MAX_SCORE) / full_scale).min(MAX_SCORE) as u8,
            contributions_used: tally.used,
            contributions_dropped: tally.dropped,
        })
        .collect();
    scores.sort_by_key(|score| Reverse(score.value));
    Ok(scores)
}


pub fn over_threshold(scores: &[Score], threshold: u8) -> Vec<&Score> {
    scores.iter().filter(|score| score.value >= threshold).collect()
}
