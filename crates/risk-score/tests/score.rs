mod common;


use common::{
    contribution, entity, weights, ALL_NOISE_RATE, CRITICAL_MILLI, CRITICAL_SCORE, FULL_SCORE, HIGH_MILLI, HIGH_ONE_RARE_MILLI, MEDIUM_MILLI,
    NOISY_RATE, NOW, OVER_RATE, RARE_RATE, TENTH_MILLI, THREE, TWO,
};
use risk_score::error::RiskError;
use risk_score::model::{Contribution, EntityKind, EntityRef, Severity};
use risk_score::score::{entity_points, over_threshold, score_entities, MAX_CONTRIBUTIONS, MAX_ENTITIES, MAX_ENTITY_ID_BYTES};
use std::error::Error;


const HALF_DECAY_SECONDS: i64 = 302_400;


const FULL_DECAY_SECONDS: i64 = 604_800;


const SKEW_SECONDS: i64 = 300;


fn points(contribution: &Contribution) -> Option<u128> {
    entity_points(contribution, &weights(), NOW)
}


#[test]
fn critical_outweighs_low() -> Result<(), Box<dyn Error>> {
    let critical = points(&contribution("a", Severity::Critical, NOW));
    let low = points(&contribution("a", Severity::Low, NOW));
    assert!(critical > low);
    assert_eq!(critical, Some(CRITICAL_MILLI));
    assert_eq!(points(&contribution("a", Severity::Medium, NOW)), Some(MEDIUM_MILLI));
    assert_eq!(points(&contribution("a", Severity::High, NOW)), Some(HIGH_MILLI));
    Ok(())
}


#[test]
fn rare_outweighs_common() -> Result<(), Box<dyn Error>> {
    let common = contribution("a", Severity::High, NOW);
    let entity_rare = Contribution {
        entity_rate: RARE_RATE,
        ..common.clone()
    };
    let fleet_rare = Contribution {
        fleet_rate: RARE_RATE,
        ..common.clone()
    };
    let both_rare = Contribution {
        entity_rate: RARE_RATE,
        fleet_rate: RARE_RATE,
        ..common.clone()
    };
    assert_eq!(points(&common), Some(HIGH_MILLI));
    assert_eq!(points(&entity_rare), Some(HIGH_ONE_RARE_MILLI));
    assert_eq!(points(&fleet_rare), Some(HIGH_ONE_RARE_MILLI));
    assert_eq!(points(&both_rare), Some(CRITICAL_MILLI));
    Ok(())
}


#[test]
fn false_positive_rule_weighs_a_tenth() -> Result<(), Box<dyn Error>> {
    let reliable = contribution("a", Severity::High, NOW);
    let noisy = Contribution {
        false_positive_rate: NOISY_RATE,
        ..reliable.clone()
    };
    assert_eq!(points(&reliable), Some(HIGH_MILLI));
    assert_eq!(points(&noisy), Some(TENTH_MILLI));
    Ok(())
}


#[test]
fn decay_is_linear_over_seven_days() -> Result<(), Box<dyn Error>> {
    assert_eq!(points(&contribution("a", Severity::Critical, NOW)), Some(CRITICAL_MILLI));
    assert_eq!(points(&contribution("a", Severity::Critical, NOW - HALF_DECAY_SECONDS)), Some(HIGH_MILLI));
    assert_eq!(points(&contribution("a", Severity::Critical, NOW - FULL_DECAY_SECONDS)), None);
    assert_eq!(points(&contribution("a", Severity::Critical, NOW - FULL_DECAY_SECONDS - 1)), None);
    Ok(())
}


#[test]
fn future_dated_beyond_skew_is_dropped_and_counted() -> Result<(), Box<dyn Error>> {
    assert_eq!(points(&contribution("a", Severity::Critical, NOW + SKEW_SECONDS)), Some(CRITICAL_MILLI));
    assert_eq!(points(&contribution("a", Severity::Critical, NOW + SKEW_SECONDS + 1)), None);
    let scores = score_entities(&[contribution("a", Severity::Critical, NOW + SKEW_SECONDS + 1)], &weights(), NOW)?;
    let first = scores.first().ok_or("no score")?;
    assert_eq!((first.value, first.contributions_used, first.contributions_dropped), (0, 0, 1));
    Ok(())
}


#[test]
fn normalisation_scales_and_saturates() -> Result<(), Box<dyn Error>> {
    assert!(score_entities(&[], &weights(), NOW)?.is_empty());
    let one = score_entities(&[contribution("a", Severity::Critical, NOW)], &weights(), NOW)?;
    assert_eq!(one.first().ok_or("no score")?.value, CRITICAL_SCORE);
    let huge: Vec<Contribution> = (0..MAX_CONTRIBUTIONS).map(|_| contribution("a", Severity::Critical, NOW)).collect();
    let saturated = score_entities(&huge, &weights(), NOW)?;
    let first = saturated.first().ok_or("no score")?;
    assert_eq!((first.value, first.contributions_used), (FULL_SCORE, MAX_CONTRIBUTIONS));
    Ok(())
}


#[test]
fn entities_are_ordered_by_score_then_entity() -> Result<(), Box<dyn Error>> {
    let contributions = vec![
        contribution("b", Severity::Low, NOW),
        contribution("c", Severity::Critical, NOW),
        contribution("a", Severity::Low, NOW),
    ];
    let scores = score_entities(&contributions, &weights(), NOW)?;
    let order: Vec<&str> = scores.iter().map(|score| score.entity.id.as_str()).collect();
    assert_eq!(order, vec!["c", "a", "b"]);
    let flagged = over_threshold(&scores, CRITICAL_SCORE);
    assert_eq!(flagged.len(), 1);
    assert_eq!(over_threshold(&scores, 1).len(), THREE);
    Ok(())
}


#[test]
fn entity_kinds_are_distinct_entities() -> Result<(), Box<dyn Error>> {
    let host = contribution("a", Severity::Low, NOW);
    let user = Contribution {
        entity: EntityRef {
            kind: EntityKind::User,
            id: "a".to_owned(),
        },
        ..host.clone()
    };
    assert_eq!(score_entities(&[host, user], &weights(), NOW)?.len(), TWO);
    Ok(())
}


#[test]
fn too_many_contributions_refused() -> Result<(), Box<dyn Error>> {
    let many: Vec<Contribution> = (0..=MAX_CONTRIBUTIONS).map(|_| contribution("a", Severity::Low, NOW)).collect();
    let refused = score_entities(&many, &weights(), NOW);
    assert!(matches!(refused, Err(RiskError::TooManyContributions { max: MAX_CONTRIBUTIONS })));
    Ok(())
}


#[test]
fn too_many_entities_refused() -> Result<(), Box<dyn Error>> {
    let many: Vec<Contribution> = (0..=MAX_ENTITIES)
        .map(|index| contribution(&format!("h{index}"), Severity::Low, NOW))
        .collect();
    assert!(matches!(
        score_entities(&many, &weights(), NOW),
        Err(RiskError::TooManyEntities { max: MAX_ENTITIES })
    ));
    let allowed: Vec<Contribution> = (0..MAX_ENTITIES)
        .map(|index| contribution(&format!("h{index}"), Severity::Low, NOW))
        .collect();
    assert_eq!(score_entities(&allowed, &weights(), NOW)?.len(), MAX_ENTITIES);
    Ok(())
}


#[test]
fn bad_entity_ids_refused() -> Result<(), Box<dyn Error>> {
    let long = "a".repeat(MAX_ENTITY_ID_BYTES + 1);
    let longest = "a".repeat(MAX_ENTITY_ID_BYTES);
    for id in ["", long.as_str(), "al\u{3164}ice", "a\nb"] {
        let refused = score_entities(&[contribution(id, Severity::Low, NOW)], &weights(), NOW);
        assert!(matches!(refused, Err(RiskError::BadEntityId { .. })));
    }
    assert_eq!(score_entities(&[contribution(&longest, Severity::Low, NOW)], &weights(), NOW)?.len(), 1);
    assert_eq!(entity("x").id, "x");
    Ok(())
}


#[test]
fn false_positive_rate_above_one_is_refused() -> Result<(), Box<dyn Error>> {
    let bad = Contribution {
        false_positive_rate: OVER_RATE,
        ..contribution("a", Severity::Low, NOW)
    };
    assert!(matches!(score_entities(&[bad], &weights(), NOW), Err(RiskError::RateOutOfRange)));
    let edge = Contribution {
        false_positive_rate: ALL_NOISE_RATE,
        ..contribution("a", Severity::Low, NOW)
    };
    assert_eq!(points(&edge), Some(0));
    Ok(())
}
