use risk_score::model::{Contribution, EntityKind, EntityRef, Severity, SeverityPoints, Weights};


pub const NOW: i64 = 10_000_000;


pub const COMMON_RATE: u32 = 500_000;


pub const RARE_RATE: u32 = 10;


pub const MEDIUM_MILLI: u128 = 5_000;


pub const HIGH_MILLI: u128 = 10_000;


pub const HIGH_ONE_RARE_MILLI: u128 = 15_000;


pub const CRITICAL_MILLI: u128 = 20_000;


pub const TENTH_MILLI: u128 = 1_000;


pub const NOISY_RATE: u32 = 900_000;


pub const ALL_NOISE_RATE: u32 = 1_000_000;


pub const OVER_RATE: u32 = 1_000_001;


pub const CRITICAL_SCORE: u8 = 20;


pub const FULL_SCORE: u8 = 100;


pub const MEDIUM_POINTS: u32 = 5;


pub const HIGH_POINTS: u32 = 10;


pub const CRITICAL_POINTS: u32 = 20;


pub const RARE_THRESHOLD: u32 = 1_000;


pub const RARE_BONUS: u32 = 500;


pub const FULL_SCORE_POINTS: u32 = 100;


pub const TWO: usize = 2;


pub const THREE: usize = 3;


pub fn weights() -> Weights {
    Weights {
        severity_points: SeverityPoints {
            low: 1,
            medium: MEDIUM_POINTS,
            high: HIGH_POINTS,
            critical: CRITICAL_POINTS,
        },
        rare_threshold_per_million: RARE_THRESHOLD,
        entity_rare_bonus_permille: RARE_BONUS,
        fleet_rare_bonus_permille: RARE_BONUS,
        full_score_points: FULL_SCORE_POINTS,
    }
}


pub fn entity(id: &str) -> EntityRef {
    EntityRef {
        kind: EntityKind::Host,
        id: id.to_owned(),
    }
}


pub fn contribution(id: &str, severity: Severity, observed_at: i64) -> Contribution {
    Contribution {
        entity: entity(id),
        rule_id: "rule".to_owned(),
        severity,
        observed_at,
        fleet_rate: COMMON_RATE,
        entity_rate: COMMON_RATE,
        false_positive_rate: 0,
    }
}
