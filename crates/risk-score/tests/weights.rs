use risk_score::error::RiskError;
use risk_score::model::{SeverityPoints, Weights};
use risk_score::weights::{check_weights, load_weights, MAX_BONUS_PERMILLE, MAX_FULL_SCORE_POINTS, MAX_PER_MILLION, MAX_SEVERITY_POINTS};
use std::error::Error;
use tempfile::tempdir;


const MEDIUM_POINTS: u32 = 5;


const HIGH_POINTS: u32 = 10;


const CRITICAL_POINTS: u32 = 20;


const RARE_THRESHOLD: u32 = 1_000;


const RARE_BONUS: u32 = 500;


const FULL_SCORE_POINTS: u32 = 100;


const VALID: &str = "severity_points: {low: 1, medium: 5, high: 10, critical: 20}\nrare_threshold_per_million: 1000\n\
entity_rare_bonus_permille: 500\nfleet_rare_bonus_permille: 500\nfull_score_points: 100\n";


fn weights() -> Weights {
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


fn load_text(text: &str) -> Result<Weights, RiskError> {
    let dir = tempdir().map_err(|source| {
        RiskError::Config(core_config::error::ConfigError::Io {
            file: "tmp".to_owned(),
            source,
        })
    })?;
    let path = dir.path().join("weights.yaml");
    std::fs::write(&path, text).map_err(|source| {
        RiskError::Config(core_config::error::ConfigError::Io {
            file: "tmp".to_owned(),
            source,
        })
    })?;
    load_weights(&path)
}


#[test]
fn valid_file_loads() -> Result<(), Box<dyn Error>> {
    assert_eq!(load_text(VALID)?, weights());
    Ok(())
}


#[test]
fn unknown_key_refused() -> Result<(), Box<dyn Error>> {
    let refused = load_text(&format!("{VALID}surprise: 1\n"));
    assert!(matches!(refused, Err(RiskError::Config(_))));
    Ok(())
}


#[test]
fn missing_file_refused() -> Result<(), Box<dyn Error>> {
    let refused = load_weights(std::path::Path::new("/nonexistent/risk-score-weights.yaml"));
    assert!(matches!(refused, Err(RiskError::Config(_))));
    Ok(())
}


#[test]
fn out_of_range_names_the_key_not_the_value() -> Result<(), Box<dyn Error>> {
    let cases = [
        ("severity_points.low", MAX_SEVERITY_POINTS + 1),
        ("severity_points.medium", MAX_SEVERITY_POINTS + 1),
        ("severity_points.high", MAX_SEVERITY_POINTS + 1),
        ("severity_points.critical", MAX_SEVERITY_POINTS + 1),
        ("rare_threshold_per_million", MAX_PER_MILLION + 1),
        ("entity_rare_bonus_permille", MAX_BONUS_PERMILLE + 1),
        ("fleet_rare_bonus_permille", MAX_BONUS_PERMILLE + 1),
        ("full_score_points", MAX_FULL_SCORE_POINTS + 1),
        ("full_score_points", 0),
    ];
    cases.iter().try_for_each(|&(key, bad)| -> Result<(), Box<dyn Error>> {
        let mut changed = weights();
        match key {
            "severity_points.low" => changed.severity_points.low = bad,
            "severity_points.medium" => changed.severity_points.medium = bad,
            "severity_points.high" => changed.severity_points.high = bad,
            "severity_points.critical" => changed.severity_points.critical = bad,
            "rare_threshold_per_million" => changed.rare_threshold_per_million = bad,
            "entity_rare_bonus_permille" => changed.entity_rare_bonus_permille = bad,
            "fleet_rare_bonus_permille" => changed.fleet_rare_bonus_permille = bad,
            _ => changed.full_score_points = bad,
        }
        let refused = check_weights(&changed).err().ok_or("accepted")?;
        let text = refused.to_string();
        assert!(text.contains(key));
        assert!(!text.contains(&bad.to_string()));
        Ok(())
    })
}


#[test]
fn bad_file_value_is_refused() -> Result<(), Box<dyn Error>> {
    let refused = load_text(&VALID.replace("full_score_points: 100", "full_score_points: 0"));
    assert!(matches!(refused, Err(RiskError::OutOfRange { key: "full_score_points" })));
    Ok(())
}
