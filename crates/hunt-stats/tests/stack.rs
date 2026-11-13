use hunt_stats::error::StatsError;
use hunt_stats::first_seen::first_seen;
use hunt_stats::model::StackLimits;
use hunt_stats::stack::rare_keys;
use hunt_stats::types::Observation;
use std::collections::BTreeSet;


const MANY_ROWS: usize = 50;


const TWO: usize = 2;


fn row(entity: &str, key: &str) -> Observation {
    (entity.to_string(), key.to_string())
}


#[test]
fn rarity_counts_entities_not_rows() -> Result<(), StatsError> {
    let mut rows: Vec<Observation> = (0..MANY_ROWS).map(|_| row("host-a", "loud.exe")).collect();
    rows.push(row("host-a", "quiet.exe"));
    rows.extend((0..MANY_ROWS).map(|index| row(&format!("host-{index}"), "common.exe")));
    rows.push(row("host-b", "quiet.exe"));
    let report = rare_keys(&rows, TWO, &StackLimits::default())?;
    let keys: Vec<(&str, usize)> = report.keys.iter().map(|entry| (entry.key.as_str(), entry.entities)).collect();
    assert_eq!(keys, vec![("loud.exe", 1), ("quiet.exe", TWO)]);
    assert_eq!(report.rows_dropped, 0);
    Ok(())
}


#[test]
fn examples_are_capped_and_sorted() -> Result<(), StatsError> {
    let rows: Vec<Observation> = ["c", "a", "b"].iter().map(|entity| row(entity, "k")).collect();
    let limits = StackLimits {
        max_examples: TWO,
        ..StackLimits::default()
    };
    let report = rare_keys(&rows, usize::MAX, &limits)?;
    assert_eq!(
        report.keys.first().map(|entry| entry.examples.clone()),
        Some(vec!["a".to_string(), "b".to_string()])
    );
    Ok(())
}


#[test]
fn equal_counts_sort_by_key() -> Result<(), StatsError> {
    let rows = vec![row("h", "z"), row("h", "a")];
    let report = rare_keys(&rows, 1, &StackLimits::default())?;
    let keys: Vec<&str> = report.keys.iter().map(|entry| entry.key.as_str()).collect();
    assert_eq!(keys, vec!["a", "z"]);
    Ok(())
}


#[test]
fn too_many_rows_is_refused() -> Result<(), StatsError> {
    let limits = StackLimits {
        max_rows: 1,
        ..StackLimits::default()
    };
    let rows = vec![row("h", "a"), row("h", "b")];
    assert!(matches!(
        rare_keys(&rows, 1, &limits),
        Err(StatsError::TooManyRows { count: TWO, max: 1 })
    ));
    assert!(matches!(
        first_seen(&BTreeSet::new(), &rows, &limits),
        Err(StatsError::TooManyRows { count: TWO, max: 1 })
    ));
    Ok(())
}


#[test]
fn extra_keys_are_counted_not_stored() -> Result<(), StatsError> {
    let limits = StackLimits {
        max_keys: 1,
        ..StackLimits::default()
    };
    let rows = vec![row("h1", "a"), row("h2", "b"), row("h3", "a"), row("h4", "c")];
    let report = rare_keys(&rows, usize::MAX, &limits)?;
    assert_eq!(report.keys.len(), 1);
    assert_eq!(report.keys.first().map(|entry| entry.entities), Some(TWO));
    assert_eq!(report.rows_dropped, TWO);
    Ok(())
}


#[test]
fn first_seen_with_empty_baseline_returns_every_key() -> Result<(), StatsError> {
    let rows = vec![row("h1", "a"), row("h2", "a"), row("h1", "b")];
    let report = first_seen(&BTreeSet::new(), &rows, &StackLimits::default())?;
    let keys: Vec<(&str, usize)> = report.keys.iter().map(|entry| (entry.key.as_str(), entry.entities)).collect();
    assert_eq!(keys, vec![("b", 1), ("a", TWO)]);
    Ok(())
}


#[test]
fn first_seen_skips_baseline_keys() -> Result<(), StatsError> {
    let baseline: BTreeSet<String> = ["a".to_string()].into_iter().collect();
    let rows = vec![row("h1", "a"), row("h2", "new")];
    let report = first_seen(&baseline, &rows, &StackLimits::default())?;
    let keys: Vec<&str> = report.keys.iter().map(|entry| entry.key.as_str()).collect();
    assert_eq!(keys, vec!["new"]);
    Ok(())
}
