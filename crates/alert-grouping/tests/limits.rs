use alert_grouping::error::LimitsError;
use alert_grouping::limits::{load_limits, MAX_ALERTS_CEILING, MAX_ALERTS_PER_GROUP_CEILING, MAX_GROUPS_CEILING, MAX_WINDOW_MICROS};
use alert_grouping::model::GroupLimits;
use std::path::Path;
use types::TestResult;


#[path = "common/types.rs"]
mod types;


fn load_text(text: &str) -> Result<Result<GroupLimits, LimitsError>, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("limits.yaml");
    std::fs::write(&path, text)?;
    Ok(load_limits(&path))
}


fn text(window: u64, alerts: u64, groups: u64, per_group: u64) -> String {
    format!("window_micros: {window}\nmax_alerts: {alerts}\nmax_groups: {groups}\nmax_alerts_per_group: {per_group}\n")
}


#[test]
fn a_valid_file_loads() -> TestResult {
    let limits = load_text(&text(
        MAX_WINDOW_MICROS,
        MAX_ALERTS_CEILING,
        MAX_GROUPS_CEILING,
        MAX_ALERTS_PER_GROUP_CEILING,
    ))??;
    assert_eq!(limits.window_micros, MAX_WINDOW_MICROS);
    assert_eq!(limits.max_alerts_per_group as u64, MAX_ALERTS_PER_GROUP_CEILING);
    assert_eq!(load_text(&text(1, 1, 1, 1))??.max_groups, 1);
    Ok(())
}


#[test]
fn each_field_is_range_checked() -> TestResult {
    let bad = [
        (text(0, 1, 1, 1), "window_micros"),
        (text(MAX_WINDOW_MICROS + 1, 1, 1, 1), "window_micros"),
        (text(1, 0, 1, 1), "max_alerts"),
        (text(1, MAX_ALERTS_CEILING + 1, 1, 1), "max_alerts"),
        (text(1, 1, 0, 1), "max_groups"),
        (text(1, 1, MAX_GROUPS_CEILING + 1, 1), "max_groups"),
        (text(1, 1, 1, 0), "max_alerts_per_group"),
        (text(1, 1, 1, MAX_ALERTS_PER_GROUP_CEILING + 1), "max_alerts_per_group"),
    ];
    bad.iter()
        .try_for_each(|(document, name)| match load_text(document).map_err(|error| error.to_string())? {
            Err(LimitsError::OutOfRange { field, .. }) if field == *name => Ok(()),
            other => Err(format!("{name}: {other:?}")),
        })?;
    Ok(())
}


#[test]
fn unknown_and_missing_fields_are_refused() -> TestResult {
    assert!(matches!(load_text("window_micros: 1\nextra: 2\n")?, Err(LimitsError::Config(_))));
    assert!(matches!(load_text("window_micros: 1\n")?, Err(LimitsError::Config(_))));
    Ok(())
}


#[test]
fn a_missing_file_is_a_config_error() -> TestResult {
    assert!(matches!(load_limits(Path::new("/nonexistent/limits.yaml")), Err(LimitsError::Config(_))));
    Ok(())
}


#[test]
fn out_of_range_message_names_the_field() -> TestResult {
    let error = load_text(&text(0, 1, 1, 1))?.err().ok_or("accepted")?;
    assert_eq!(error.to_string(), format!("`window_micros` is 0, outside 1 to {MAX_WINDOW_MICROS}"));
    Ok(())
}
