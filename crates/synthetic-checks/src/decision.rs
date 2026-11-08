use crate::model::{Check, CheckResult, LocationHistory, MAX_BODY_EXCERPT_BYTES};


/// A location fails when its last `consecutive_failures` results are all failures; fewer results than that never fail.
pub fn location_failing(history: &LocationHistory, consecutive_failures: u64) -> bool {
    let needed = consecutive_failures as usize;
    history.results.iter().rev().take(needed).filter(|succeeded| !**succeeded).count() == needed
}


/// Alerts only when at least `min_failing_locations` declared locations are failing; histories of undeclared locations are ignored.
pub fn should_alert(check: &Check, histories: &[LocationHistory]) -> bool {
    let failing = check
        .locations
        .iter()
        .filter(|location| {
            histories
                .iter()
                .any(|history| history.location == **location && location_failing(history, check.consecutive_failures))
        })
        .count();
    failing as u64 >= check.min_failing_locations
}


/// The most urgent threshold crossed: the smallest declared threshold that is at least the days left (expired counts as crossed).
pub fn certificate_threshold(thresholds: &[u64], days_left: i64) -> Option<u64> {
    thresholds.iter().copied().filter(|threshold| days_left <= *threshold as i64).min()
}


pub fn excerpt(body: &[u8]) -> String {
    let bounded: Vec<u8> = body.iter().copied().take(MAX_BODY_EXCERPT_BYTES).collect();
    let mut used = 0;
    String::from_utf8_lossy(&bounded)
        .chars()
        .take_while(|character| {
            used += character.len_utf8();
            used <= MAX_BODY_EXCERPT_BYTES
        })
        .collect()
}


pub fn check_result(check: &str, location: &str, succeeded: bool, body: &[u8]) -> CheckResult {
    CheckResult {
        check: check.to_string(),
        location: location.to_string(),
        succeeded,
        body_excerpt: excerpt(body),
    }
}
