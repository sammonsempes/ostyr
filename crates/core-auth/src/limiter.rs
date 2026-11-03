use crate::types::AttemptMap;
use time::{Duration, OffsetDateTime};


pub const ACCOUNT_MAX_FAILURES: usize = 5;


pub const SOURCE_MAX_FAILURES: usize = 20;


pub const FAILURE_WINDOW_SECONDS: i64 = 900;


pub const LOCKOUT_SECONDS: i64 = 900;


pub fn account_key(username: &str) -> String {
    format!("account:{username}")
}


pub fn source_key(source: &str) -> String {
    format!("source:{source}")
}


pub fn locked_until(attempts: &AttemptMap, key: &str, now: OffsetDateTime) -> Option<OffsetDateTime> {
    attempts.get(key).and_then(|entry| entry.locked_until).filter(|until| *until > now)
}


/// Records one failure and returns the lock expiry when this failure starts a lockout.
pub fn record_failure(attempts: &mut AttemptMap, key: &str, max_failures: usize, now: OffsetDateTime) -> Option<OffsetDateTime> {
    let entry = attempts.entry(key.to_owned()).or_default();
    entry
        .failures
        .retain(|failed_at| now - *failed_at < Duration::seconds(FAILURE_WINDOW_SECONDS));
    entry.failures.push(now);
    let until = now + Duration::seconds(LOCKOUT_SECONDS);
    let lock = (entry.failures.len() >= max_failures).then_some(until);
    if lock.is_some() {
        entry.failures.clear();
        entry.locked_until = lock;
    }
    lock
}


pub fn clear_failures(attempts: &mut AttemptMap, key: &str) {
    attempts.remove(key);
}
