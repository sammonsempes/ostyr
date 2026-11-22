use crate::checks::{domain_sid, has_class, has_gap, is_domain_rid, is_enabled, CLASS_COMPUTER, CLASS_USER, DOMAIN_CLASSES, SECONDS_PER_DAY};
use crate::error::IndicatorError;
use crate::model::{Entry, IndicatorCounts, IndicatorOutcome, IndicatorRow, Logon, Refusal, Snapshot};
use core_pg::scope::{tenant_of, tenant_scope};
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};


pub const INDICATOR_NAME: &str = "identity.inactive_accounts";


/// CIS Controls v8 safeguard 5.3: an enabled account with no logon for 45 days is inactive. Never read from the thresholds file.
pub const INDICATOR_INACTIVE_DAYS: i64 = 45;


/// A capture older than this is stale: it matches `max_age_hours` of the control.
pub const MAX_CAPTURE_AGE_SECONDS: i64 = 172_800;


/// The largest gap accepted between a caller's `now` and the system clock.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 300;


pub const ADMINISTRATOR_RID_SUFFIX: &str = "-500";


pub const MIN_YEAR: i32 = 0;


pub const MAX_YEAR: i32 = 9_999;


pub const FIELD_OBJECT_CLASS: [&str; 1] = ["objectClass"];


/// The caller's `now`, accepted only within `MAX_CLOCK_SKEW_SECONDS` of the system clock.
pub fn checked_now(requested: i64, system: i64) -> Result<i64, IndicatorError> {
    if requested.abs_diff(system) > MAX_CLOCK_SKEW_SECONDS {
        Err(IndicatorError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS })
    } else {
        Ok(requested)
    }
}


/// The capture time in UTC: years 0 to 9999, not after `now`, not more than 48 hours before it.
pub fn captured_of(text: Option<&str>, now: i64) -> Result<OffsetDateTime, Refusal> {
    let parsed = OffsetDateTime::parse(text.ok_or(Refusal::NoCaptureTime)?, &Rfc3339).map_err(|_| Refusal::BadCaptureTime)?;
    let utc = parsed.checked_to_offset(UtcOffset::UTC).ok_or(Refusal::BadCaptureTime)?;
    let unix = utc.unix_timestamp();
    if !(MIN_YEAR..=MAX_YEAR).contains(&utc.year()) {
        Err(Refusal::BadCaptureTime)
    } else if unix > now {
        Err(Refusal::CaptureInFuture)
    } else if unix < now.saturating_sub(MAX_CAPTURE_AGE_SECONDS) {
        Err(Refusal::CaptureTooOld)
    } else {
        Ok(utc)
    }
}


/// True when the object class cannot be told: none was exported, or a value of it was refused.
pub fn is_unknown_class(entry: &Entry) -> bool {
    entry.classes.is_empty() || has_gap(entry, &FIELD_OBJECT_CLASS)
}


/// An enabled account that is not known to be a computer; an unknown class reads as a user.
pub fn counts_as_account(entry: &Entry) -> bool {
    is_enabled(entry) && !has_class(entry, CLASS_COMPUTER) && (has_class(entry, CLASS_USER) || is_unknown_class(entry))
}


/// Inactivity is measured from the capture time, never from the clock of the caller.
pub fn logon_of(entry: &Entry, captured: i64) -> Logon {
    match entry.last_logon {
        None => Logon::Never,
        Some(logon) if logon > captured => Logon::Future,
        Some(logon) if logon < captured.saturating_sub(INDICATOR_INACTIVE_DAYS * SECONDS_PER_DAY) => Logon::Stale,
        Some(_) => Logon::Fresh,
    }
}


/// An unreadable entry counts as one inactive account.
pub fn tally(snapshot: &Snapshot, captured: i64) -> IndicatorCounts {
    let unreadable = snapshot.unreadable.len();
    let start = IndicatorCounts {
        entries: snapshot.entries.len().saturating_add(unreadable),
        accounts: unreadable,
        inactive: unreadable,
        never_logged: 0,
        future: 0,
        unreadable,
    };
    snapshot
        .entries
        .iter()
        .filter(|entry| counts_as_account(entry))
        .fold(start, |counts, entry| add_account(counts, logon_of(entry, captured)))
}


pub fn add_account(counts: IndicatorCounts, logon: Logon) -> IndicatorCounts {
    let inactive = logon != Logon::Fresh;
    IndicatorCounts {
        accounts: counts.accounts + 1,
        inactive: counts.inactive + usize::from(inactive),
        never_logged: counts.never_logged + usize::from(logon == Logon::Never),
        future: counts.future + usize::from(logon == Logon::Future),
        ..counts
    }
}


/// The snapshot proves it holds the domain: its SID, the domain object under it, and the RID 500 user under it.
pub fn completeness(snapshot: &Snapshot) -> Result<(), Refusal> {
    let domain = domain_sid(snapshot).ok_or(Refusal::NoDomain)?;
    let has_domain_object = snapshot
        .entries
        .iter()
        .any(|entry| DOMAIN_CLASSES.iter().any(|class| has_class(entry, class)) && entry.sid.as_deref() == Some(domain.as_str()));
    let has_administrator = snapshot.entries.iter().any(|entry| {
        has_class(entry, CLASS_USER)
            && entry
                .sid
                .as_deref()
                .is_some_and(|sid| is_domain_rid(sid, &domain, ADMINISTRATOR_RID_SUFFIX))
    });
    if !has_domain_object {
        Err(Refusal::NoDomainObject)
    } else if !has_administrator {
        Err(Refusal::NoAdministrator)
    } else {
        Ok(())
    }
}


/// Integers only, no name, DN or SID.
pub fn source_of(counts: &IndicatorCounts, now: i64) -> String {
    format!(
        "ad:computed={};entries={};accounts={};inactive={};never_logged={};future={};unreadable={};inactive_days={}",
        now, counts.entries, counts.accounts, counts.inactive, counts.never_logged, counts.future, counts.unreadable, INDICATOR_INACTIVE_DAYS
    )
}


/// The refusal that stops the indicator, or the capture time and the completeness it rests on.
pub fn check_snapshot(snapshot: &Snapshot, captured: Option<&str>, now: i64) -> Result<OffsetDateTime, Refusal> {
    if snapshot.bounds.is_empty() {
        let time = captured_of(captured, now)?;
        completeness(snapshot)?;
        Ok(time)
    } else {
        Err(Refusal::BoundHit)
    }
}


/// RFC 3339 in UTC to the second, written by hand: the capture time is already checked to years 0 to 9999, so nothing can fail.
pub fn observed_at_of(time: &OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}


/// The indicator of one snapshot: a row, or the reason there is none (an incomplete or stale snapshot is never a figure).
pub fn indicator_of(snapshot: &Snapshot, captured: Option<&str>, now: i64, tenant: &str) -> Result<IndicatorOutcome, IndicatorError> {
    let scope = tenant_scope(tenant).map_err(IndicatorError::InvalidTenant)?;
    match check_snapshot(snapshot, captured, now) {
        Err(refusal) => Ok(IndicatorOutcome::Refused {
            refusal,
            entries: snapshot.entries.len().saturating_add(snapshot.unreadable.len()),
        }),
        Ok(time) => {
            let counts = tally(snapshot, time.unix_timestamp());
            Ok(IndicatorOutcome::Row(IndicatorRow {
                tenant: tenant_of(&scope).to_owned(),
                name: INDICATOR_NAME,
                value: counts.inactive,
                observed_at: observed_at_of(&time),
                source: source_of(&counts, now),
            }))
        }
    }
}


/// The JSON array the GRC evaluator reads: one object, or an empty array.
pub fn indicator_json(outcome: &IndicatorOutcome) -> String {
    match outcome {
        IndicatorOutcome::Row(row) => json!([{
            "tenant": row.tenant,
            "name": row.name,
            "value": row.value,
            "observed_at": row.observed_at,
            "source": row.source,
        }])
        .to_string(),
        IndicatorOutcome::Refused { .. } => json!([]).to_string(),
    }
}


/// A fixed text and a count: nothing read from the directory.
pub fn warning_line(outcome: &IndicatorOutcome) -> Option<String> {
    match outcome {
        IndicatorOutcome::Row(_) => None,
        IndicatorOutcome::Refused { refusal, entries } => Some(format!("no indicator: {} (entries={entries})", reason_of(*refusal))),
    }
}


pub fn reason_of(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::BoundHit => "a global bound of the snapshot was reached",
        Refusal::NoCaptureTime => "the snapshot has no usable capture time",
        Refusal::BadCaptureTime => "the capture time is not a valid RFC 3339 time in years 0 to 9999",
        Refusal::CaptureInFuture => "the capture time is after the current time",
        Refusal::CaptureTooOld => "the capture is more than 48 hours old",
        Refusal::NoDomain => "the domain SID cannot be determined",
        Refusal::NoDomainObject => "the domain object is missing",
        Refusal::NoAdministrator => "the RID 500 user is missing",
    }
}
