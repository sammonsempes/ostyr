use crate::model::{Coverage, CoverageStatus, Declarations, Listing};
use time::{Duration, OffsetDateTime};


pub const FUTURE_SKEW_SECONDS: i64 = 300;


/// The newest snapshot of `host` across the listings, ignoring any dated after `horizon`.
pub fn newest_for(listings: &[Listing], host: &str, horizon: OffsetDateTime) -> Option<OffsetDateTime> {
    listings
        .iter()
        .flat_map(|listing| listing.snapshots.iter())
        .filter(|snapshot| snapshot.host.as_deref() == Some(host) && snapshot.time <= horizon)
        .map(|snapshot| snapshot.time)
        .max()
}


pub fn status_of(newest: Option<OffsetDateTime>, now: OffsetDateTime, max_age_hours: u32) -> CoverageStatus {
    match newest {
        None => CoverageStatus::Missing,
        Some(time) => {
            let age = (now - time).max(Duration::ZERO);
            if age <= Duration::hours(i64::from(max_age_hours)) {
                CoverageStatus::Ok
            } else {
                CoverageStatus::Stale { age }
            }
        }
    }
}


/// One entry per critical host, in declaration order; a snapshot dated over five minutes after `now` is ignored, so a forged future time proves nothing.
pub fn coverage(listings: &[Listing], declarations: &Declarations, now: OffsetDateTime) -> Vec<Coverage> {
    let horizon = now.checked_add(Duration::seconds(FUTURE_SKEW_SECONDS)).unwrap_or(now);
    declarations
        .critical
        .iter()
        .map(|critical| {
            let newest = newest_for(listings, &critical.host, horizon);
            Coverage {
                tenant: declarations.tenant.clone(),
                host: critical.host.clone(),
                newest,
                status: status_of(newest, now, critical.max_age_hours),
            }
        })
        .collect()
}
