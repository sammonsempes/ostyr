use crate::error::SlaError;
use crate::model::{CheckResult, ErrorBudget, Impact, Incident, Limits, MaintenanceWindow, Period, SlaFigure, Totals};


pub const PPM: u32 = 1_000_000;


pub const METHOD: &str = "Each check result covers the time until the next result, at most max_gap_seconds; time beyond that, or before the first \
result, is unknown and never counted as up. Covered time is down when the check failed or a declared outage incident covers it, else up. Time \
inside a maintenance window is excluded from numerator and denominator. Availability is up / (up + down), rounded down; allowed downtime is \
(1 - objective) x (up + down), rounded down. Results out of order or outside the period, and empty incidents or windows, are ignored and counted.";


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentState {
    Excluded,
    Unknown,
    Down,
    Up,
}


fn check_tenant(expected: &str, found: &str) -> Result<(), SlaError> {
    let mismatch = SlaError::TenantMismatch {
        expected: expected.to_string(),
        found: found.to_string(),
    };
    (expected == found).then_some(()).ok_or(mismatch)
}


pub fn validate_inputs(
    results: &[CheckResult],
    incidents: &[Incident],
    windows: &[MaintenanceWindow],
    period: &Period,
    objective_ppm: u32,
    limits: &Limits,
) -> Result<(), SlaError> {
    let too_many_results = SlaError::TooManyResults {
        count: results.len(),
        max: limits.max_results,
    };
    let too_many_incidents = SlaError::TooManyIncidents {
        count: incidents.len(),
        max: limits.max_incidents,
    };
    let too_many_windows = SlaError::TooManyWindows {
        count: windows.len(),
        max: limits.max_windows,
    };
    let bad_period = SlaError::InvalidPeriod {
        start: period.start,
        end: period.end,
    };
    (results.len() <= limits.max_results).then_some(()).ok_or(too_many_results)?;
    (incidents.len() <= limits.max_incidents).then_some(()).ok_or(too_many_incidents)?;
    (windows.len() <= limits.max_windows).then_some(()).ok_or(too_many_windows)?;
    (objective_ppm <= PPM).then_some(()).ok_or(SlaError::InvalidObjective { objective_ppm })?;
    period
        .end
        .checked_sub(period.start)
        .filter(|length| *length > 0)
        .map(|_| ())
        .ok_or(bad_period)?;
    results.iter().try_for_each(|result| check_tenant(&period.tenant, &result.tenant))?;
    incidents.iter().try_for_each(|incident| check_tenant(&period.tenant, &incident.tenant))?;
    windows.iter().try_for_each(|window| check_tenant(&period.tenant, &window.tenant))
}


pub fn accept_results(results: &[CheckResult], period: &Period) -> (Vec<CheckResult>, usize) {
    results.iter().fold((Vec::new(), 0), |(mut accepted, ignored), result| {
        let in_period = result.at >= period.start && result.at < period.end;
        let in_order = accepted.last().is_none_or(|last: &CheckResult| result.at > last.at);
        let keep = in_period && in_order;
        let ignored_next = ignored + usize::from(!keep);
        if keep {
            accepted.push(result.clone());
        }
        (accepted, ignored_next)
    })
}


fn covers(start: i64, end: i64, at: i64) -> bool {
    start <= at && at < end
}


pub fn segment_state(at: i64, accepted: &[CheckResult], incidents: &[Incident], windows: &[MaintenanceWindow], max_gap_seconds: i64) -> SegmentState {
    let in_window = windows.iter().any(|window| covers(window.start, window.end, at));
    let latest = accepted
        .partition_point(|result| result.at <= at)
        .checked_sub(1)
        .and_then(|index| accepted.get(index));
    let outage = incidents
        .iter()
        .any(|incident| incident.impact == Impact::Outage && covers(incident.start, incident.end, at));
    match latest {
        _ if in_window => SegmentState::Excluded,
        None => SegmentState::Unknown,
        Some(result) if at >= result.at.saturating_add(max_gap_seconds) => SegmentState::Unknown,
        Some(result) if !result.ok || outage => SegmentState::Down,
        Some(_) => SegmentState::Up,
    }
}


pub fn boundaries(
    accepted: &[CheckResult],
    incidents: &[Incident],
    windows: &[MaintenanceWindow],
    period: &Period,
    max_gap_seconds: i64,
) -> Vec<i64> {
    let from_results = accepted.iter().flat_map(|result| [result.at, result.at.saturating_add(max_gap_seconds)]);
    let from_incidents = incidents.iter().flat_map(|incident| [incident.start, incident.end]);
    let from_windows = windows.iter().flat_map(|window| [window.start, window.end]);
    let mut points: Vec<i64> = from_results
        .chain(from_incidents)
        .chain(from_windows)
        .map(|point| point.clamp(period.start, period.end))
        .chain([period.start, period.end])
        .collect();
    points.sort_unstable();
    points.dedup();
    points
}


pub fn error_budget(up_seconds: i64, down_seconds: i64, objective_ppm: u32) -> ErrorBudget {
    let measured = i128::from(up_seconds) + i128::from(down_seconds);
    let allowed = measured * i128::from(PPM - objective_ppm) / i128::from(PPM);
    let allowed_seconds = allowed as i64;
    ErrorBudget {
        allowed_seconds,
        consumed_seconds: down_seconds,
        remaining_seconds: (allowed_seconds - down_seconds).max(0),
        exhausted: down_seconds > allowed_seconds,
    }
}


pub fn availability_ppm(up_seconds: i64, down_seconds: i64) -> Option<u32> {
    let measured = i128::from(up_seconds) + i128::from(down_seconds);
    (measured > 0).then(|| (i128::from(up_seconds) * i128::from(PPM) / measured) as u32)
}


pub fn add_segment(totals: Totals, state: SegmentState, seconds: i64) -> Totals {
    match state {
        SegmentState::Excluded => Totals {
            excluded_seconds: totals.excluded_seconds + seconds,
            ..totals
        },
        SegmentState::Unknown => Totals {
            unknown_seconds: totals.unknown_seconds + seconds,
            ..totals
        },
        SegmentState::Down => Totals {
            down_seconds: totals.down_seconds + seconds,
            ..totals
        },
        SegmentState::Up => Totals {
            up_seconds: totals.up_seconds + seconds,
            ..totals
        },
    }
}


pub fn availability(
    results: &[CheckResult],
    incidents: &[Incident],
    windows: &[MaintenanceWindow],
    period: &Period,
    objective_ppm: u32,
    limits: &Limits,
) -> Result<SlaFigure, SlaError> {
    validate_inputs(results, incidents, windows, period, objective_ppm, limits)?;
    let (accepted, ignored_results) = accept_results(results, period);
    let valid_incidents: Vec<Incident> = incidents.iter().filter(|incident| incident.end > incident.start).cloned().collect();
    let valid_windows: Vec<MaintenanceWindow> = windows.iter().filter(|window| window.end > window.start).cloned().collect();
    let ignored = ignored_results + (incidents.len() - valid_incidents.len()) + (windows.len() - valid_windows.len());
    let gap = limits.max_gap_seconds;
    let points = boundaries(&accepted, &valid_incidents, &valid_windows, period, gap);
    let totals = points.iter().zip(points.iter().skip(1)).fold(Totals::default(), |sums, (from, to)| {
        let state = segment_state(*from, &accepted, &valid_incidents, &valid_windows, gap);
        add_segment(sums, state, to - from)
    });
    Ok(SlaFigure {
        up_seconds: totals.up_seconds,
        down_seconds: totals.down_seconds,
        unknown_seconds: totals.unknown_seconds,
        excluded_seconds: totals.excluded_seconds,
        availability_ppm: availability_ppm(totals.up_seconds, totals.down_seconds),
        budget: error_budget(totals.up_seconds, totals.down_seconds, objective_ppm),
        ignored,
        method: METHOD.to_string(),
    })
}
