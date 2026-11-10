use sla_report::availability::{availability, error_budget, METHOD, PPM};
use sla_report::error::SlaError;
use sla_report::model::{CheckResult, Impact, Incident, Limits, MaintenanceWindow, Period};


const MONTH: i64 = 2_592_000;


const OUTAGE_START: i64 = 1_000_000;


const OUTAGE_SECONDS: i64 = 2_580;


const OBJECTIVE_999: u32 = 999_000;


const LIMIT_COUNT: usize = 10;


const SMALL_LIMIT: usize = 1;


const SHORT_GAP: i64 = 100;


const SECOND_RESULT_AT: i64 = 1_000;


const WINDOW_START: i64 = 1_000_500;


const WINDOW_END: i64 = 1_001_000;


const INCIDENT_START: i64 = 500;


const INCIDENT_END: i64 = 800;


const THIRD_RESULT_AT: i64 = 2_000;


const FAR_PAST: i64 = -50;


const TWO: i64 = 2;


const TWO_COUNT: usize = 2;


const IGNORED_COUNT: usize = 6;


const EXPECTED_PPM: u32 = 999_004;


const EXPECTED_ALLOWED: i64 = 2_592;


const EXPECTED_REMAINING: i64 = 12;


const TENANT: &str = "acme";


const OTHER: &str = "globex";


fn limits() -> Limits {
    Limits {
        max_results: LIMIT_COUNT,
        max_incidents: LIMIT_COUNT,
        max_windows: LIMIT_COUNT,
        max_gap_seconds: MONTH,
    }
}


fn period(start: i64, end: i64) -> Period {
    Period {
        tenant: TENANT.to_string(),
        start,
        end,
    }
}


fn result(tenant: &str, at: i64, ok: bool) -> CheckResult {
    CheckResult {
        tenant: tenant.to_string(),
        at,
        ok,
    }
}


fn incident(tenant: &str, start: i64, end: i64, impact: Impact) -> Incident {
    Incident {
        tenant: tenant.to_string(),
        start,
        end,
        impact,
    }
}


fn window(tenant: &str, start: i64, end: i64) -> MaintenanceWindow {
    MaintenanceWindow {
        tenant: tenant.to_string(),
        start,
        end,
    }
}


fn outage_results() -> Vec<CheckResult> {
    vec![
        result(TENANT, 0, true),
        result(TENANT, OUTAGE_START, false),
        result(TENANT, OUTAGE_START + OUTAGE_SECONDS, true),
    ]
}


#[test]
fn known_outage_figure_and_budget() -> Result<(), SlaError> {
    let figure = availability(&outage_results(), &[], &[], &period(0, MONTH), OBJECTIVE_999, &limits())?;
    assert_eq!(figure.down_seconds, OUTAGE_SECONDS);
    assert_eq!(figure.up_seconds, MONTH - OUTAGE_SECONDS);
    assert_eq!(figure.unknown_seconds, 0);
    assert_eq!(figure.excluded_seconds, 0);
    assert_eq!(figure.availability_ppm, Some(EXPECTED_PPM));
    assert_eq!(figure.budget.allowed_seconds, EXPECTED_ALLOWED);
    assert_eq!(figure.budget.consumed_seconds, OUTAGE_SECONDS);
    assert_eq!(figure.budget.remaining_seconds, EXPECTED_REMAINING);
    assert!(!figure.budget.exhausted);
    assert_eq!(figure.ignored, 0);
    assert_eq!(figure.method, METHOD);
    Ok(())
}


#[test]
fn outage_overlapping_maintenance_window() -> Result<(), SlaError> {
    let windows = [window(TENANT, WINDOW_START, WINDOW_END)];
    let figure = availability(&outage_results(), &[], &windows, &period(0, MONTH), OBJECTIVE_999, &limits())?;
    assert_eq!(figure.excluded_seconds, WINDOW_END - WINDOW_START);
    assert_eq!(figure.down_seconds, OUTAGE_SECONDS - (WINDOW_END - WINDOW_START));
    assert_eq!(figure.up_seconds + figure.down_seconds + figure.excluded_seconds, MONTH);
    Ok(())
}


#[test]
fn gap_beyond_maximum_is_unknown() -> Result<(), SlaError> {
    let results = [result(TENANT, 0, true), result(TENANT, SECOND_RESULT_AT, true)];
    let small_gap = Limits {
        max_gap_seconds: SHORT_GAP,
        ..limits()
    };
    let figure = availability(&results, &[], &[], &period(0, THIRD_RESULT_AT), OBJECTIVE_999, &small_gap)?;
    assert_eq!(figure.up_seconds, SHORT_GAP * TWO);
    assert_eq!(figure.unknown_seconds, THIRD_RESULT_AT - SHORT_GAP * TWO);
    Ok(())
}


#[test]
fn time_before_first_result_is_unknown() -> Result<(), SlaError> {
    let results = [result(TENANT, SECOND_RESULT_AT, true)];
    let figure = availability(&results, &[], &[], &period(0, THIRD_RESULT_AT), OBJECTIVE_999, &limits())?;
    assert_eq!(figure.unknown_seconds, SECOND_RESULT_AT);
    assert_eq!(figure.up_seconds, THIRD_RESULT_AT - SECOND_RESULT_AT);
    Ok(())
}


#[test]
fn incident_without_failing_checks_counts_down_only_for_outage() -> Result<(), SlaError> {
    let results = [result(TENANT, 0, true)];
    let incidents = [
        incident(TENANT, INCIDENT_START, INCIDENT_END, Impact::Outage),
        incident(TENANT, INCIDENT_END, THIRD_RESULT_AT, Impact::Degraded),
    ];
    let figure = availability(&results, &incidents, &[], &period(0, THIRD_RESULT_AT), OBJECTIVE_999, &limits())?;
    assert_eq!(figure.down_seconds, INCIDENT_END - INCIDENT_START);
    assert_eq!(figure.up_seconds, THIRD_RESULT_AT - (INCIDENT_END - INCIDENT_START));
    Ok(())
}


#[test]
fn objective_one_hundred_percent() -> Result<(), SlaError> {
    let clean = availability(&[result(TENANT, 0, true)], &[], &[], &period(0, MONTH), PPM, &limits())?;
    assert_eq!(clean.budget.allowed_seconds, 0);
    assert!(!clean.budget.exhausted);
    assert_eq!(clean.availability_ppm, Some(PPM));
    let broken = availability(&outage_results(), &[], &[], &period(0, MONTH), PPM, &limits())?;
    assert_eq!(broken.budget.remaining_seconds, 0);
    assert!(broken.budget.exhausted);
    Ok(())
}


#[test]
fn exhausted_budget_never_negative_remaining() -> Result<(), SlaError> {
    let budget = error_budget(MONTH, OUTAGE_SECONDS * TWO, OBJECTIVE_999)?;
    assert!(budget.exhausted);
    assert_eq!(budget.remaining_seconds, 0);
    Ok(())
}


#[test]
fn no_results_is_all_unknown() -> Result<(), SlaError> {
    let figure = availability(&[], &[], &[], &period(0, MONTH), OBJECTIVE_999, &limits())?;
    assert_eq!(figure.unknown_seconds, MONTH);
    assert_eq!(figure.availability_ppm, None);
    assert!(!figure.budget.exhausted);
    Ok(())
}


#[test]
fn empty_or_reversed_period_is_refused() -> Result<(), SlaError> {
    let empty = availability(&[], &[], &[], &period(1, 1), OBJECTIVE_999, &limits());
    assert_eq!(empty.err(), Some(SlaError::InvalidPeriod { start: 1, end: 1 }));
    let reversed = availability(&[], &[], &[], &period(MONTH, 0), OBJECTIVE_999, &limits());
    assert_eq!(reversed.err(), Some(SlaError::InvalidPeriod { start: MONTH, end: 0 }));
    let overflowing = availability(&[], &[], &[], &period(i64::MIN, i64::MAX), OBJECTIVE_999, &limits());
    assert!(overflowing.is_err());
    Ok(())
}


#[test]
fn invalid_objective_is_refused() -> Result<(), SlaError> {
    let refused = availability(&[], &[], &[], &period(0, MONTH), PPM + 1, &limits());
    assert_eq!(refused.err(), Some(SlaError::InvalidObjective { objective_ppm: PPM + 1 }));
    Ok(())
}


#[test]
fn limits_are_enforced() -> Result<(), SlaError> {
    let tight = Limits {
        max_results: SMALL_LIMIT,
        max_incidents: SMALL_LIMIT,
        max_windows: SMALL_LIMIT,
        max_gap_seconds: MONTH,
    };
    let two_results = [result(TENANT, 0, true), result(TENANT, 1, true)];
    let two_incidents = [incident(TENANT, 0, 1, Impact::Outage), incident(TENANT, 0, 1, Impact::Outage)];
    let two_windows = [window(TENANT, 0, 1), window(TENANT, 0, 1)];
    let full_period = period(0, MONTH);
    let by_results = availability(&two_results, &[], &[], &full_period, OBJECTIVE_999, &tight);
    assert_eq!(
        by_results.err(),
        Some(SlaError::TooManyResults {
            count: TWO_COUNT,
            max: SMALL_LIMIT
        })
    );
    let by_incidents = availability(&[], &two_incidents, &[], &full_period, OBJECTIVE_999, &tight);
    assert_eq!(
        by_incidents.err(),
        Some(SlaError::TooManyIncidents {
            count: TWO_COUNT,
            max: SMALL_LIMIT
        })
    );
    let by_windows = availability(&[], &[], &two_windows, &full_period, OBJECTIVE_999, &tight);
    assert_eq!(
        by_windows.err(),
        Some(SlaError::TooManyWindows {
            count: TWO_COUNT,
            max: SMALL_LIMIT
        })
    );
    Ok(())
}


#[test]
fn mixed_tenants_are_refused() -> Result<(), SlaError> {
    let full_period = period(0, MONTH);
    let expected = SlaError::TenantMismatch {
        expected: TENANT.to_string(),
        found: OTHER.to_string(),
    };
    let by_result = availability(&[result(OTHER, 0, true)], &[], &[], &full_period, OBJECTIVE_999, &limits());
    assert_eq!(by_result.err(), Some(expected.clone()));
    let by_incident = availability(&[], &[incident(OTHER, 0, 1, Impact::Outage)], &[], &full_period, OBJECTIVE_999, &limits());
    assert_eq!(by_incident.err(), Some(expected.clone()));
    let by_window = availability(&[], &[], &[window(OTHER, 0, 1)], &full_period, OBJECTIVE_999, &limits());
    assert_eq!(by_window.err(), Some(expected));
    Ok(())
}


#[test]
fn bad_timestamps_are_counted_and_ignored() -> Result<(), SlaError> {
    let results = [
        result(TENANT, FAR_PAST, true),
        result(TENANT, SECOND_RESULT_AT, true),
        result(TENANT, SECOND_RESULT_AT, false),
        result(TENANT, SHORT_GAP, false),
        result(TENANT, MONTH, true),
    ];
    let incidents = [incident(TENANT, INCIDENT_END, INCIDENT_START, Impact::Outage)];
    let windows = [window(TENANT, INCIDENT_END, INCIDENT_END)];
    let figure = availability(&results, &incidents, &windows, &period(0, THIRD_RESULT_AT), OBJECTIVE_999, &limits())?;
    assert_eq!(figure.ignored, IGNORED_COUNT);
    assert_eq!(figure.up_seconds, THIRD_RESULT_AT - SECOND_RESULT_AT);
    Ok(())
}


#[test]
fn incident_and_window_outside_period_are_clipped() -> Result<(), SlaError> {
    let results = [result(TENANT, 0, true)];
    let incidents = [incident(TENANT, FAR_PAST, INCIDENT_START, Impact::Outage)];
    let windows = [window(TENANT, THIRD_RESULT_AT - INCIDENT_START, MONTH)];
    let figure = availability(&results, &incidents, &windows, &period(0, THIRD_RESULT_AT), OBJECTIVE_999, &limits())?;
    assert_eq!(figure.down_seconds, INCIDENT_START);
    assert_eq!(figure.excluded_seconds, INCIDENT_START);
    Ok(())
}


#[test]
fn errors_display_their_cause() -> Result<(), SlaError> {
    let errors = [
        SlaError::TooManyResults {
            count: TWO_COUNT,
            max: SMALL_LIMIT,
        },
        SlaError::TooManyIncidents {
            count: TWO_COUNT,
            max: SMALL_LIMIT,
        },
        SlaError::TooManyWindows {
            count: TWO_COUNT,
            max: SMALL_LIMIT,
        },
        SlaError::TenantMismatch {
            expected: TENANT.to_string(),
            found: OTHER.to_string(),
        },
        SlaError::InvalidObjective { objective_ppm: PPM + 1 },
        SlaError::InvalidPeriod { start: 1, end: 0 },
    ];
    assert!(errors.iter().all(|error| !error.to_string().is_empty()));
    Ok(())
}


#[test]
fn error_budget_refuses_an_objective_above_ppm() -> Result<(), SlaError> {
    let at_limit = error_budget(MONTH, 0, PPM)?;
    assert_eq!(at_limit.allowed_seconds, 0);
    let over = PPM + 1;
    assert_eq!(error_budget(MONTH, 0, over), Err(SlaError::InvalidObjective { objective_ppm: over }));
    Ok(())
}
