mod common;


use common::types::TestResult;
use sla_report::error::ScheduleError;
use sla_report::model::{default_grace_seconds, Cadence, ReportDefinition, ReportFormat, ReportLimits, Span, DEFAULT_GRACE_SECONDS};
use sla_report::schedule::{
    check_rfc3339_range, due_periods, format_rfc3339, load_report_file, parse_report_file, period_containing, validate_report_file, MAX_DUE_PERIODS,
    MAX_FILE_BYTES, MAX_GRACE_SECONDS, MAX_ID_BYTES, MAX_REPORTS,
};
use std::error::Error;
use std::io::{self, Read};
use std::path::Path;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }
}


const OFFSETS: [i32; 4] = [-720, 0, 345, 840];


const MAX_OFFSET: i32 = 840;


const MIN_OFFSET: i32 = -720;


const BAD_OFFSETS: [i32; 4] = [5, 841, -721, 14];


const SECONDS_PER_MINUTE: i64 = 60;


const DAY: i64 = 86_400;


const WEEK: i64 = 604_800;


const GRACE: i64 = 3_600;


const OBJECTIVE: u32 = 999_000;


const MONDAY_1109: i64 = 1_794_182_400;


const MONDAY_1116: i64 = 1_794_787_200;


const FEB_2026: i64 = 1_769_904_000;


const MAR_2026: i64 = 1_772_323_200;


const FEB_2024: i64 = 1_706_745_600;


const MAR_2024: i64 = 1_709_251_200;


const APR_2026: i64 = 1_775_001_600;


const MAY_2026: i64 = 1_777_593_600;


const JAN_2026: i64 = 1_767_225_600;


const JUL_2026: i64 = 1_782_864_000;


const OCT_2026: i64 = 1_790_812_800;


const DEC_2026: i64 = 1_796_083_200;


const JAN_2027: i64 = 1_798_761_600;


const YEAR_0_START: i64 = -62_167_219_200;


const YEAR_9999_LAST_SECOND: i64 = 253_402_300_799;


const DAYS_JANUARY: i64 = 31;


const DAYS_FEBRUARY: i64 = 28;


const DAYS_FEBRUARY_LEAP: i64 = 29;


const DAYS_APRIL: i64 = 30;


const DAYS_INTO_QUARTER: i64 = 45;


const DAYS_CATCH_UP: i64 = 400;


const THREE: usize = 3;


const THREE_WEEKS: i64 = 3;


const UNALIGNED_SECONDS: i64 = 100;


const MONTHLY_OFFSET: i32 = -300;


const WEEKLY_FIXTURE_OFFSET: i32 = 60;


const MONTHLY_FIXTURE_GRACE: i64 = 7_200;


const FIXTURE_REPORTS: usize = 3;


const LONG_TITLE: usize = 257;


const LONG_SERVICE: usize = 129;


const MAX_NAME: usize = 128;


const SERVICE_CAP: usize = 10;


const SHORT_NAME: usize = 2;


const FIXTURE: &str = "tests/fixtures/reports.yaml";


const BASE: &str = "reports:
  - id: weekly-1
    tenant: acme
    title: Weekly
    services: [web]
    cadence: weekly
    utc_offset_minutes: 60
    objective_ppm: 999000
    formats: [csv, json]
";


fn shift(base: i64, offset_minutes: i32) -> i64 {
    base - i64::from(offset_minutes) * SECONDS_PER_MINUTE
}


fn definition(cadence: Cadence, offset_minutes: i32) -> ReportDefinition {
    ReportDefinition {
        id: "report".to_string(),
        tenant: "acme".to_string(),
        title: "Title".to_string(),
        services: vec!["web".to_string()],
        cadence,
        utc_offset_minutes: offset_minutes,
        objective_ppm: OBJECTIVE,
        grace_seconds: DEFAULT_GRACE_SECONDS,
        formats: vec![ReportFormat::Csv],
    }
}


fn parse(text: &str) -> Result<sla_report::model::ReportFile, ScheduleError> {
    parse_report_file(&mut text.as_bytes(), "reports.yaml")
}


fn refused_field(text: &str) -> Result<&'static str, Box<dyn Error>> {
    match parse(text) {
        Err(ScheduleError::Invalid { field, .. }) => Ok(field),
        other => Err(format!("expected Invalid, got {other:?}").into()),
    }
}


fn assert_period(cadence: Cadence, start: i64, end: i64) -> TestResult {
    OFFSETS.iter().try_for_each(|offset| -> TestResult {
        let expected = Span {
            start: shift(start, *offset),
            end: shift(end, *offset),
        };
        let inside = [expected.start, expected.start + GRACE, expected.end - 1];
        inside.iter().try_for_each(|at| -> TestResult {
            let found = period_containing(cadence, *offset, *at)?;
            (found == expected).then_some(()).ok_or_else(|| format!("wrong period {found:?}").into())
        })?;
        let next = period_containing(cadence, *offset, expected.end)?;
        (next.start == expected.end && next.end > expected.end)
            .then_some(())
            .ok_or("end is not the start of the next period")?;
        let previous = period_containing(cadence, *offset, expected.start - 1)?;
        (previous.end == expected.start)
            .then_some(())
            .ok_or("previous period does not end at the start")?;
        Ok(())
    })
}


#[test]
fn weekly_period_starts_on_monday_in_every_offset() -> TestResult {
    assert_period(Cadence::Weekly, MONDAY_1109, MONDAY_1116)
}


#[test]
fn monthly_31_day_month() -> TestResult {
    assert_eq!(FEB_2026 - JAN_2026, DAYS_JANUARY * DAY);
    assert_period(Cadence::Monthly, JAN_2026, FEB_2026)
}


#[test]
fn monthly_28_day_month() -> TestResult {
    assert_eq!(MAR_2026 - FEB_2026, DAYS_FEBRUARY * DAY);
    assert_period(Cadence::Monthly, FEB_2026, MAR_2026)
}


#[test]
fn monthly_29_day_month() -> TestResult {
    assert_eq!(MAR_2024 - FEB_2024, DAYS_FEBRUARY_LEAP * DAY);
    assert_period(Cadence::Monthly, FEB_2024, MAR_2024)
}


#[test]
fn monthly_30_day_month() -> TestResult {
    assert_eq!(MAY_2026 - APR_2026, DAYS_APRIL * DAY);
    assert_period(Cadence::Monthly, APR_2026, MAY_2026)
}


#[test]
fn monthly_december_to_january() -> TestResult {
    assert_period(Cadence::Monthly, DEC_2026, JAN_2027)
}


#[test]
fn quarterly_boundaries() -> TestResult {
    assert_period(Cadence::Quarterly, JAN_2026, APR_2026)?;
    assert_period(Cadence::Quarterly, JUL_2026, OCT_2026)?;
    assert_period(Cadence::Quarterly, OCT_2026, JAN_2027)
}


#[test]
fn quarterly_middle_month_maps_to_the_quarter() -> TestResult {
    let span = period_containing(Cadence::Quarterly, 0, OCT_2026 + DAYS_INTO_QUARTER * DAY)?;
    assert_eq!(
        span,
        Span {
            start: OCT_2026,
            end: JAN_2027
        }
    );
    Ok(())
}


#[test]
fn invalid_offsets_are_refused() -> TestResult {
    BAD_OFFSETS.iter().for_each(|minutes| {
        assert!(matches!(
            period_containing(Cadence::Weekly, *minutes, MONDAY_1109),
            Err(ScheduleError::InvalidOffset { .. })
        ));
    });
    Ok(())
}


#[test]
fn due_exactly_at_end_plus_grace() -> TestResult {
    let weekly = definition(Cadence::Weekly, 0);
    let due = due_periods(&weekly, Some(MONDAY_1109), MONDAY_1116 + GRACE, MAX_DUE_PERIODS)?;
    assert_eq!(due.len(), 1);
    let first = due.first().ok_or("none")?;
    assert_eq!((first.start, first.end, first.tenant.as_str()), (MONDAY_1109, MONDAY_1116, "acme"));
    Ok(())
}


#[test]
fn not_due_one_second_before_end_plus_grace() -> TestResult {
    let weekly = definition(Cadence::Weekly, 0);
    assert!(due_periods(&weekly, Some(MONDAY_1109), MONDAY_1116 + GRACE - 1, MAX_DUE_PERIODS)?.is_empty());
    Ok(())
}


#[test]
fn grace_zero_is_due_at_the_end() -> TestResult {
    let mut weekly = definition(Cadence::Weekly, 0);
    weekly.grace_seconds = 0;
    assert_eq!(due_periods(&weekly, Some(MONDAY_1109), MONDAY_1116, MAX_DUE_PERIODS)?.len(), 1);
    assert!(due_periods(&weekly, Some(MONDAY_1109), MONDAY_1116 - 1, MAX_DUE_PERIODS)?.is_empty());
    Ok(())
}


#[test]
fn without_history_only_the_last_elapsed_period_is_due() -> TestResult {
    let weekly = definition(Cadence::Weekly, 0);
    let at_boundary = due_periods(&weekly, None, MONDAY_1116 + GRACE, MAX_DUE_PERIODS)?;
    assert_eq!(
        at_boundary.iter().map(|period| (period.start, period.end)).collect::<Vec<_>>(),
        vec![(MONDAY_1109, MONDAY_1116)]
    );
    let before = due_periods(&weekly, None, MONDAY_1116 + GRACE - 1, MAX_DUE_PERIODS)?;
    assert_eq!(
        before.iter().map(|period| (period.start, period.end)).collect::<Vec<_>>(),
        vec![(MONDAY_1109 - WEEK, MONDAY_1109)]
    );
    Ok(())
}


#[test]
fn catch_up_is_capped_and_contiguous() -> TestResult {
    let weekly = definition(Cadence::Weekly, 0);
    let now = MONDAY_1109 + DAYS_CATCH_UP * DAY;
    let three = due_periods(&weekly, Some(MONDAY_1109), now, THREE)?;
    assert_eq!(three.len(), THREE);
    let all = due_periods(&weekly, Some(MONDAY_1109), now, MAX_DUE_PERIODS)?;
    assert_eq!(all.len(), MAX_DUE_PERIODS);
    assert!(all
        .windows(SHORT_NAME)
        .all(|pair| pair.first().map(|first| first.end) == pair.get(1).map(|second| second.start)));
    assert_eq!(all.first().map(|period| period.start), Some(MONDAY_1109));
    assert!(due_periods(&weekly, Some(MONDAY_1109), now, 0)?.is_empty());
    Ok(())
}


#[test]
fn catch_up_stops_at_the_last_due_period() -> TestResult {
    let weekly = definition(Cadence::Weekly, 0);
    let due = due_periods(&weekly, Some(MONDAY_1109), MONDAY_1109 + THREE_WEEKS * WEEK + GRACE, MAX_DUE_PERIODS)?;
    assert_eq!(due.len(), THREE);
    Ok(())
}


#[test]
fn unaligned_last_done_skips_to_the_next_period() -> TestResult {
    let weekly = definition(Cadence::Weekly, 0);
    let due = due_periods(
        &weekly,
        Some(MONDAY_1109 + UNALIGNED_SECONDS),
        MONDAY_1116 + WEEK + GRACE,
        MAX_DUE_PERIODS,
    )?;
    assert_eq!(due.first().map(|period| period.start), Some(MONDAY_1116));
    Ok(())
}


#[test]
fn monthly_due_across_a_year_end() -> TestResult {
    let monthly = definition(Cadence::Monthly, MONTHLY_OFFSET);
    let december = shift(DEC_2026, MONTHLY_OFFSET);
    let january = shift(JAN_2027, MONTHLY_OFFSET);
    let due = due_periods(&monthly, Some(december), january + GRACE + 1, MAX_DUE_PERIODS)?;
    assert_eq!(due.len(), 1);
    assert_eq!(due.first().map(|period| period.end), Some(january));
    Ok(())
}


#[test]
fn too_many_periods_requested_is_refused() -> TestResult {
    let weekly = definition(Cadence::Weekly, 0);
    assert!(matches!(
        due_periods(&weekly, None, MONDAY_1116, MAX_DUE_PERIODS + 1),
        Err(ScheduleError::TooManyPeriods { .. })
    ));
    Ok(())
}


#[test]
fn grace_out_of_range_is_refused() -> TestResult {
    let mut weekly = definition(Cadence::Weekly, 0);
    weekly.grace_seconds = -1;
    assert!(matches!(
        due_periods(&weekly, None, MONDAY_1116, 1),
        Err(ScheduleError::InvalidGrace { .. })
    ));
    weekly.grace_seconds = MAX_GRACE_SECONDS + 1;
    assert!(matches!(
        due_periods(&weekly, None, MONDAY_1116, 1),
        Err(ScheduleError::InvalidGrace { .. })
    ));
    Ok(())
}


#[test]
fn extreme_times_are_refused_without_panic() -> TestResult {
    let weekly = definition(Cadence::Weekly, 0);
    assert!(due_periods(&weekly, None, i64::MAX, 1).is_err());
    assert!(due_periods(&weekly, None, i64::MIN, 1).is_err());
    assert!(due_periods(&weekly, Some(i64::MAX), MONDAY_1116, 1).is_err());
    assert!(period_containing(Cadence::Weekly, 0, i64::MAX).is_err());
    assert!(period_containing(Cadence::Weekly, 0, i64::MIN).is_err());
    Ok(())
}


#[test]
fn year_9999_boundary_is_refused() -> TestResult {
    [Cadence::Weekly, Cadence::Monthly, Cadence::Quarterly].iter().for_each(|cadence| {
        assert!(period_containing(*cadence, 0, YEAR_9999_LAST_SECOND).is_err());
        assert!(period_containing(*cadence, 0, YEAR_9999_LAST_SECOND + 1).is_err());
        assert!(due_periods(&definition(*cadence, 0), None, YEAR_9999_LAST_SECOND + GRACE, 1).is_err());
    });
    Ok(())
}


const MONDAY_9999_1220: i64 = 253_401_264_000;


const MONDAY_9999_1227: i64 = 253_401_868_800;


#[test]
fn a_due_period_whose_successor_leaves_the_range_is_refused() -> TestResult {
    let weekly = definition(Cadence::Weekly, 0);
    assert!(period_containing(Cadence::Weekly, 0, MONDAY_9999_1220)?.end == MONDAY_9999_1227);
    assert!(due_periods(&weekly, Some(MONDAY_9999_1220), MONDAY_9999_1227 + GRACE, 1).is_err());
    assert!(due_periods(&weekly, Some(MONDAY_9999_1220), MONDAY_9999_1227 - 1, 1)?.is_empty());
    Ok(())
}


#[test]
fn year_0_boundary_is_refused() -> TestResult {
    assert!(period_containing(Cadence::Monthly, 0, YEAR_0_START + DAY).is_ok());
    assert!(period_containing(Cadence::Monthly, 0, YEAR_0_START - 1).is_err());
    assert!(period_containing(Cadence::Monthly, MAX_OFFSET, YEAR_0_START + DAY).is_err());
    assert!(period_containing(Cadence::Monthly, MIN_OFFSET, YEAR_0_START).is_err());
    Ok(())
}


#[test]
fn rfc3339_range_and_format() -> TestResult {
    assert_eq!(format_rfc3339(0)?, "1970-01-01T00:00:00Z");
    assert_eq!(check_rfc3339_range(YEAR_9999_LAST_SECOND)?, YEAR_9999_LAST_SECOND);
    assert!(matches!(check_rfc3339_range(YEAR_9999_LAST_SECOND + 1), Err(ScheduleError::Time(_))));
    assert!(matches!(check_rfc3339_range(YEAR_0_START - 1), Err(ScheduleError::OutOfRange)));
    assert!(matches!(format_rfc3339(i64::MAX), Err(ScheduleError::Time(_))));
    Ok(())
}


#[test]
fn fixture_loads() -> TestResult {
    let file = load_report_file(Path::new(FIXTURE))?;
    assert_eq!(file.reports.len(), FIXTURE_REPORTS);
    let cadences: Vec<(Cadence, i32, i64)> = file
        .reports
        .iter()
        .map(|report| (report.cadence, report.utc_offset_minutes, report.grace_seconds))
        .collect();
    assert_eq!(
        cadences,
        vec![
            (Cadence::Weekly, WEEKLY_FIXTURE_OFFSET, DEFAULT_GRACE_SECONDS),
            (Cadence::Monthly, MONTHLY_OFFSET, MONTHLY_FIXTURE_GRACE),
            (Cadence::Quarterly, 0, DEFAULT_GRACE_SECONDS)
        ]
    );
    assert_eq!(default_grace_seconds(), DEFAULT_GRACE_SECONDS);
    Ok(())
}


#[test]
fn missing_file_is_refused() -> TestResult {
    assert!(matches!(
        load_report_file(Path::new("tests/fixtures/absent.yaml")),
        Err(ScheduleError::Config(_))
    ));
    Ok(())
}


#[test]
fn failing_reader_is_refused() -> TestResult {
    assert!(matches!(
        parse_report_file(&mut FailingReader, "reports.yaml"),
        Err(ScheduleError::Config(_))
    ));
    Ok(())
}


#[test]
fn oversized_file_is_refused() -> TestResult {
    let padding = " ".repeat(usize::try_from(MAX_FILE_BYTES)? + 1);
    assert!(matches!(
        parse_report_file(&mut padding.as_bytes(), "reports.yaml"),
        Err(ScheduleError::FileTooLarge { .. })
    ));
    Ok(())
}


#[test]
fn too_many_reports_is_refused() -> TestResult {
    let entry = BASE.trim_start_matches("reports:\n");
    let text = format!("reports:\n{}", entry.repeat(MAX_REPORTS + 1));
    assert!(matches!(parse(&text), Err(ScheduleError::TooManyReports { .. })));
    Ok(())
}


#[test]
fn base_is_valid() -> TestResult {
    assert_eq!(parse(BASE)?.reports.len(), 1);
    Ok(())
}


#[test]
fn unknown_field_and_bad_cadence_are_refused() -> TestResult {
    assert!(matches!(parse(&format!("{BASE}    extra: 1\n")), Err(ScheduleError::Config(_))));
    assert!(matches!(parse(&BASE.replace("weekly\n", "daily\n")), Err(ScheduleError::Config(_))));
    Ok(())
}


#[test]
fn every_field_refusal() -> TestResult {
    let long_id = "a".repeat(MAX_ID_BYTES + 1);
    let long_title = "t".repeat(LONG_TITLE);
    let cases = [
        (BASE.replace("weekly-1", "-x"), "id"),
        (BASE.replace("weekly-1", &long_id), "id"),
        (BASE.replace("weekly-1", "a b"), "id"),
        (BASE.replace("tenant: acme", "tenant: -x"), "tenant"),
        (BASE.replace("title: Weekly", &format!("title: {long_title}")), "title"),
        (BASE.replace("title: Weekly", "title: \"\""), "title"),
        (BASE.replace("[web]", "[]"), "services"),
        (BASE.replace("[web]", "[\"\"]"), "services"),
        (BASE.replace("[web]", &format!("[{}]", "w".repeat(LONG_SERVICE))), "services"),
        (BASE.replace("utc_offset_minutes: 60", "utc_offset_minutes: 7"), "utc_offset_minutes"),
        (BASE.replace("utc_offset_minutes: 60", "utc_offset_minutes: 855"), "utc_offset_minutes"),
        (BASE.replace("999000", "1000001"), "objective_ppm"),
        (format!("{BASE}    grace_seconds: -1\n"), "grace_seconds"),
        (format!("{BASE}    grace_seconds: 604801\n"), "grace_seconds"),
        (BASE.replace("[csv, json]", "[]"), "formats"),
        (BASE.replace("[csv, json]", "[csv, csv]"), "formats"),
    ];
    cases.iter().try_for_each(|(text, field)| -> TestResult {
        let found = refused_field(text)?;
        (found == *field)
            .then_some(())
            .ok_or_else(|| format!("wrong field {found} for {text}").into())
    })
}


#[test]
fn boundary_values_are_accepted() -> TestResult {
    let text = BASE
        .replace("utc_offset_minutes: 60", "utc_offset_minutes: 840")
        .replace("999000", "1000000")
        .replace("[csv, json]", "[json]");
    parse(&format!("{text}    grace_seconds: 604800\n"))?;
    parse(&BASE.replace("utc_offset_minutes: 60", "utc_offset_minutes: -720"))?;
    Ok(())
}


#[test]
fn pdf_is_refused_as_not_supported() -> TestResult {
    assert!(matches!(
        parse(&BASE.replace("[csv, json]", "[csv, pdf]")),
        Err(ScheduleError::PdfNotSupported { index: 0, .. })
    ));
    Ok(())
}


#[test]
fn duplicate_id_is_refused() -> TestResult {
    let second = BASE.trim_start_matches("reports:\n");
    assert!(matches!(parse(&format!("{BASE}{second}")), Err(ScheduleError::DuplicateId { .. })));
    Ok(())
}


#[test]
fn service_cap_follows_the_limits() -> TestResult {
    let file = parse(&BASE.replace("[web]", "[web, api]"))?;
    let tight = ReportLimits {
        max_services: 1,
        max_name_bytes: MAX_NAME,
    };
    assert!(matches!(
        validate_report_file(&file, "reports.yaml", &tight),
        Err(ScheduleError::Invalid { field: "services", .. })
    ));
    let short_names = ReportLimits {
        max_services: SERVICE_CAP,
        max_name_bytes: SHORT_NAME,
    };
    assert!(matches!(
        validate_report_file(&file, "reports.yaml", &short_names),
        Err(ScheduleError::Invalid { field: "services", .. })
    ));
    Ok(())
}
