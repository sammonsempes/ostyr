use sla_report::availability::availability;
use sla_report::error::{ExportError, SlaError};
use sla_report::export::{neutralise_cell, to_csv, to_json, CSV_HEADER};
use sla_report::model::{CheckResult, Limits, MaintenanceWindow, Period, Report, ReportLimits, ServiceInput, SlaFigure};
use sla_report::report::{
    build_report, cut_name, default_report_limits, percent_from_ppm, DEFAULT_MAX_NAME_BYTES, DEFAULT_MAX_SERVICES, NAME_CUT_MARKER,
};
use std::io::{self, Write};


const TENANT: &str = "acme";


const OTHER: &str = "globex";


const PERIOD_END: i64 = 1_000;


const BAD_AT: i64 = 900;


const SHORT_GAP: i64 = 400;


const WINDOW_START: i64 = 100;


const WINDOW_END: i64 = 200;


const OBJECTIVE: u32 = 999_000;


const FULL_OBJECTIVE: u32 = 1_000_000;


const EXPECTED_DOWN: i64 = 100;


const EXPECTED_UNKNOWN: i64 = 600;


const THREE: usize = 3;


const SMALL_SERVICES: usize = 2;


const SMALL_NAME: usize = 3;


const BIG: usize = 1_000;


const CUT_AT_TWO: usize = 2;


const PPM_EXAMPLE: u32 = 999_004;


const PPM_ONE: u32 = 5;


const COLUMNS: usize = 7;


const AVAILABILITY_COLUMN: usize = 2;


fn period(tenant: &str) -> Period {
    Period {
        tenant: tenant.to_string(),
        start: 0,
        end: PERIOD_END,
    }
}


fn limits(gap: i64) -> Limits {
    Limits {
        max_results: BIG,
        max_incidents: BIG,
        max_windows: BIG,
        max_gap_seconds: gap,
    }
}


fn result(at: i64, ok: bool) -> CheckResult {
    CheckResult {
        tenant: TENANT.to_string(),
        at,
        ok,
    }
}


fn figure(results: &[CheckResult], windows: &[MaintenanceWindow], gap: i64, objective: u32) -> Result<SlaFigure, SlaError> {
    availability(results, &[], windows, &period(TENANT), objective, &limits(gap))
}


fn service(tenant: &str, name: &str, figure: SlaFigure, objective: u32) -> ServiceInput {
    ServiceInput {
        tenant: tenant.to_string(),
        name: name.to_string(),
        objective_ppm: objective,
        figure,
    }
}


fn three_services() -> Result<Vec<ServiceInput>, SlaError> {
    let api = figure(&[result(0, true), result(BAD_AT, false)], &[], PERIOD_END, OBJECTIVE)?;
    let window = MaintenanceWindow {
        tenant: TENANT.to_string(),
        start: WINDOW_START,
        end: WINDOW_END,
    };
    let db = figure(&[result(0, true)], &[window], SHORT_GAP, FULL_OBJECTIVE)?;
    let web = figure(&[result(0, true)], &[], PERIOD_END, OBJECTIVE)?;
    Ok(vec![
        service(TENANT, "b-api", api, OBJECTIVE),
        service(TENANT, "c-web", web, OBJECTIVE),
        service(TENANT, "a-db", db, FULL_OBJECTIVE),
    ])
}


fn report_of(services: &[ServiceInput]) -> Result<Report, SlaError> {
    build_report(TENANT, &period(TENANT), services, &default_report_limits())
}


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


struct FlushFailing;


impl Write for FlushFailing {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("injected"))
    }
}


#[test]
fn report_has_sorted_lines_and_totals() -> Result<(), SlaError> {
    let report = report_of(&three_services()?)?;
    let names: Vec<&str> = report.lines.iter().map(|line| line.name.as_str()).collect();
    assert_eq!(names, vec!["a-db", "b-api", "c-web"]);
    assert_eq!(report.totals.services, THREE);
    assert_eq!(report.totals.down_seconds, EXPECTED_DOWN);
    assert_eq!(report.totals.unknown_seconds, EXPECTED_UNKNOWN);
    let used: i64 = report.lines.iter().map(|line| line.budget_used_seconds).sum();
    assert_eq!(report.totals.budget_used_seconds, used);
    let first = report
        .lines
        .first()
        .map(|line| (line.availability_percent.clone(), line.objective_percent.clone()));
    assert_eq!(first, Some((Some("100.0000".to_string()), "100.0000".to_string())));
    let second = report
        .lines
        .get(1)
        .map(|line| (line.availability_percent.clone(), line.objective_percent.clone()));
    assert_eq!(second, Some((Some("90.0000".to_string()), "99.9000".to_string())));
    assert_eq!((report.tenant.as_str(), report.start, report.end), (TENANT, 0, PERIOD_END));
    Ok(())
}


#[test]
fn tenant_mix_is_refused() -> Result<(), SlaError> {
    let mut services = three_services()?;
    services.push(service(OTHER, "intruder", figure(&[], &[], PERIOD_END, OBJECTIVE)?, OBJECTIVE));
    let expected = SlaError::TenantMismatch {
        expected: TENANT.to_string(),
        found: OTHER.to_string(),
    };
    assert_eq!(report_of(&services), Err(expected));
    let wrong_period = build_report(OTHER, &period(TENANT), &[], &default_report_limits());
    assert_eq!(
        wrong_period,
        Err(SlaError::TenantMismatch {
            expected: OTHER.to_string(),
            found: TENANT.to_string()
        })
    );
    Ok(())
}


#[test]
fn unknown_availability_is_empty_in_csv() -> Result<(), Box<dyn std::error::Error>> {
    let empty = figure(&[], &[], PERIOD_END, OBJECTIVE)?;
    assert_eq!(empty.availability_ppm, None);
    let report = report_of(&[service(TENANT, "idle", empty, OBJECTIVE)])?;
    let mut output = Vec::new();
    to_csv(&report, &mut output)?;
    let rows: Vec<csv::StringRecord> = csv::Reader::from_reader(output.as_slice()).records().collect::<Result<_, _>>()?;
    assert_eq!(rows.first().and_then(|row| row.get(AVAILABILITY_COLUMN)), Some(""));
    Ok(())
}


#[test]
fn service_cap_uses_injected_limit() -> Result<(), SlaError> {
    let services = three_services()?;
    let small = ReportLimits {
        max_services: SMALL_SERVICES,
        max_name_bytes: DEFAULT_MAX_NAME_BYTES,
    };
    let refused = build_report(TENANT, &period(TENANT), &services, &small);
    assert_eq!(
        refused,
        Err(SlaError::TooManyServices {
            count: THREE,
            max: SMALL_SERVICES
        })
    );
    assert_eq!(default_report_limits().max_services, DEFAULT_MAX_SERVICES);
    Ok(())
}


#[test]
fn long_name_is_cut_with_marker() -> Result<(), SlaError> {
    assert_eq!(cut_name("abcdef", SMALL_NAME), format!("abc{NAME_CUT_MARKER}"));
    assert_eq!(cut_name("abc", SMALL_NAME), "abc");
    assert_eq!(cut_name("\u{e9}\u{e9}", SMALL_NAME), format!("\u{e9}{NAME_CUT_MARKER}"));
    assert_eq!(cut_name("\u{e9}\u{e9}", CUT_AT_TWO), format!("\u{e9}{NAME_CUT_MARKER}"));
    assert_eq!(cut_name("abc", 0), NAME_CUT_MARKER);
    Ok(())
}


#[test]
fn report_line_names_are_cut() -> Result<(), SlaError> {
    let limits = ReportLimits {
        max_services: BIG,
        max_name_bytes: SMALL_NAME,
    };
    let services = vec![service(TENANT, "abcdef", figure(&[], &[], PERIOD_END, OBJECTIVE)?, OBJECTIVE)];
    let report = build_report(TENANT, &period(TENANT), &services, &limits)?;
    assert_eq!(report.lines.first().map(|line| line.name.clone()), Some(format!("abc{NAME_CUT_MARKER}")));
    Ok(())
}


#[test]
fn percent_is_exact_with_four_decimals() -> Result<(), SlaError> {
    assert_eq!(percent_from_ppm(PPM_EXAMPLE), "99.9004");
    assert_eq!(percent_from_ppm(PPM_ONE), "0.0005");
    assert_eq!(percent_from_ppm(FULL_OBJECTIVE), "100.0000");
    Ok(())
}


#[test]
fn csv_neutralises_every_injection_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let prefixed = ["=1+1", "+x", "-x", "@x", "\tx", "\rx"];
    let safe_cell = neutralise_cell("safe");
    assert_eq!(safe_cell, "safe");
    let services: Vec<ServiceInput> = prefixed
        .iter()
        .map(|name| Ok(service(TENANT, name, figure(&[], &[], PERIOD_END, OBJECTIVE)?, OBJECTIVE)))
        .collect::<Result<_, SlaError>>()?;
    let report = report_of(&services)?;
    let mut output = Vec::new();
    to_csv(&report, &mut output)?;
    let mut reader = csv::Reader::from_reader(output.as_slice());
    let header: Vec<String> = reader.headers()?.iter().map(str::to_string).collect();
    assert_eq!(header, CSV_HEADER.to_vec());
    let cells: Vec<String> = reader
        .records()
        .map(|row| row.map(|record| record.get(0).unwrap_or("").to_string()))
        .collect::<Result<_, _>>()?;
    let mut expected: Vec<String> = prefixed.iter().map(|name| format!("'{name}")).collect();
    expected.sort();
    assert_eq!(cells, expected);
    assert_eq!(reader.headers()?.len(), COLUMNS);
    Ok(())
}


#[test]
fn json_round_trips_the_figures() -> Result<(), Box<dyn std::error::Error>> {
    let report = report_of(&three_services()?)?;
    let mut output = Vec::new();
    to_json(&report, &mut output)?;
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(value.pointer("/totals/services"), Some(&serde_json::json!(THREE)));
    assert_eq!(value.pointer("/lines/1/availability_percent"), Some(&serde_json::json!("90.0000")));
    assert_eq!(value.pointer("/tenant"), Some(&serde_json::json!(TENANT)));
    Ok(())
}


#[test]
fn write_errors_are_propagated() -> Result<(), SlaError> {
    let report = report_of(&three_services()?)?;
    assert!(matches!(to_csv(&report, FailingWriter), Err(ExportError::Csv(_))));
    assert!(matches!(to_csv(&report, FlushFailing), Err(ExportError::Io(_))));
    assert!(matches!(to_json(&report, FailingWriter), Err(ExportError::Json(_))));
    Ok(())
}


fn huge_service(name: &str, field: &str) -> Result<ServiceInput, SlaError> {
    let mut base = figure(&[], &[], PERIOD_END, OBJECTIVE)?;
    base.down_seconds = 0;
    base.unknown_seconds = 0;
    base.budget.consumed_seconds = 0;
    match field {
        "down_seconds" => base.down_seconds = i64::MAX,
        "unknown_seconds" => base.unknown_seconds = i64::MAX,
        _ => base.budget.consumed_seconds = i64::MAX,
    }
    Ok(service(TENANT, name, base, OBJECTIVE))
}


#[test]
fn overflowing_totals_are_refused() -> Result<(), SlaError> {
    ["down_seconds", "unknown_seconds", "budget_used_seconds"].iter().try_for_each(|field| {
        let services = [huge_service("a", field)?, huge_service("b", field)?];
        let outcome = report_of(&services);
        assert_eq!(outcome, Err(SlaError::TotalOverflow { field }));
        let single = report_of(services.get(..1).unwrap_or(&[]))?;
        assert_eq!(single.totals.services, 1);
        Ok(())
    })
}


#[test]
fn leading_whitespace_and_full_width_prefixes_are_neutralised() -> Result<(), SlaError> {
    ["\u{FF1D}x", "\u{FF0B}x", "\u{FF0D}x", "\u{FF20}x", " =1+1", "\n=1+1", " \t@x", "  -x"]
        .iter()
        .for_each(|cell| assert_eq!(neutralise_cell(cell), format!("'{cell}")));
    ["a=b", "  plain", ""].iter().for_each(|cell| assert_eq!(neutralise_cell(cell), *cell));
    Ok(())
}
