use crate::suite::common::TestResult;
use app_health::error::NtpError;
use app_health::grammar::{is_sub_state, is_unit_name};
use app_health::model::{ActiveState, Expectation, LoadState, UnitFileState, UnitHealth, UnitState};
use app_health::units::{assess_unit, load_expectations, parse_unit_show};
use std::io::Read;


const UNIT: &str = "demo.service";


const MAX_SHOW: u64 = 4096;


const MAX_UNITS: usize = 512;


const MAX_NAME: usize = 255;


const HUGE_VALUE: usize = 10_000_000;


const FLAP: u32 = 3;


const RESTARTS_BASE: u32 = 10;


const FLAP_UPPER: u32 = 100;


const SUB_STATE_LIMIT: usize = 64;


const UNKNOWN_FIELDS: usize = 4;


const LOADED_UNITS: usize = 2;


const SEVEN: u32 = 7;


const NINE: u32 = 9;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected"))
    }
}


fn show(unit: &str, load: &str, active: &str, sub: &str, file: &str, restarts: &str, status: &str) -> String {
    format!(
        "Id={unit}\nLoadState={load}\nActiveState={active}\nSubState={sub}\nUnitFileState={file}\nNRestarts={restarts}\nExecMainStatus={status}\n"
    )
}


fn healthy_show() -> String {
    show(UNIT, "loaded", "active", "running", "enabled", "0", "0")
}


fn expectation(should_run: bool, should_be_enabled: bool) -> Expectation {
    Expectation {
        unit: UNIT.to_string(),
        should_run,
        should_be_enabled,
        flap_restarts: FLAP,
    }
}


fn state(load: LoadState, active: ActiveState, file: UnitFileState, restarts: u32) -> UnitState {
    UnitState {
        load: Some(load),
        active: Some(active),
        sub_state: Some("running".to_string()),
        file_state: Some(file),
        restarts,
        exec_main_status: 0,
        unknown_values: 0,
    }
}


fn good(restarts: u32) -> UnitState {
    state(LoadState::Loaded, ActiveState::Active, UnitFileState::Enabled, restarts)
}


fn malformed(result: Result<UnitState, NtpError>, wanted: &str) {
    assert!(matches!(result, Err(NtpError::Malformed { reason }) if reason == wanted), "{wanted}");
}


#[test]
fn expectations_load_with_defaults() -> TestResult {
    let text = "units:\n  - unit: a.service\n    should_run: true\n    should_be_enabled: false\n  - unit: b.timer\n    should_run: false\n    should_be_enabled: true\n    flap_restarts: 100\n";
    let loaded = load_expectations(text, "e.yaml")?;
    assert_eq!(loaded.len(), LOADED_UNITS);
    assert_eq!(loaded.first().map(|item| item.flap_restarts), Some(FLAP));
    assert_eq!(loaded.get(1).map(|item| item.flap_restarts), Some(FLAP_UPPER));
    Ok(())
}


fn document(units: usize, name: &str) -> String {
    let item = format!("  - unit: {name}\n    should_run: true\n    should_be_enabled: true\n");
    format!("units:\n{}", item.repeat(units))
}


#[test]
fn unit_count_is_bounded() -> TestResult {
    assert_eq!(load_expectations(&document(MAX_UNITS, UNIT), "e")?.len(), MAX_UNITS);
    let refused = load_expectations(&document(MAX_UNITS + 1, UNIT), "e");
    assert!(matches!(refused, Err(NtpError::OutOfRange { field: "units" })));
    Ok(())
}


#[test]
fn hostile_unit_names_and_flap_values_are_refused() -> TestResult {
    let long = format!("{}.service", "a".repeat(MAX_NAME));
    let names = [
        "-x.service",
        "foo.service;rm",
        "plain",
        ".service",
        "a b.service",
        "x.target",
        "",
        long.as_str(),
    ];
    names.iter().for_each(|name| {
        let quoted = format!("\"{name}\"");
        let result = load_expectations(&document(1, &quoted), "e");
        assert!(matches!(result, Err(NtpError::OutOfRange { field: "unit" })), "{name}");
    });
    let flaps = ["0", "101"];
    flaps.iter().for_each(|flap| {
        let text = format!("{}    flap_restarts: {flap}\n", document(1, UNIT));
        assert!(
            matches!(load_expectations(&text, "e"), Err(NtpError::OutOfRange { field: "flap_restarts" })),
            "{flap}"
        );
    });
    Ok(())
}


#[test]
fn unknown_fields_and_oversized_files_are_refused() -> TestResult {
    let extra = format!("{}    extra: 1\n", document(1, UNIT));
    assert!(matches!(load_expectations(&extra, "e"), Err(NtpError::Config(_))));
    let huge = format!("{}#{}\n", document(1, UNIT), "x".repeat(HUGE_VALUE));
    assert!(matches!(load_expectations(&huge, "e"), Err(NtpError::Oversized { .. })));
    Ok(())
}


#[test]
fn name_grammar_boundaries() -> TestResult {
    assert!(is_unit_name("sshd.service"));
    assert!(is_unit_name("getty@tty1.service"));
    assert!(is_unit_name("a:b_c.d-e.timer"));
    assert!(is_unit_name("x.socket"));
    assert!(is_unit_name(&format!("{}.service", "a".repeat(MAX_NAME - ".service".len()))));
    assert!(!is_unit_name(&format!("{}.service", "a".repeat(MAX_NAME))));
    assert!(!is_unit_name("..service"));
    assert!(!is_unit_name(".x.service"));
    assert!(!is_unit_name("-x.service"));
    assert!(!is_unit_name("_x.service"));
    assert!(is_unit_name("0.service"));
    assert!(is_sub_state("start-pre"));
    assert!(!is_sub_state(""));
    assert!(!is_sub_state("a b"));
    assert!(is_sub_state(&"a".repeat(SUB_STATE_LIMIT)));
    assert!(!is_sub_state(&"a".repeat(SUB_STATE_LIMIT + 1)));
    Ok(())
}


#[test]
fn healthy_show_parses() -> TestResult {
    let parsed = parse_unit_show(healthy_show().as_bytes(), MAX_SHOW, UNIT)?;
    assert_eq!(parsed, good(0));
    Ok(())
}


#[test]
fn every_known_value_parses() -> TestResult {
    let loads = ["loaded", "not-found", "masked", "error", "bad-setting", "stub", "merged"];
    let actives = [
        "active",
        "inactive",
        "failed",
        "activating",
        "deactivating",
        "reloading",
        "maintenance",
        "refreshing",
    ];
    let files = [
        "enabled",
        "enabled-runtime",
        "linked",
        "linked-runtime",
        "alias",
        "masked",
        "masked-runtime",
        "static",
        "indirect",
        "disabled",
        "generated",
        "transient",
        "bad",
        "",
    ];
    let parse = |load: &str, active: &str, file: &str| parse_unit_show(show(UNIT, load, active, "dead", file, "0", "0").as_bytes(), MAX_SHOW, UNIT);
    loads
        .iter()
        .try_for_each(|value| parse(value, "active", "enabled").map(|item| assert!(item.load.is_some(), "{value}")))?;
    actives
        .iter()
        .try_for_each(|value| parse("loaded", value, "enabled").map(|item| assert!(item.active.is_some(), "{value}")))?;
    files
        .iter()
        .try_for_each(|value| parse("loaded", "active", value).map(|item| assert!(item.file_state.is_some(), "{value}")))?;
    let empty = parse_unit_show(show(UNIT, "loaded", "inactive", "dead", "", "0", "0").as_bytes(), MAX_SHOW, UNIT)?;
    assert_eq!(empty.file_state, Some(UnitFileState::Empty));
    assert_eq!(empty.unknown_values, 0);
    Ok(())
}


#[test]
fn unknown_values_are_none_and_counted() -> TestResult {
    let text = show(UNIT, "weird", "odd", "bad sub", "strange", "7", "9");
    let parsed = parse_unit_show(text.as_bytes(), MAX_SHOW, UNIT)?;
    assert_eq!(
        (parsed.load, parsed.active, parsed.sub_state, parsed.file_state),
        (None, None, None, None)
    );
    assert_eq!(parsed.unknown_values, UNKNOWN_FIELDS);
    assert_eq!((parsed.restarts, parsed.exec_main_status), (SEVEN, NINE));
    Ok(())
}


#[test]
fn duplicate_missing_and_extra_lines_are_malformed() -> TestResult {
    malformed(
        parse_unit_show(format!("{}Id={UNIT}\n", healthy_show()).as_bytes(), MAX_SHOW, UNIT),
        "duplicate key",
    );
    malformed(parse_unit_show("Id=demo.service\n".as_bytes(), MAX_SHOW, UNIT), "missing key");
    malformed(
        parse_unit_show(format!("{}Other=1\n", healthy_show()).as_bytes(), MAX_SHOW, UNIT),
        "unexpected line",
    );
    malformed(
        parse_unit_show(format!("{}\n", healthy_show()).as_bytes(), MAX_SHOW, UNIT),
        "unexpected line",
    );
    Ok(())
}


#[test]
fn another_units_id_is_refused() -> TestResult {
    let other = show("other.service", "loaded", "active", "running", "enabled", "0", "0");
    malformed(parse_unit_show(other.as_bytes(), MAX_SHOW, UNIT), "unexpected unit");
    Ok(())
}


#[test]
fn counters_are_digits_only() -> TestResult {
    ["-1", "+1", "", "1.5", "99999999999", "x"].iter().for_each(|bad| {
        let restarts = show(UNIT, "loaded", "active", "running", "enabled", bad, "0");
        malformed(parse_unit_show(restarts.as_bytes(), MAX_SHOW, UNIT), "bad counter");
        let status = show(UNIT, "loaded", "active", "running", "enabled", "0", bad);
        malformed(parse_unit_show(status.as_bytes(), MAX_SHOW, UNIT), "bad counter");
    });
    Ok(())
}


#[test]
fn huge_values_and_read_errors_are_refused() -> TestResult {
    let huge = show(UNIT, "loaded", "active", &"a".repeat(HUGE_VALUE), "enabled", "0", "0");
    assert!(matches!(
        parse_unit_show(huge.as_bytes(), MAX_SHOW, UNIT),
        Err(NtpError::Oversized { .. })
    ));
    assert!(matches!(parse_unit_show(FailingReader, MAX_SHOW, UNIT), Err(NtpError::Read(_))));
    Ok(())
}


#[test]
fn healthy_and_each_failure_kind() -> TestResult {
    let want = expectation(true, true);
    assert_eq!(assess_unit(&want, None, &good(0)), UnitHealth::Healthy);
    let missing = state(LoadState::NotFound, ActiveState::Inactive, UnitFileState::Empty, 0);
    assert_eq!(assess_unit(&want, None, &missing), UnitHealth::NotFound);
    let failed = state(LoadState::Loaded, ActiveState::Failed, UnitFileState::Enabled, 0);
    assert_eq!(assess_unit(&want, None, &failed), UnitHealth::Failed);
    let stopped = state(LoadState::Loaded, ActiveState::Inactive, UnitFileState::Enabled, 0);
    assert_eq!(assess_unit(&want, None, &stopped), UnitHealth::Stopped);
    let disabled = state(LoadState::Loaded, ActiveState::Active, UnitFileState::Disabled, 0);
    assert_eq!(assess_unit(&want, None, &disabled), UnitHealth::Disabled);
    Ok(())
}


#[test]
fn expectations_gate_stopped_and_disabled() -> TestResult {
    let stopped = state(LoadState::Loaded, ActiveState::Inactive, UnitFileState::Disabled, 0);
    assert_eq!(assess_unit(&expectation(false, false), None, &stopped), UnitHealth::Healthy);
    assert_eq!(assess_unit(&expectation(false, true), None, &stopped), UnitHealth::Disabled);
    let runtime = state(LoadState::Loaded, ActiveState::Active, UnitFileState::EnabledRuntime, 0);
    assert_eq!(assess_unit(&expectation(true, true), None, &runtime), UnitHealth::Healthy);
    Ok(())
}


#[test]
fn unknown_state_is_never_healthy_when_expected() -> TestResult {
    let mut unknown = good(0);
    unknown.active = None;
    assert_eq!(assess_unit(&expectation(true, false), None, &unknown), UnitHealth::Stopped);
    let mut no_file = good(0);
    no_file.file_state = None;
    assert_eq!(assess_unit(&expectation(false, true), None, &no_file), UnitHealth::Disabled);
    Ok(())
}


#[test]
fn flapping_boundary_and_reset() -> TestResult {
    let want = expectation(true, true);
    let before = good(RESTARTS_BASE);
    assert_eq!(assess_unit(&want, Some(&before), &good(RESTARTS_BASE + FLAP - 1)), UnitHealth::Healthy);
    assert_eq!(
        assess_unit(&want, Some(&before), &good(RESTARTS_BASE + FLAP)),
        UnitHealth::Flapping { restarts: FLAP }
    );
    assert_eq!(assess_unit(&want, Some(&before), &good(0)), UnitHealth::Healthy);
    assert_eq!(assess_unit(&want, Some(&before), &good(RESTARTS_BASE)), UnitHealth::Healthy);
    assert_eq!(assess_unit(&want, None, &good(RESTARTS_BASE + FLAP)), UnitHealth::Healthy);
    Ok(())
}


#[test]
fn precedence_at_each_boundary() -> TestResult {
    let want = expectation(true, true);
    let before = good(0);
    let flapping_failed = state(LoadState::Loaded, ActiveState::Failed, UnitFileState::Disabled, FLAP);
    assert_eq!(assess_unit(&want, Some(&before), &flapping_failed), UnitHealth::Failed);
    let flapping_missing = state(LoadState::NotFound, ActiveState::Failed, UnitFileState::Disabled, FLAP);
    assert_eq!(assess_unit(&want, Some(&before), &flapping_missing), UnitHealth::NotFound);
    let restarting = state(LoadState::Loaded, ActiveState::Activating, UnitFileState::Disabled, FLAP);
    assert_eq!(assess_unit(&want, Some(&before), &restarting), UnitHealth::Flapping { restarts: FLAP });
    let stopped_disabled = state(LoadState::Loaded, ActiveState::Inactive, UnitFileState::Disabled, 0);
    assert_eq!(assess_unit(&want, Some(&before), &stopped_disabled), UnitHealth::Stopped);
    Ok(())
}


#[test]
fn a_trailing_carriage_return_is_malformed() -> TestResult {
    let crlf = healthy_show().replace('\n', "\r\n");
    assert!(matches!(
        parse_unit_show(crlf.as_bytes(), MAX_SHOW, UNIT),
        Err(NtpError::Malformed { .. })
    ));
    let one = healthy_show().replacen("LoadState=loaded", "LoadState=loaded\r", 1);
    assert!(matches!(parse_unit_show(one.as_bytes(), MAX_SHOW, UNIT), Err(NtpError::Malformed { .. })));
    Ok(())
}
