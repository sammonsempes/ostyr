#[path = "common/types.rs"]
mod types;


use agent_windows::defender::{
    defender_args, is_leap, is_utc_time, DEFAULT_DEFENDER_INTERVAL_SECONDS, DEFENDER_DEADLINE_SECONDS, DEFENDER_MAX_OUTPUT_BYTES, MAX_ASR_RULES,
    MIN_DEFENDER_INTERVAL_SECONDS, POWERSHELL_PATH, SCRIPT, STATUS_FIELDS,
};
use agent_windows::defender_parse::{action_name, parse_defender, refusal_reason};
use agent_windows::defender_run::{defender_once, defender_refused_line, parsed_line, run_defender_rounds};
use agent_windows::error::{DefenderError, RunError};
use agent_windows::model::{DefenderRefusal, RunEnd, RunRequest};
use serde_json::{json, Value};
use std::io;
use std::sync::LazyLock;
use types::TestResult;


static LOGGING: LazyLock<bool> =
    LazyLock::new(|| tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(io::sink).finish()).is_ok());


const GUID: &str = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84";


const MARKER: &str = "SECRETMARKER";


const FIELD_COUNT: usize = 9;


const OVER_LIMIT: usize = 65;


const HOSTILE_ELEMENTS: usize = 3_000;


const RUNS: u32 = 3;


const DEEP: usize = 200;


const SMALL_INTERVAL: u64 = 299;


const SIGNATURE_AGE: u64 = 2;


const AUDIT: u64 = 2;


const NUMBER: u64 = 5;


const WARN: u64 = 6;


const UNKNOWN_ACTION: u64 = 3;


const UNKNOWN_MODE: u64 = 9;


const OVER_ACTION: u64 = 256;


const REFUSED_COUNT: u64 = 7;


const OVER_U32: u64 = 4_294_967_296;


const FRACTION: f64 = 1.5;


const DEFAULT_INTERVAL: u64 = 3_600;


const YEAR_2000: u32 = 2_000;


const YEAR_1900: u32 = 1_900;


const YEAR_2024: u32 = 2_024;


const YEAR_2023: u32 = 2_023;


const LINES: usize = 3;


const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];


const BAD_UTF8: [u8; 3] = [0xFF, 0xFE, 0x7B];


fn base() -> Value {
    json!({
        "status": {
            "AMServiceEnabled": true,
            "AntivirusEnabled": true,
            "RealTimeProtectionEnabled": false,
            "BehaviorMonitorEnabled": true,
            "IoavProtectionEnabled": true,
            "IsTamperProtected": true,
            "AntivirusSignatureLastUpdated": "2026-11-20T04:51:39.0000000Z",
            "AntivirusSignatureAge": SIGNATURE_AGE,
            "AMRunningMode": "Normal"
        },
        "preference": {
            "AttackSurfaceReductionRules_Ids": null,
            "AttackSurfaceReductionRules_Actions": null,
            "EnableControlledFolderAccess": 0
        }
    })
}


fn parsed(root: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let map = parse_defender(root.to_string().as_bytes()).map_err(|refusal| format!("{refusal:?}"))?;
    Ok(Value::Object(map))
}


fn set(root: &mut Value, pointer: &str, value: Value) -> TestResult {
    *root.pointer_mut(pointer).ok_or("no such pointer")? = value;
    Ok(())
}


fn remove(root: &mut Value, section: &str, key: &str) -> TestResult {
    root.pointer_mut(section)
        .and_then(Value::as_object_mut)
        .ok_or("no such section")?
        .remove(key);
    Ok(())
}


fn unknown_of(defender: &Value) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let list = defender.get("unknown").and_then(Value::as_array).ok_or("no unknown list")?;
    Ok(list
        .iter()
        .map(|entry| {
            let field = entry.get("field").and_then(Value::as_str).unwrap_or("?").to_string();
            let reason = entry.get("reason").and_then(Value::as_str).unwrap_or("?").to_string();
            (field, reason)
        })
        .collect())
}


fn refusal_of(bytes: &[u8]) -> Result<DefenderRefusal, Box<dyn std::error::Error>> {
    assert!(*LOGGING);
    Ok(parse_defender(bytes).err().ok_or("expected a refusal")?)
}


fn rules_root(ids: Value, actions: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let mut root = base();
    set(&mut root, "/preference/AttackSurfaceReductionRules_Ids", ids)?;
    set(&mut root, "/preference/AttackSurfaceReductionRules_Actions", actions)?;
    Ok(root)
}


#[test]
fn the_argument_vector_is_the_const_script_and_flags_only() -> TestResult {
    let expected = [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        SCRIPT,
    ];
    assert_eq!(defender_args(), expected);
    assert_eq!(POWERSHELL_PATH, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
    for qualified in [
        "Defender\\Get-MpComputerStatus",
        "Defender\\Get-MpPreference",
        "Microsoft.PowerShell.Utility\\Select-Object",
        "Microsoft.PowerShell.Utility\\ConvertTo-Json -Compress -Depth 3",
    ] {
        assert!(SCRIPT.contains(qualified));
    }
    assert!(SCRIPT.starts_with("$ErrorActionPreference = 'SilentlyContinue'; $env:Path = 'C:\\Windows\\System32;C:\\Windows'; "));
    assert_eq!(
        SCRIPT.matches("Select-Object").count(),
        SCRIPT.matches("Microsoft.PowerShell.Utility\\Select-Object").count()
    );
    assert_eq!(SCRIPT.matches("Get-Mp").count(), SCRIPT.matches("Defender\\Get-Mp").count());
    assert!(SCRIPT.contains("$env:PSModulePath = $env:SystemRoot"));
    assert_eq!(DEFAULT_DEFENDER_INTERVAL_SECONDS, DEFAULT_INTERVAL);
    Ok(())
}


#[test]
fn every_field_present_gives_every_value() -> TestResult {
    let defender = parsed(&base())?;
    assert_eq!(defender.get("real_time_protection_enabled"), Some(&json!(false)));
    assert_eq!(defender.get("tamper_protected"), Some(&json!(true)));
    assert_eq!(defender.get("antivirus_signature_age"), Some(&json!(SIGNATURE_AGE)));
    assert_eq!(defender.get("am_running_mode"), Some(&json!("Normal")));
    assert_eq!(
        defender.get("antivirus_signature_last_updated"),
        Some(&json!("2026-11-20T04:51:39.0000000Z"))
    );
    assert_eq!(defender.get("controlled_folder_access_name"), Some(&json!("disabled")));
    assert_eq!(defender.get("asr_rules"), Some(&json!([])));
    assert!(unknown_of(&defender)?.is_empty());
    assert_eq!(defender.get("findings"), Some(&json!([])));
    Ok(())
}


#[test]
fn each_missing_field_is_named_absent_with_reason_missing() -> TestResult {
    assert_eq!(STATUS_FIELDS.len(), FIELD_COUNT);
    STATUS_FIELDS.iter().try_for_each(|spec| {
        let mut root = base();
        remove(&mut root, "/status", spec.source)?;
        let defender = parsed(&root)?;
        assert!(defender.get(spec.name).is_none());
        assert_eq!(unknown_of(&defender)?, vec![(spec.name.to_string(), "missing".to_string())]);
        Ok(())
    })
}


#[test]
fn a_null_value_is_missing() -> TestResult {
    let mut root = base();
    set(&mut root, "/status/AntivirusSignatureLastUpdated", Value::Null)?;
    assert_eq!(
        unknown_of(&parsed(&root)?)?,
        vec![("antivirus_signature_last_updated".to_string(), "missing".to_string())]
    );
    Ok(())
}


#[test]
fn a_wrong_typed_value_is_named_wrong_type() -> TestResult {
    let cases = [
        ("/status/AMServiceEnabled", json!("true"), "am_service_enabled"),
        ("/status/AntivirusSignatureAge", json!(true), "antivirus_signature_age"),
        ("/status/AMRunningMode", json!(1), "am_running_mode"),
        ("/status/AntivirusSignatureLastUpdated", json!(NUMBER), "antivirus_signature_last_updated"),
        ("/preference/EnableControlledFolderAccess", json!("1"), "controlled_folder_access"),
    ];
    cases.iter().try_for_each(|(pointer, value, name)| {
        let mut root = base();
        set(&mut root, pointer, value.clone())?;
        let defender = parsed(&root)?;
        assert_eq!(unknown_of(&defender)?, vec![((*name).to_string(), "wrong_type".to_string())]);
        assert!(defender.get(*name).is_none());
        Ok(())
    })
}


#[test]
fn a_refused_value_is_named_refused_and_never_echoed() -> TestResult {
    let long = "A".repeat(MAX_ASR_RULES);
    let cases = [
        ("/status/AntivirusSignatureAge", json!(OVER_U32), "antivirus_signature_age"),
        ("/status/AntivirusSignatureAge", json!(-1), "antivirus_signature_age"),
        ("/status/AntivirusSignatureAge", json!(FRACTION), "antivirus_signature_age"),
        ("/status/AMRunningMode", json!(format!("{MARKER}!")), "am_running_mode"),
        ("/status/AMRunningMode", json!(""), "am_running_mode"),
        ("/status/AMRunningMode", json!(long), "am_running_mode"),
        (
            "/status/AntivirusSignatureLastUpdated",
            json!("\\/Date(1763614299000)\\/"),
            "antivirus_signature_last_updated",
        ),
        ("/status/AntivirusSignatureLastUpdated", json!(MARKER), "antivirus_signature_last_updated"),
    ];
    cases.iter().try_for_each(|(pointer, value, name)| {
        let mut root = base();
        set(&mut root, pointer, value.clone())?;
        let defender = parsed(&root)?;
        assert_eq!(unknown_of(&defender)?, vec![((*name).to_string(), "refused".to_string())]);
        assert!(!defender.to_string().contains(MARKER));
        Ok(())
    })
}


#[test]
fn controlled_folder_access_modes_are_named() -> TestResult {
    let names = [(0, "disabled"), (1, "enabled"), (AUDIT, "audit_mode"), (UNKNOWN_MODE, "unknown")];
    names.iter().try_for_each(|(mode, name)| {
        let mut root = base();
        set(&mut root, "/preference/EnableControlledFolderAccess", json!(mode))?;
        assert_eq!(parsed(&root)?.get("controlled_folder_access_name"), Some(&json!(name)));
        Ok(())
    })
}


#[test]
fn time_text_accepts_only_the_seven_digit_utc_form() -> TestResult {
    let good = [
        "2026-11-20T04:51:39.0000000Z",
        "2024-02-29T23:59:59.9999999Z",
        "0000-01-01T00:00:00.0000000Z",
        "9999-12-31T23:59:59.1234567Z",
    ];
    let bad = [
        "2026-11-20T04:51:39Z",
        "2026-11-20T04:51:39.0000000+01:00",
        "2026-13-20T04:51:39.0000000Z",
        "2026-00-20T04:51:39.0000000Z",
        "2026-11-00T04:51:39.0000000Z",
        "2026-11-31T04:51:39.0000000Z",
        "2023-02-29T04:51:39.0000000Z",
        "1900-02-29T04:51:39.0000000Z",
        "2026-11-20T24:51:39.0000000Z",
        "2026-11-20T04:60:39.0000000Z",
        "2026-11-20T04:51:60.0000000Z",
        "2026-11-20T04:51:39.0000000Z\0",
        "2026-11-20T04:51:39.000000\u{ff10}Z",
        "2026-11-20 04:51:39.0000000Z",
        "２026-11-20T04:51:39.0000000Z",
        "",
        "2026",
    ];
    assert!(good.iter().all(|text| is_utc_time(text)));
    assert!(bad.iter().all(|text| !is_utc_time(text)));
    assert!(is_leap(YEAR_2000) && !is_leap(YEAR_1900) && is_leap(YEAR_2024) && !is_leap(YEAR_2023));
    Ok(())
}


#[test]
fn one_rule_in_audit_mode_is_a_list_of_one() -> TestResult {
    let defender = parsed(&rules_root(json!([GUID]), json!([AUDIT]))?)?;
    assert_eq!(
        defender.get("asr_rules"),
        Some(&json!([{"id": GUID, "action": AUDIT, "action_name": "audit"}]))
    );
    Ok(())
}


#[test]
fn a_guid_is_lower_cased() -> TestResult {
    let defender = parsed(&rules_root(json!([GUID.to_ascii_uppercase()]), json!([1]))?)?;
    assert_eq!(
        defender.get("asr_rules"),
        Some(&json!([{"id": GUID, "action": 1, "action_name": "block"}]))
    );
    Ok(())
}


#[test]
fn unequal_arrays_are_one_named_finding_and_no_pairing() -> TestResult {
    let defender = parsed(&rules_root(json!([GUID, GUID]), json!([1]))?)?;
    assert_eq!(defender.get("findings"), Some(&json!(["asr_arrays_mismatch"])));
    assert!(defender.get("asr_rules").is_none());
    let one_null = parsed(&rules_root(Value::Null, json!([1]))?)?;
    assert_eq!(one_null.get("findings"), Some(&json!(["asr_arrays_mismatch"])));
    Ok(())
}


#[test]
fn sixty_five_rules_are_refused_by_name_with_no_element_read() -> TestResult {
    let ids = vec![GUID; OVER_LIMIT];
    let actions = vec![1; OVER_LIMIT];
    let defender = parsed(&rules_root(json!(ids), json!(actions))?)?;
    assert!(defender.get("asr_rules").is_none());
    assert_eq!(defender.get("asr_rules_over_limit"), Some(&json!(OVER_LIMIT)));
    assert_eq!(defender.get("findings"), Some(&json!(["asr_rules_over_limit"])));
    let exact = parsed(&rules_root(json!(vec![GUID; MAX_ASR_RULES]), json!(vec![1; MAX_ASR_RULES]))?)?;
    assert_eq!(exact.get("asr_rules").and_then(Value::as_array).map(Vec::len), Some(MAX_ASR_RULES));
    Ok(())
}


#[test]
fn a_huge_array_of_hostile_elements_is_counted_not_built() -> TestResult {
    let element = "[[[[[[[[[[1]]]]]]]]]]";
    let items = vec![element; HOSTILE_ELEMENTS].join(",");
    let text = format!(
        r#"{{"status":{{"AMServiceEnabled":true}},"preference":{{"AttackSurfaceReductionRules_Ids":[{items}],"AttackSurfaceReductionRules_Actions":[]}}}}"#
    );
    let defender = parse_defender(text.as_bytes()).map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(defender.get("findings"), Some(&json!(["asr_arrays_mismatch"])));
    assert!(defender.get("asr_rules").is_none());
    Ok(())
}


#[test]
fn sixty_five_deeply_nested_ids_are_counted_not_built() -> TestResult {
    let element = format!("{}1{}", "[".repeat(DEEP), "]".repeat(DEEP));
    let ids = vec![element; OVER_LIMIT].join(",");
    let actions = vec!["1"; OVER_LIMIT].join(",");
    let text = format!(
        r#"{{"status":{{"AMServiceEnabled":true}},"preference":{{"AttackSurfaceReductionRules_Ids":[{ids}],"AttackSurfaceReductionRules_Actions":[{actions}]}}}}"#
    );
    let defender = parse_defender(text.as_bytes()).map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(defender.get("findings"), Some(&json!(["asr_rules_over_limit"])));
    assert_eq!(defender.get("asr_rules_over_limit"), Some(&json!(OVER_LIMIT)));
    Ok(())
}


#[test]
fn a_duplicated_status_key_is_malformed_and_a_bad_number_is_wrong_type() -> TestResult {
    assert_eq!(
        refusal_of(br#"{"status":{"AMServiceEnabled":true,"AMServiceEnabled":false}}"#)?,
        DefenderRefusal::Malformed
    );
    let mut root = base();
    set(&mut root, "/status/AntivirusSignatureAge", json!(0))?;
    let text = root.to_string().replace("\"AntivirusSignatureAge\":0", "\"AntivirusSignatureAge\":1e999");
    let defender = Value::Object(parse_defender(text.as_bytes()).map_err(|refusal| format!("{refusal:?}"))?);
    assert!(unknown_of(&defender)?.contains(&("antivirus_signature_age".to_string(), "wrong_type".to_string())));
    let nested = br#"{"status":{"AMServiceEnabled":{"a":[1]},"AntivirusEnabled":true}}"#;
    let kept = Value::Object(parse_defender(nested).map_err(|refusal| format!("{refusal:?}"))?);
    assert!(unknown_of(&kept)?.contains(&("am_service_enabled".to_string(), "wrong_type".to_string())));
    Ok(())
}


#[test]
fn an_id_element_that_cannot_be_built_refuses_its_pair() -> TestResult {
    let text =
        br#"{"status":{"AMServiceEnabled":true},"preference":{"AttackSurfaceReductionRules_Ids":[1e999],"AttackSurfaceReductionRules_Actions":[1]}}"#;
    let defender = parse_defender(text).map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(defender.get("asr_rules_refused"), Some(&json!(1)));
    assert_eq!(defender.get("findings"), Some(&json!(["asr_rules_refused"])));
    Ok(())
}


#[test]
fn an_empty_status_is_unavailable_and_a_non_object_preference_is_wrong_type() -> TestResult {
    assert_eq!(refusal_of(br#"{"status":{},"preference":{}}"#)?, DefenderRefusal::Unavailable);
    let mut root = base();
    set(&mut root, "/preference", json!("text"))?;
    let reasons = unknown_of(&parsed(&root)?)?;
    assert!(reasons.contains(&("controlled_folder_access".to_string(), "wrong_type".to_string())));
    assert!(reasons.contains(&("asr_rules".to_string(), "wrong_type".to_string())));
    Ok(())
}


#[test]
fn a_non_guid_id_or_a_bad_action_is_refused_and_counted() -> TestResult {
    let lookalike = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc8\u{0663}";
    let ids = json!([
        GUID,
        "not-a-guid",
        lookalike,
        format!("{GUID}\0"),
        "75668c1f173b5-4cf0-bb93-3ecf5cb7cc84",
        GUID,
        GUID,
        NUMBER
    ]);
    let actions = json!([1, 1, 1, 1, 1, OVER_ACTION, "1", 1]);
    let defender = parsed(&rules_root(ids, actions)?)?;
    assert_eq!(defender.get("asr_rules").and_then(Value::as_array).map(Vec::len), Some(1));
    assert_eq!(defender.get("asr_rules_refused"), Some(&json!(REFUSED_COUNT)));
    assert_eq!(defender.get("findings"), Some(&json!(["asr_rules_refused"])));
    Ok(())
}


#[test]
fn a_missing_or_bare_asr_array_is_named_unknown() -> TestResult {
    let mut no_ids = base();
    remove(&mut no_ids, "/preference", "AttackSurfaceReductionRules_Ids")?;
    assert_eq!(unknown_of(&parsed(&no_ids)?)?, vec![("asr_rules".to_string(), "missing".to_string())]);
    let mut no_actions = base();
    remove(&mut no_actions, "/preference", "AttackSurfaceReductionRules_Actions")?;
    assert_eq!(unknown_of(&parsed(&no_actions)?)?, vec![("asr_rules".to_string(), "missing".to_string())]);
    let bare = parsed(&rules_root(json!(GUID), json!([1]))?)?;
    assert_eq!(unknown_of(&bare)?, vec![("asr_rules".to_string(), "wrong_type".to_string())]);
    let bare_actions = parsed(&rules_root(json!([GUID]), json!(1))?)?;
    assert_eq!(unknown_of(&bare_actions)?, vec![("asr_rules".to_string(), "wrong_type".to_string())]);
    Ok(())
}


#[test]
fn a_missing_preference_section_names_every_preference_field() -> TestResult {
    let mut root = base();
    root.as_object_mut().ok_or("not an object")?.remove("preference");
    let reasons = unknown_of(&parsed(&root)?)?;
    assert!(reasons.contains(&("controlled_folder_access".to_string(), "missing".to_string())));
    assert!(reasons.contains(&("asr_rules".to_string(), "missing".to_string())));
    Ok(())
}


#[test]
fn a_bom_before_the_json_is_dropped() -> TestResult {
    let mut bytes = UTF8_BOM.to_vec();
    bytes.extend_from_slice(base().to_string().as_bytes());
    assert!(parse_defender(&bytes).is_ok());
    Ok(())
}


#[test]
fn empty_or_null_status_is_defender_unavailable() -> TestResult {
    assert_eq!(refusal_of(b"")?, DefenderRefusal::Unavailable);
    assert_eq!(refusal_of(b" \r\n\t ")?, DefenderRefusal::Unavailable);
    assert_eq!(refusal_of(br#"{"status":null,"preference":null}"#)?, DefenderRefusal::Unavailable);
    assert_eq!(refusal_of(br#"{"preference":{}}"#)?, DefenderRefusal::Unavailable);
    assert_eq!(refusal_reason(DefenderRefusal::Unavailable), "defender_unavailable");
    Ok(())
}


#[test]
fn undecodable_and_malformed_output_is_refused_with_fixed_reasons() -> TestResult {
    assert_eq!(refusal_of(&BAD_UTF8)?, DefenderRefusal::Undecodable);
    assert_eq!(refusal_of(format!("{{{MARKER}").as_bytes())?, DefenderRefusal::Malformed);
    assert_eq!(refusal_of(b"[1,2]")?, DefenderRefusal::Malformed);
    assert_eq!(refusal_of(br#"{"status":"x"}"#)?, DefenderRefusal::Malformed);
    let deep = format!("{}{}", "[".repeat(DEEP), "]".repeat(DEEP));
    assert_eq!(refusal_of(deep.as_bytes())?, DefenderRefusal::Malformed);
    assert_eq!(refusal_of(format!("{}{MARKER}", base()).as_bytes())?, DefenderRefusal::Malformed);
    assert_eq!(refusal_reason(DefenderRefusal::Undecodable), "undecodable");
    assert_eq!(refusal_reason(DefenderRefusal::Malformed), "malformed");
    let line = parsed_line(format!("{{{MARKER}").as_bytes());
    assert!(!line.contains(MARKER));
    assert!(line.contains("\"reason\":\"malformed\""));
    Ok(())
}


#[test]
fn action_names_follow_the_documented_numbers() -> TestResult {
    let names = [
        (0, "off"),
        (1, "block"),
        (AUDIT, "audit"),
        (NUMBER, "not_configured"),
        (WARN, "warn"),
        (UNKNOWN_ACTION, "unknown"),
    ];
    assert!(names.iter().all(|(number, name)| action_name(*number) == *name));
    Ok(())
}


fn run_once(end: Result<RunEnd, RunError>, output: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let mut seen: Vec<(String, Vec<String>, usize, u64)> = Vec::new();
    assert!(*LOGGING);
    let mut pending = Some(end);
    let mut runner = |request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| {
        seen.push((
            request.program.to_string(),
            request.args.to_vec(),
            request.max_bytes,
            request.deadline_seconds,
        ));
        sink(output);
        pending.take().unwrap_or(Err(RunError::Reader))
    };
    let line = defender_once(&mut runner);
    assert_eq!(seen.len(), 1);
    let (program, args, max_bytes, deadline) = seen.first().ok_or("no request")?;
    assert_eq!(program, POWERSHELL_PATH);
    assert_eq!(args, &defender_args());
    assert_eq!(*max_bytes, DEFENDER_MAX_OUTPUT_BYTES);
    assert_eq!(*deadline, DEFENDER_DEADLINE_SECONDS);
    Ok(serde_json::from_str(&line)?)
}


fn reason_of(line: &Value) -> Option<&str> {
    line.pointer("/agent/event_refused/reason").and_then(Value::as_str)
}


#[test]
fn a_run_gives_one_state_line() -> TestResult {
    let line = run_once(Ok(RunEnd::Done), base().to_string().as_bytes())?;
    assert_eq!(line.pointer("/event/dataset"), Some(&json!("ostyr.windows.defender")));
    assert_eq!(line.pointer("/event/kind"), Some(&json!("state")));
    assert_eq!(line.pointer("/defender/tamper_protected"), Some(&json!(true)));
    Ok(())
}


#[test]
fn a_failed_run_is_one_refused_line_with_a_fixed_reason_and_no_values() -> TestResult {
    let partial = base().to_string();
    let cases = [
        (Ok(RunEnd::Deadline), "timeout"),
        (Ok(RunEnd::Failed(Some(1))), "exit_nonzero"),
        (Ok(RunEnd::Failed(None)), "exit_nonzero"),
        (Ok(RunEnd::Capped), "oversized"),
        (Err(RunError::Reader), "run_failed"),
    ];
    cases.into_iter().try_for_each(|(end, reason)| {
        let line = run_once(end, partial.as_bytes())?;
        assert_eq!(reason_of(&line), Some(reason));
        assert!(line.get("defender").is_none());
        Ok(())
    })
}


#[test]
fn an_unavailable_run_is_one_refused_line() -> TestResult {
    let line = run_once(Ok(RunEnd::Done), b"")?;
    assert_eq!(reason_of(&line), Some("defender_unavailable"));
    assert!(defender_refused_line("x").contains("ostyr.windows.defender"));
    Ok(())
}


#[test]
fn an_interval_below_the_floor_is_refused_before_any_run() -> TestResult {
    let mut calls = 0u32;
    let mut runner = |_: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| {
        calls += 1;
        Ok(RunEnd::Done)
    };
    let mut lines = 0u32;
    let mut sink = |_: &str| {
        lines += 1;
        Ok(())
    };
    let refused = run_defender_rounds(SMALL_INTERVAL, 1, &mut runner, &mut |_| (), &mut sink);
    assert!(matches!(refused, Err(DefenderError::IntervalBelowFloor)));
    assert_eq!(
        refused.err().map(|error| error.to_string()),
        Some("the interval is below the 300 second floor".to_string())
    );
    assert_eq!((calls, lines), (0, 0));
    assert_eq!(MIN_DEFENDER_INTERVAL_SECONDS, SMALL_INTERVAL + 1);
    Ok(())
}


#[test]
fn rounds_write_one_line_per_run_and_pause_between_runs_only() -> TestResult {
    let mut pauses: Vec<u64> = Vec::new();
    let mut written: Vec<String> = Vec::new();
    let mut runner = |_: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| {
        sink(base().to_string().as_bytes());
        Ok(RunEnd::Done)
    };
    let mut sink = |line: &str| {
        written.push(line.to_string());
        Ok(())
    };
    let done = run_defender_rounds(
        MIN_DEFENDER_INTERVAL_SECONDS,
        RUNS,
        &mut runner,
        &mut |seconds| pauses.push(seconds),
        &mut sink,
    )?;
    assert_eq!(done, RUNS);
    assert_eq!(written.len(), LINES);
    assert_eq!(pauses, vec![MIN_DEFENDER_INTERVAL_SECONDS, MIN_DEFENDER_INTERVAL_SECONDS]);
    Ok(())
}


#[test]
fn a_failing_sink_stops_the_rounds() -> TestResult {
    let mut runner = |_: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| Ok(RunEnd::Done);
    let mut sink = |_: &str| Err(io::Error::other("sink"));
    let failed = run_defender_rounds(MIN_DEFENDER_INTERVAL_SECONDS, RUNS, &mut runner, &mut |_| (), &mut sink);
    assert!(matches!(failed, Err(DefenderError::Sink(_))));
    assert_eq!(
        failed.err().map(|error| error.to_string()),
        Some("writing the defender line failed".to_string())
    );
    Ok(())
}
