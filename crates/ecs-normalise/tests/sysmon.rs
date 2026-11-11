#[path = "common/types.rs"]
mod types;


use core_export::ecs::{to_json, EcsEvent};
use ecs_normalise::error::SysmonError;
use ecs_normalise::sysmon::{normalise_sysmon, KINDS};
use ecs_normalise::sysmon_input::{parse_event, MAX_EVENT_BYTES, MAX_FIELDS, MAX_FIELD_BYTES};
use serde_json::Value;
use sigma_sql::mapping::parse_mapping;
use std::collections::BTreeSet;
use std::error::Error;
use types::TestResult;


const MAPPING: &str = include_str!("../../sigma-sql/mappings/ecs.yaml");


const CASES: [(&str, &str); 17] = [
    (include_str!("fixtures/sysmon_1.xml"), include_str!("snapshots/sysmon_1.json")),
    (include_str!("fixtures/sysmon_3.xml"), include_str!("snapshots/sysmon_3.json")),
    (include_str!("fixtures/sysmon_5.xml"), include_str!("snapshots/sysmon_5.json")),
    (include_str!("fixtures/sysmon_7.xml"), include_str!("snapshots/sysmon_7.json")),
    (include_str!("fixtures/sysmon_8.xml"), include_str!("snapshots/sysmon_8.json")),
    (include_str!("fixtures/sysmon_10.xml"), include_str!("snapshots/sysmon_10.json")),
    (include_str!("fixtures/sysmon_11.xml"), include_str!("snapshots/sysmon_11.json")),
    (include_str!("fixtures/sysmon_12.xml"), include_str!("snapshots/sysmon_12.json")),
    (include_str!("fixtures/sysmon_13.xml"), include_str!("snapshots/sysmon_13.json")),
    (include_str!("fixtures/sysmon_14.xml"), include_str!("snapshots/sysmon_14.json")),
    (include_str!("fixtures/sysmon_22.xml"), include_str!("snapshots/sysmon_22.json")),
    (include_str!("fixtures/sysmon_23.xml"), include_str!("snapshots/sysmon_23.json")),
    (include_str!("fixtures/sysmon_26.xml"), include_str!("snapshots/sysmon_26.json")),
    (include_str!("fixtures/sysmon_27.xml"), include_str!("snapshots/sysmon_27.json")),
    (include_str!("fixtures/sysmon_28.xml"), include_str!("snapshots/sysmon_28.json")),
    (include_str!("fixtures/sysmon_json.json"), include_str!("snapshots/sysmon_json.json")),
    (include_str!("fixtures/sysmon_unknown.xml"), include_str!("snapshots/sysmon_unknown.json")),
];


const UNKNOWN_ID: u32 = 99;


const UNKNOWN: &str = include_str!("fixtures/sysmon_unknown.xml");


const TIME: &str = r#"<Data Name="UtcTime">2026-11-03 10:00:00.123</Data>"#;


const WRAP_START: &str = "<Event><System><EventID>";


fn render(id: &str, data: &str) -> String {
    format!("{WRAP_START}{id}</EventID><Computer>H</Computer></System><EventData>{TIME}{data}</EventData></Event>")
}


fn convert(text: &str) -> Result<EcsEvent, SysmonError> {
    normalise_sysmon(text, &mut BTreeSet::new())
}


fn error_of(text: &str) -> Result<SysmonError, Box<dyn Error>> {
    match convert(text) {
        Ok(_) => Err(format!("expected an error for {text}").into()),
        Err(error) => Ok(error),
    }
}


fn json_of(text: &str) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(&to_json(&convert(text)?)?)?)
}


#[test]
fn every_event_id_matches_its_snapshot() -> TestResult {
    CASES.iter().try_for_each(|(fixture, snapshot)| {
        let json = format!("{}\n", to_json(&convert(fixture)?)?);
        assert_eq!(&json, snapshot);
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn every_supported_id_has_a_fixture_and_a_sigma_category() -> TestResult {
    let codes: BTreeSet<String> = CASES
        .iter()
        .map(|(fixture, _)| convert(fixture).map(|event| event.event.code))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    assert!(KINDS.iter().all(|kind| codes.contains(kind.id)));
    let actions: BTreeSet<&str> = KINDS.iter().map(|kind| kind.action).collect();
    [
        "process_creation",
        "network_connection",
        "image_load",
        "create_remote_thread",
        "process_access",
        "file_event",
        "registry_event",
        "dns_query",
        "file_delete",
        "file_block_executable",
        "file_block_shredding",
    ]
    .iter()
    .for_each(|action| assert!(actions.contains(action), "missing {action}"));
    Ok(())
}


fn has_path(value: &Value, path: &str) -> bool {
    path.split('.').try_fold(value, |current, key| current.get(key)).is_some()
}


#[test]
fn every_column_of_the_sigma_mapping_is_produced_for_windows() -> TestResult {
    let mapping = parse_mapping(MAPPING)?;
    let produced: Vec<Value> = CASES.iter().map(|(fixture, _)| json_of(fixture)).collect::<Result<_, _>>()?;
    mapping
        .categories
        .values()
        .flat_map(|category| category.fields.values())
        .try_for_each(|column| {
            produced
                .iter()
                .any(|event| has_path(event, column))
                .then_some(())
                .ok_or_else(|| format!("column {column} is never produced"))
        })?;
    assert!(produced
        .iter()
        .all(|event| event.pointer("/host/os/type") == Some(&Value::String("windows".to_string()))));
    Ok(())
}


#[test]
fn registry_types_follow_the_event_type() -> TestResult {
    let cases = [
        ("CreateKey", "creation"),
        ("DeleteKey", "deletion"),
        ("DeleteValue", "deletion"),
        ("SetValue", "change"),
        ("", "change"),
    ];
    cases.iter().try_for_each(|(event_type, expected)| {
        let data = format!(r#"<Data Name="EventType">{event_type}</Data><Data Name="TargetObject">HKLM\k</Data>"#);
        let event = json_of(&render("13", &data))?;
        assert_eq!(event.pointer("/event/type/0").and_then(Value::as_str), Some(*expected));
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn unknown_ids_are_logged_once_and_keep_their_raw_fields() -> TestResult {
    let mut seen = BTreeSet::new();
    let first = normalise_sysmon(UNKNOWN, &mut seen)?;
    let second = normalise_sysmon(UNKNOWN, &mut seen)?;
    assert_eq!(first, second);
    assert_eq!(seen.len(), 1);
    assert!(seen.contains(&UNKNOWN_ID));
    assert_eq!(first.sysmon.get("Foo").map(String::as_str), Some("bar"));
    Ok(())
}


#[test]
fn limits_are_typed_errors() -> TestResult {
    let big = "x".repeat(MAX_EVENT_BYTES + 1);
    assert!(matches!(error_of(&big)?, SysmonError::TooLong { .. }));
    let many: String = (0..=MAX_FIELDS).map(|index| format!(r#"<Data Name="f{index}">v</Data>"#)).collect();
    assert!(matches!(error_of(&render("1", &many))?, SysmonError::TooManyFields { .. }));
    let long_value = format!(r#"<Data Name="CommandLine">{}</Data>"#, "v".repeat(MAX_FIELD_BYTES + 1));
    let cut = json_of(&render("1", &long_value))?;
    assert!(cut
        .pointer("/process/command_line")
        .and_then(Value::as_str)
        .ok_or("no command line")?
        .contains("[cut, "));
    let long_name = format!(r#"<Data Name="{}">v</Data>"#, "n".repeat(MAX_FIELD_BYTES + 1));
    assert!(matches!(error_of(&render("1", &long_name))?, SysmonError::FieldTooLong { .. }));
    let exact = format!(r#"<Data Name="a">{}</Data>"#, "v".repeat(MAX_FIELD_BYTES));
    assert!(convert(&render("1", &exact)).is_ok());
    Ok(())
}


#[test]
fn malformed_xml_is_a_typed_error() -> TestResult {
    assert!(matches!(error_of("<Event><System></Event>")?, SysmonError::Xml(_)));
    assert!(matches!(error_of("<Event")?, SysmonError::Xml(_)));
    assert!(matches!(
        error_of(r#"<Event><EventData><Data Name="a" Name="b">v</Data></EventData></Event>"#)?,
        SysmonError::Xml(_)
    ));
    assert!(matches!(
        error_of(&render("1", "<Data Name=\"a\">&nope;</Data>"))?,
        SysmonError::UnknownEntity(_)
    ));
    assert!(matches!(error_of(&render("1", "<Data Name=\"a\">&#xZZ;</Data>"))?, SysmonError::Xml(_)));
    assert!(matches!(error_of("<Event></Event>")?, SysmonError::MissingField("EventID")));
    assert!(matches!(error_of("")?, SysmonError::MissingField("EventID")));
    Ok(())
}


#[test]
fn bad_values_are_typed_errors() -> TestResult {
    assert!(matches!(error_of(&render("one", ""))?, SysmonError::BadEventId(_)));
    assert!(matches!(
        error_of(&render("1", r#"<Data Name="ProcessId">abc</Data>"#))?,
        SysmonError::BadNumber { .. }
    ));
    assert!(matches!(
        error_of(&render("3", r#"<Data Name="SourcePort">70000</Data>"#))?,
        SysmonError::BadNumber { .. }
    ));
    assert!(matches!(
        error_of(&render("1", r#"<Data Name="Hashes">SHA256</Data>"#))?,
        SysmonError::BadHashes
    ));
    let bad_time = "<Event><System><EventID>1</EventID></System><EventData><Data Name=\"UtcTime\">yesterday</Data></EventData></Event>";
    assert!(matches!(error_of(bad_time)?, SysmonError::BadTime(_)));
    let bad_system_time = "<Event><System><EventID>1</EventID><TimeCreated SystemTime=\"x\"/></System><EventData></EventData></Event>";
    assert!(matches!(error_of(bad_system_time)?, SysmonError::BadTime(_)));
    let no_time = "<Event><System><EventID>1</EventID></System><EventData></EventData></Event>";
    assert!(matches!(error_of(no_time)?, SysmonError::MissingField("UtcTime")));
    Ok(())
}


#[test]
fn xml_details_are_handled() -> TestResult {
    let data = concat!(
        r#"<Data Foo="x" Name="CommandLine"><![CDATA[a & b]]></Data>"#,
        r#"<Data Name="Image">C:&#92;a&#x5c;b.exe</Data>"#,
        r#"<Data Name="User">nodomain</Data>"#,
        r#"<Data Name="Empty"/>"#,
        "<Data>unnamed</Data>",
        r#"<Data Name="Hashes">sha1=aa, Imphash=bb</Data>"#
    );
    let text = format!("<?xml version=\"1.0\"?><!-- c -->{}", render("1", data));
    let event = json_of(&text)?;
    assert_eq!(event.pointer("/process/command_line").and_then(Value::as_str), Some("a & b"));
    assert_eq!(event.pointer("/process/executable").and_then(Value::as_str), Some("C:\\a\\b.exe"));
    assert_eq!(event.pointer("/user/name").and_then(Value::as_str), Some("nodomain"));
    assert!(event.pointer("/user/domain").is_none());
    assert_eq!(event.pointer("/process/hash/sha1").and_then(Value::as_str), Some("aa"));
    assert!(event.pointer("/process/hash/sha256").is_none());
    Ok(())
}


#[test]
fn json_variants_and_errors() -> TestResult {
    let flat = r#"{"EventID":"22","EventData":{"UtcTime":"2026-11-03 10:00:00.1","QueryName":"a.test","QueryResults":""}}"#;
    let event = json_of(flat)?;
    assert_eq!(event.pointer("/dns/question/name").and_then(Value::as_str), Some("a.test"));
    assert!(event.pointer("/dns/resolved_ip").is_none());
    assert!(event.pointer("/host/name").is_none());
    assert!(matches!(error_of("{")?, SysmonError::Json(_)));
    assert!(matches!(error_of(r#"{"EventID":1}"#)?, SysmonError::MissingField("EventData")));
    assert!(matches!(
        error_of(r#"{"EventData":{"UtcTime":"2026-11-03 10:00:00.1"}}"#)?,
        SysmonError::MissingField("EventID")
    ));
    assert!(matches!(error_of(r#"{"EventID":1,"EventData":{"a":null}}"#)?, SysmonError::BadValue(_)));
    assert!(matches!(
        error_of(r#"{"EventID":[1],"EventData":{}}"#)?,
        SysmonError::MissingField("EventID")
    ));
    let flags = parse_event(r#"{"EventID":1,"EventData":{"a":true,"b":2}}"#)?;
    assert_eq!(flags.fields.get("a").map(String::as_str), Some("true"));
    assert_eq!(flags.fields.get("b").map(String::as_str), Some("2"));
    Ok(())
}


#[test]
fn errors_display_and_keep_their_cause() -> TestResult {
    let error = error_of(&render("1", r#"<Data Name="ProcessId">abc</Data>"#))?;
    assert!(error.to_string().starts_with("`ProcessId` is not a valid number"));
    assert!(error.source().is_some());
    assert_eq!(
        error_of(&"x".repeat(MAX_EVENT_BYTES + 1))?.to_string(),
        "the event is longer than 65536 bytes"
    );
    Ok(())
}


#[test]
fn a_flat_sysmon_event_with_a_provider_is_accepted() -> TestResult {
    let text = r#"{"Provider":{"Name":"Microsoft-Windows-Sysmon"},"EventID":1,"EventData":{"Image":"a"}}"#;
    let event = parse_event(text)?;
    assert_eq!(event.provider.as_deref(), Some("Microsoft-Windows-Sysmon"));
    Ok(())
}


#[test]
fn serde_json_duplicate_key_message_still_contains_duplicate() -> TestResult {
    let error = parse_event(r#"{"EventID":1,"EventID":2,"EventData":{}}"#)
        .err()
        .ok_or("expected an error")?;
    assert!(matches!(error, SysmonError::DuplicateKey(_)), "{error}");
    Ok(())
}
