#[path = "common/types.rs"]
mod types;


use hardware_health::error::SmartError;
use hardware_health::limits::default_redfish_limits;
use hardware_health::model::{BlindReason, ComponentKind, Health, Reading, RedfishHealth, RedfishLimits, RedfishReport};
use hardware_health::redfish::{nesting_depth, parse_redfish};
use hardware_health::redfish_assess::{assess_redfish, redfish_measures};
use serde_json::Value;
use types::TestResult;


const CHASSIS: &str = include_str!("fixtures/lab-redfish-chassis.json");


const THERMAL: &str = include_str!("fixtures/lab-redfish-thermal.json");


const POWER: &str = include_str!("fixtures/lab-redfish-power.json");


const SYSTEM: &str = include_str!("fixtures/lab-redfish-system.json");


const DOC_COUNT: usize = 4;


const CHASSIS_DOC: usize = 0;


const THERMAL_DOC: usize = 1;


const POWER_DOC: usize = 2;


const SYSTEM_DOC: usize = 3;


const SMALL_LIMIT: usize = 2;


const TINY_BYTES: u64 = 10;


const DEEP_LEVELS: usize = 200;


const EMPTY_OBJECTS: usize = 100_000;


const WIDE_BYTES: u64 = 4_194_304;


const DEFAULT_SENSORS: usize = 256;


const LONG_TEXT: usize = 200;


const NAME_BOUND: usize = 100;


const DEPTH_THREE: usize = 3;


const SUPPLY_WATTS: f64 = 150.0;


const CHASSIS_JSON: &str = r#"{"Status": {"Health": "OK", "HealthRollup": "OK", "State": "Enabled"}}"#;


const THERMAL_JSON: &str = r#"{
    "Temperatures": [{"Name": "CPU1 Temp", "ReadingCelsius": 40, "UpperThresholdCritical": 90, "Status": {"Health": "OK", "State": "Enabled"}}],
    "Fans": [{"Name": "Fan1", "Reading": 5000, "ReadingUnits": "RPM", "Status": {"Health": "OK", "State": "Enabled"}}]
}"#;


const POWER_JSON: &str = r#"{
    "PowerSupplies": [{"Name": "PS1", "LastPowerOutputWatts": 200, "Status": {"Health": "OK", "State": "Enabled"}}],
    "Voltages": [{"Name": "V1", "ReadingVolts": 12.5, "Status": {"Health": "OK", "State": "Enabled"}}]
}"#;


const SYSTEM_JSON: &str = r#"{"Status": {"Health": "OK", "State": "Enabled"}}"#;


fn base() -> Result<[Value; DOC_COUNT], serde_json::Error> {
    Ok([
        serde_json::from_str(CHASSIS_JSON)?,
        serde_json::from_str(THERMAL_JSON)?,
        serde_json::from_str(POWER_JSON)?,
        serde_json::from_str(SYSTEM_JSON)?,
    ])
}


fn set(mut docs: [Value; DOC_COUNT], index: usize, pointer: &str, value: &str) -> Result<[Value; DOC_COUNT], Box<dyn std::error::Error>> {
    let document = docs.get_mut(index).ok_or("no document")?;
    let slot = document.pointer_mut(pointer).ok_or_else(|| format!("no such path {pointer}"))?;
    *slot = serde_json::from_str(value)?;
    Ok(docs)
}


fn limits(max_sensors: usize) -> RedfishLimits {
    RedfishLimits {
        max_bytes: default_redfish_limits().max_bytes,
        max_sensors,
    }
}


fn run_texts(texts: [&str; DOC_COUNT], limits: &RedfishLimits) -> Result<RedfishReport, SmartError> {
    let mut readers = texts.map(str::as_bytes);
    let [chassis, thermal, power, system] = &mut readers;
    parse_redfish(Some(chassis), Some(thermal), Some(power), Some(system), limits)
}


fn run_with(docs: &[Value; DOC_COUNT], limits: &RedfishLimits) -> Result<RedfishReport, SmartError> {
    let texts = docs.each_ref().map(Value::to_string);
    run_texts(texts.each_ref().map(String::as_str), limits)
}


fn run(docs: &[Value; DOC_COUNT]) -> Result<RedfishReport, SmartError> {
    run_with(docs, &default_redfish_limits())
}


fn verdict(docs: &[Value; DOC_COUNT]) -> Result<Health, SmartError> {
    Ok(assess_redfish(&run(docs)?))
}


fn blind(field: &str) -> Health {
    Health::BlindSpot(BlindReason::UnreadableHealthField(field.to_string()))
}


fn degraded(cause: &str) -> Health {
    Health::Degraded(vec![cause.to_string()])
}


#[test]
fn healthy_baseline() -> TestResult {
    assert_eq!(verdict(&base()?)?, Health::Healthy);
    Ok(())
}


#[test]
fn lab_fixtures_parse() -> TestResult {
    let report = run_texts([CHASSIS, THERMAL, POWER, SYSTEM], &default_redfish_limits())?;
    assert!(report.missing_documents.is_empty());
    assert!(matches!(report.chassis_rollup, Reading::Found(_)));
    assert_eq!(assess_redfish(&report), degraded("power supply 0 warning"));
    let disabled = report
        .components
        .iter()
        .filter(|item| item.state == Reading::Found(hardware_health::model::RedfishState::Disabled));
    assert_eq!(disabled.count(), 1);
    Ok(())
}


#[test]
fn measures_have_units_and_labels() -> TestResult {
    let percent = set(base()?, THERMAL_DOC, "/Fans/0/ReadingUnits", r#""Percent""#)?;
    let docs = set(percent, POWER_DOC, "/PowerSupplies/0/Name", r#""bad,name""#)?;
    let measures = redfish_measures(&run(&docs)?, "bmc-1");
    let names: Vec<(&str, &str)> = measures.iter().map(|item| (item.name.as_str(), item.unit.as_str())).collect();
    assert_eq!(
        names,
        [
            ("hw.redfish.temperature", "Cel"),
            ("hw.redfish.fan", "%"),
            ("hw.redfish.power_supply", "W"),
            ("hw.redfish.voltage", "V")
        ]
    );
    assert_eq!(measures.first().map(|item| item.labels.len()), Some(SMALL_LIMIT));
    assert_eq!(measures.get(SMALL_LIMIT).map(|item| item.labels.len()), Some(1));
    let anonymous = redfish_measures(&run(&docs)?, "bad,device");
    assert_eq!(
        anonymous.first().map(|item| item.labels.clone()),
        Some(vec![("sensor".to_string(), "CPU1 Temp".to_string())])
    );
    Ok(())
}


#[test]
fn power_output_watts_and_fan_name_and_rpm_default() -> TestResult {
    let supplied = set(
        base()?,
        POWER_DOC,
        "/PowerSupplies/0",
        r#"{"PowerOutputWatts": 150, "Status": {"Health": "OK", "State": "Enabled"}}"#,
    )?;
    let docs = set(
        supplied,
        THERMAL_DOC,
        "/Fans/0",
        r#"{"FanName": "FanX", "Reading": 1, "Status": {"Health": "OK", "State": "Enabled"}}"#,
    )?;
    let measures = redfish_measures(&run(&docs)?, "bmc");
    let fan = measures.iter().find(|item| item.name == "hw.redfish.fan");
    assert_eq!(fan.map(|item| item.unit.as_str()), Some("{rpm}"));
    assert_eq!(fan.map(|item| item.labels.len()), Some(SMALL_LIMIT));
    let supply = measures.iter().find(|item| item.name == "hw.redfish.power_supply");
    assert_eq!(supply.map(|item| item.value), Some(SUPPLY_WATTS));
    Ok(())
}


#[test]
fn missing_document_is_blind() -> TestResult {
    let texts = base()?.map(|document| document.to_string());
    let mut readers = texts.each_ref().map(|text| text.as_bytes());
    let [chassis, thermal, power, _system] = &mut readers;
    let report = parse_redfish(Some(chassis), Some(thermal), Some(power), None, &default_redfish_limits())?;
    assert_eq!(assess_redfish(&report), blind("system document"));
    Ok(())
}


#[test]
fn every_document_missing_is_listed() -> TestResult {
    let report = parse_redfish(None, None, None, None, &default_redfish_limits())?;
    assert_eq!(report.missing_documents, ["chassis", "thermal", "power", "system"]);
    assert!(report.components.is_empty());
    assert_eq!(assess_redfish(&report), blind("chassis document"));
    Ok(())
}


#[test]
fn chassis_and_system_health_are_required() -> TestResult {
    let chassis = set(base()?, CHASSIS_DOC, "/Status", r#"{"HealthRollup": "OK", "State": "Enabled"}"#)?;
    assert_eq!(verdict(&chassis)?, blind("chassis 0 Health"));
    let system = set(base()?, SYSTEM_DOC, "/Status", r#"{"State": "Enabled"}"#)?;
    assert_eq!(verdict(&system)?, blind("system 0 Health"));
    let voltage = set(base()?, POWER_DOC, "/Voltages/0/Status", r#"{"State": "Enabled"}"#)?;
    assert_eq!(verdict(&voltage)?, blind("voltage 0 Health"));
    let supply = set(base()?, POWER_DOC, "/PowerSupplies/0/Status", r#"{"State": "Enabled"}"#)?;
    assert_eq!(verdict(&supply)?, blind("power supply 0 Health"));
    Ok(())
}


#[test]
fn oversized_malformed_and_not_object_are_refused() -> TestResult {
    let tiny = RedfishLimits {
        max_bytes: TINY_BYTES,
        max_sensors: SMALL_LIMIT,
    };
    let oversized = run_texts([r#"{"Status": {}, "x": 1}"#, "{}", "{}", "{}"], &tiny);
    assert!(matches!(oversized, Err(SmartError::Document { document: "chassis", .. })));
    let bad = run_texts(["{}", "{", "{}", "{}"], &default_redfish_limits());
    assert!(matches!(bad, Err(SmartError::Document { document: "thermal", .. })));
    let array = run_texts(["{}", "{}", "[]", "{}"], &default_redfish_limits());
    assert!(matches!(array, Err(SmartError::Document { document: "power", .. })));
    let message = array.err().map(|error| error.to_string());
    assert_eq!(message.as_deref(), Some("redfish power document refused"));
    Ok(())
}


#[test]
fn deep_nesting_is_refused() -> TestResult {
    let deep = format!("{}{}", "[".repeat(DEEP_LEVELS), "]".repeat(DEEP_LEVELS));
    let text = format!("{{\"Fans\": {deep}}}");
    let outcome = run_texts(["{}", &text, "{}", "{}"], &default_redfish_limits());
    let refused = matches!(&outcome, Err(SmartError::Document { document: "thermal", source }) if matches!(**source, SmartError::TooDeep { .. }));
    assert!(refused);
    let nested = format!("{{\"Fans\": [{{\"Oem\": {deep}}}]}}");
    assert!(run_texts(["{}", &nested, "{}", "{}"], &default_redfish_limits()).is_err());
    let top_level = format!("{{\"Oem\": {deep}}}");
    assert!(run_texts([&top_level, "{}", "{}", "{}"], &default_redfish_limits()).is_err());
    Ok(())
}


#[test]
fn nesting_depth_ignores_brackets_in_strings() -> TestResult {
    let text = r#"{"a": "[[[[", "b": "\"[[", "c": [1, {"d": 2}]}"#;
    assert_eq!(nesting_depth(text.as_bytes()), DEPTH_THREE);
    assert_eq!(nesting_depth(b"]]]"), 0);
    Ok(())
}


#[test]
fn too_many_sensors_is_refused_whole() -> TestResult {
    let docs = set(base()?, THERMAL_DOC, "/Fans", "[{}, {}, {}]")?;
    let report = run_with(&docs, &limits(SMALL_LIMIT))?;
    assert_eq!(report.refused_collections, ["Fans"]);
    assert!(report.components.iter().all(|item| item.kind != ComponentKind::Fan));
    assert_eq!(assess_redfish(&report), Health::BlindSpot(BlindReason::TooManyAttributes));
    Ok(())
}


#[test]
fn many_empty_objects_are_refused_before_building() -> TestResult {
    let text = format!("{{\"Temperatures\": [{}{{}}]}}", "{},".repeat(EMPTY_OBJECTS));
    let wide = RedfishLimits {
        max_bytes: WIDE_BYTES,
        max_sensors: DEFAULT_SENSORS,
    };
    let report = run_texts(["{}", &text, "{}", "{}"], &wide)?;
    assert_eq!(report.refused_collections, ["Temperatures"]);
    assert!(report.components.iter().all(|item| item.kind != ComponentKind::Temperature));
    Ok(())
}


#[test]
fn wrong_typed_collections_are_blind() -> TestResult {
    let text_collection = set(base()?, THERMAL_DOC, "/Fans", r#""many""#)?;
    assert_eq!(verdict(&text_collection)?, blind("Fans"));
    let null_member = set(base()?, POWER_DOC, "/Voltages", "[null]")?;
    assert_eq!(verdict(&null_member)?, blind("Voltages"));
    let emptied = set(set(base()?, THERMAL_DOC, "", "{}")?, POWER_DOC, "", "{}")?;
    assert_eq!(verdict(&emptied)?, Health::Healthy);
    Ok(())
}


#[test]
fn unreadable_health_on_enabled_fan_is_blind() -> TestResult {
    let long_text = format!("\"{}\"", "x".repeat(LONG_TEXT));
    let bad_values = ["\"ok\"", "null", "5", long_text.as_str(), r#"{"a": 1}"#];
    bad_values.iter().try_for_each(|value| -> TestResult {
        let docs = set(base()?, THERMAL_DOC, "/Fans/0/Status/Health", value)?;
        assert_eq!(verdict(&docs)?, blind("fan 0 Health"));
        Ok(())
    })?;
    let no_health = set(base()?, THERMAL_DOC, "/Fans/0/Status", r#"{"State": "Enabled"}"#)?;
    assert_eq!(verdict(&no_health)?, blind("fan 0 Health"));
    let no_status = set(base()?, THERMAL_DOC, "/Fans/0", r#"{"Name": "Fan1"}"#)?;
    assert_eq!(verdict(&no_status)?, blind("fan 0 Health"));
    let status_text = set(base()?, THERMAL_DOC, "/Fans/0/Status", r#""fine""#)?;
    assert_eq!(verdict(&status_text)?, blind("fan 0 Health"));
    Ok(())
}


#[test]
fn unreadable_state_is_blind() -> TestResult {
    let docs = set(base()?, THERMAL_DOC, "/Fans/0/Status/State", r#""Sleeping""#)?;
    assert_eq!(verdict(&docs)?, blind("fan 0 State"));
    let numeric = set(base()?, THERMAL_DOC, "/Fans/0/Status/State", "5")?;
    assert_eq!(verdict(&numeric)?, blind("fan 0 State"));
    Ok(())
}


#[test]
fn missing_state_counts_as_enabled() -> TestResult {
    let docs = set(base()?, THERMAL_DOC, "/Fans/0/Status", r#"{"Health": "Critical"}"#)?;
    assert_eq!(verdict(&docs)?, Health::Failing);
    Ok(())
}


#[test]
fn absent_and_disabled_components_are_not_blind() -> TestResult {
    let absent = set(base()?, THERMAL_DOC, "/Fans/0/Status", r#"{"Health": "Critical", "State": "Absent"}"#)?;
    assert_eq!(verdict(&absent)?, Health::Healthy);
    let disabled = set(base()?, THERMAL_DOC, "/Fans/0/Status", r#"{"Health": "Critical", "State": "Disabled"}"#)?;
    assert_eq!(verdict(&disabled)?, Health::Healthy);
    let silent = set(base()?, THERMAL_DOC, "/Fans/0/Status", r#"{"State": "StandbySpare"}"#)?;
    assert_eq!(verdict(&silent)?, Health::Healthy);
    let absent_psu = set(
        base()?,
        POWER_DOC,
        "/PowerSupplies/0/Status",
        r#"{"Health": "Critical", "State": "Absent"}"#,
    )?;
    assert_eq!(verdict(&absent_psu)?, Health::Healthy);
    Ok(())
}


#[test]
fn critical_components_fail() -> TestResult {
    let psu = set(base()?, POWER_DOC, "/PowerSupplies/0/Status/Health", r#""Critical""#)?;
    assert_eq!(verdict(&psu)?, Health::Failing);
    let disabled_psu = set(
        base()?,
        POWER_DOC,
        "/PowerSupplies/0/Status",
        r#"{"Health": "Critical", "State": "Disabled"}"#,
    )?;
    assert_eq!(verdict(&disabled_psu)?, Health::Failing);
    let system = set(base()?, SYSTEM_DOC, "/Status/Health", r#""Critical""#)?;
    assert_eq!(verdict(&system)?, Health::Failing);
    let rollup = set(base()?, CHASSIS_DOC, "/Status/HealthRollup", r#""Critical""#)?;
    assert_eq!(verdict(&rollup)?, Health::Failing);
    Ok(())
}


#[test]
fn chassis_rollup_must_be_readable() -> TestResult {
    let missing = set(base()?, CHASSIS_DOC, "/Status", r#"{"State": "Enabled"}"#)?;
    assert_eq!(verdict(&missing)?, blind("chassis HealthRollup"));
    let health_only = set(base()?, CHASSIS_DOC, "/Status", r#"{"Health": "OK", "State": "Enabled"}"#)?;
    assert_eq!(verdict(&health_only)?, Health::Healthy);
    let bad = set(base()?, CHASSIS_DOC, "/Status/HealthRollup", r#""fine""#)?;
    assert_eq!(verdict(&bad)?, blind("chassis HealthRollup"));
    let report = run(&base()?)?;
    assert_eq!(report.chassis_rollup, Reading::Found(RedfishHealth::Ok));
    Ok(())
}


#[test]
fn warnings_and_offline_states_degrade() -> TestResult {
    let warn = set(base()?, THERMAL_DOC, "/Fans/0/Status/Health", r#""Warning""#)?;
    assert_eq!(verdict(&warn)?, degraded("fan 0 warning"));
    let offline = set(base()?, THERMAL_DOC, "/Fans/0/Status/State", r#""UnavailableOffline""#)?;
    assert_eq!(verdict(&offline)?, degraded("fan 0 unavailable"));
    let disabled = set(base()?, POWER_DOC, "/PowerSupplies/0/Status/State", r#""Disabled""#)?;
    assert_eq!(verdict(&disabled)?, degraded("power supply 0 disabled"));
    let rollup = set(base()?, CHASSIS_DOC, "/Status/HealthRollup", r#""Warning""#)?;
    assert_eq!(verdict(&rollup)?, degraded("chassis health rollup warning"));
    Ok(())
}


#[test]
fn hot_temperature_degrades() -> TestResult {
    let hot = set(base()?, THERMAL_DOC, "/Temperatures/0/ReadingCelsius", "90")?;
    assert_eq!(verdict(&hot)?, degraded("temperature 0 at critical threshold"));
    let cool = set(base()?, THERMAL_DOC, "/Temperatures/0/ReadingCelsius", "89.5")?;
    assert_eq!(verdict(&cool)?, Health::Healthy);
    Ok(())
}


#[test]
fn unreadable_readings_are_blind_only_with_a_threshold() -> TestResult {
    let bad_readings = [r#""NaN""#, r#""hot""#, "null", r#"{"x": 1}"#];
    bad_readings.iter().try_for_each(|value| -> TestResult {
        let docs = set(base()?, THERMAL_DOC, "/Temperatures/0/ReadingCelsius", value)?;
        assert_eq!(verdict(&docs)?, blind("temperature 0 Reading"));
        Ok(())
    })?;
    let overflow = THERMAL_JSON.replace("\"ReadingCelsius\": 40", "\"ReadingCelsius\": 1e400");
    let report = run_texts([CHASSIS_JSON, &overflow, POWER_JSON, SYSTEM_JSON], &default_redfish_limits())?;
    assert_eq!(assess_redfish(&report), blind("temperature 0 Reading"));
    let bad_threshold = set(base()?, THERMAL_DOC, "/Temperatures/0/UpperThresholdCritical", r#""high""#)?;
    assert_eq!(verdict(&bad_threshold)?, blind("temperature 0 Reading"));
    let no_threshold = set(
        base()?,
        THERMAL_DOC,
        "/Temperatures/0",
        r#"{"ReadingCelsius": "NaN", "Status": {"Health": "OK", "State": "Enabled"}}"#,
    )?;
    assert_eq!(verdict(&no_threshold)?, Health::Healthy);
    let disabled = set(base()?, THERMAL_DOC, "/Temperatures/0/Status/State", r#""Disabled""#)?;
    let off_blind = set(disabled, THERMAL_DOC, "/Temperatures/0/UpperThresholdCritical", r#""high""#)?;
    assert_eq!(verdict(&off_blind)?, Health::Healthy);
    Ok(())
}


#[test]
fn names_are_checked() -> TestResult {
    let numeric = set(base()?, THERMAL_DOC, "/Fans/0/Name", "5")?;
    assert!(run(&numeric)?.components.iter().all(|item| item.name != Some("5".to_string())));
    let long = set(base()?, THERMAL_DOC, "/Fans/0/Name", &format!("\"{}\"", "n".repeat(LONG_TEXT)))?;
    let report = run(&long)?;
    assert!(report
        .components
        .iter()
        .all(|item| item.name.as_ref().is_none_or(|name| name.len() < NAME_BOUND)));
    Ok(())
}
