//! Bounded, strict parse of the Redfish chassis, thermal, power and system documents.

use crate::error::SmartError;
use crate::grammar::is_clean_ident;
use crate::limits::{MAX_NESTING_DEPTH, MAX_SCALAR_BYTES};
use crate::model::{Component, ComponentKind, Reading, RedfishHealth, RedfishLimits, RedfishReport, RedfishState};
use crate::parse::read_bounded;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::io::Read;


const NO_THERMAL_ARRAYS: &str = "Temperatures or Fans";


const NO_SUPPLY_ARRAY: &str = "PowerSupplies";


const UNIT_NONE: &str = "1";


const UNIT_CELSIUS: &str = "Cel";


const UNIT_RPM: &str = "{rpm}";


const UNIT_PERCENT: &str = "%";


const UNIT_WATT: &str = "W";


const UNIT_VOLT: &str = "V";


const PERCENT_UNITS: &str = "Percent";


#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Top<'a> {
    #[serde(borrow)]
    status: Option<&'a RawValue>,
    #[serde(borrow)]
    temperatures: Option<&'a RawValue>,
    #[serde(borrow)]
    fans: Option<&'a RawValue>,
    #[serde(borrow)]
    power_supplies: Option<&'a RawValue>,
    #[serde(borrow)]
    voltages: Option<&'a RawValue>,
}


#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Member<'a> {
    #[serde(borrow)]
    name: Option<&'a RawValue>,
    #[serde(borrow)]
    fan_name: Option<&'a RawValue>,
    #[serde(borrow)]
    status: Option<&'a RawValue>,
    #[serde(borrow)]
    reading_celsius: Option<&'a RawValue>,
    #[serde(borrow)]
    reading: Option<&'a RawValue>,
    #[serde(borrow)]
    reading_units: Option<&'a RawValue>,
    #[serde(borrow)]
    last_power_output_watts: Option<&'a RawValue>,
    #[serde(borrow)]
    power_output_watts: Option<&'a RawValue>,
    #[serde(borrow)]
    reading_volts: Option<&'a RawValue>,
    #[serde(borrow)]
    upper_threshold_critical: Option<&'a RawValue>,
}


#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StatusDocument<'a> {
    #[serde(borrow)]
    health: Option<&'a RawValue>,
    #[serde(borrow)]
    health_rollup: Option<&'a RawValue>,
    #[serde(borrow)]
    state: Option<&'a RawValue>,
}


struct StatusReading {
    health: Reading<RedfishHealth>,
    state: Reading<RedfishState>,
    rollup: Reading<RedfishHealth>,
}


enum Scalar {
    Text(String),
    Number(f64),
    Bad,
}


enum Collection<'a> {
    Absent,
    Refused,
    Unreadable,
    Members(Vec<Member<'a>>),
}


struct Spec {
    name: &'static str,
    kind: ComponentKind,
    unit: fn(&Member) -> &'static str,
    reading: fn(&Member) -> Reading<f64>,
    upper: fn(&Member) -> Reading<f64>,
}


fn scalar(raw: &RawValue) -> Scalar {
    let text = raw.get();
    if text.len() > MAX_SCALAR_BYTES {
        Scalar::Bad
    } else {
        match serde_json::from_str::<String>(text) {
            Ok(content) => Scalar::Text(content),
            Err(_) => serde_json::from_str::<f64>(text).map_or(Scalar::Bad, Scalar::Number),
        }
    }
}


fn reading_of<Value>(raw: Option<&RawValue>, convert: fn(Scalar) -> Option<Value>) -> Reading<Value> {
    match raw {
        None => Reading::Missing,
        Some(found) => convert(scalar(found)).map_or(Reading::Unreadable, Reading::Found),
    }
}


fn health_of(item: Scalar) -> Option<RedfishHealth> {
    match item {
        Scalar::Text(label) => match label.as_str() {
            "OK" => Some(RedfishHealth::Ok),
            "Warning" => Some(RedfishHealth::Warning),
            "Critical" => Some(RedfishHealth::Critical),
            _ => None,
        },
        Scalar::Number(_) | Scalar::Bad => None,
    }
}


fn state_of(item: Scalar) -> Option<RedfishState> {
    const STATES: [(&str, RedfishState); 13] = [
        ("Enabled", RedfishState::Enabled),
        ("Disabled", RedfishState::Disabled),
        ("StandbyOffline", RedfishState::StandbyOffline),
        ("StandbySpare", RedfishState::StandbySpare),
        ("InTest", RedfishState::InTest),
        ("Starting", RedfishState::Starting),
        ("Absent", RedfishState::Absent),
        ("UnavailableOffline", RedfishState::UnavailableOffline),
        ("Deferring", RedfishState::Deferring),
        ("Quiesced", RedfishState::Quiesced),
        ("Updating", RedfishState::Updating),
        ("Qualified", RedfishState::Qualified),
        ("Degraded", RedfishState::Degraded),
    ];
    match item {
        Scalar::Text(label) => STATES.iter().find(|(known, _)| *known == label).map(|(_, state)| *state),
        Scalar::Number(_) | Scalar::Bad => None,
    }
}


fn number_of(item: Scalar) -> Option<f64> {
    match item {
        Scalar::Number(value) => Some(value),
        Scalar::Text(_) | Scalar::Bad => None,
    }
}


fn number(raw: Option<&RawValue>) -> Reading<f64> {
    reading_of(raw, number_of)
}


fn name_of(raw: Option<&RawValue>) -> Option<String> {
    match raw.map(scalar) {
        Some(Scalar::Text(label)) if is_clean_ident(&label) => Some(label),
        _ => None,
    }
}


fn status(raw: Option<&RawValue>) -> StatusReading {
    match raw.map(|found| serde_json::from_str::<StatusDocument>(found.get())) {
        None => StatusReading {
            health: Reading::Missing,
            state: Reading::Missing,
            rollup: Reading::Missing,
        },
        Some(Ok(document)) => StatusReading {
            health: reading_of(document.health, health_of),
            state: reading_of(document.state, state_of),
            rollup: reading_of(document.health_rollup, health_of),
        },
        Some(Err(_)) => StatusReading {
            health: Reading::Unreadable,
            state: Reading::Unreadable,
            rollup: Reading::Unreadable,
        },
    }
}


fn collection<'a>(raw: Option<&'a RawValue>, max_sensors: usize) -> Collection<'a> {
    match raw {
        None => Collection::Absent,
        Some(found) => match serde_json::from_str::<Vec<IgnoredAny>>(found.get()) {
            Err(_) => Collection::Unreadable,
            Ok(items) if items.len() > max_sensors => Collection::Refused,
            Ok(_) => serde_json::from_str::<Vec<Member>>(found.get()).map_or(Collection::Unreadable, Collection::Members),
        },
    }
}


fn temperature_unit(_member: &Member) -> &'static str {
    UNIT_CELSIUS
}


fn temperature_reading(member: &Member) -> Reading<f64> {
    number(member.reading_celsius)
}


fn temperature_upper(member: &Member) -> Reading<f64> {
    number(member.upper_threshold_critical)
}


fn fan_unit(member: &Member) -> &'static str {
    match member.reading_units.map(scalar) {
        Some(Scalar::Text(label)) if label == PERCENT_UNITS => UNIT_PERCENT,
        _ => UNIT_RPM,
    }
}


fn fan_reading(member: &Member) -> Reading<f64> {
    number(member.reading)
}


fn supply_unit(_member: &Member) -> &'static str {
    UNIT_WATT
}


fn supply_reading(member: &Member) -> Reading<f64> {
    number(member.last_power_output_watts.or(member.power_output_watts))
}


fn voltage_unit(_member: &Member) -> &'static str {
    UNIT_VOLT
}


fn voltage_reading(member: &Member) -> Reading<f64> {
    number(member.reading_volts)
}


fn no_threshold(_member: &Member) -> Reading<f64> {
    Reading::Missing
}


const TEMPERATURES: Spec = Spec {
    name: "Temperatures",
    kind: ComponentKind::Temperature,
    unit: temperature_unit,
    reading: temperature_reading,
    upper: temperature_upper,
};


const FANS: Spec = Spec {
    name: "Fans",
    kind: ComponentKind::Fan,
    unit: fan_unit,
    reading: fan_reading,
    upper: no_threshold,
};


const SUPPLIES: Spec = Spec {
    name: "PowerSupplies",
    kind: ComponentKind::PowerSupply,
    unit: supply_unit,
    reading: supply_reading,
    upper: no_threshold,
};


const VOLTAGES: Spec = Spec {
    name: "Voltages",
    kind: ComponentKind::Voltage,
    unit: voltage_unit,
    reading: voltage_reading,
    upper: no_threshold,
};


fn component(spec: &Spec, index: usize, member: &Member) -> Component {
    let reported = status(member.status);
    Component {
        kind: spec.kind,
        index,
        name: name_of(member.name.or(member.fan_name)),
        health: reported.health,
        state: reported.state,
        reading: (spec.reading)(member),
        upper_critical: (spec.upper)(member),
        unit: (spec.unit)(member),
    }
}


fn add_collection(report: &mut RedfishReport, raw: Option<&RawValue>, spec: &Spec, max_sensors: usize) {
    match collection(raw, max_sensors) {
        Collection::Absent => {}
        Collection::Refused => report.refused_collections.push(spec.name),
        Collection::Unreadable => report.unreadable.push(spec.name),
        Collection::Members(members) => report
            .components
            .extend(members.iter().enumerate().map(|(index, member)| component(spec, index, member))),
    }
}


#[derive(Clone, Copy)]
struct Scan {
    depth: usize,
    deepest: usize,
    in_string: bool,
    escaped: bool,
}


fn step(scan: Scan, byte: u8) -> Scan {
    match (scan.in_string, scan.escaped, byte) {
        (true, true, _) => Scan { escaped: false, ..scan },
        (true, false, b'\\') => Scan { escaped: true, ..scan },
        (true, false, b'"') => Scan { in_string: false, ..scan },
        (true, false, _) => scan,
        (false, _, b'"') => Scan { in_string: true, ..scan },
        (false, _, b'[' | b'{') => Scan {
            depth: scan.depth + 1,
            deepest: scan.deepest.max(scan.depth + 1),
            ..scan
        },
        (false, _, b']' | b'}') => Scan {
            depth: scan.depth.saturating_sub(1),
            ..scan
        },
        (false, _, _) => scan,
    }
}


pub fn nesting_depth(bytes: &[u8]) -> usize {
    let start = Scan {
        depth: 0,
        deepest: 0,
        in_string: false,
        escaped: false,
    };
    bytes.iter().fold(start, |scan, byte| step(scan, *byte)).deepest
}


fn read_checked(source: &mut dyn Read, max_bytes: u64) -> Result<Vec<u8>, SmartError> {
    let bytes = read_bounded(source, max_bytes)?;
    if nesting_depth(&bytes) > MAX_NESTING_DEPTH {
        Err(SmartError::TooDeep { limit: MAX_NESTING_DEPTH })
    } else {
        Ok(bytes)
    }
}


fn load(document: &'static str, reader: Option<&mut dyn Read>, max_bytes: u64) -> Result<Option<Vec<u8>>, SmartError> {
    reader
        .map(|source| read_checked(source, max_bytes))
        .transpose()
        .map_err(|source| SmartError::Document {
            document,
            source: Box::new(source),
        })
}


fn top<'a>(document: &'static str, bytes: &'a [u8]) -> Result<Top<'a>, SmartError> {
    serde_json::from_slice(bytes).map_err(|source| SmartError::Document {
        document,
        source: Box::new(SmartError::from(source)),
    })
}


fn parsed<'a>(document: &'static str, bytes: &'a Option<Vec<u8>>, missing: &mut Vec<&'static str>) -> Result<Option<Top<'a>>, SmartError> {
    if bytes.is_none() {
        missing.push(document);
    }
    bytes.as_ref().map(|content| top(document, content)).transpose()
}


fn chassis_rollup(reported: StatusReading) -> Reading<RedfishHealth> {
    match reported.rollup {
        Reading::Missing => reported.health,
        Reading::Found(_) | Reading::Unreadable => reported.rollup,
    }
}


fn add_status(report: &mut RedfishReport, kind: ComponentKind, raw: Option<&RawValue>) {
    let reported = status(raw);
    report.components.push(Component {
        kind,
        index: 0,
        name: None,
        health: reported.health,
        state: reported.state,
        reading: Reading::Missing,
        upper_critical: Reading::Missing,
        unit: UNIT_NONE,
    });
}


pub fn parse_redfish(
    chassis: Option<&mut dyn Read>,
    thermal: Option<&mut dyn Read>,
    power: Option<&mut dyn Read>,
    system: Option<&mut dyn Read>,
    limits: &RedfishLimits,
) -> Result<RedfishReport, SmartError> {
    let chassis_bytes = load("chassis", chassis, limits.max_bytes)?;
    let thermal_bytes = load("thermal", thermal, limits.max_bytes)?;
    let power_bytes = load("power", power, limits.max_bytes)?;
    let system_bytes = load("system", system, limits.max_bytes)?;
    let mut report = RedfishReport {
        components: Vec::new(),
        chassis_rollup: Reading::Missing,
        system_rollup: Reading::Missing,
        missing_documents: Vec::new(),
        refused_collections: Vec::new(),
        unreadable: Vec::new(),
    };
    let chassis_top = parsed("chassis", &chassis_bytes, &mut report.missing_documents)?;
    let thermal_top = parsed("thermal", &thermal_bytes, &mut report.missing_documents)?;
    let power_top = parsed("power", &power_bytes, &mut report.missing_documents)?;
    let system_top = parsed("system", &system_bytes, &mut report.missing_documents)?;
    if let Some(found) = chassis_top {
        report.chassis_rollup = chassis_rollup(status(found.status));
        add_status(&mut report, ComponentKind::Chassis, found.status);
    }
    if let Some(found) = system_top {
        report.system_rollup = status(found.status).rollup;
        add_status(&mut report, ComponentKind::System, found.status);
    }
    if let Some(found) = thermal_top {
        if found.temperatures.is_none() && found.fans.is_none() {
            report.unreadable.push(NO_THERMAL_ARRAYS);
        }
        add_collection(&mut report, found.temperatures, &TEMPERATURES, limits.max_sensors);
        add_collection(&mut report, found.fans, &FANS, limits.max_sensors);
    }
    if let Some(found) = power_top {
        if found.power_supplies.is_none() {
            report.unreadable.push(NO_SUPPLY_ARRAY);
        }
        add_collection(&mut report, found.power_supplies, &SUPPLIES, limits.max_sensors);
        add_collection(&mut report, found.voltages, &VOLTAGES, limits.max_sensors);
    }
    Ok(report)
}
