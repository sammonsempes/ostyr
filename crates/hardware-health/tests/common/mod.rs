use hardware_health::error::SmartError;
use hardware_health::limits::default_limits;
use hardware_health::model::SmartReport;
use hardware_health::parse::parse_smartctl;
use serde_json::Value;


mod types;


pub use types::TestResult;


pub fn report_from(document: &Value) -> Result<SmartReport, SmartError> {
    parse_smartctl(serde_json::to_vec(document)?.as_slice(), &default_limits())
}


pub fn fixture(text: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(text)
}


pub fn set(mut document: Value, pointer: &str, value: Value) -> Result<Value, String> {
    let slot = document.pointer_mut(pointer).ok_or_else(|| format!("no such path {pointer}"))?;
    *slot = value;
    Ok(document)
}
