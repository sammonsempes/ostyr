//! Measures for the metrics pipeline.

use crate::grammar::is_clean_ident;
use crate::model::{Measure, SmartReport};


fn measure(name: &str, unit: &str, value: f64, labels: Vec<(String, String)>) -> Measure {
    Measure {
        name: name.to_string(),
        unit: unit.to_string(),
        value,
        labels,
    }
}


pub fn measures(report: &SmartReport) -> Vec<Measure> {
    let nvme = report.nvme.as_ref();
    let plain = [
        ("hw.disk.temperature", "Cel", report.temperature_celsius.map(|degrees| degrees as f64)),
        ("hw.disk.power_on_hours", "h", report.power_on_hours.map(|hours| hours as f64)),
        (
            "hw.disk.percentage_used",
            "%",
            nvme.and_then(|health| health.percentage_used).map(|used| used as f64),
        ),
        (
            "hw.disk.media_errors",
            "{error}",
            nvme.and_then(|health| health.media_errors).map(|errors| errors as f64),
        ),
    ];
    let attributes = report.attributes.iter().filter_map(|attribute| {
        attribute.raw_value.map(|raw| {
            let labels = [
                Some(("id".to_string(), attribute.id.to_string())),
                attribute.name.as_ref().map(|name| ("name".to_string(), name.clone())),
            ];
            let checked = labels.into_iter().flatten().filter(|(_, label)| is_clean_ident(label)).collect();
            measure("hw.disk.smart_attribute", "1", raw as f64, checked)
        })
    });
    plain
        .iter()
        .filter_map(|(name, unit, value)| value.map(|found| measure(name, unit, found, Vec::new())))
        .chain(attributes)
        .collect()
}
