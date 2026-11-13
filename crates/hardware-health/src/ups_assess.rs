//! UPS health verdict and measures, pure.

use crate::grammar::is_clean_ident;
use crate::model::{BlindReason, Health, Measure, UpsFlag, UpsReport, UpsThresholds};
use std::collections::BTreeSet;


pub fn assess_ups(report: &UpsReport, thresholds: &UpsThresholds) -> Health {
    let flags = match &report.status {
        Some(found) => found.clone(),
        None => BTreeSet::new(),
    };
    let on_battery = flags.contains(&UpsFlag::OnBattery);
    let blind_charge = on_battery && report.unreadable.iter().any(|name| name == "battery.charge");
    let status_unreadable = report.unreadable.iter().any(|name| name == "ups.status");
    let causes = degraded_causes(report, &flags, thresholds);
    match () {
        _ if status_unreadable => Health::BlindSpot(BlindReason::UnreadableHealthField("ups.status".to_string())),
        _ if flags.is_empty() => Health::BlindSpot(BlindReason::NoVerdict),
        _ if blind_charge => Health::BlindSpot(BlindReason::UnreadableHealthField("battery.charge".to_string())),
        _ if is_failing(&flags) => Health::Failing,
        _ if causes.is_empty() => Health::Healthy,
        _ => Health::Degraded(causes),
    }
}


fn is_failing(flags: &BTreeSet<UpsFlag>) -> bool {
    let dead_battery = flags.contains(&UpsFlag::OnBattery) && flags.contains(&UpsFlag::LowBattery);
    dead_battery || flags.contains(&UpsFlag::ForcedShutdown) || flags.contains(&UpsFlag::Off) || flags.contains(&UpsFlag::Overload)
}


fn degraded_causes(report: &UpsReport, flags: &BTreeSet<UpsFlag>, thresholds: &UpsThresholds) -> Vec<String> {
    let charge_low = report
        .battery_charge
        .is_some_and(|charge| charge < f64::from(thresholds.min_battery_charge));
    let runtime_low = report
        .battery_runtime
        .is_some_and(|seconds| seconds < f64::from(thresholds.min_runtime_seconds));
    let no_line = !flags.contains(&UpsFlag::Online) && !flags.contains(&UpsFlag::OnBattery);
    [
        (flags.contains(&UpsFlag::OnBattery), "on battery"),
        (flags.contains(&UpsFlag::ReplaceBattery), "replace battery"),
        (flags.contains(&UpsFlag::Alarm), "alarm"),
        (charge_low, "battery charge below threshold"),
        (runtime_low, "battery runtime below threshold"),
        (flags.contains(&UpsFlag::Bypass), "bypass"),
        (no_line, "line status unknown"),
    ]
    .iter()
    .filter(|(present, _)| *present)
    .map(|(_, cause)| (*cause).to_string())
    .collect()
}


pub fn ups_measures(report: &UpsReport, ups_name: &str) -> Vec<Measure> {
    let labels: Vec<(String, String)> = Some(ups_name)
        .filter(|name| is_clean_ident(name))
        .map(|name| ("ups".to_string(), name.to_string()))
        .into_iter()
        .collect();
    [
        ("hw.ups.battery_charge", "%", report.battery_charge),
        ("hw.ups.battery_runtime", "s", report.battery_runtime),
        ("hw.ups.input_voltage", "V", report.input_voltage),
        ("hw.ups.output_voltage", "V", report.output_voltage),
        ("hw.ups.load", "%", report.load),
        ("hw.ups.temperature", "Cel", report.temperature),
    ]
    .iter()
    .filter_map(|(name, unit, value)| {
        value.map(|found| Measure {
            name: (*name).to_string(),
            unit: (*unit).to_string(),
            value: found,
            labels: labels.clone(),
        })
    })
    .collect()
}
