//! Redfish health verdict and measures, pure.

use crate::grammar::is_clean_ident;
use crate::model::{BlindReason, Component, ComponentKind, Health, Measure, Reading, RedfishHealth, RedfishReport, RedfishState};


pub fn kind_name(kind: ComponentKind) -> &'static str {
    match kind {
        ComponentKind::Chassis => "chassis",
        ComponentKind::System => "system",
        ComponentKind::Temperature => "temperature",
        ComponentKind::Fan => "fan",
        ComponentKind::PowerSupply => "power_supply",
        ComponentKind::Voltage => "voltage",
    }
}


fn label(item: &Component) -> String {
    format!("{} {}", kind_name(item.kind).replace('_', " "), item.index)
}


fn is_absent(item: &Component) -> bool {
    item.state == Reading::Found(RedfishState::Absent)
}


fn is_enabled(item: &Component) -> bool {
    !matches!(item.state, Reading::Found(state) if state != RedfishState::Enabled)
}


fn threshold_blind(item: &Component) -> bool {
    let reading_found = matches!(item.reading, Reading::Found(_));
    item.upper_critical != Reading::Missing && (item.upper_critical == Reading::Unreadable || !reading_found)
}


fn component_blind(item: &Component) -> Option<String> {
    let enabled = is_enabled(item);
    [
        (enabled && !matches!(item.health, Reading::Found(_)), "Health"),
        (item.state == Reading::Unreadable, "State"),
        (enabled && threshold_blind(item), "Reading"),
    ]
    .iter()
    .find(|(blind, _)| *blind)
    .map(|(_, field)| format!("{} {field}", label(item)))
}


fn blind_spot(report: &RedfishReport) -> Option<BlindReason> {
    let missing = report.missing_documents.first().map(|name| format!("{name} document"));
    let unreadable = report.unreadable.first().map(|name| (*name).to_string());
    let rollup = (!matches!(report.chassis_rollup, Reading::Found(_))).then(|| "chassis HealthRollup".to_string());
    let field = missing
        .or(unreadable)
        .or(rollup)
        .or_else(|| report.components.iter().find_map(component_blind));
    match (report.refused_collections.is_empty(), field) {
        (false, _) => Some(BlindReason::TooManyAttributes),
        (true, found) => found.map(BlindReason::UnreadableHealthField),
    }
}


fn is_failing(report: &RedfishReport) -> bool {
    let rollup_critical = report.chassis_rollup == Reading::Found(RedfishHealth::Critical);
    let component_critical = report.components.iter().any(|item| {
        let counts = is_enabled(item) || (item.kind == ComponentKind::PowerSupply && !is_absent(item));
        counts && item.health == Reading::Found(RedfishHealth::Critical)
    });
    rollup_critical || component_critical
}


fn degraded_causes(report: &RedfishReport) -> Vec<String> {
    let rollup = (report.chassis_rollup == Reading::Found(RedfishHealth::Warning)).then(|| "chassis health rollup warning".to_string());
    let reasons = report.components.iter().filter(|item| !is_absent(item)).flat_map(|item| {
        let hot = matches!((item.reading, item.upper_critical), (Reading::Found(now), Reading::Found(limit)) if now >= limit);
        [
            (item.health == Reading::Found(RedfishHealth::Warning), "warning"),
            (item.state == Reading::Found(RedfishState::UnavailableOffline), "unavailable"),
            (
                item.kind == ComponentKind::PowerSupply && item.state == Reading::Found(RedfishState::Disabled),
                "disabled",
            ),
            (hot, "at critical threshold"),
        ]
        .into_iter()
        .filter(|(present, _)| *present)
        .map(|(_, cause)| format!("{} {cause}", label(item)))
        .collect::<Vec<String>>()
    });
    rollup.into_iter().chain(reasons).collect()
}


pub fn assess_redfish(report: &RedfishReport) -> Health {
    let causes = degraded_causes(report);
    match blind_spot(report) {
        Some(reason) => Health::BlindSpot(reason),
        None if is_failing(report) => Health::Failing,
        None if causes.is_empty() => Health::Healthy,
        None => Health::Degraded(causes),
    }
}


pub fn redfish_measures(report: &RedfishReport, device_name: &str) -> Vec<Measure> {
    report
        .components
        .iter()
        .filter_map(|item| {
            let value = match item.reading {
                Reading::Found(found) => Some(found),
                Reading::Unreadable | Reading::Missing => None,
            };
            value.map(|found| Measure {
                name: format!("hw.redfish.{}", kind_name(item.kind)),
                unit: item.unit.to_string(),
                value: found,
                labels: [("device", Some(device_name)), ("sensor", item.name.as_deref())]
                    .iter()
                    .filter_map(|(key, text)| {
                        text.filter(|content| is_clean_ident(content))
                            .map(|content| ((*key).to_string(), content.to_string()))
                    })
                    .collect(),
            })
        })
        .collect()
}
