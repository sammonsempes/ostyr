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


fn is_disabled(item: &Component) -> bool {
    item.state == Reading::Found(RedfishState::Disabled)
}


pub fn state_name(state: RedfishState) -> &'static str {
    match state {
        RedfishState::Enabled => "enabled",
        RedfishState::Disabled => "disabled",
        RedfishState::StandbyOffline => "standby_offline",
        RedfishState::StandbySpare => "standby_spare",
        RedfishState::InTest => "in_test",
        RedfishState::Starting => "starting",
        RedfishState::Absent => "absent",
        RedfishState::UnavailableOffline => "unavailable_offline",
        RedfishState::Deferring => "deferring",
        RedfishState::Quiesced => "quiesced",
        RedfishState::Updating => "updating",
        RedfishState::Qualified => "qualified",
        RedfishState::Degraded => "degraded",
    }
}


fn critical_is_failing(item: &Component) -> bool {
    match item.state {
        Reading::Found(state) => matches!(state, RedfishState::Enabled | RedfishState::Degraded | RedfishState::UnavailableOffline),
        Reading::Missing | Reading::Unreadable => false,
    }
}


fn threshold_blind(item: &Component) -> bool {
    let reading_found = matches!(item.reading, Reading::Found(_));
    item.upper_critical != Reading::Missing && (item.upper_critical == Reading::Unreadable || !reading_found)
}


fn component_blind(item: &Component) -> Option<String> {
    let live = !is_absent(item);
    let judged = live && !is_disabled(item);
    [
        (judged && !matches!(item.health, Reading::Found(_)), "Health"),
        (live && !matches!(item.state, Reading::Found(_)), "State"),
        (judged && threshold_blind(item), "Reading"),
    ]
    .iter()
    .find(|(blind, _)| *blind)
    .map(|(_, field)| format!("{} {field}", label(item)))
}


fn blind_spot(report: &RedfishReport) -> Option<BlindReason> {
    let missing = report.missing_documents.first().map(|name| format!("{name} document"));
    let unreadable = report.unreadable.first().map(|name| (*name).to_string());
    let system = (!matches!(report.system_rollup, Reading::Found(_))).then(|| "system HealthRollup".to_string());
    let rollup = (!matches!(report.chassis_rollup, Reading::Found(_))).then(|| "chassis HealthRollup".to_string());
    let field = missing
        .or(unreadable)
        .or(system)
        .or(rollup)
        .or_else(|| report.components.iter().find_map(component_blind));
    match (report.refused_collections.is_empty(), field) {
        (false, _) => Some(BlindReason::TooManyAttributes),
        (true, found) => found.map(BlindReason::UnreadableHealthField),
    }
}


fn is_failing(report: &RedfishReport) -> bool {
    let rollup_critical = [report.chassis_rollup, report.system_rollup].contains(&Reading::Found(RedfishHealth::Critical));
    let component_critical = report.components.iter().filter(|item| !is_absent(item)).any(|item| {
        let counts = critical_is_failing(item) || item.kind == ComponentKind::PowerSupply;
        counts && item.health == Reading::Found(RedfishHealth::Critical)
    });
    rollup_critical || component_critical
}


fn critical_cause(item: &Component) -> String {
    let state = match item.state {
        Reading::Found(found) => state_name(found),
        Reading::Unreadable | Reading::Missing => "unknown",
    };
    format!("{} critical while {state}", label(item))
}


fn component_causes(item: &Component) -> Vec<String> {
    let hot = matches!((item.reading, item.upper_critical), (Reading::Found(now), Reading::Found(limit)) if now >= limit);
    let critical = item.health == Reading::Found(RedfishHealth::Critical) && !critical_is_failing(item);
    let simple = [
        (item.health == Reading::Found(RedfishHealth::Warning), "warning"),
        (item.state == Reading::Found(RedfishState::Degraded), "degraded"),
        (item.state == Reading::Found(RedfishState::UnavailableOffline), "unavailable"),
        (item.kind == ComponentKind::PowerSupply && is_disabled(item), "disabled"),
        (hot, "at critical threshold"),
    ];
    critical
        .then(|| critical_cause(item))
        .into_iter()
        .chain(
            simple
                .into_iter()
                .filter(|(present, _)| *present)
                .map(|(_, cause)| format!("{} {cause}", label(item))),
        )
        .collect()
}


fn warns_itself(report: &RedfishReport, kind: ComponentKind) -> bool {
    report
        .components
        .iter()
        .any(|item| item.kind == kind && !is_absent(item) && item.health == Reading::Found(RedfishHealth::Warning))
}


fn degraded_causes(report: &RedfishReport) -> Vec<String> {
    let rollups = [
        ("system", report.system_rollup, ComponentKind::System),
        ("chassis", report.chassis_rollup, ComponentKind::Chassis),
    ]
    .into_iter()
    .filter(|(_, rollup, kind)| *rollup == Reading::Found(RedfishHealth::Warning) && !warns_itself(report, *kind))
    .map(|(name, _, _)| format!("{name} health rollup warning"));
    let reasons = report.components.iter().filter(|item| !is_absent(item)).flat_map(component_causes);
    rollups.chain(reasons).collect()
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
