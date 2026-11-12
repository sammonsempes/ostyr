//! Health verdict, pure.

use crate::model::{Attribute, BlindReason, Health, NvmeHealth, SmartReport, WhenFailed};


pub const UNREADABLE_EXIT_BITS: u8 = 0b111;


pub const WEAR_LIMIT_PERCENT: u64 = 100;


pub fn assess(report: &SmartReport) -> Health {
    let causes = predictive_causes(report);
    match (report.exit_status, report.smart_passed) {
        (None, _) => Health::BlindSpot(BlindReason::ExitStatusMissing),
        (Some(status), _) if status & UNREADABLE_EXIT_BITS != 0 => Health::BlindSpot(BlindReason::CommandFailed(status)),
        (_, None) => Health::BlindSpot(BlindReason::NoVerdict),
        (_, Some(false)) => Health::Failing,
        _ if causes.is_empty() => Health::Healthy,
        _ => Health::PredictiveFailure(causes),
    }
}


fn attribute_cause(attribute: &Attribute) -> Option<String> {
    let failing = attribute.prefailure == Some(true) && attribute.when_failed == Some(WhenFailed::Now);
    failing.then(|| format!("attribute {} {}", attribute.id, attribute.name.as_deref().unwrap_or("unnamed")))
}


fn nvme_causes(health: &NvmeHealth) -> Vec<String> {
    let warning = health.critical_warning.is_some_and(|flags| flags != 0);
    let worn = health.percentage_used.is_some_and(|used| used >= WEAR_LIMIT_PERCENT);
    let spare_low = matches!((health.available_spare, health.available_spare_threshold), (Some(spare), Some(threshold)) if spare < threshold);
    [
        (warning, "nvme critical_warning"),
        (worn, "nvme percentage_used"),
        (spare_low, "nvme available_spare"),
    ]
    .iter()
    .filter(|(raised, _)| *raised)
    .map(|(_, cause)| (*cause).to_string())
    .collect()
}


fn predictive_causes(report: &SmartReport) -> Vec<String> {
    let nvme = report.nvme.as_ref().map_or_else(Vec::new, nvme_causes);
    report.attributes.iter().filter_map(attribute_cause).chain(nvme).collect()
}
