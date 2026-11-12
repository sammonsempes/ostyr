//! Health verdict, pure.

use crate::model::{Attribute, BlindReason, Health, NvmeHealth, SmartReport, WhenFailed};


pub const UNREADABLE_EXIT_BITS: u8 = 0b111;


pub const DISK_FAILING_BIT: u8 = 0b1000;


pub const PREFAIL_BELOW_THRESHOLD_BIT: u8 = 0b1_0000;


pub const OLD_AGE_BIT: u8 = 0b10_0000;


pub const ERROR_LOG_BIT: u8 = 0b100_0000;


pub const SELF_TEST_LOG_BIT: u8 = 0b1000_0000;


pub const SUPPORTED_FORMAT_MAJOR: u64 = 1;


pub const WEAR_LIMIT_PERCENT: u64 = 100;


pub fn assess(report: &SmartReport) -> Health {
    let causes = predictive_causes(report);
    let degraded = degraded_causes(report);
    match (report.exit_status, report.smart_passed, report.unreadable_health.first()) {
        _ if report.format_major != Some(SUPPORTED_FORMAT_MAJOR) => Health::BlindSpot(BlindReason::UnknownFormat),
        (None, _, _) => Health::BlindSpot(BlindReason::ExitStatusMissing),
        (Some(status), _, _) if status & UNREADABLE_EXIT_BITS != 0 => Health::BlindSpot(BlindReason::CommandFailed(status)),
        (Some(status), _, _) if status & DISK_FAILING_BIT != 0 => Health::Failing,
        (_, Some(false), _) => Health::Failing,
        (_, _, Some(name)) => Health::BlindSpot(BlindReason::UnreadableHealthField(name.clone())),
        _ if report.omitted_attributes > 0 => Health::BlindSpot(BlindReason::TooManyAttributes),
        (_, None, _) => Health::BlindSpot(BlindReason::NoVerdict),
        _ if !causes.is_empty() => Health::PredictiveFailure(causes),
        _ if degraded.is_empty() => Health::Healthy,
        _ => Health::Degraded(degraded),
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
    let exit_bit = report
        .exit_status
        .is_some_and(|status| status & PREFAIL_BELOW_THRESHOLD_BIT != 0)
        .then(|| "exit status bit 4".to_string());
    report.attributes.iter().filter_map(attribute_cause).chain(nvme).chain(exit_bit).collect()
}


fn degraded_causes(report: &SmartReport) -> Vec<String> {
    let status = report.exit_status.unwrap_or(0);
    [
        (OLD_AGE_BIT, "old_age"),
        (ERROR_LOG_BIT, "error_log"),
        (SELF_TEST_LOG_BIT, "self_test_log"),
    ]
    .iter()
    .filter(|(bit, _)| status & bit != 0)
    .map(|(_, cause)| (*cause).to_string())
    .collect()
}
