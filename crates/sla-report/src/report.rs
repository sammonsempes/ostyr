use crate::error::SlaError;
use crate::model::{Period, Report, ReportLimits, ReportLine, ReportTotals, ServiceInput};


pub const DEFAULT_MAX_SERVICES: usize = 500;


pub const DEFAULT_MAX_NAME_BYTES: usize = 128;


pub const NAME_CUT_MARKER: &str = "...[cut]";


const PPM_PER_PERCENT: u32 = 10_000;


pub fn default_report_limits() -> ReportLimits {
    ReportLimits {
        max_services: DEFAULT_MAX_SERVICES,
        max_name_bytes: DEFAULT_MAX_NAME_BYTES,
    }
}


pub fn percent_from_ppm(ppm: u32) -> String {
    format!("{}.{:04}", ppm / PPM_PER_PERCENT, ppm % PPM_PER_PERCENT)
}


pub fn cut_name(name: &str, max_bytes: usize) -> String {
    let cut = (0..=max_bytes.min(name.len()))
        .rev()
        .find(|index| name.is_char_boundary(*index))
        .unwrap_or(0);
    let kept = name.get(..cut).unwrap_or("");
    let marker = if cut < name.len() { NAME_CUT_MARKER } else { "" };
    format!("{kept}{marker}")
}


pub fn report_line(service: &ServiceInput, max_name_bytes: usize) -> ReportLine {
    ReportLine {
        name: cut_name(&service.name, max_name_bytes),
        objective_percent: percent_from_ppm(service.objective_ppm),
        availability_percent: service.figure.availability_ppm.map(percent_from_ppm),
        budget_used_seconds: service.figure.budget.consumed_seconds,
        budget_allowed_seconds: service.figure.budget.allowed_seconds,
        down_seconds: service.figure.down_seconds,
        unknown_seconds: service.figure.unknown_seconds,
    }
}


pub fn check_service_tenant(tenant: &str, service: &ServiceInput) -> Result<(), SlaError> {
    let mismatch = SlaError::TenantMismatch {
        expected: tenant.to_string(),
        found: service.tenant.clone(),
    };
    (service.tenant == tenant).then_some(()).ok_or(mismatch)
}


pub fn build_report(tenant: &str, period: &Period, services: &[ServiceInput], limits: &ReportLimits) -> Result<Report, SlaError> {
    let too_many = SlaError::TooManyServices {
        count: services.len(),
        max: limits.max_services,
    };
    (services.len() <= limits.max_services).then_some(()).ok_or(too_many)?;
    let period_mismatch = SlaError::TenantMismatch {
        expected: tenant.to_string(),
        found: period.tenant.clone(),
    };
    (period.tenant == tenant).then_some(()).ok_or(period_mismatch)?;
    services.iter().try_for_each(|service| check_service_tenant(tenant, service))?;
    let mut lines: Vec<ReportLine> = services.iter().map(|service| report_line(service, limits.max_name_bytes)).collect();
    lines.sort_by(|left, right| left.name.cmp(&right.name));
    let totals = lines.iter().fold(ReportTotals::default(), |sums, line| ReportTotals {
        services: sums.services + 1,
        budget_used_seconds: sums.budget_used_seconds + line.budget_used_seconds,
        down_seconds: sums.down_seconds + line.down_seconds,
        unknown_seconds: sums.unknown_seconds + line.unknown_seconds,
    });
    Ok(Report {
        tenant: tenant.to_string(),
        start: period.start,
        end: period.end,
        lines,
        totals,
    })
}
