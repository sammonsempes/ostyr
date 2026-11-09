use crate::error::SlaError;
use crate::model::{Period, Report, ReportLimits, ReportLine, ReportTotals, ServiceInput};


pub const DEFAULT_MAX_SERVICES: usize = 500;


pub const DEFAULT_MAX_NAME_BYTES: usize = 128;


pub const NAME_CUT_MARKER: &str = "...[cut]";


const MAX_OBJECTIVE_PPM: u32 = 1_000_000;


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


pub fn report_line(service: &ServiceInput, max_name_bytes: usize) -> Result<ReportLine, SlaError> {
    let objective_ppm = service.objective_ppm;
    (objective_ppm <= MAX_OBJECTIVE_PPM)
        .then_some(())
        .ok_or(SlaError::InvalidObjective { objective_ppm })?;
    Ok(ReportLine {
        name: cut_name(&service.name, max_name_bytes),
        objective_percent: percent_from_ppm(service.objective_ppm),
        availability_percent: service.figure.availability_ppm.map(percent_from_ppm),
        budget_used_seconds: service.figure.budget.consumed_seconds,
        budget_allowed_seconds: service.figure.budget.allowed_seconds,
        down_seconds: service.figure.down_seconds,
        unknown_seconds: service.figure.unknown_seconds,
    })
}


pub fn checked_total(total: i64, addend: i64, field: &'static str) -> Result<i64, SlaError> {
    total.checked_add(addend).ok_or(SlaError::TotalOverflow { field })
}


pub fn add_line_to_totals(sums: ReportTotals, line: &ReportLine) -> Result<ReportTotals, SlaError> {
    Ok(ReportTotals {
        services: sums.services + 1,
        budget_used_seconds: checked_total(sums.budget_used_seconds, line.budget_used_seconds, "budget_used_seconds")?,
        down_seconds: checked_total(sums.down_seconds, line.down_seconds, "down_seconds")?,
        unknown_seconds: checked_total(sums.unknown_seconds, line.unknown_seconds, "unknown_seconds")?,
    })
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
    let mut lines = services
        .iter()
        .map(|service| report_line(service, limits.max_name_bytes))
        .collect::<Result<Vec<ReportLine>, SlaError>>()?;
    lines.sort_by(|left, right| left.name.cmp(&right.name));
    let totals = lines.iter().try_fold(ReportTotals::default(), add_line_to_totals)?;
    Ok(Report {
        tenant: tenant.to_string(),
        start: period.start,
        end: period.end,
        lines,
        totals,
    })
}
