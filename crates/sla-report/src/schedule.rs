use crate::error::ScheduleError;
use crate::model::{Cadence, Period, ReportDefinition, ReportFile, ReportFormat, ReportLimits, Span};
use crate::report::default_report_limits;
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text};
use core_pg::scope::tenant_scope;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time};


pub const MAX_FILE_BYTES: u64 = 1_048_576;


pub const MAX_REPORTS: usize = 1000;


pub const MAX_ID_BYTES: usize = 64;


pub const MAX_TITLE_BYTES: usize = 256;


pub const MIN_OFFSET_MINUTES: i32 = -720;


pub const MAX_OFFSET_MINUTES: i32 = 840;


pub const OFFSET_STEP_MINUTES: i32 = 15;


pub const SECONDS_PER_MINUTE: i64 = 60;


pub const MAX_GRACE_SECONDS: i64 = 604_800;


pub const MAX_DUE_PERIODS: usize = 24;


pub const MAX_OBJECTIVE_PPM: u32 = 1_000_000;


pub const MONTHS_PER_YEAR: u8 = 12;


pub const MONTHS_PER_QUARTER: u8 = 3;


pub const MIN_YEAR: i32 = 0;


pub const MAX_YEAR: i32 = 9999;


/// Reads at most `MAX_FILE_BYTES`, parses strictly and validates against the default report limits; `file` only labels errors.
pub fn parse_report_file(reader: &mut dyn Read, file: &str) -> Result<ReportFile, ScheduleError> {
    let text = read_text(&mut Read::take(reader, MAX_FILE_BYTES + 1), file)?;
    (text.len() as u64 <= MAX_FILE_BYTES)
        .then_some(())
        .ok_or_else(|| ScheduleError::FileTooLarge {
            file: file.to_string(),
            max: MAX_FILE_BYTES,
        })?;
    let report_file = parse_document::<ReportFile>(&text, file)?;
    validate_report_file(&report_file, file, &default_report_limits())?;
    Ok(report_file)
}


pub fn load_report_file(path: &Path) -> Result<ReportFile, ScheduleError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    parse_report_file(&mut handle, &file)
}


pub fn validate_report_file(report_file: &ReportFile, file: &str, limits: &ReportLimits) -> Result<(), ScheduleError> {
    (report_file.reports.len() <= MAX_REPORTS)
        .then_some(())
        .ok_or_else(|| ScheduleError::TooManyReports {
            file: file.to_string(),
            count: report_file.reports.len(),
            max: MAX_REPORTS,
        })?;
    report_file
        .reports
        .iter()
        .enumerate()
        .try_fold(BTreeSet::new(), |mut seen, (index, report)| {
            validate_report(file, index, report, limits)?;
            seen.insert(report.id.as_str()).then_some(seen).ok_or_else(|| ScheduleError::DuplicateId {
                file: file.to_string(),
                id: report.id.clone(),
            })
        })
        .map(|_| ())
}


pub fn validate_report(file: &str, index: usize, report: &ReportDefinition, limits: &ReportLimits) -> Result<(), ScheduleError> {
    let checks = [
        ("id", id_ok(&report.id)),
        ("tenant", tenant_scope(&report.tenant).is_ok()),
        ("title", (1..=MAX_TITLE_BYTES).contains(&report.title.len())),
        ("services", services_ok(&report.services, limits)),
        ("utc_offset_minutes", offset_ok(report.utc_offset_minutes)),
        ("objective_ppm", report.objective_ppm <= MAX_OBJECTIVE_PPM),
        ("grace_seconds", (0..=MAX_GRACE_SECONDS).contains(&report.grace_seconds)),
        ("formats", formats_ok(&report.formats)),
    ];
    checks.iter().find(|check| !check.1).map_or(Ok(()), |check| {
        Err(ScheduleError::Invalid {
            file: file.to_string(),
            index,
            field: check.0,
        })
    })?;
    report.formats.contains(&ReportFormat::Pdf).then_some(()).map_or(Ok(()), |()| {
        Err(ScheduleError::PdfNotSupported {
            file: file.to_string(),
            index,
        })
    })
}


pub fn id_ok(id: &str) -> bool {
    let mut characters = id.chars();
    id.len() <= MAX_ID_BYTES
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && characters.all(|next| next.is_ascii_alphanumeric() || matches!(next, '_' | '.' | '-'))
}


pub fn services_ok(services: &[String], limits: &ReportLimits) -> bool {
    (1..=limits.max_services).contains(&services.len()) && services.iter().all(|service| (1..=limits.max_name_bytes).contains(&service.len()))
}


pub fn offset_ok(minutes: i32) -> bool {
    (MIN_OFFSET_MINUTES..=MAX_OFFSET_MINUTES).contains(&minutes) && minutes % OFFSET_STEP_MINUTES == 0
}


pub fn formats_ok(formats: &[ReportFormat]) -> bool {
    let distinct: BTreeSet<&ReportFormat> = formats.iter().collect();
    !formats.is_empty() && distinct.len() == formats.len()
}


pub fn offset_seconds(minutes: i32) -> Result<i64, ScheduleError> {
    offset_ok(minutes).then_some(()).ok_or(ScheduleError::InvalidOffset { minutes })?;
    Ok(i64::from(minutes) * SECONDS_PER_MINUTE)
}


/// The seconds unchanged when their UTC date is in the years RFC 3339 can write, else `OutOfRange`.
pub fn check_rfc3339_range(seconds: i64) -> Result<i64, ScheduleError> {
    let year = OffsetDateTime::from_unix_timestamp(seconds)?.year();
    (MIN_YEAR..=MAX_YEAR).contains(&year).then_some(seconds).ok_or(ScheduleError::OutOfRange)
}


pub fn format_rfc3339(seconds: i64) -> Result<String, ScheduleError> {
    let time = OffsetDateTime::from_unix_timestamp(check_rfc3339_range(seconds)?)?;
    Ok(time.format(&Rfc3339)?)
}


pub fn months_in(cadence: Cadence) -> Option<u8> {
    match cadence {
        Cadence::Weekly => None,
        Cadence::Monthly => Some(1),
        Cadence::Quarterly => Some(MONTHS_PER_QUARTER),
    }
}


pub fn first_day_of_period(cadence: Cadence, date: Date) -> Result<Date, ScheduleError> {
    match months_in(cadence) {
        None => {
            let back = Duration::days(i64::from(date.weekday().number_days_from_monday()));
            date.checked_sub(back).ok_or(ScheduleError::OutOfRange)
        }
        Some(span) => {
            let months_into_year = (u8::from(date.month()) - 1) / span * span;
            let month = Month::January.nth_next(months_into_year);
            Ok(Date::from_calendar_date(date.year(), month, 1)?)
        }
    }
}


pub fn first_day_after_period(cadence: Cadence, first: Date) -> Result<Date, ScheduleError> {
    match months_in(cadence) {
        None => first.checked_add(Duration::weeks(1)).ok_or(ScheduleError::OutOfRange),
        Some(span) => {
            let months_into_year = u8::from(first.month()) - 1 + span;
            let year = first.year() + i32::from(months_into_year / MONTHS_PER_YEAR);
            let month = Month::January.nth_next(months_into_year);
            Ok(Date::from_calendar_date(year, month, 1)?)
        }
    }
}


pub fn local_midnight_to_unix(date: Date, offset_seconds: i64) -> Result<i64, ScheduleError> {
    let local = PrimitiveDateTime::new(date, Time::MIDNIGHT).assume_utc().unix_timestamp();
    check_rfc3339_range(local - offset_seconds)
}


/// The `[start, end)` period of `cadence` in the fixed UTC offset that contains `at`.
pub fn period_containing(cadence: Cadence, offset_minutes: i32, at: i64) -> Result<Span, ScheduleError> {
    let offset = offset_seconds(offset_minutes)?;
    let local = OffsetDateTime::from_unix_timestamp(check_rfc3339_range(at)? + offset)?;
    let first = first_day_of_period(cadence, local.date())?;
    let after = first_day_after_period(cadence, first)?;
    Ok(Span {
        start: local_midnight_to_unix(first, offset)?,
        end: local_midnight_to_unix(after, offset)?,
    })
}


/// The first period still to report: the one at or after `last_done_end`, or the last elapsed one when nothing was done yet.
pub fn first_candidate(definition: &ReportDefinition, last_done_end: Option<i64>, cutoff: i64) -> Result<Span, ScheduleError> {
    let containing = |at: i64| period_containing(definition.cadence, definition.utc_offset_minutes, at);
    match last_done_end {
        Some(end) => {
            let found = containing(end)?;
            if found.start == end {
                Ok(found)
            } else {
                containing(found.end)
            }
        }
        None => {
            let current = containing(cutoff)?;
            containing(current.start - 1)
        }
    }
}


/// At most `max_periods` periods, oldest first, whose end plus the grace has passed at `now`.
pub fn due_periods(definition: &ReportDefinition, last_done_end: Option<i64>, now: i64, max_periods: usize) -> Result<Vec<Period>, ScheduleError> {
    (max_periods <= MAX_DUE_PERIODS).then_some(()).ok_or(ScheduleError::TooManyPeriods {
        requested: max_periods,
        max: MAX_DUE_PERIODS,
    })?;
    (0..=MAX_GRACE_SECONDS)
        .contains(&definition.grace_seconds)
        .then_some(())
        .ok_or(ScheduleError::InvalidGrace {
            seconds: definition.grace_seconds,
        })?;
    let cutoff = now.checked_sub(definition.grace_seconds).ok_or(ScheduleError::OutOfRange)?;
    let first = first_candidate(definition, last_done_end, cutoff)?;
    let (spans, _) = (0..max_periods).try_fold((Vec::new(), Some(first)), |(mut spans, cursor), _| {
        let following = match cursor.filter(|span| span.end <= cutoff) {
            Some(span) => {
                spans.push(span);
                Some(period_containing(definition.cadence, definition.utc_offset_minutes, span.end)?)
            }
            None => None,
        };
        Ok::<_, ScheduleError>((spans, following))
    })?;
    Ok(spans
        .into_iter()
        .map(|span| Period {
            tenant: definition.tenant.clone(),
            start: span.start,
            end: span.end,
        })
        .collect())
}
