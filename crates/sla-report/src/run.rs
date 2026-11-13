use crate::error::{RunError, ScheduleError, SlaError};
use crate::export::{to_csv, to_json};
use crate::model::{DefinitionRun, Period, Progress, Report, ReportDefinition, ReportFormat, ReportLimits, RunSummary, ServiceInput, WriteOutcome};
use crate::report::build_report;
use crate::schedule::{due_periods, format_rfc3339, id_ok, MAX_DUE_PERIODS};
use crate::types::FiguresFn;
use std::collections::BTreeMap;
use std::io::{ErrorKind, Write};
use std::path::Path;
use tempfile::NamedTempFile;


pub fn period_stamp(start: i64) -> Result<String, ScheduleError> {
    Ok(format_rfc3339(start)?
        .chars()
        .filter(|character| !matches!(character, '-' | ':'))
        .collect())
}


pub fn format_extension(format: ReportFormat) -> Result<&'static str, RunError> {
    match format {
        ReportFormat::Csv => Ok("csv"),
        ReportFormat::Json => Ok("json"),
        ReportFormat::Pdf => Err(RunError::PdfNotSupported),
    }
}


pub fn report_file_name(id: &str, start: i64, format: ReportFormat) -> Result<String, RunError> {
    Ok(format!("{id}_{}.{}", period_stamp(start)?, format_extension(format)?))
}


pub fn render<Output: Write>(format: ReportFormat, report: &Report, output: Output) -> Result<(), RunError> {
    match format {
        ReportFormat::Csv => Ok(to_csv(report, output)?),
        ReportFormat::Json => Ok(to_json(report, output)?),
        ReportFormat::Pdf => Err(RunError::PdfNotSupported),
    }
}


pub fn outcome_of_persist(persisted: Result<(), std::io::Error>) -> Result<WriteOutcome, RunError> {
    match persisted {
        Ok(()) => Ok(WriteOutcome::Written),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(WriteOutcome::AlreadyWritten),
        Err(error) => Err(RunError::Io(error)),
    }
}


/// Writes to a temporary name, syncs, then links it into place without replacing: an existing file is left untouched.
pub fn write_once(out_dir: &Path, file_name: &str, format: ReportFormat, report: &Report) -> Result<WriteOutcome, RunError> {
    let mut temporary = NamedTempFile::new_in(out_dir)?;
    render(format, report, &mut temporary)?;
    temporary.as_file().sync_all()?;
    let persisted = temporary
        .persist_noclobber(out_dir.join(file_name))
        .map(|_| ())
        .map_err(|failure| failure.error);
    outcome_of_persist(persisted)
}


pub fn period_report(definition: &ReportDefinition, period: &Period, figures: &FiguresFn, limits: &ReportLimits) -> Result<Report, RunError> {
    let too_many = SlaError::TooManyServices {
        count: definition.services.len(),
        max: limits.max_services,
    };
    (definition.services.len() <= limits.max_services).then_some(()).ok_or(too_many)?;
    let services = definition
        .services
        .iter()
        .map(|name| {
            Ok(ServiceInput {
                tenant: definition.tenant.clone(),
                name: name.clone(),
                objective_ppm: definition.objective_ppm,
                figure: figures(name, period).map_err(RunError::Figures)?,
            })
        })
        .collect::<Result<Vec<ServiceInput>, RunError>>()?;
    Ok(build_report(&definition.tenant, period, &services, limits)?)
}


pub fn add_progress(left: Progress, right: Progress) -> Progress {
    Progress {
        written: left.written + right.written,
        already_written: left.already_written + right.already_written,
        failed: left.failed + right.failed,
    }
}


pub fn count_outcome(progress: Progress, outcome: WriteOutcome) -> Progress {
    match outcome {
        WriteOutcome::Written => Progress {
            written: progress.written + 1,
            ..progress
        },
        WriteOutcome::AlreadyWritten => Progress {
            already_written: progress.already_written + 1,
            ..progress
        },
    }
}


pub fn failed_progress() -> Progress {
    Progress {
        failed: 1,
        ..Progress::default()
    }
}


pub fn write_period(definition: &ReportDefinition, period: &Period, report: &Report, out_dir: &Path) -> (Progress, Option<RunError>) {
    definition
        .formats
        .iter()
        .fold((Progress::default(), None), |(progress, failure), format| match failure {
            Some(_) => (progress, failure),
            None => {
                let written = report_file_name(&definition.id, period.start, *format).and_then(|name| write_once(out_dir, &name, *format, report));
                match written {
                    Ok(outcome) => (count_outcome(progress, outcome), None),
                    Err(error) => (progress, Some(error)),
                }
            }
        })
}


pub fn run_period(
    definition: &ReportDefinition,
    period: &Period,
    figures: &FiguresFn,
    out_dir: &Path,
    limits: &ReportLimits,
) -> (Progress, Option<RunError>) {
    match period_report(definition, period, figures, limits) {
        Ok(report) => write_period(definition, period, &report, out_dir),
        Err(error) => (Progress::default(), Some(error)),
    }
}


pub fn step_period(
    state: DefinitionRun,
    definition: &ReportDefinition,
    period: &Period,
    figures: &FiguresFn,
    out_dir: &Path,
    limits: &ReportLimits,
) -> DefinitionRun {
    if state.stopped {
        state
    } else {
        let (progress, failure) = run_period(definition, period, figures, out_dir, limits);
        let total = add_progress(state.progress, progress);
        match failure {
            None => DefinitionRun {
                progress: total,
                last_done: Some(period.end),
                stopped: false,
            },
            Some(error) => {
                tracing::warn!(period_start = period.start, "period not written, definition stopped: {error}");
                DefinitionRun {
                    progress: add_progress(total, failed_progress()),
                    stopped: true,
                    ..state
                }
            }
        }
    }
}


pub fn run_definition(
    definition: &ReportDefinition,
    figures: &FiguresFn,
    out_dir: &Path,
    last_done: Option<i64>,
    now: i64,
    limits: &ReportLimits,
) -> DefinitionRun {
    let start = DefinitionRun {
        progress: Progress::default(),
        last_done,
        stopped: false,
    };
    let periods = id_ok(&definition.id)
        .then_some(())
        .ok_or(RunError::InvalidId)
        .and_then(|()| Ok(due_periods(definition, last_done, now, MAX_DUE_PERIODS)?));
    match periods {
        Err(error) => {
            tracing::warn!("report not run: {error}");
            DefinitionRun {
                progress: failed_progress(),
                ..start
            }
        }
        Ok(due) => due
            .iter()
            .fold(start, |state, period| step_period(state, definition, period, figures, out_dir, limits)),
    }
}


pub fn run_due(
    definitions: &[ReportDefinition],
    figures: &FiguresFn,
    out_dir: &Path,
    last_done: &BTreeMap<String, i64>,
    now: i64,
    limits: &ReportLimits,
) -> RunSummary {
    definitions.iter().fold(RunSummary::default(), |mut summary, definition| {
        let run = run_definition(definition, figures, out_dir, last_done.get(&definition.id).copied(), now, limits);
        summary.written += run.progress.written;
        summary.already_written += run.progress.already_written;
        summary.failed += run.progress.failed;
        if let Some(end) = run.last_done {
            summary.last_done.insert(definition.id.clone(), end);
        }
        summary
    })
}
