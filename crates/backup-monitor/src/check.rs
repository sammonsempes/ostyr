//! One round over every declared repository: each repository is one `Result`, so a bad one never stops the others (Unix only).

use crate::borg::{parse_run as borg_parse_run, plan as borg_plan, run_raw as borg_run, BorgError, BorgTarget};
use crate::coverage::coverage;
use crate::error::BackupError;
use crate::model::{BorgSource, Coverage, Declarations, Finding, Limits, Listing, ResticSource};
use crate::parse::{parse_borg, parse_restic};
use crate::report::{read_report, write_report, ReportError};
use crate::restic::{findings, parse_run, plan, run_raw, RawRun, ResticError};
use crate::secrets::SecretsDir;
use crate::types::Clock;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, warn};


pub const MAX_KEY_BYTES: u64 = 256;


/// What one round needs: the program paths, the checked secrets directory, the state directory and its report handle, the limits and the clock.
#[derive(Debug)]
pub struct RoundContext<'a> {
    pub restic_program: &'a Path,
    pub borg_program: &'a Path,
    pub secrets: &'a SecretsDir,
    pub state: Option<&'a Path>,
    pub reports: Option<&'a OwnedFd>,
    pub limits: &'a Limits,
    pub deadline: Duration,
    pub euid: u32,
    pub clock: Clock,
}


/// The previous run of one repository: its listing, and whether stored files exist that could not be read as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Previous {
    pub listing: Option<Listing>,
    pub unreadable: bool,
}


/// A successful check: the listing, its findings and whether the previous report was unreadable (compared against nothing, and loud).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryCheck {
    pub listing: Listing,
    pub findings: Vec<Finding>,
    pub previous_unreadable: bool,
}


/// A fixed category per failure: no location, secret path or listing text is kept.
#[derive(Debug, Error)]
pub enum CheckError {
    #[error("restic: {0}")]
    Restic(#[from] ResticError),
    #[error("borg: {0}")]
    Borg(#[from] BorgError),
    #[error("report: {0}")]
    Report(#[from] ReportError),
    #[error("borg needs a state directory")]
    NoStateDirectory,
}


/// Every repository in plan order (restic, then Borg) with its own result, the refused entry indexes and the coverage of the repositories that succeeded.
#[derive(Debug)]
pub struct RoundOutcome {
    pub repositories: Vec<(String, Result<RepositoryCheck, CheckError>)>,
    pub refused_restic: Vec<usize>,
    pub refused_borg: Vec<usize>,
    pub coverage: Vec<Coverage>,
    pub not_run: Vec<String>,
    pub next_start: usize,
}


/// Where the round starts in plan order (restic, then Borg) and whether another repository may start, given how many already did.
pub struct RoundControl<'a> {
    pub start: usize,
    pub may_start: &'a (dyn Fn(usize) -> bool + Sync),
}


/// One planned repository: its declared source.
#[derive(Debug, Clone, Copy)]
pub enum Planned<'a> {
    Restic(&'a ResticSource),
    Borg(&'a BorgSource),
}


fn absent() -> Previous {
    Previous {
        listing: None,
        unreadable: false,
    }
}


fn unreadable() -> Previous {
    debug!("previous report is not readable as a listing");
    Previous {
        listing: None,
        unreadable: true,
    }
}


/// A listing parsed from the stored bytes, or `unreadable` (never `.ok()`): a corrupt previous report is loud, and the new one replaces it.
pub fn previous_from(parsed: Result<Listing, BackupError>) -> Previous {
    parsed.map_or_else(
        |_| unreadable(),
        |listing| Previous {
            listing: Some(listing),
            unreadable: false,
        },
    )
}


/// Both stored files of a restic repository, or neither; exactly one, or bytes that do not parse, is `unreadable`.
pub fn previous_restic(reports: Option<&OwnedFd>, name: &str, euid: u32, limits: &Limits) -> Result<Previous, ReportError> {
    reports.map_or(Ok(absent()), |directory| {
        let key = read_report(directory, &format!("{name}.restic.id"), euid, MAX_KEY_BYTES)?;
        let stored = read_report(directory, &format!("{name}.restic.snapshots"), euid, limits.max_bytes.saturating_add(1))?;
        Ok(match (key, stored) {
            (None, None) => absent(),
            (Some(id), Some(listing)) => previous_from(parse_restic(listing.as_slice(), String::from_utf8_lossy(&id).trim(), limits)),
            _ => unreadable(),
        })
    })
}


/// The stored Borg listing, or none; bytes that do not parse are `unreadable`.
pub fn previous_borg(reports: Option<&OwnedFd>, name: &str, source: &BorgSource, euid: u32, limits: &Limits) -> Result<Previous, ReportError> {
    reports.map_or(Ok(absent()), |directory| {
        let stored = read_report(directory, &format!("{name}.borg.snapshots"), euid, limits.max_bytes.saturating_add(1))?;
        Ok(stored.map_or_else(absent, |listing| {
            previous_from(parse_borg(listing.as_slice(), source.hostname_from_name, limits))
        }))
    })
}


fn save_restic(reports: Option<&OwnedFd>, name: &str, raw: &RawRun) -> Result<(), ReportError> {
    reports.map_or(Ok(()), |directory| {
        write_report(directory, &format!("{name}.restic.id"), raw.key.as_bytes())?;
        write_report(directory, &format!("{name}.restic.snapshots"), &raw.snapshots)
    })
}


fn save_borg(reports: Option<&OwnedFd>, name: &str, raw: &[u8]) -> Result<(), ReportError> {
    reports.map_or(Ok(()), |directory| write_report(directory, &format!("{name}.borg.snapshots"), raw))
}


/// Runs, parses, compares with the previous report and saves the new one: any error is returned for this repository alone.
pub fn check_restic(
    context: &RoundContext<'_>,
    declarations: &Declarations,
    name: &str,
    source: &crate::model::ResticSource,
) -> Result<RepositoryCheck, CheckError> {
    let raw = run_raw(
        context.restic_program,
        context.secrets,
        source,
        context.limits,
        context.deadline,
        context.euid,
    )?;
    let current = parse_run(&raw, context.limits)?;
    let previous = previous_restic(context.reports, name, context.euid, context.limits)?;
    let found = findings(name, previous.listing.as_ref(), &current, declarations);
    save_restic(context.reports, name, &raw)?;
    Ok(RepositoryCheck {
        listing: current,
        findings: found,
        previous_unreadable: previous.unreadable,
    })
}


/// As `check_restic` for one Borg repository; Borg needs the state directory for its base directory.
pub fn check_borg(context: &RoundContext<'_>, declarations: &Declarations, name: &str, source: &BorgSource) -> Result<RepositoryCheck, CheckError> {
    let state = context.state.ok_or(CheckError::NoStateDirectory)?;
    let raw = borg_run(
        context.borg_program,
        context.secrets,
        source,
        &BorgTarget {
            tenant: &declarations.tenant,
            repository: name,
            state,
        },
        context.limits,
        context.deadline,
        context.euid,
    )?;
    let current = borg_parse_run(&raw, source, context.limits)?;
    let previous = previous_borg(context.reports, name, source, context.euid, context.limits)?;
    let found = findings(name, previous.listing.as_ref(), &current, declarations);
    save_borg(context.reports, name, &raw)?;
    Ok(RepositoryCheck {
        listing: current,
        findings: found,
        previous_unreadable: previous.unreadable,
    })
}


fn log_failure(name: &str, result: &Result<RepositoryCheck, CheckError>) {
    if let Err(error) = result {
        let reason = error.to_string();
        warn!(repository = name, reason, "repository check failed");
    }
}


fn always(_started: usize) -> bool {
    true
}


fn check_planned(context: &RoundContext<'_>, declarations: &Declarations, name: &str, planned: Planned<'_>) -> Result<RepositoryCheck, CheckError> {
    match planned {
        Planned::Restic(source) => check_restic(context, declarations, name, source),
        Planned::Borg(source) => check_borg(context, declarations, name, source),
    }
}


/// Checks every declared restic and Borg repository once; the failure of one is that repository's `Err` and the others still run.
pub fn run_round(context: &RoundContext<'_>, declarations: &Declarations) -> RoundOutcome {
    run_round_with(
        context,
        declarations,
        &RoundControl {
            start: 0,
            may_start: &always,
        },
    )
}


/// The plan indexes in rotated order from `control.start`, each with whether it ran: `run` is called while `may_start` allows it.
pub fn rotated_turns(total: usize, control: &RoundControl<'_>, run: &mut dyn FnMut(usize)) -> Vec<(usize, bool)> {
    let first = control.start.checked_rem(total).unwrap_or(0);
    let mut started = 0;
    let mut cut = false;
    (0..total)
        .map(|offset| (first + offset) % total)
        .map(|index| {
            cut = cut || !(control.may_start)(started);
            if !cut {
                run(index);
                started += 1;
            }
            (index, !cut)
        })
        .collect()
}


/// As `run_round` from `control.start`; the repositories after the cut are `not_run`; coverage only when every one ran.
pub fn run_round_with(context: &RoundContext<'_>, declarations: &Declarations, control: &RoundControl<'_>) -> RoundOutcome {
    let restic = plan(declarations);
    let borg = borg_plan(declarations);
    let planned: Vec<(&str, Planned<'_>)> = restic
        .runnable
        .iter()
        .map(|(name, source)| (*name, Planned::Restic(source)))
        .chain(borg.runnable.iter().map(|(name, source)| (*name, Planned::Borg(source))))
        .collect();
    let mut repositories: Vec<(String, Result<RepositoryCheck, CheckError>)> = Vec::new();
    let turns = rotated_turns(planned.len(), control, &mut |index| {
        planned
            .get(index)
            .into_iter()
            .for_each(|(name, source)| repositories.push(((*name).to_owned(), check_planned(context, declarations, name, *source))));
    });
    let left_out: Vec<usize> = turns.iter().filter(|(_, ran)| !ran).map(|(index, _)| *index).collect();
    let not_run: Vec<String> = left_out
        .iter()
        .filter_map(|index| planned.get(*index).map(|(name, _)| (*name).to_owned()))
        .collect();
    repositories.iter().for_each(|(name, result)| log_failure(name, result));
    let listings: Vec<Listing> = repositories
        .iter()
        .filter_map(|(_, result)| result.as_ref().ok().map(|check| check.listing.clone()))
        .collect();
    let counted = if left_out.is_empty() {
        coverage(&listings, declarations, (context.clock)())
    } else {
        Vec::new()
    };
    RoundOutcome {
        coverage: counted,
        repositories,
        refused_restic: restic.refused,
        refused_borg: borg.refused,
        not_run,
        next_start: left_out.first().copied().unwrap_or(0),
    }
}
