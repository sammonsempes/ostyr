//! Usage: backup_report <restic|borg> <previous.json> <current.json> <declarations.yaml> <now RFC 3339> <repository> (restic name, ignored for borg).

use backup_monitor::compare::compare;
use backup_monitor::coverage::coverage;
use backup_monitor::declarations::load_declarations;
use backup_monitor::model::{CoverageStatus, FindingKind, Limits, Listing};
use backup_monitor::parse::{parse_borg, parse_restic};
use core_config::parse::read_file;
use core_pg::scope::tenant_of;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const ARGUMENT_KIND: usize = 1;


const ARGUMENT_PREVIOUS: usize = 2;


const ARGUMENT_CURRENT: usize = 3;


const ARGUMENT_DECLARATIONS: usize = 4;


const ARGUMENT_NOW: usize = 5;


const ARGUMENT_REPOSITORY: usize = 6;


const USAGE: &str = "usage: backup_report <restic|borg> <previous.json> <current.json> <declarations.yaml> <now> <repository>";


fn read_listing(kind: &str, path: &str, from_name: bool, repository: &str) -> Result<Listing, Box<dyn Error>> {
    let file = File::open(path)?;
    match kind {
        "restic" => Ok(parse_restic(file, repository, &Limits::default())?),
        "borg" => Ok(parse_borg(file, from_name, &Limits::default())?),
        _ => Err(USAGE.into()),
    }
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    let kind = arguments.get(ARGUMENT_KIND).ok_or(USAGE)?;
    let previous_path = arguments.get(ARGUMENT_PREVIOUS).ok_or(USAGE)?;
    let current_path = arguments.get(ARGUMENT_CURRENT).ok_or(USAGE)?;
    let declarations_path = arguments.get(ARGUMENT_DECLARATIONS).ok_or(USAGE)?;
    let now = OffsetDateTime::parse(arguments.get(ARGUMENT_NOW).ok_or(USAGE)?, &Rfc3339)?;
    let repository = arguments.get(ARGUMENT_REPOSITORY).ok_or(USAGE)?;
    let declarations = load_declarations(&read_file(Path::new(declarations_path))?, declarations_path)?;
    let previous = read_listing(kind, previous_path, declarations.hostname_from_name, repository)?;
    let current = read_listing(kind, current_path, declarations.hostname_from_name, repository)?;
    let mut out = stdout();
    writeln!(out, "tenant {}", tenant_of(&declarations.tenant))?;
    writeln!(out, "snapshots {} skipped {:?}", current.snapshots.len(), current.skipped)?;
    coverage(std::slice::from_ref(&current), &declarations, now)
        .iter()
        .try_for_each(|entry| match &entry.status {
            CoverageStatus::Ok => writeln!(out, "coverage {} ok", entry.host),
            CoverageStatus::Stale { age } => writeln!(out, "coverage {} stale age {age}", entry.host),
            CoverageStatus::Missing => writeln!(out, "coverage {} missing", entry.host),
        })?;
    compare(&previous, &current, &declarations)
        .iter()
        .try_for_each(|finding| match &finding.kind {
            FindingKind::Deleted { id, time, host } => writeln!(out, "finding deleted {id} time {time} host {host:?}"),
            FindingKind::RetentionBelowFloor { count, floor } => writeln!(out, "finding retention below floor: {count} snapshots, floor {floor}"),
            FindingKind::RepositoryChanged { previous: old, current: new } => writeln!(out, "finding repository changed {old} -> {new}"),
        })?;
    Ok(())
}
