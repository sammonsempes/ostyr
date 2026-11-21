//! Usage: backup_run <declarations.yaml> <restic-binary> [state-dir]: runs every declared restic and Borg repository (Unix only), prints coverage and findings; the state directory keeps the previous run and Borg's own base directory (required for Borg).

#[cfg(unix)]
mod run {
    use backup_monitor::borg::{plan as borg_plan, run_raw as borg_run, BORG_PROGRAM};
    use backup_monitor::coverage::coverage;
    use backup_monitor::declarations::load_declarations;
    use backup_monitor::model::{BorgSource, CoverageStatus, Declarations, FindingKind, Limits, Listing};
    use backup_monitor::parse::{parse_borg, parse_restic};
    use backup_monitor::restic::{findings, parse_run, plan, run_raw, RawRun};
    use core_config::parse::read_file;
    use core_pg::scope::tenant_of;
    use std::error::Error;
    use std::fs;
    use std::io::{stdout, Stdout, Write};
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use time::OffsetDateTime;


    const ARGUMENT_DECLARATIONS: usize = 1;


    const ARGUMENT_PROGRAM: usize = 2;


    const ARGUMENT_STATE: usize = 3;


    const DEADLINE_SECONDS: u64 = 120;


    const USAGE: &str = "usage: backup_run <declarations.yaml> <restic-binary> [state-dir]";


    fn previous_listing(state: Option<&Path>, name: &str, limits: &Limits) -> Option<Listing> {
        let directory = state?;
        let key = fs::read_to_string(directory.join(format!("{name}.restic.id"))).ok()?;
        let bytes = fs::read(directory.join(format!("{name}.restic.snapshots"))).ok()?;
        parse_restic(bytes.as_slice(), key.trim(), limits).ok()
    }


    fn previous_borg(state: Option<&Path>, name: &str, source: &BorgSource, limits: &Limits) -> Option<Listing> {
        let bytes = fs::read(state?.join(format!("{name}.borg.snapshots"))).ok()?;
        parse_borg(bytes.as_slice(), source.hostname_from_name, limits).ok()
    }


    fn save_borg(state: Option<&Path>, name: &str, raw: &[u8]) -> Result<(), Box<dyn Error>> {
        state.map_or(Ok(()), |directory| Ok(fs::write(directory.join(format!("{name}.borg.snapshots")), raw)?))
    }


    fn save(state: Option<&Path>, name: &str, raw: &RawRun) -> Result<(), Box<dyn Error>> {
        state.map_or(Ok(()), |directory| {
            fs::write(directory.join(format!("{name}.restic.id")), &raw.key)?;
            fs::write(directory.join(format!("{name}.restic.snapshots")), &raw.snapshots)?;
            Ok(())
        })
    }


    fn print_findings(
        out: &mut Stdout,
        name: &str,
        previous: Option<&Listing>,
        current: &Listing,
        declarations: &Declarations,
    ) -> std::io::Result<()> {
        findings(name, previous, current, declarations)
            .iter()
            .try_for_each(|finding| match &finding.kind {
                FindingKind::Deleted { id, time, host } => writeln!(out, "finding {name} deleted {id} time {time} host {host:?}"),
                FindingKind::RetentionBelowFloor { count, floor } => {
                    writeln!(out, "finding {name} retention below floor: {count} snapshots, floor {floor}")
                }
                FindingKind::RepositoryChanged { previous: old, current: new } => writeln!(out, "finding {name} repository changed {old} -> {new}"),
            })
    }


    pub fn execute() -> Result<(), Box<dyn Error>> {
        let arguments: Vec<String> = std::env::args().collect();
        let declarations_path = arguments.get(ARGUMENT_DECLARATIONS).ok_or(USAGE)?;
        let program = PathBuf::from(arguments.get(ARGUMENT_PROGRAM).ok_or(USAGE)?);
        let state = arguments.get(ARGUMENT_STATE).map(Path::new);
        let declarations = load_declarations(&read_file(Path::new(declarations_path))?, declarations_path)?;
        let limits = Limits::default();
        let mut out = stdout();
        writeln!(out, "tenant {}", tenant_of(&declarations.tenant))?;
        let runs = plan(&declarations);
        runs.refused
            .iter()
            .try_for_each(|index| writeln!(out, "refused repository entry {index}"))?;
        let mut listings = Vec::new();
        runs.runnable.iter().try_for_each(|(name, source)| -> Result<(), Box<dyn Error>> {
            let outcome = run_raw(&program, source, &limits, Duration::from_secs(DEADLINE_SECONDS))
                .and_then(|raw| parse_run(&raw, &limits).map(|listing| (raw, listing)));
            match outcome {
                Ok((raw, current)) => {
                    writeln!(
                        out,
                        "repository {name} key {} snapshots {} skipped {:?}",
                        current.repository,
                        current.snapshots.len(),
                        current.skipped
                    )?;
                    let previous = previous_listing(state, name, &limits);
                    print_findings(&mut out, name, previous.as_ref(), &current, &declarations)?;
                    save(state, name, &raw)?;
                    listings.push(current);
                }
                Err(error) => writeln!(out, "repository {name} failed: {error}")?,
            }
            Ok(())
        })?;
        let borg = borg_plan(&declarations);
        borg.refused
            .iter()
            .try_for_each(|index| writeln!(out, "refused repository entry {index}"))?;
        borg.runnable.iter().try_for_each(|(name, source)| -> Result<(), Box<dyn Error>> {
            let outcome = state.ok_or("borg needs a state directory".into()).and_then(|directory: &Path| {
                borg_run(
                    Path::new(BORG_PROGRAM),
                    source,
                    &declarations.tenant,
                    directory,
                    &limits,
                    Duration::from_secs(DEADLINE_SECONDS),
                )
                .map_err(Box::<dyn Error>::from)
                .and_then(|raw| Ok((parse_borg(raw.as_slice(), source.hostname_from_name, &limits)?, raw)))
            });
            match outcome {
                Ok((current, raw)) => {
                    writeln!(
                        out,
                        "repository {name} key {} snapshots {} skipped {:?}",
                        current.repository,
                        current.snapshots.len(),
                        current.skipped
                    )?;
                    let previous = previous_borg(state, name, source, &limits);
                    print_findings(&mut out, name, previous.as_ref(), &current, &declarations)?;
                    save_borg(state, name, &raw)?;
                    listings.push(current);
                }
                Err(error) => writeln!(out, "repository {name} failed: {error}")?,
            }
            Ok(())
        })?;
        coverage(&listings, &declarations, OffsetDateTime::now_utc())
            .iter()
            .try_for_each(|entry| match &entry.status {
                CoverageStatus::Ok => writeln!(out, "coverage {} ok", entry.host),
                CoverageStatus::Stale { age } => writeln!(out, "coverage {} stale age {age}", entry.host),
                CoverageStatus::Missing => writeln!(out, "coverage {} missing", entry.host),
            })?;
        Ok(())
    }
}


#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run::execute()
}


#[cfg(not(unix))]
fn main() {}
