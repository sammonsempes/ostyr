//! Usage: backup_run restore-test <declarations.yaml> <restic-binary> [--store <pg.yaml> [--cap <rows>]] prints one JSON line per declared restore test (times as RFC 3339) and, with `--store`, writes the results to PostgreSQL and prints the write counts; backup_run <declarations.yaml> <restic-binary> [state-dir]: runs every declared restic and Borg repository (Unix only), prints coverage and findings; the state directory keeps the previous run (under `reports/<tenant>/`, 0600) and Borg's own base directory (required for Borg).

#[cfg(unix)]
mod run {
    use backup_monitor::borg::{plan as borg_plan, run_raw as borg_run, BORG_PROGRAM};
    use backup_monitor::coverage::coverage;
    use backup_monitor::declarations::load_declarations;
    use backup_monitor::model::{BorgSource, CoverageStatus, Declarations, FindingKind, Limits, Listing};
    use backup_monitor::parse::{parse_borg, parse_restic};
    use backup_monitor::report::{read_report, report_directory, write_report};
    use backup_monitor::restic::{findings, parse_run, plan, run_raw, RawRun};
    use backup_monitor::restore::{outcome_label, restore_plan, restore_test, skip_label, RestoreOutcome, RestoreResult};
    use backup_monitor::store::{
        record_restore_results_with_cap, run_error_category, test_key, RunErrorRecord, TestKey, MAX_RESTORE_ROWS, MIGRATIONS, MIGRATION_NAMESPACE,
    };
    use backup_monitor::text::rfc3339_text;
    use backup_monitor::types::RowFuture;
    use core_config::parse::read_file;
    use core_pg::connect::connect;
    use core_pg::error::PgError;
    use core_pg::migrate::migrate;
    use core_pg::query::{column_text, scoped_query};
    use core_pg::scope::{tenant_of, TenantScope};
    use core_pg::settings::load_settings;
    use core_pg::types::SqlParameter;
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::io::{stdout, Stdout, Write};
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use time::OffsetDateTime;
    use tokio_postgres::Client;


    const ARGUMENT_DECLARATIONS: usize = 1;


    const ARGUMENT_PROGRAM: usize = 2;


    const ARGUMENT_STATE: usize = 3;


    const DEADLINE_SECONDS: u64 = 120;


    const STORE_DEADLINE_SECONDS: u64 = 30;


    const ARGUMENT_STORE_FLAG: usize = 4;


    const STORE_CAP_FLAG_OFFSET: usize = 2;


    const STORE_FLAG: &str = "--store";


    const CAP_FLAG: &str = "--cap";


    const GAP_COUNTERS: usize = 3;


    const MAX_KEY_BYTES: u64 = 256;


    const RESTORE_MODE: &str = "restore-test";


    const USAGE: &str = "usage: backup_run [restore-test] <declarations.yaml> <restic-binary> [absolute-state-dir]";


    fn previous_listing(reports: Option<&OwnedFd>, name: &str, limits: &Limits) -> Result<Option<Listing>, Box<dyn Error>> {
        let cap = limits.max_bytes.saturating_add(1);
        reports.map_or(Ok(None), |directory| {
            let stored_key = read_report(directory, &format!("{name}.restic.id"), euid(), MAX_KEY_BYTES)?;
            let stored = read_report(directory, &format!("{name}.restic.snapshots"), euid(), cap)?;
            Ok(stored_key
                .zip(stored)
                .and_then(|(id, listing)| parse_restic(listing.as_slice(), String::from_utf8_lossy(&id).trim(), limits).ok()))
        })
    }


    fn previous_borg(reports: Option<&OwnedFd>, name: &str, source: &BorgSource, limits: &Limits) -> Result<Option<Listing>, Box<dyn Error>> {
        let cap = limits.max_bytes.saturating_add(1);
        reports.map_or(Ok(None), |directory| {
            let stored = read_report(directory, &format!("{name}.borg.snapshots"), euid(), cap)?;
            Ok(stored.and_then(|listing| parse_borg(listing.as_slice(), source.hostname_from_name, limits).ok()))
        })
    }


    fn save_borg(reports: Option<&OwnedFd>, name: &str, raw: &[u8]) -> Result<(), Box<dyn Error>> {
        reports.map_or(Ok(()), |directory| Ok(write_report(directory, &format!("{name}.borg.snapshots"), raw)?))
    }


    fn save(reports: Option<&OwnedFd>, name: &str, raw: &RawRun) -> Result<(), Box<dyn Error>> {
        reports.map_or(Ok(()), |directory| {
            write_report(directory, &format!("{name}.restic.id"), raw.key.as_bytes())?;
            Ok(write_report(directory, &format!("{name}.restic.snapshots"), &raw.snapshots)?)
        })
    }


    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
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


    fn restore_mode(arguments: &[String]) -> Result<(), Box<dyn Error>> {
        let declarations_path = arguments.get(ARGUMENT_DECLARATIONS + 1).ok_or(USAGE)?;
        let program = PathBuf::from(arguments.get(ARGUMENT_PROGRAM + 1).ok_or(USAGE)?);
        let declarations = load_declarations(&read_file(Path::new(declarations_path))?, declarations_path)?;
        let limits = Limits::default();
        let store_options = arguments.get(ARGUMENT_STORE_FLAG..);
        let store_path = store_options.and_then(|options| match options {
            [flag, path, ..] if flag == STORE_FLAG => Some(path.as_str()),
            _ => None,
        });
        let cap = store_options
            .and_then(|options| options.get(STORE_CAP_FLAG_OFFSET..))
            .and_then(|options| match options {
                [flag, value, ..] if flag == CAP_FLAG => Some(value.parse::<u64>()),
                _ => None,
            })
            .transpose()?
            .unwrap_or(MAX_RESTORE_ROWS);
        let mut out = stdout();
        let runs = restore_plan(&declarations);
        let declared: Vec<TestKey> = runs.runnable.iter().map(|(name, _, test)| test_key(name, test)).collect();
        let mut stored: Vec<(TestKey, RestoreResult)> = Vec::new();
        let mut failed: Vec<(TestKey, RunErrorRecord)> = Vec::new();
        runs.refused
            .iter()
            .try_for_each(|index| writeln!(out, "{}", serde_json::json!({"refused_entry": index})))?;
        runs.runnable.iter().try_for_each(|(name, source, test)| -> Result<(), Box<dyn Error>> {
            let deadline = Duration::from_secs(DEADLINE_SECONDS);
            match restore_test(&program, &declarations.tenant, source, test, &limits, deadline, OffsetDateTime::now_utc) {
                Ok(result) => {
                    stored.push((test_key(name, test), result.clone()));
                    let snapshot_time = result.snapshot_time.map(rfc3339_text);
                    let tested_at = rfc3339_text(result.tested_at);
                    let (code, skipped, gaps) = match &result.outcome {
                        RestoreOutcome::Failed { code } => (*code, None, None),
                        RestoreOutcome::ListingGap {
                            skipped,
                            future,
                            unloadable,
                            unlisted,
                        } => {
                            let by_reason: BTreeMap<&str, u64> = skipped.iter().map(|(reason, count)| (skip_label(reason), *count)).collect();
                            (None, Some(by_reason), Some([*future, *unloadable, *unlisted]))
                        }
                        _ => (None, None, None),
                    };
                    let [future, unloadable, unlisted] = gaps.map_or([None; GAP_COUNTERS], |counts| counts.map(Some));
                    let line = serde_json::json!({
                        "tenant": tenant_of(&result.tenant),
                        "repository": name,
                        "config_id": result.config_id,
                        "snapshot_id": result.snapshot_id,
                        "snapshot_time": snapshot_time.clone().flatten(),
                        "tested_at": tested_at,
                        "time_refused": tested_at.is_none() || snapshot_time == Some(None),
                        "outcome": outcome_label(&result.outcome),
                        "code": code,
                        "skipped": skipped,
                        "future": future,
                        "unloadable": unloadable,
                        "unlisted": unlisted,
                    });
                    writeln!(out, "{line}")?
                }
                Err(error) => {
                    failed.push((
                        test_key(name, test),
                        RunErrorRecord {
                            tenant: declarations.tenant.clone(),
                            tested_at: OffsetDateTime::now_utc(),
                            category: run_error_category(&error),
                        },
                    ));
                    writeln!(out, "{}", serde_json::json!({"repository": name, "failed": error.to_string()}))?
                }
            }
            Ok(())
        })?;
        store_path.map_or(Ok(()), |path| {
            store_results(path, &declarations.tenant, &stored, &failed, &declared, cap, &mut out)
        })
    }


    async fn pg_rows(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<String>) -> Result<Vec<Vec<String>>, PgError> {
        let bound: Vec<SqlParameter<'_>> = params.iter().map(|param| param as SqlParameter<'_>).collect();
        let rows = scoped_query(client, &scope, sql, &bound, Duration::from_secs(STORE_DEADLINE_SECONDS)).await?;
        rows.iter()
            .map(|row| (0..row.len()).map(|index| column_text(row, index)).collect())
            .collect()
    }


    fn store_results(
        settings_path: &str,
        tenant: &TenantScope,
        results: &[(TestKey, RestoreResult)],
        errors: &[(TestKey, RunErrorRecord)],
        declared: &[TestKey],
        cap: u64,
        out: &mut Stdout,
    ) -> Result<(), Box<dyn Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let counts = runtime.block_on(async {
            let settings = load_settings(Path::new(settings_path))?;
            let client = connect(&settings).await?;
            migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, Duration::from_secs(STORE_DEADLINE_SECONDS)).await?;
            let exec =
                |scope: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> { Box::pin(pg_rows(&client, scope, sql, params)) };
            Ok::<_, Box<dyn Error>>(record_restore_results_with_cap(&exec, tenant, results, errors, declared, cap).await?)
        })?;
        writeln!(
            out,
            "{}",
            serde_json::json!({"store": {
                "written": counts.written,
                "stale_write": counts.stale_write,
                "config_changed": counts.config_changed,
                "pruned": counts.pruned,
                "skipped_invalid": counts.skipped_invalid,
                "run_error": counts.run_error,
            }})
        )?;
        Ok(())
    }


    pub fn execute() -> Result<(), Box<dyn Error>> {
        let arguments: Vec<String> = std::env::args().collect();
        if arguments.get(1).map(String::as_str) == Some(RESTORE_MODE) {
            restore_mode(&arguments)
        } else {
            execute_runs(&arguments)
        }
    }


    fn execute_runs(arguments: &[String]) -> Result<(), Box<dyn Error>> {
        let declarations_path = arguments.get(ARGUMENT_DECLARATIONS).ok_or(USAGE)?;
        let program = PathBuf::from(arguments.get(ARGUMENT_PROGRAM).ok_or(USAGE)?);
        let base_state = arguments.get(ARGUMENT_STATE).map(Path::new);
        let declarations = load_declarations(&read_file(Path::new(declarations_path))?, declarations_path)?;
        let reports_handle = base_state
            .map(|state| report_directory(state, &declarations.tenant, euid()))
            .transpose()?;
        let state = reports_handle.as_ref();
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
                    let previous = previous_listing(state, name, &limits)?;
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
            let outcome = base_state.ok_or("borg needs a state directory".into()).and_then(|directory: &Path| {
                borg_run(
                    Path::new(BORG_PROGRAM),
                    source,
                    &declarations.tenant,
                    name,
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
                    let previous = previous_borg(state, name, source, &limits)?;
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
