//! Usage: backup_run restore-test <declarations.yaml> <restic-binary> <secrets-dir> [--store <pg.yaml> [--cap <rows>]] prints one JSON line per declared restore test (times as RFC 3339) and, with `--store`, writes the results to PostgreSQL and prints the write counts; backup_run <declarations.yaml> <restic-binary> <secrets-dir> [state-dir]: runs every declared restic and Borg repository (Unix only), prints coverage and findings; the state directory keeps the previous run (under `reports/<tenant>/`, 0600) and Borg's own base directory (required for Borg).

#[cfg(unix)]
mod run {
    use backup_monitor::borg::BORG_PROGRAM;
    use backup_monitor::check::{run_round, RoundContext};
    use backup_monitor::declarations::load_declarations;
    use backup_monitor::model::{CoverageStatus, Finding, FindingKind, Limits};
    use backup_monitor::report::report_directory;
    use backup_monitor::restore::{outcome_label, restore_plan, restore_test, skip_label, RestoreOutcome, RestoreResult, RestoreTarget};
    use backup_monitor::secrets::open_secrets_dir;
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
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use time::OffsetDateTime;
    use tokio_postgres::Client;


    const ARGUMENT_DECLARATIONS: usize = 1;


    const ARGUMENT_PROGRAM: usize = 2;


    const ARGUMENT_SECRETS: usize = 3;


    const ARGUMENT_STATE: usize = 4;


    const DEADLINE_SECONDS: u64 = 120;


    const STORE_DEADLINE_SECONDS: u64 = 30;


    const ARGUMENT_STORE_FLAG: usize = 5;


    const STORE_CAP_FLAG_OFFSET: usize = 2;


    const STORE_FLAG: &str = "--store";


    const CAP_FLAG: &str = "--cap";


    const GAP_COUNTERS: usize = 3;


    const RESTORE_MODE: &str = "restore-test";


    const USAGE: &str = "usage: backup_run [restore-test] <declarations.yaml> <restic-binary> <absolute-secrets-dir> [absolute-state-dir]";


    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }


    fn print_findings(out: &mut Stdout, name: &str, found: &[Finding]) -> std::io::Result<()> {
        found.iter().try_for_each(|finding| match &finding.kind {
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
        let secrets = open_secrets_dir(Path::new(arguments.get(ARGUMENT_SECRETS + 1).ok_or(USAGE)?), euid())?;
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
            match restore_test(
                &program,
                &secrets,
                &RestoreTarget {
                    tenant: &declarations.tenant,
                    source,
                    test,
                },
                &limits,
                deadline,
                OffsetDateTime::now_utc,
            ) {
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
        let secrets = open_secrets_dir(Path::new(arguments.get(ARGUMENT_SECRETS).ok_or(USAGE)?), euid())?;
        let base_state = arguments.get(ARGUMENT_STATE).map(Path::new);
        let declarations = load_declarations(&read_file(Path::new(declarations_path))?, declarations_path)?;
        let reports_handle = base_state
            .map(|state| report_directory(state, &declarations.tenant, euid()))
            .transpose()?;
        let limits = Limits::default();
        let context = RoundContext {
            restic_program: &program,
            borg_program: Path::new(BORG_PROGRAM),
            secrets: &secrets,
            state: base_state,
            reports: reports_handle.as_ref(),
            limits: &limits,
            deadline: Duration::from_secs(DEADLINE_SECONDS),
            euid: euid(),
            clock: OffsetDateTime::now_utc,
        };
        let mut out = stdout();
        writeln!(out, "tenant {}", tenant_of(&declarations.tenant))?;
        let round = run_round(&context, &declarations);
        round
            .refused_restic
            .iter()
            .chain(round.refused_borg.iter())
            .try_for_each(|index| writeln!(out, "refused repository entry {index}"))?;
        round.repositories.iter().try_for_each(|(name, result)| match result {
            Ok(check) => {
                writeln!(
                    out,
                    "repository {name} key {} snapshots {} skipped {:?}",
                    check.listing.repository,
                    check.listing.snapshots.len(),
                    check.listing.skipped
                )?;
                if check.previous_unreadable {
                    writeln!(out, "repository {name} previous_unreadable")?;
                }
                print_findings(&mut out, name, &check.findings)
            }
            Err(error) => writeln!(out, "repository {name} failed: {error}"),
        })?;
        round.coverage.iter().try_for_each(|entry| match &entry.status {
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
