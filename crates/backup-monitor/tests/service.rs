#![cfg(unix)]


#[path = "common/site.rs"]
mod site;
#[path = "common/types.rs"]
mod types;


use backup_monitor::borg::private_handle;
use backup_monitor::declarations::load_declarations;
use backup_monitor::error::{BackupError, RestoreStoreError};
use backup_monitor::model::Limits;
use backup_monitor::report::report_directory;
use backup_monitor::secrets::open_secrets_dir;
use backup_monitor::serve::{
    exit_code, interrupt_wait, production_options, refuse_root, reload_audit, run_job, run_main, run_with_euid, start, Cursor, StartOptions,
};
use backup_monitor::service::{
    check_outcome, check_parameters, check_round, declarations_refusal, declarations_state, failure_category, load_settings, may_start_after,
    next_due, open_declarations_engine, open_service_settings_from, production_programs, production_timing, restore_outcome, restore_round,
    settings_state, start_only_changed, state_identity, validate_settings, Programs, ServiceSettings, Shared, StoreFailure, Timing,
    MAX_INTERVAL_SECONDS, MAX_ROUND_SECONDS, MIN_INTERVAL_SECONDS, TENANT_SWAP_REASON,
};
use backup_monitor::store::{category_label, run_error_category};
use backup_monitor::types::{InterruptWait, SettingsReader};
use core_audit::log::open_file_log;
use core_audit::model::Outcome;
use core_audit::model::Record;
use core_config::error::ConfigError;
use core_config::reload::{reload, ReloadOutcome};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use site::{declarations_text, site, Site, CANARY, CONFIG_ID, PG_PASSWORD, PRIVATE_DIRECTORY};
use std::error::Error;
use std::fs;
use std::future::{pending, ready};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use time::macros::datetime;
use time::OffsetDateTime;
use tokio::sync::oneshot;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-backup-monitor");


const PATIENT: Duration = Duration::from_secs(120);


const ONE_ROUND: usize = 1;


const TWO_ROUNDS: usize = 2;


const TWO: usize = 2;


const THREE: usize = 3;


const FOUR: usize = 4;


const FIRST: usize = 0;


const SECOND: usize = 1;


const ATTEMPTS: usize = 600;


const POLL: Duration = Duration::from_millis(50);


const SHORT_INTERVAL: u64 = 1;


const LIVE_INTERVAL: u64 = 7200;


const BAD_INTERVAL: u64 = 3599;


const TOO_LONG_INTERVAL: u64 = 86_401;


const FAR_NOW: u64 = 10_000;


const SECOND_PLANNED: u64 = 7200;


const NO_CONNECTION_PORT: u16 = 1;


const WORLD_READABLE: u32 = 0o755;


const SETTING_COUNT: usize = 8;


const DIGEST_LENGTH: usize = 64;


const GUARD: Duration = Duration::from_secs(60);


static LOGGING: LazyLock<bool> =
    LazyLock::new(|| tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(io::sink).finish()).is_ok());


fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}


const NOW: OffsetDateTime = datetime!(2026-11-20 12:00 UTC);


fn clock() -> OffsetDateTime {
    NOW
}


fn timing(max_round: Duration) -> Timing {
    Timing {
        command_deadline: PATIENT,
        max_round,
    }
}


fn reader() -> SettingsReader {
    Arc::new(|file: &Path| load_settings(file))
}


fn options(site: &Site, rounds: usize, max_round: Duration) -> StartOptions {
    StartOptions {
        programs: Programs {
            restic: site.restic.clone(),
            borg: PathBuf::from("/nonexistent/borg"),
        },
        timing: timing(max_round),
        read: reader(),
        rounds,
        euid: euid(),
        clock,
    }
}


fn never() -> InterruptWait {
    Box::pin(pending())
}


fn recording() -> Handler {
    Arc::new(|sql| {
        if sql.contains("backup_restore_record") {
            Reply::Rows(vec![["ok", "1", "0", "0", "0", "1"].iter().map(|cell| (*cell).to_owned()).collect()])
        } else {
            Reply::Done
        }
    })
}


fn accepting() -> Handler {
    Arc::new(|_| Reply::Done)
}


async fn fake_with(handler: Handler) -> Result<(Fake, String), Box<dyn Error>> {
    LazyLock::force(&LOGGING);
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler).await?;
    Ok((fake, pki.ca_pem))
}


async fn running_site(handler: Handler, declarations: &str) -> Result<(Fake, Site), Box<dyn Error>> {
    let (fake, ca_pem) = fake_with(handler).await?;
    let built = site(fake.port, &ca_pem, declarations)?;
    Ok((fake, built))
}


fn records(site: &Site) -> Result<Vec<Record>, Box<dyn Error>> {
    fs::read_to_string(&site.audit)?
        .lines()
        .map(|line| Ok(serde_json::from_str::<Record>(line)?))
        .collect()
}


fn args_lines(site: &Site) -> usize {
    fs::read_to_string(site.bin.join("args")).map_or(0, |text| text.lines().count())
}


async fn wait_for(path: &Path) -> TestResult {
    let mut attempts = 0;
    while !path.exists() && attempts < ATTEMPTS {
        tokio::time::sleep(POLL).await;
        attempts += 1;
    }
    if path.exists() {
        Ok(())
    } else {
        Err("the file never appeared".into())
    }
}


async fn wait_for_records(site: &Site, wanted: usize) -> TestResult {
    let mut attempts = 0;
    while fs::read_to_string(&site.audit).map_or(0, |text| text.lines().count()) < wanted && attempts < ATTEMPTS {
        tokio::time::sleep(POLL).await;
        attempts += 1;
    }
    if fs::read_to_string(&site.audit).map_or(0, |text| text.lines().count()) >= wanted {
        Ok(())
    } else {
        Err("the audit records never appeared".into())
    }
}


fn interrupt_from(receiver: oneshot::Receiver<()>) -> InterruptWait {
    Box::pin(async move { receiver.await.map_err(|_closed| io::Error::other("sender dropped")) })
}


fn shared_for(site: &Site, max_round: Duration) -> Result<Shared, Box<dyn Error>> {
    let scope = tenant_scope("acme")?;
    let state_handle = private_handle(&site.state, euid())?;
    Ok(Shared {
        programs: Programs {
            restic: site.restic.clone(),
            borg: PathBuf::from("/nonexistent/borg"),
        },
        secrets: open_secrets_dir(&site.secrets, euid())?,
        state: site.state.clone(),
        state_identity: state_identity(&state_handle)?,
        reports: report_directory(&site.state, &scope, euid())?,
        limits: Limits::default(),
        timing: timing(max_round),
        euid: euid(),
        clock,
    })
}


fn plain_site(names: &[&str], tested: usize) -> Result<Site, Box<dyn Error>> {
    LazyLock::force(&LOGGING);
    site(NO_CONNECTION_PORT, "", &declarations_text("acme", names, tested))
}


fn declarations_of(site: &Site) -> Result<backup_monitor::model::Declarations, Box<dyn Error>> {
    Ok(load_declarations(&fs::read_to_string(&site.declarations)?, "declarations.yaml")?)
}


fn names_of(round: &backup_monitor::check::RoundOutcome) -> Vec<&str> {
    round.repositories.iter().map(|(name, _)| name.as_str()).collect()
}


#[test]
fn the_next_due_second_skips_every_missed_tick() -> TestResult {
    assert_eq!(next_due(0, MIN_INTERVAL_SECONDS, 0), (MIN_INTERVAL_SECONDS, 0));
    assert_eq!(next_due(0, MIN_INTERVAL_SECONDS, MIN_INTERVAL_SECONDS - 1), (MIN_INTERVAL_SECONDS, 0));
    assert_eq!(next_due(0, MIN_INTERVAL_SECONDS, MIN_INTERVAL_SECONDS), (SECOND_PLANNED, 1));
    assert_eq!(
        next_due(0, MIN_INTERVAL_SECONDS, FAR_NOW),
        (SECOND_PLANNED + MIN_INTERVAL_SECONDS, TWO as u64)
    );
    assert_eq!(next_due(u64::MAX, 1, u64::MAX), (u64::MAX, 1));
    Ok(())
}


#[test]
fn a_command_may_start_only_before_the_stop_and_the_bound_but_the_first_always_does() -> TestResult {
    let stop = AtomicBool::new(false);
    let started = std::time::Instant::now();
    assert!(may_start_after(&stop, started, Duration::ZERO, 0));
    assert!(!may_start_after(&stop, started, Duration::ZERO, 1));
    assert!(may_start_after(&stop, started, Duration::from_secs(MAX_ROUND_SECONDS), 1));
    stop.store(true, Ordering::SeqCst);
    assert!(!may_start_after(&stop, started, Duration::from_secs(MAX_ROUND_SECONDS), 0));
    Ok(())
}


#[test]
fn the_round_bound_is_below_the_smallest_interval() -> TestResult {
    assert!(production_timing().max_round <= Duration::from_secs(MIN_INTERVAL_SECONDS));
    assert_eq!(production_timing().max_round, Duration::from_secs(MAX_ROUND_SECONDS));
    assert_eq!(production_programs().restic, PathBuf::from(backup_monitor::restic::RESTIC_PROGRAM));
    assert_eq!(production_programs().borg, PathBuf::from(backup_monitor::borg::BORG_PROGRAM));
    Ok(())
}


#[test]
fn root_is_refused_and_an_exit_code_follows_the_result() -> TestResult {
    assert!(refuse_root(0).is_err_and(|reason| reason.contains("root")));
    assert!(refuse_root(1).is_ok());
    assert_eq!(format!("{:?}", exit_code(Ok(()))), format!("{:?}", std::process::ExitCode::SUCCESS));
    assert_eq!(
        format!("{:?}", exit_code(Err("x".into()))),
        format!("{:?}", std::process::ExitCode::FAILURE)
    );
    Ok(())
}


fn settings_value(site: &Site) -> Result<ServiceSettings, ConfigError> {
    load_settings(&site.settings)
}


#[test]
fn the_settings_are_bounded_and_only_the_intervals_are_live() -> TestResult {
    let site = plain_site(&["alpha"], 0)?;
    let base = settings_value(&site)?;
    let with = |change: fn(&mut ServiceSettings)| {
        let mut copy = base.clone();
        change(&mut copy);
        copy
    };
    assert!(validate_settings(&base).is_ok());
    assert!(validate_settings(&with(|settings| settings.tenant = "all".to_owned())).is_err());
    assert!(validate_settings(&with(|settings| settings.interval_seconds = BAD_INTERVAL)).is_err());
    assert!(validate_settings(&with(|settings| settings.interval_seconds = TOO_LONG_INTERVAL)).is_err());
    assert!(validate_settings(&with(|settings| settings.restore_interval_seconds = BAD_INTERVAL)).is_err());
    assert!(validate_settings(&with(|settings| settings.restore_interval_seconds = MAX_INTERVAL_SECONDS)).is_ok());
    assert!(!start_only_changed(&base, &with(|settings| settings.interval_seconds = LIVE_INTERVAL)));
    assert!(!start_only_changed(
        &base,
        &with(|settings| settings.restore_interval_seconds = LIVE_INTERVAL)
    ));
    assert!(start_only_changed(&base, &with(|settings| settings.tenant = "other".to_owned())));
    assert!(start_only_changed(&base, &with(|settings| settings.audit_file = PathBuf::from("/x"))));
    assert!(start_only_changed(&base, &with(|settings| settings.secrets_dir = PathBuf::from("/x"))));
    assert!(start_only_changed(&base, &with(|settings| settings.state_dir = PathBuf::from("/x"))));
    assert!(start_only_changed(&base, &with(|settings| settings.pg_settings = PathBuf::from("/x"))));
    assert!(start_only_changed(
        &base,
        &with(|settings| settings.declarations_file = PathBuf::from("/x"))
    ));
    assert_eq!(settings_state(&base).len(), SETTING_COUNT);
    Ok(())
}


#[test]
fn an_unknown_settings_key_is_refused() -> TestResult {
    let site = plain_site(&["alpha"], 0)?;
    fs::write(&site.settings, format!("{}extra: 1\n", fs::read_to_string(&site.settings)?))?;
    assert!(load_settings(&site.settings).is_err());
    Ok(())
}


fn audit_for(site: &Site) -> Result<Arc<core_audit::log::AuditLog<fs::File>>, Box<dyn Error>> {
    Ok(Arc::new(open_file_log(&site.audit)?))
}


#[test]
fn a_settings_reload_applies_the_intervals_and_refuses_a_start_only_change_audited_under_all() -> TestResult {
    let site = plain_site(&["alpha"], 0)?;
    let log = audit_for(&site)?;
    let baseline = settings_value(&site)?;
    let engine = open_service_settings_from(&site.settings, baseline, reader(), reload_audit(&log))?;
    let original = fs::read_to_string(&site.settings)?;
    fs::write(
        &site.settings,
        original.replace("interval_seconds: 3600\nrestore", "interval_seconds: 7200\nrestore"),
    )?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    fs::write(&site.settings, original.replace("tenant: acme", "tenant: other"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    fs::write(&site.settings, "tenant: [\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    let written = records(&site)?;
    assert_eq!(written.len(), THREE);
    assert!(written.iter().all(|record| record.tenant == "all"));
    assert!(written.iter().any(|record| format!("{:?}", record.outcome) == "Denied"));
    Ok(())
}


#[test]
fn a_declarations_swap_to_another_tenant_is_refused_whole_and_audited_denied_under_all() -> TestResult {
    let site = plain_site(&["alpha"], 0)?;
    let log = audit_for(&site)?;
    let engine = open_declarations_engine(&site.declarations, "acme", reload_audit(&log))?;
    fs::write(&site.declarations, declarations_text("victim", &["alpha"], 0))?;
    let outcome = reload(&engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains(TENANT_SWAP_REASON)),
        "{outcome:?}"
    );
    let current = core_config::reload::current_config(&engine);
    assert_eq!(core_pg::scope::tenant_of(&current.tenant), "acme");
    let written = records(&site)?;
    let last = written.last().ok_or("no record")?;
    assert_eq!(last.tenant, "all");
    assert_eq!(format!("{:?}", last.outcome), "Denied");
    assert!(!fs::read_to_string(&site.audit)?.contains("victim"));
    Ok(())
}


#[test]
fn a_declarations_start_with_another_tenant_is_refused() -> TestResult {
    let site = plain_site(&["alpha"], 0)?;
    let log = audit_for(&site)?;
    assert!(open_declarations_engine(&site.declarations, "other", reload_audit(&log)).is_err());
    assert!(open_declarations_engine(&site.dir.path().join("absent.yaml"), "acme", reload_audit(&log)).is_err());
    Ok(())
}


#[test]
fn a_declarations_reload_audits_digests_never_a_location_and_refuses_an_alias() -> TestResult {
    let site = plain_site(&["alpha"], 0)?;
    let log = audit_for(&site)?;
    let engine = open_declarations_engine(&site.declarations, "acme", reload_audit(&log))?;
    fs::write(&site.declarations, declarations_text("acme", &["alpha", "beta"], 0))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    fs::write(
        &site.declarations,
        "tenant: acme\ncritical:\n  - &a\n    host: web1\n    max_age_hours: 1\n",
    )?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    fs::write(
        &site.declarations,
        "tenant: acme\nrepositories:\n  - repository: -bad\n    expected_min_snapshots: 1\n",
    )?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    let text = fs::read_to_string(&site.audit)?;
    assert!(!text.contains("/srv/alpha"));
    assert!(!text.contains("password"));
    assert!(text.contains("repository.beta"));
    Ok(())
}


#[test]
fn the_declarations_state_names_repositories_and_hides_their_text() -> TestResult {
    let site = plain_site(&["alpha"], 1)?;
    let state = declarations_state(&declarations_of(&site)?);
    assert!(state.contains_key("repository.alpha") && state.contains_key("critical") && state.contains_key("tenant"));
    assert!(state.values().all(|value| !value.contains("/srv/alpha")));
    Ok(())
}


#[test]
fn a_refusal_keeps_its_fixed_reason() -> TestResult {
    let tenant = declarations_refusal(BackupError::InvalidDeclarations { what: "entry count" });
    assert!(tenant.to_string().contains("entry count"));
    let kept = declarations_refusal(BackupError::Declarations(ConfigError::WatchedFile {
        file: "f".to_owned(),
        reason: "r".to_owned(),
    }));
    assert!(kept.to_string().contains("`f`"));
    Ok(())
}


#[test]
fn a_store_failure_has_a_fixed_category() -> TestResult {
    assert_eq!(failure_category(&StoreFailure::Connect(PgError::InvalidTenant)), "connect");
    assert_eq!(failure_category(&StoreFailure::Record(RestoreStoreError::BadRow)), "record");
    assert_eq!(
        category_label(run_error_category(&backup_monitor::restic::ResticError::Timeout)),
        "timeout"
    );
    Ok(())
}


#[test]
fn a_full_check_round_runs_every_repository_and_a_cut_round_rotates_through_them() -> TestResult {
    let site = plain_site(&["alpha", "beta", "gamma"], 0)?;
    let declarations = declarations_of(&site)?;
    let stop = AtomicBool::new(false);
    let full = check_round(&shared_for(&site, Duration::from_secs(MAX_ROUND_SECONDS))?, &declarations, FIRST, &stop)?;
    assert_eq!(names_of(&full), ["alpha", "beta", "gamma"]);
    assert!(full.not_run.is_empty() && !full.coverage.is_empty());
    assert_eq!(full.next_start, FIRST);
    let before = args_lines(&site);
    let shared = shared_for(&site, Duration::ZERO)?;
    let first = check_round(&shared, &declarations, FIRST, &stop)?;
    assert_eq!(names_of(&first), ["alpha"]);
    assert_eq!(first.not_run, ["beta", "gamma"]);
    assert_eq!(first.next_start, SECOND);
    assert!(first.coverage.is_empty());
    let second = check_round(&shared, &declarations, first.next_start, &stop)?;
    assert_eq!(names_of(&second), ["beta"]);
    assert_eq!(second.not_run, ["gamma", "alpha"]);
    assert_eq!(second.next_start, TWO);
    let third = check_round(&shared, &declarations, second.next_start, &stop)?;
    assert_eq!(names_of(&third), ["gamma"]);
    assert_eq!(third.next_start, FIRST);
    assert_eq!(args_lines(&site) - before, THREE * TWO);
    let wrapped = check_round(&shared, &declarations, FOUR, &stop)?;
    assert_eq!(names_of(&wrapped), ["beta"]);
    Ok(())
}


#[test]
fn a_stopped_round_starts_nothing() -> TestResult {
    let site = plain_site(&["alpha", "beta"], TWO)?;
    let declarations = declarations_of(&site)?;
    let stop = AtomicBool::new(true);
    let shared = shared_for(&site, Duration::from_secs(MAX_ROUND_SECONDS))?;
    let check = check_round(&shared, &declarations, FIRST, &stop)?;
    assert!(check.repositories.is_empty());
    assert_eq!(check.not_run.len(), TWO);
    let restore = restore_round(&shared, &declarations, FIRST, &stop)?;
    assert!(restore.results.is_empty() && restore.errors.is_empty());
    assert_eq!(restore.not_run, TWO);
    assert_eq!(restore.declared.len(), TWO);
    assert_eq!(args_lines(&site), 0);
    Ok(())
}


#[test]
fn a_failing_repository_is_its_own_failure_and_the_others_still_run() -> TestResult {
    let site = plain_site(&["alpha", "beta"], TWO)?;
    let declarations = declarations_of(&site)?;
    fs::write(site.bin.join("fail_dump"), "")?;
    let stop = AtomicBool::new(false);
    let shared = shared_for(&site, Duration::from_secs(MAX_ROUND_SECONDS))?;
    let dumped = restore_round(&shared, &declarations, FIRST, &stop)?;
    assert_eq!(dumped.results.len(), TWO);
    assert!(dumped.errors.is_empty());
    fs::remove_file(site.bin.join("fail_dump"))?;
    fs::write(site.bin.join("fail_config"), "")?;
    let restore = restore_round(&shared, &declarations, FIRST, &stop)?;
    assert_eq!(restore.errors.len(), TWO);
    assert!(restore.results.is_empty());
    let check = check_round(&shared, &declarations, FIRST, &stop)?;
    assert!(check.repositories.iter().all(|(_, result)| result.is_err()));
    assert_eq!(check.repositories.len(), TWO);
    Ok(())
}


#[test]
fn a_restore_round_rotates_and_counts_a_refused_entry() -> TestResult {
    let site = plain_site(&["alpha", "beta"], TWO)?;
    fs::write(
        &site.declarations,
        format!(
            "{}  - repository: delta\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/delta\n      password_file: password\n    restore_test:\n      \
             host: web1\n      path: /etc/passwd\n      sha256: {}\n      max_bytes: 100\n",
            declarations_text("acme", &["alpha", "beta"], TWO),
            "0".repeat(DIGEST_LENGTH)
        ),
    )?;
    let declarations = declarations_of(&site)?;
    let stop = AtomicBool::new(false);
    let shared = shared_for(&site, Duration::ZERO)?;
    let first = restore_round(&shared, &declarations, FIRST, &stop)?;
    assert_eq!((first.results.len(), first.not_run, first.next_start, first.refused), (1, 1, 1, 1));
    let second = restore_round(&shared, &declarations, first.next_start, &stop)?;
    assert_eq!((second.results.len(), second.not_run, second.next_start), (1, 1, FIRST));
    let full = restore_round(&shared_for(&site, Duration::from_secs(MAX_ROUND_SECONDS))?, &declarations, FIRST, &stop)?;
    assert_eq!((full.results.len(), full.not_run), (TWO, 0));
    assert!(full.results.iter().all(|(_, result)| result.config_id == CONFIG_ID));
    Ok(())
}


#[test]
fn a_state_directory_that_is_not_the_one_opened_at_start_spawns_nothing() -> TestResult {
    let site = plain_site(&["alpha"], 1)?;
    let declarations = declarations_of(&site)?;
    let stop = AtomicBool::new(false);
    let shared = shared_for(&site, Duration::from_secs(MAX_ROUND_SECONDS))?;
    fs::rename(&site.state, site.dir.path().join("state.moved"))?;
    site::private_dir(&site.state)?;
    assert!(check_round(&shared, &declarations, FIRST, &stop).is_err_and(|refusal| refusal.to_string().contains("not the one opened at start")));
    assert!(restore_round(&shared, &declarations, FIRST, &stop).is_err());
    fs::set_permissions(&site.state, fs::Permissions::from_mode(WORLD_READABLE))?;
    assert!(check_round(&shared, &declarations, FIRST, &stop).is_err_and(|refusal| refusal.to_string().contains("refused")));
    assert_eq!(args_lines(&site), 0);
    Ok(())
}


#[tokio::test]
async fn a_round_stores_the_restore_results_under_the_pinned_tenant_and_audits_under_all() -> TestResult {
    let (mut fake, site) = running_site(recording(), &declarations_text("acme", &["alpha", "beta"], 1)).await?;
    start(&site.settings, options(&site, ONE_ROUND, Duration::from_secs(MAX_ROUND_SECONDS)), never()).await?;
    let written = records(&site)?;
    assert_eq!(written.len(), TWO);
    assert!(written.iter().all(|record| record.tenant == "all" && record.module == "backup-monitor"));
    let restore = written
        .iter()
        .find(|record| record.action == "backup.restore_round")
        .ok_or("no restore record")?;
    assert_eq!(restore.parameters.get("store").map(String::as_str), Some("ok"));
    assert_eq!(restore.parameters.get("restored").map(String::as_str), Some("1"));
    let check = written
        .iter()
        .find(|record| record.action == "backup.check_round")
        .ok_or("no check record")?;
    assert_eq!(check.parameters.get("repositories").map(String::as_str), Some("2"));
    assert_eq!(check.parameters.get("coverage_ok").map(String::as_str), Some("1"));
    assert_eq!(check.target, "acme");
    let statements: Vec<String> = std::iter::from_fn(|| fake.statements.try_recv().ok()).collect();
    let record = statements
        .iter()
        .rposition(|statement| statement.starts_with("SELECT outcome") && statement.contains("backup_restore_record"))
        .ok_or("no store statement")?;
    assert!(
        statements.get(record + 1).is_some_and(|params| params.starts_with("PARAMS acme|")),
        "{statements:?}"
    );
    let text = fs::read_to_string(&site.audit)?;
    assert!(!text.contains("/srv/") && !text.contains("hunter2") && !text.contains("password"));
    Ok(())
}


#[tokio::test]
async fn a_failing_store_is_a_named_category_and_the_round_still_ends() -> TestResult {
    let (_fake, site) = running_site(accepting(), &declarations_text("acme", &["alpha"], 1)).await?;
    start(&site.settings, options(&site, ONE_ROUND, Duration::from_secs(MAX_ROUND_SECONDS)), never()).await?;
    let written = records(&site)?;
    let restore = written
        .iter()
        .find(|record| record.action == "backup.restore_round")
        .ok_or("no restore record")?;
    assert_eq!(restore.parameters.get("store").map(String::as_str), Some("record"));
    assert_eq!(format!("{:?}", restore.outcome), "Failure");
    Ok(())
}


#[tokio::test]
async fn a_database_that_cannot_be_reached_stops_the_start_and_a_later_store_failure_is_connect() -> TestResult {
    let site = plain_site(&["alpha"], 1)?;
    assert!(start(&site.settings, options(&site, ONE_ROUND, PATIENT), never()).await.is_err());
    let (fake, ready_site) = running_site(accepting(), &declarations_text("acme", &["alpha"], 1)).await?;
    let pg = core_pg::settings::load_settings(&ready_site.pg)?;
    let broken = core_pg::settings::PgSettings {
        port: NO_CONNECTION_PORT,
        ..pg
    };
    let scope = tenant_scope("acme")?;
    let run = backup_monitor::service::RestoreRun {
        results: Vec::new(),
        errors: Vec::new(),
        declared: Vec::new(),
        refused: 0,
        not_run: 0,
        next_start: 0,
    };
    let failure = backup_monitor::service::store_restore(&broken, &scope, &run).await;
    assert!(matches!(failure, Err(StoreFailure::Connect(_))));
    drop(fake);
    Ok(())
}


#[tokio::test]
async fn the_start_reads_the_settings_file_once_and_a_second_read_that_differs_is_refused() -> TestResult {
    let (_fake, site) = running_site(accepting(), &declarations_text("acme", &["alpha"], 0)).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let other_audit = site.dir.path().join("other-audit.log");
    let counted = Arc::clone(&calls);
    let swapping: SettingsReader = Arc::new(move |file: &Path| {
        let mut settings = load_settings(file)?;
        if counted.fetch_add(1, Ordering::SeqCst) > 0 {
            settings.audit_file = other_audit.clone();
        }
        Ok(settings)
    });
    let mut built = options(&site, ONE_ROUND, PATIENT);
    built.read = swapping;
    let error = start(&site.settings, built, never()).await.err().ok_or("the start must refuse")?;
    assert!(error.to_string().contains("start-only"), "{error}");
    assert!(!site.dir.path().join("other-audit.log").exists());
    Ok(())
}


#[tokio::test]
async fn the_start_reads_the_settings_file_exactly_twice_when_nothing_changes() -> TestResult {
    let (_fake, site) = running_site(accepting(), &declarations_text("acme", &["alpha"], 0)).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let counting: SettingsReader = Arc::new(move |file: &Path| {
        counted.fetch_add(1, Ordering::SeqCst);
        load_settings(file)
    });
    let mut built = options(&site, FIRST, PATIENT);
    built.read = counting;
    start(&site.settings, built, never()).await?;
    assert_eq!(calls.load(Ordering::SeqCst), TWO);
    Ok(())
}


#[tokio::test]
async fn two_passes_run_both_schedules_each_time() -> TestResult {
    let (_fake, site) = running_site(recording(), &declarations_text("acme", &["alpha"], 1)).await?;
    let quick: SettingsReader = Arc::new(|file: &Path| {
        let mut settings = load_settings(file)?;
        settings.interval_seconds = SHORT_INTERVAL;
        settings.restore_interval_seconds = SHORT_INTERVAL;
        Ok(settings)
    });
    let mut built = options(&site, TWO_ROUNDS, Duration::from_secs(MAX_ROUND_SECONDS));
    built.read = quick;
    start(&site.settings, built, never()).await?;
    assert_eq!(records(&site)?.len(), FOUR);
    Ok(())
}


#[tokio::test]
async fn an_interrupt_during_a_check_round_starts_no_new_command_and_ends_cleanly() -> TestResult {
    let (_fake, site) = running_site(recording(), &declarations_text("acme", &["alpha", "beta"], 0)).await?;
    fs::write(site.bin.join("block"), "config")?;
    let (sender, receiver) = oneshot::channel();
    let service = start(
        &site.settings,
        options(&site, usize::MAX, Duration::from_secs(MAX_ROUND_SECONDS)),
        interrupt_from(receiver),
    );
    let driver = async {
        wait_for(&site.bin.join("blocked")).await?;
        sender.send(()).map_err(|()| "the service ended early")?;
        fs::write(site.bin.join("release"), "")?;
        Ok::<(), Box<dyn Error>>(())
    };
    let (ended, driven) = tokio::join!(service, driver);
    ended?;
    driven?;
    assert_eq!(args_lines(&site), TWO);
    let written = records(&site)?;
    assert_eq!(written.len(), ONE_ROUND);
    assert_eq!(
        written.first().and_then(|record| record.parameters.get("not_run")).map(String::as_str),
        Some("1")
    );
    Ok(())
}


#[tokio::test]
async fn an_interrupt_during_a_restore_round_starts_no_new_command_and_ends_cleanly() -> TestResult {
    let (_fake, site) = running_site(recording(), &declarations_text("acme", &["alpha", "beta"], TWO)).await?;
    fs::write(site.bin.join("block"), "dump")?;
    let (sender, receiver) = oneshot::channel();
    let service = start(
        &site.settings,
        options(&site, usize::MAX, Duration::from_secs(MAX_ROUND_SECONDS)),
        interrupt_from(receiver),
    );
    let driver = async {
        wait_for(&site.bin.join("blocked")).await?;
        sender.send(()).map_err(|()| "the service ended early")?;
        fs::write(site.bin.join("release"), "")?;
        Ok::<(), Box<dyn Error>>(())
    };
    let (ended, driven) = tokio::join!(service, driver);
    ended?;
    driven?;
    let dumps = fs::read_to_string(site.bin.join("args"))?
        .lines()
        .filter(|line| line.contains(" dump "))
        .count();
    assert_eq!(dumps, ONE_ROUND);
    let written = records(&site)?;
    let restore = written
        .iter()
        .find(|record| record.action == "backup.restore_round")
        .ok_or("no restore record")?;
    assert_eq!(restore.parameters.get("not_run").map(String::as_str), Some("1"));
    Ok(())
}


#[tokio::test]
async fn an_interrupt_while_waiting_for_the_next_round_ends_cleanly() -> TestResult {
    let (_fake, site) = running_site(recording(), &declarations_text("acme", &["alpha"], 1)).await?;
    let (sender, receiver) = oneshot::channel();
    let service = start(
        &site.settings,
        options(&site, usize::MAX, Duration::from_secs(MAX_ROUND_SECONDS)),
        interrupt_from(receiver),
    );
    let driver = async {
        wait_for_records(&site, TWO).await?;
        sender.send(()).map_err(|()| "the service ended early")?;
        Ok::<(), Box<dyn Error>>(())
    };
    let (ended, driven) = tokio::join!(service, driver);
    ended?;
    driven?;
    assert_eq!(records(&site)?.len(), TWO);
    Ok(())
}


#[tokio::test]
async fn a_failing_interrupt_wait_is_an_error_in_a_round_and_while_waiting() -> TestResult {
    let (_fake, site) = running_site(recording(), &declarations_text("acme", &["alpha"], 0)).await?;
    let failing: InterruptWait = Box::pin(ready(Err(io::Error::other("no signal"))));
    let error = start(&site.settings, options(&site, usize::MAX, PATIENT), failing)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(error.to_string().contains("no signal"));
    let (sender, receiver) = oneshot::channel::<()>();
    drop(sender);
    let late: InterruptWait = interrupt_from(receiver);
    let stop = AtomicBool::new(false);
    let other = run_job(|| (), &stop, &mut late_failure()).await;
    assert!(other.is_err());
    drop(late);
    Ok(())
}


fn late_failure() -> InterruptWait {
    Box::pin(ready(Err(io::Error::other("no signal"))))
}


#[tokio::test]
async fn a_job_that_ends_first_returns_its_value_not_interrupted() -> TestResult {
    let stop = AtomicBool::new(false);
    let mut wait = never();
    let (value, interrupted) = run_job(|| THREE, &stop, &mut wait).await?;
    assert_eq!((value, interrupted), (THREE, false));
    assert!(!stop.load(Ordering::SeqCst));
    Ok(())
}


#[tokio::test]
async fn the_start_refuses_every_unusable_input() -> TestResult {
    let (_fake, site) = running_site(accepting(), &declarations_text("acme", &["alpha"], 0)).await?;
    let good = fs::read_to_string(&site.settings)?;
    assert!(start(&site.dir.path().join("absent.yaml"), options(&site, FIRST, PATIENT), never())
        .await
        .is_err());
    fs::write(
        &site.settings,
        good.replace(&site.audit.display().to_string(), "/nonexistent/dir/audit.log"),
    )?;
    assert!(start(&site.settings, options(&site, FIRST, PATIENT), never()).await.is_err());
    fs::write(&site.settings, &good)?;
    fs::set_permissions(&site.secrets, fs::Permissions::from_mode(WORLD_READABLE))?;
    assert!(start(&site.settings, options(&site, FIRST, PATIENT), never()).await.is_err());
    fs::set_permissions(&site.secrets, fs::Permissions::from_mode(PRIVATE_DIRECTORY))?;
    fs::set_permissions(&site.state, fs::Permissions::from_mode(WORLD_READABLE))?;
    assert!(start(&site.settings, options(&site, FIRST, PATIENT), never()).await.is_err());
    fs::set_permissions(&site.state, fs::Permissions::from_mode(PRIVATE_DIRECTORY))?;
    fs::remove_file(&site.pg)?;
    assert!(start(&site.settings, options(&site, FIRST, PATIENT), never()).await.is_err());
    Ok(())
}


#[tokio::test]
async fn the_production_entry_checks_the_arguments_then_refuses_root() -> TestResult {
    let site = plain_site(&["alpha"], 0)?;
    let file = site.settings.display().to_string();
    let usage = run_with_euid(&[], never(), 1).await.err().ok_or("usage")?;
    assert!(usage.to_string().contains("usage: ostyr-backup-monitor"));
    assert!(run_with_euid(&[file.clone(), file.clone()], never(), 1).await.is_err());
    let root = run_with_euid(std::slice::from_ref(&file), never(), 0).await.err().ok_or("root")?;
    assert!(root.to_string().contains("refusing to run as root"));
    let missing = run_with_euid(&[format!("{file}.absent")], never(), 1).await.err().ok_or("missing")?;
    assert!(missing.to_string().contains("absent"));
    assert_eq!(production_options(1).rounds, usize::MAX);
    Ok(())
}


#[tokio::test]
async fn the_interrupt_wait_resolves_on_sigterm_and_on_sigint() -> TestResult {
    let pid = rustix::process::getpid();
    let first = interrupt_wait()?;
    rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
    tokio::time::timeout(GUARD, first).await??;
    let second = interrupt_wait()?;
    rustix::process::kill_process(pid, rustix::process::Signal::INT)?;
    tokio::time::timeout(GUARD, second).await??;
    Ok(())
}


#[test]
fn the_cursor_starts_at_zero() -> TestResult {
    assert_eq!(
        Cursor::default(),
        Cursor {
            check_due: 0,
            restore_due: 0,
            check_start: 0,
            restore_start: 0
        }
    );
    let canary = CANARY;
    assert!(!canary.is_empty());
    Ok(())
}


fn spawn_binary(arguments: &[&Path]) -> Result<Child, Box<dyn Error>> {
    Ok(Command::new(PROGRAM)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?)
}


fn refused_with(arguments: &[&Path], marker: &str) -> TestResult {
    let output = spawn_binary(arguments)?.wait_with_output()?;
    let text = String::from_utf8(output.stderr)?;
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


#[test]
fn the_binary_prints_the_usage_and_fails_without_one_argument() -> TestResult {
    refused_with(&[], "usage: ostyr-backup-monitor <settings.yaml>")?;
    refused_with(&[Path::new("a"), Path::new("b")], "usage: ostyr-backup-monitor")
}


#[test]
fn the_binary_refuses_an_invalid_settings_file_or_root() -> TestResult {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let file = dir.path().join("backup-monitor.yaml");
    fs::write(&file, "tenant: [\n")?;
    let marker = if euid() == 0 { "refusing to run as root" } else { "backup-monitor.yaml" };
    refused_with(&[&file], marker)
}


fn signal(child: &Child, name: &str) -> TestResult {
    let status = Command::new("kill").arg(format!("-{name}")).arg(child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


async fn serve_and_stop(name: &str) -> TestResult {
    let (_fake, site) = running_site(recording(), &declarations_text("acme", &["alpha"], 1)).await?;
    let child = spawn_binary(&[&site.settings])?;
    if euid() == 0 {
        let output = child.wait_with_output()?;
        assert!(String::from_utf8(output.stderr)?.contains("refusing to run as root"));
        assert!(!output.status.success());
    } else {
        wait_for_records(&site, TWO).await?;
        signal(&child, name)?;
        let output = child.wait_with_output()?;
        let text = String::from_utf8(output.stderr)?;
        assert!(output.status.success(), "{text}");
        assert!(text.contains("serving"), "{text}");
        assert_eq!(records(&site)?.len(), TWO);
    }
    Ok(())
}


#[tokio::test]
async fn the_binary_serves_a_round_and_exits_zero_on_sigint() -> TestResult {
    serve_and_stop("INT").await
}


#[tokio::test]
async fn the_binary_serves_a_round_and_exits_zero_on_sigterm() -> TestResult {
    serve_and_stop("TERM").await
}


#[tokio::test]
async fn a_state_directory_swapped_during_a_round_refuses_the_next_rounds_and_audits_them() -> TestResult {
    let (_fake, site) = running_site(recording(), &declarations_text("acme", &["alpha"], 1)).await?;
    fs::write(site.bin.join("block"), "config")?;
    let quick: SettingsReader = Arc::new(|file: &Path| {
        let mut settings = load_settings(file)?;
        settings.interval_seconds = SHORT_INTERVAL;
        settings.restore_interval_seconds = SHORT_INTERVAL;
        Ok(settings)
    });
    let mut built = options(&site, TWO_ROUNDS, Duration::from_secs(MAX_ROUND_SECONDS));
    built.read = quick;
    let service = start(&site.settings, built, never());
    let driver = async {
        wait_for(&site.bin.join("blocked")).await?;
        fs::rename(&site.state, site.dir.path().join("state.moved"))?;
        site::private_dir(&site.state)?;
        fs::write(site.bin.join("release"), "")?;
        Ok::<(), Box<dyn Error>>(())
    };
    let (ended, driven) = tokio::join!(service, driver);
    ended?;
    driven?;
    let written = records(&site)?;
    assert_eq!(written.len(), FOUR);
    let refused = written.iter().filter(|record| record.parameters.contains_key("round_error")).count();
    assert_eq!(refused, THREE);
    assert!(written
        .iter()
        .all(|record| !record.parameters.values().any(|value| value.contains("state.moved"))));
    Ok(())
}


#[tokio::test]
async fn the_main_wrapper_installs_the_signals_and_refuses_root_with_an_error() -> TestResult {
    let site = plain_site(&["alpha"], 0)?;
    let file = site.settings.display().to_string();
    let refusal = run_main(std::slice::from_ref(&file), 0).await.err().ok_or("root")?;
    assert!(refusal.to_string().contains("refusing to run as root"));
    Ok(())
}


async fn passes_with(check_interval: u64, restore_interval: u64) -> Result<usize, Box<dyn Error>> {
    let (_fake, site) = running_site(recording(), &declarations_text("acme", &["alpha"], 1)).await?;
    let uneven: SettingsReader = Arc::new(move |file: &Path| {
        let mut settings = load_settings(file)?;
        settings.interval_seconds = check_interval;
        settings.restore_interval_seconds = restore_interval;
        Ok(settings)
    });
    let mut built = options(&site, TWO_ROUNDS, Duration::from_secs(MAX_ROUND_SECONDS));
    built.read = uneven;
    start(&site.settings, built, never()).await?;
    Ok(records(&site)?.len())
}


#[tokio::test]
async fn a_schedule_that_is_not_due_is_skipped_in_a_pass() -> TestResult {
    assert_eq!(passes_with(SHORT_INTERVAL, LIVE_INTERVAL).await?, THREE);
    assert_eq!(passes_with(LIVE_INTERVAL, SHORT_INTERVAL).await?, THREE);
    Ok(())
}


fn snapshot_json(digit: char, time: &str) -> String {
    format!(
        "{{\"time\":\"{time}\",\"paths\":[\"/data\"],\"hostname\":\"web1\",\"id\":\"{}\",\"short_id\":\"x\"}}",
        digit.to_string().repeat(DIGEST_LENGTH)
    )
}


fn counts(round: &backup_monitor::check::RoundOutcome, keys: [&str; THREE]) -> Vec<String> {
    let parameters = check_parameters(round, 0);
    keys.iter()
        .map(|key| parameters.get(*key).cloned().unwrap_or_else(|| "absent".to_owned()))
        .collect()
}


#[test]
fn the_audited_counts_name_each_kind_of_finding() -> TestResult {
    let site = plain_site(&["alpha"], 0)?;
    let declarations = declarations_of(&site)?;
    let stop = AtomicBool::new(false);
    let shared = shared_for(&site, Duration::from_secs(MAX_ROUND_SECONDS))?;
    let keys = ["deleted", "repository_changed", "retention_below_floor"];
    let all = [
        snapshot_json('a', "2026-11-18T10:00:00Z"),
        snapshot_json('b', "2026-11-19T10:00:00Z"),
        snapshot_json('c', "2026-11-20T10:00:00Z"),
    ];
    fs::write(site.bin.join("snapshots.json"), format!("[{}]", all.join(",")))?;
    assert_eq!(counts(&check_round(&shared, &declarations, FIRST, &stop)?, keys), ["0", "0", "0"]);
    fs::write(
        site.bin.join("snapshots.json"),
        format!("[{},{}]", all.first().ok_or("a")?, all.get(TWO).ok_or("c")?),
    )?;
    assert_eq!(counts(&check_round(&shared, &declarations, FIRST, &stop)?, keys), ["1", "0", "0"]);
    fs::write(
        site.bin.join("config.json"),
        format!("{{\"version\":2,\"id\":\"{}\"}}", "b".repeat(DIGEST_LENGTH)),
    )?;
    fs::write(site.bin.join("snapshots.json"), "[]")?;
    assert_eq!(counts(&check_round(&shared, &declarations, FIRST, &stop)?, keys), ["0", "1", "1"]);
    Ok(())
}


#[test]
fn a_settings_file_with_an_interval_out_of_range_is_refused_on_load() -> TestResult {
    let site = plain_site(&["alpha"], 0)?;
    fs::write(
        &site.settings,
        fs::read_to_string(&site.settings)?.replace("interval_seconds: 3600\nrestore", "interval_seconds: 1\nrestore"),
    )?;
    assert!(load_settings(&site.settings).is_err_and(|refusal| refusal.to_string().contains("interval_seconds")));
    Ok(())
}


#[tokio::test]
async fn a_store_that_answers_with_an_error_is_the_record_category() -> TestResult {
    let handler: Handler = Arc::new(|sql| {
        if sql.starts_with("SELECT outcome") {
            Reply::Error("XX000")
        } else {
            Reply::Done
        }
    });
    let (_fake, site) = running_site(handler, &declarations_text("acme", &["alpha"], 1)).await?;
    start(&site.settings, options(&site, ONE_ROUND, Duration::from_secs(MAX_ROUND_SECONDS)), never()).await?;
    let written = records(&site)?;
    let restore = written
        .iter()
        .find(|record| record.action == "backup.restore_round")
        .ok_or("no restore record")?;
    assert_eq!(restore.parameters.get("store").map(String::as_str), Some("record"));
    Ok(())
}


#[test]
fn a_round_is_a_success_only_when_everything_ran_and_nothing_failed() -> TestResult {
    let site = plain_site(&["alpha", "beta"], TWO)?;
    let declarations = declarations_of(&site)?;
    let stop = AtomicBool::new(false);
    let shared = shared_for(&site, Duration::from_secs(MAX_ROUND_SECONDS))?;
    let stored = Ok(backup_monitor::store::WriteCounts::default());
    let good_check = check_round(&shared, &declarations, FIRST, &stop)?;
    let good_restore = restore_round(&shared, &declarations, FIRST, &stop)?;
    assert_eq!(check_outcome(&good_check), Outcome::Success);
    assert_eq!(restore_outcome(&good_restore, &stored), Outcome::Success);
    fs::write(site.bin.join("fail_config"), "")?;
    assert_eq!(check_outcome(&check_round(&shared, &declarations, FIRST, &stop)?), Outcome::Failure);
    assert_eq!(
        restore_outcome(&restore_round(&shared, &declarations, FIRST, &stop)?, &stored),
        Outcome::Failure
    );
    let cut = shared_for(&site, Duration::ZERO)?;
    assert_eq!(check_outcome(&check_round(&cut, &declarations, FIRST, &stop)?), Outcome::Failure);
    fs::remove_file(site.bin.join("fail_config"))?;
    assert_eq!(
        restore_outcome(&restore_round(&cut, &declarations, FIRST, &stop)?, &stored),
        Outcome::Failure
    );
    let refused = Err(StoreFailure::Connect(PgError::InvalidTenant));
    assert_eq!(restore_outcome(&good_restore, &refused), Outcome::Failure);
    Ok(())
}
