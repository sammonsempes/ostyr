use crate::support::{append, lines, scoped_logging, setup, EXEC, LEN_TWO, LINE_LIMIT, RELOADED_MILLIS, THREE, TWO};
use crate::types::TestResult;
use agent_channel::types::{PauseFn, PauseFuture};
use agent_linux::app::{run_linux, run_linux_with, source_paths};
use agent_linux::cursor::write_cursor;
use agent_linux::error::{SensorError, SourceError};
use agent_linux::exec_probe::{EXEC_PROBE_JOIN_POLL_MILLIS, THREAD_NAME};
use agent_linux::model::{Cursor, LinuxFile, Report, SourceSettings, Totals, DEFAULT_POLL_MILLIS};
use agent_linux::run::{run_source, tally};
use agent_linux::types::RunFuture;
use arc_swap::ArcSwap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tempfile::tempdir;


pub fn no_systemctl(_program: PathBuf, _arguments: Vec<String>) -> RunFuture {
    Box::pin(async { Err(SensorError::Exit(None)) })
}


#[tokio::test]
async fn a_program_path_in_the_settings_file_is_refused_at_start() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    for setting in ["systemctl_path: /usr/sbin/reboot\n", "nft_path: /usr/sbin/reboot\n"] {
        let text = fs::read_to_string(&config)?;
        fs::write(&config, format!("{text}{setting}"))?;
        assert!(matches!(
            run_linux(&config, 1, &|_| Box::pin(async {}), no_systemctl).await,
            Err(SourceError::Config(_))
        ));
        fs::write(&config, text)?;
    }
    assert!(!dir.path().join("linux-audit").exists());
    Ok(())
}


#[tokio::test]
async fn the_source_polls_and_reads_the_settings_afresh_each_time() -> TestResult {
    let _log = scoped_logging();
    let setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n"))?;
    let shared = Arc::new(ArcSwap::from_pointee(SourceSettings::default()));
    let pauses: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&pauses);
    let swapped = Arc::clone(&shared);
    let pause = move |delay: Duration| -> PauseFuture {
        seen.lock().unwrap_or_else(PoisonError::into_inner).push(delay);
        swapped.store(Arc::new(SourceSettings {
            poll_millis: RELOADED_MILLIS,
            ..SourceSettings::default()
        }));
        Box::pin(async {})
    };
    let totals = run_source(&shared, &setup.paths, LINE_LIMIT, THREE, &pause).await?;
    assert_eq!((totals.polls, totals.spooled, totals.failures), (THREE, TWO, 0));
    let kept = pauses.lock().map_err(|error| error.to_string())?.clone();
    assert_eq!(
        kept,
        vec![
            Duration::from_millis(DEFAULT_POLL_MILLIS),
            Duration::from_millis(RELOADED_MILLIS),
            Duration::from_millis(RELOADED_MILLIS)
        ]
    );
    assert_eq!(lines(&setup.paths.spool)?.len(), LEN_TWO);
    Ok(())
}


#[tokio::test]
async fn a_failing_poll_is_counted_and_the_next_one_runs() -> TestResult {
    let _log = scoped_logging();
    let setup = setup()?;
    let target = setup.dir.path().join("target");
    append(&target, "x\n")?;
    symlink(&target, &setup.paths.export)?;
    let shared = Arc::new(ArcSwap::from_pointee(SourceSettings::default()));
    let totals = run_source(&shared, &setup.paths, LINE_LIMIT, TWO, &|_| Box::pin(async {})).await?;
    assert_eq!((totals.polls, totals.failures, totals.spooled), (TWO, TWO, 0));
    Ok(())
}


#[tokio::test]
async fn a_corrupt_cursor_stops_the_source_at_start() -> TestResult {
    let setup = setup()?;
    fs::write(&setup.paths.cursor_file, "garbage")?;
    let shared = Arc::new(ArcSwap::from_pointee(SourceSettings::default()));
    let outcome = run_source(&shared, &setup.paths, LINE_LIMIT, 1, &|_| Box::pin(async {})).await;
    assert!(matches!(outcome, Err(SourceError::Cursor(_))));
    write_cursor(&setup.state, &setup.paths.cursor_file, Cursor::default())?;
    Ok(())
}


#[test]
fn the_totals_add_up_and_a_missing_file_is_logged_once() -> TestResult {
    let _log = scoped_logging();
    let missing = Report {
        missing: true,
        ..Report::default()
    };
    let first = tally(Totals::default(), Ok(missing));
    assert!(first.waiting);
    let second = tally(first, Ok(missing));
    let found = tally(
        second,
        Ok(Report {
            spooled: TWO,
            malformed: 1,
            unknown: 1,
            oversized: 1,
            rotated: true,
            ..Report::default()
        }),
    );
    assert_eq!(
        (
            found.polls,
            found.spooled,
            found.malformed,
            found.unknown,
            found.oversized,
            found.rotations
        ),
        (THREE, TWO, 1, 1, 1, 1)
    );
    assert!(!found.waiting);
    Ok(())
}


fn write_files(dir: &std::path::Path) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let agent = dir.join("agent.yaml");
    fs::write(
        &agent,
        format!(
            "server: 127.0.0.1:1\nserver_name: server\ncertificate: {root}/absent.pem\nkey: {root}/absent.key\nplatform_ca: {root}/absent-ca.pem\ntenant: t1\nagent_id: a1\nkeys_file: {root}/keys\nstate_file: {root}/state\naudit_file: {root}/agent-audit\nspool_file: {root}/spool\nsequence_file: {root}/sequence\nexecuted_file: {root}/executed\n",
            root = dir.display()
        ),
    )?;
    fs::write(dir.join("process-cred"), "true")?;
    let config = dir.join("linux.yaml");
    fs::write(
        &config,
        format!(
            "agent_file: {root}/agent.yaml\nexport_path: {root}/export.json\ncursor_file: {root}/cursor\naudit_file: {root}/linux-audit\n\
             credentials_path: {root}/process-cred\n",
            root = dir.display()
        ),
    )?;
    Ok(config)
}


#[tokio::test]
async fn the_linux_agent_runs_the_source_and_the_agent_side_by_side() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    append(&dir.path().join("export.json"), &format!("{EXEC}\n{EXEC}\n"))?;
    let totals = run_linux(&config, TWO, &|_| Box::pin(async {}), no_systemctl).await?;
    assert_eq!((totals.polls, totals.spooled, totals.agent_runs), (TWO, TWO, 0));
    let spooled = lines(&dir.path().join("spool"))?;
    assert_eq!(spooled.len(), LEN_TWO + 1 + LEN_TWO);
    assert_eq!(spooled.iter().filter(|line| line.contains("ostyr.host_metrics")).count(), LEN_TWO);
    assert!(spooled.iter().any(|line| line.contains("agent.capabilities")));
    Ok(())
}


#[tokio::test]
async fn the_linux_agent_refuses_missing_files() -> TestResult {
    let dir = tempdir()?;
    assert!(run_linux(&dir.path().join("absent.yaml"), 1, &|_| Box::pin(async {}), no_systemctl)
        .await
        .is_err());
    let config = write_files(dir.path())?;
    fs::remove_file(dir.path().join("agent.yaml"))?;
    assert!(run_linux(&config, 1, &|_| Box::pin(async {}), no_systemctl).await.is_err());
    Ok(())
}


#[test]
fn the_source_paths_come_from_the_agent_spool() -> TestResult {
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    let file = core_config::load::load_file::<LinuxFile>(&config)?;
    let agent = agent_channel::agent_app::load_agent_file(&file.agent_file)?;
    let paths = source_paths(&file, &agent);
    assert_eq!(paths.spool, agent.spool_file);
    assert!(paths.sending.to_string_lossy().ends_with("spool.sending"));
    Ok(())
}


#[tokio::test]
async fn a_source_that_fails_at_start_ends_the_agent_at_once() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    let yielding: &PauseFn = &|_| Box::pin(tokio::task::yield_now());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(WORLD_WRITABLE))?;
    assert!(matches!(
        run_linux(&config, u64::MAX, yielding, no_systemctl).await,
        Err(SourceError::App(agent_channel::error::AppError::SpoolDir { .. }))
    ));
    let mut left = fs::read_dir(dir.path())?
        .map(|entry| entry.map(|found| found.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    left.sort();
    assert_eq!(left, ["agent.yaml", "linux.yaml", "process-cred"]);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(PRIVATE))?;
    fs::write(dir.path().join("cursor"), "garbage")?;
    assert!(matches!(
        run_linux(&config, u64::MAX, yielding, no_systemctl).await,
        Err(SourceError::Cursor(_))
    ));
    fs::remove_file(dir.path().join("cursor"))?;
    assert!(Command::new("mkfifo").arg(dir.path().join("cursor")).status()?.success());
    assert!(matches!(
        run_linux(&config, u64::MAX, yielding, no_systemctl).await,
        Err(SourceError::NotRegular(_))
    ));
    Ok(())
}


const WORLD_WRITABLE: u32 = 0o777;


const PRIVATE: u32 = 0o700;


#[tokio::test]
async fn a_group_writable_audit_directory_ends_the_start_and_creates_nothing() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    let audit_dir = dir.path().join("audit");
    fs::create_dir(&audit_dir)?;
    fs::set_permissions(&audit_dir, fs::Permissions::from_mode(WORLD_WRITABLE))?;
    let text = fs::read_to_string(&config)?.replace(
        &format!("{}/linux-audit", dir.path().display()),
        &format!("{}/audit/linux-audit", dir.path().display()),
    );
    fs::write(&config, text)?;
    assert!(matches!(
        run_linux(&config, 1, &|_| Box::pin(async {}), no_systemctl).await,
        Err(SourceError::App(agent_channel::error::AppError::SpoolDir { .. }))
    ));
    assert_eq!(fs::read_dir(&audit_dir)?.count(), 0);
    assert!(!dir.path().join("spool").exists());
    Ok(())
}


#[tokio::test]
async fn a_group_writable_spool_directory_ends_the_start_before_any_spool_file_exists() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    let spool_dir = dir.path().join("spool-dir");
    fs::create_dir(&spool_dir)?;
    fs::set_permissions(&spool_dir, fs::Permissions::from_mode(WORLD_WRITABLE))?;
    let agent = dir.path().join("agent.yaml");
    let text = fs::read_to_string(&agent)?.replace(
        &format!("{}/spool\n", dir.path().display()),
        &format!("{}/spool-dir/spool\n", dir.path().display()),
    );
    fs::write(&agent, text)?;
    assert!(matches!(
        run_linux(&config, 1, &|_| Box::pin(async {}), no_systemctl).await,
        Err(SourceError::App(agent_channel::error::AppError::SpoolDir { .. }))
    ));
    assert_eq!(fs::read_dir(&spool_dir)?.count(), 0);
    assert!(!dir.path().join("linux-audit").exists());
    Ok(())
}


const STOP_SPINS: u32 = 4_000_000;


const FINISH_YIELDS: u32 = 20_000;


const WAIT_ATTEMPTS: u32 = 100_000;


fn probe_until_stopped(
    stop: &AtomicBool,
    _max_polls: u32,
    attached: &mut dyn FnMut(),
    _deliver: &mut dyn FnMut(ebpf_probes::drain::Drained),
) -> agent_linux::types::ProbeResult {
    attached();
    (0..STOP_SPINS)
        .take_while(|_| !stop.load(Ordering::Relaxed))
        .for_each(|_| std::thread::yield_now());
    Ok(0)
}


fn probe_thread_alive() -> bool {
    fs::read_dir("/proc/self/task").is_ok_and(|tasks| {
        tasks
            .flatten()
            .any(|task| fs::read_to_string(task.path().join("comm")).is_ok_and(|name| name.trim_end() == THREAD_NAME))
    })
}


fn joining_pause(delay: Duration) -> PauseFuture {
    if delay == Duration::from_millis(EXEC_PROBE_JOIN_POLL_MILLIS) {
        (0..STOP_SPINS)
            .take_while(|_| probe_thread_alive())
            .for_each(|_| std::thread::yield_now());
        (0..FINISH_YIELDS).for_each(|_| std::thread::yield_now());
        Box::pin(async {})
    } else {
        Box::pin(tokio::task::yield_now())
    }
}


fn enable_exec_probe(config: &std::path::Path) -> TestResult {
    let text = fs::read_to_string(config)?;
    fs::write(config, format!("{text}exec_probe:\n  enabled: true\n"))?;
    Ok(())
}


async fn wait_for_text(path: PathBuf, needle: &str) -> bool {
    let mut found = false;
    let mut attempts = 0;
    while !found && attempts < WAIT_ATTEMPTS {
        found = fs::read_to_string(&path).is_ok_and(|text| text.contains(needle));
        tokio::task::yield_now().await;
        attempts += 1;
    }
    found
}


#[test]
fn a_producer_failing_after_the_probe_started_still_unloads_it_before_the_agent_ends() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    enable_exec_probe(&config)?;
    fs::write(dir.path().join("cursor"), "garbage")?;
    let audit_path = dir.path().join("linux-audit");
    let (release, held) = std::sync::mpsc::channel::<()>();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()?;
    let run = run_linux_with(
        &config,
        u64::MAX,
        &joining_pause,
        no_systemctl,
        probe_until_stopped,
        std::future::pending(),
    );
    let holder = async {
        let blocker = tokio::task::spawn_blocking(move || held.recv());
        wait_for_text(audit_path.clone(), "exec_probe.load").await;
        release.send(())?;
        blocker.await??;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let (ended, held_result) = runtime.block_on(async { tokio::join!(run, holder) });
    held_result?;
    assert!(matches!(ended, Err(SourceError::Cursor(_))));
    let audit = fs::read_to_string(&audit_path)?;
    assert_eq!(audit.matches("exec_probe.unload").count(), 1, "{audit}");
    assert!(audit.contains("unloaded") && !audit.contains("unload_unknown"), "{audit}");
    Ok(())
}


#[tokio::test]
async fn a_terminate_request_joins_the_probe_and_ends_the_agent_cleanly() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    enable_exec_probe(&config)?;
    let audit_path = dir.path().join("linux-audit");
    let terminate = async {
        wait_for_text(audit_path.clone(), "exec_probe.load").await;
    };
    let ended = run_linux_with(&config, u64::MAX, &joining_pause, no_systemctl, probe_until_stopped, terminate).await?;
    assert_eq!(ended.agent_runs, 0);
    let audit = fs::read_to_string(&audit_path)?;
    assert_eq!(audit.matches("exec_probe.load").count(), 1, "{audit}");
    assert_eq!(audit.matches("exec_probe.unload").count(), 1, "{audit}");
    assert!(audit.contains("unloaded"), "{audit}");
    Ok(())
}
