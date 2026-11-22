use crate::support::LEN_TWO;
use crate::types::TestResult;
use agent_channel::types::PauseFuture;
use agent_linux::capabilities::read_bounded;
use agent_linux::error::SourceError;
use agent_linux::hostmetrics::MAX_MOUNTS;
use agent_linux::metrics::{busy_ratio, metrics_line, run_metrics};
use agent_linux::model::{HostSample, MetricsEnv, MetricsMemory, MetricsSettings, MetricsTotals, SourceSettings};
use agent_linux::settings::invalid_metrics_settings;
use agent_linux::types::{SharedMetrics, SharedSource, SpoolLock};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rustix::fs::{StatVfs, StatVfsMountFlags};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};


const BOOT_A: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";


const BOOT_B: &str = "1a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";


const STAT_FIRST: &str = "cpu  100 0 100 800 0 0 0 0 0 0\n";


const STAT_SECOND: &str = "cpu  200 0 200 1600 0 0 0 0 0 0\n";


const MEMINFO: &str = "MemTotal:       16384 kB\nMemAvailable:    8192 kB\nSwapTotal:       2048 kB\nSwapFree:        1024 kB\n";


const LOADAVG: &str = "0.25 0.50 0.75 1/234 5678\n";


const VMSTAT: &str = "oom_kill 3\n";


const UPTIME: &str = "1234.5 4321.0\n";


const INTERVAL: u64 = 30;


const SWAPPED_INTERVAL: u64 = 20;


const ROUNDS: u64 = 3;


const ROUNDS_TWO: u64 = 2;


const FOUR_PAUSES: usize = 4;


const KIB: u64 = 1_024;


const MEM_TOTAL: u64 = 16_384 * KIB;


const MEM_AVAILABLE: u64 = 8_192 * KIB;


const SWAP_TOTAL: u64 = 2_048 * KIB;


const SWAP_FREE: u64 = KIB * KIB;


const LOAD_ONE: f64 = 0.25;


const LOAD_FIVE: f64 = 0.5;


const LOAD_FIFTEEN: f64 = 0.75;


const OOM_KILLS: u64 = 3;


const UPTIME_SECONDS: f64 = 1234.5;


const LINE_LIMIT: usize = 1_000_000;


const TINY_LINE_LIMIT: usize = 10;


const TINY_SPOOL: u64 = 10;


const BIG_SPOOL: u64 = 1_000_000;


const BLOCK_SIZE: u64 = 4_096;


const BLOCKS: u64 = 1_000;


const FREE_BLOCKS: u64 = 400;


const TICK: u64 = 100;


const EXPECTED_RATIO: f64 = 0.2;


const BELOW_FLOOR: u64 = 9;


const ABOVE_CEILING: u64 = 3_601;


struct Fixture {
    dir: TempDir,
    env: MetricsEnv,
}


fn usage() -> StatVfs {
    StatVfs {
        f_bsize: BLOCK_SIZE,
        f_frsize: BLOCK_SIZE,
        f_blocks: BLOCKS,
        f_bfree: FREE_BLOCKS,
        f_bavail: FREE_BLOCKS,
        f_files: 0,
        f_ffree: 0,
        f_favail: 0,
        f_fsid: 0,
        f_flag: StatVfsMountFlags::empty(),
        f_namemax: 0,
    }
}


fn stat_ok(_: &Path) -> rustix::io::Result<StatVfs> {
    Ok(usage())
}


fn stat_failing(_: &Path) -> rustix::io::Result<StatVfs> {
    Err(rustix::io::Errno::NOENT)
}


fn write_proc(root: &Path, stat: &str, boot: &str) -> TestResult {
    fs::create_dir_all(root.join("proc/sys/kernel/random"))?;
    fs::write(root.join("proc/stat"), stat)?;
    fs::write(root.join("proc/meminfo"), MEMINFO)?;
    fs::write(root.join("proc/loadavg"), LOADAVG)?;
    fs::write(root.join("proc/vmstat"), VMSTAT)?;
    fs::write(root.join("proc/uptime"), UPTIME)?;
    fs::write(root.join("proc/sys/kernel/random/boot_id"), format!("{boot}\n"))?;
    Ok(())
}


fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    write_proc(dir.path(), STAT_FIRST, BOOT_A)?;
    let env = MetricsEnv {
        root: dir.path().to_path_buf(),
        spool: dir.path().join("spool"),
        sending: dir.path().join("spool.sending"),
        lock: SpoolLock::default(),
        line_limit: LINE_LIMIT,
        read: read_bounded,
        stat: stat_ok,
    };
    Ok(Fixture { dir, env })
}


fn metrics_of(interval_seconds: u64) -> SharedMetrics {
    Arc::new(ArcSwap::from_pointee(MetricsSettings {
        interval_seconds,
        mounts: vec![PathBuf::from("/")],
    }))
}


fn source_of(max_spool_bytes: u64) -> SharedSource {
    Arc::new(ArcSwap::from_pointee(SourceSettings {
        max_spool_bytes,
        ..SourceSettings::default()
    }))
}


fn quiet(_: Duration) -> PauseFuture {
    Box::pin(async {})
}


fn spooled(fixture: &Fixture) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    Ok(fs::read_to_string(&fixture.env.spool)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?)
}


fn value<'a>(line: &'a Value, name: &str) -> Option<&'a Value> {
    line.get("metrics")?.get(name)
}


fn rewriting(root: PathBuf, stat: &'static str, boot: &'static str) -> impl Fn(Duration) -> PauseFuture {
    let done = AtomicU64::new(0);
    move |_| {
        if done.fetch_add(1, Ordering::SeqCst) == 0 {
            let rewritten =
                fs::write(root.join("proc/stat"), stat).and_then(|()| fs::write(root.join("proc/sys/kernel/random/boot_id"), format!("{boot}\n")));
            if let Err(error) = rewritten {
                tracing::warn!(%error, "test fixture not rewritten");
            }
        }
        Box::pin(async {})
    }
}


#[tokio::test]
async fn two_rounds_give_one_line_without_and_one_with_the_ratio() -> TestResult {
    let fixture = fixture()?;
    let pause = rewriting(fixture.dir.path().to_path_buf(), STAT_SECOND, BOOT_A);
    let totals = run_metrics(&metrics_of(INTERVAL), &source_of(BIG_SPOOL), &fixture.env, ROUNDS_TWO, &pause, &|| 0).await?;
    assert_eq!(
        totals,
        MetricsTotals {
            published: ROUNDS_TWO,
            spool_full: 0,
            too_long: 0
        }
    );
    let lines = spooled(&fixture)?;
    let first = lines.first().ok_or("no first line")?;
    let second = lines.get(1).ok_or("no second line")?;
    assert!(value(first, "system.cpu.utilization").is_none());
    let ratio = value(second, "system.cpu.utilization").and_then(Value::as_f64).ok_or("no ratio")?;
    assert!((ratio - EXPECTED_RATIO).abs() < f64::EPSILON * TICK as f64);
    assert_eq!(first.pointer("/event/dataset"), Some(&Value::from("ostyr.host_metrics")));
    assert_eq!(first.pointer("/event/kind"), Some(&Value::from("metric")));
    assert_eq!(first.pointer("/host/boot_id"), Some(&Value::from(BOOT_A)));
    assert_eq!(value(first, "system.memory.limit"), Some(&Value::from(MEM_TOTAL)));
    assert_eq!(value(first, "system.memory.available"), Some(&Value::from(MEM_AVAILABLE)));
    assert_eq!(value(first, "system.paging.limit"), Some(&Value::from(SWAP_TOTAL)));
    assert_eq!(value(first, "system.paging.free"), Some(&Value::from(SWAP_FREE)));
    assert_eq!(value(first, "system.cpu.load_average.1m"), Some(&Value::from(LOAD_ONE)));
    assert_eq!(value(first, "system.cpu.load_average.5m"), Some(&Value::from(LOAD_FIVE)));
    assert_eq!(value(first, "system.cpu.load_average.15m"), Some(&Value::from(LOAD_FIFTEEN)));
    assert_eq!(value(first, "system.oom_kills"), Some(&Value::from(OOM_KILLS)));
    assert_eq!(value(first, "system.uptime"), Some(&Value::from(UPTIME_SECONDS)));
    let limit = value(first, "system.filesystem.limit").and_then(|found| found.get(0)).ok_or("no limit")?;
    assert_eq!(limit.get("mountpoint"), Some(&Value::from("/")));
    assert_eq!(limit.get("value"), Some(&Value::from(BLOCKS * BLOCK_SIZE)));
    let free = value(first, "system.filesystem.free").and_then(|found| found.get(0)).ok_or("no free")?;
    assert_eq!(free.get("value"), Some(&Value::from(FREE_BLOCKS * BLOCK_SIZE)));
    assert_eq!(first.get("metrics_omitted"), Some(&Value::from(0)));
    assert_eq!(first.get("metrics_failed"), Some(&Value::from(0)));
    Ok(())
}


#[tokio::test]
async fn a_boot_id_change_drops_the_ratio() -> TestResult {
    let fixture = fixture()?;
    let pause = rewriting(fixture.dir.path().to_path_buf(), STAT_SECOND, BOOT_B);
    run_metrics(&metrics_of(INTERVAL), &source_of(BIG_SPOOL), &fixture.env, ROUNDS_TWO, &pause, &|| 0).await?;
    let lines = spooled(&fixture)?;
    let second = lines.get(1).ok_or("no second line")?;
    assert!(value(second, "system.cpu.utilization").is_none());
    assert_eq!(second.pointer("/host/boot_id"), Some(&Value::from(BOOT_B)));
    Ok(())
}


#[test]
fn the_ratio_needs_a_known_boot_both_times_and_both_cpu_readings() -> TestResult {
    let cpu = agent_linux::hostmetrics::parse_cpu(STAT_FIRST);
    let later = agent_linux::hostmetrics::parse_cpu(STAT_SECOND);
    let known = |boot: Option<&str>, readings| HostSample {
        boot_id: boot.map(str::to_owned),
        cpu: readings,
        ..HostSample::default()
    };
    let memory = |boot: Option<&str>| MetricsMemory {
        boot_id: boot.map(str::to_owned),
        cpu,
    };
    assert!(busy_ratio(&memory(Some(BOOT_A)), &known(Some(BOOT_A), later)).is_some());
    assert!(busy_ratio(&memory(Some(BOOT_A)), &known(Some(BOOT_B), later)).is_none());
    assert!(busy_ratio(&memory(None), &known(None, later)).is_none());
    assert!(busy_ratio(&memory(Some(BOOT_A)), &known(None, later)).is_none());
    assert!(busy_ratio(&memory(Some(BOOT_A)), &known(Some(BOOT_A), None)).is_none());
    assert!(busy_ratio(&memory(Some(BOOT_A)), &known(Some(BOOT_A), cpu)).is_none());
    assert!(busy_ratio(&MetricsMemory::default(), &known(Some(BOOT_A), later)).is_none());
    Ok(())
}


#[tokio::test]
async fn a_missing_vmstat_drops_only_the_oom_counter() -> TestResult {
    let fixture = fixture()?;
    fs::remove_file(fixture.dir.path().join("proc/vmstat"))?;
    run_metrics(&metrics_of(INTERVAL), &source_of(BIG_SPOOL), &fixture.env, 1, &quiet, &|| 0).await?;
    let lines = spooled(&fixture)?;
    let line = lines.first().ok_or("no line")?;
    assert!(value(line, "system.oom_kills").is_none());
    assert!(value(line, "system.uptime").is_some());
    assert!(value(line, "system.memory.limit").is_some());
    assert!(value(line, "system.cpu.load_average.1m").is_some());
    assert!(value(line, "system.filesystem.limit").is_some());
    Ok(())
}


#[tokio::test]
async fn a_failing_mount_is_counted_and_leaves_no_filesystem_key() -> TestResult {
    let fixture = fixture()?;
    let env = MetricsEnv {
        stat: stat_failing,
        ..fixture.env.clone()
    };
    run_metrics(&metrics_of(INTERVAL), &source_of(BIG_SPOOL), &env, 1, &quiet, &|| 0).await?;
    let lines = spooled(&fixture)?;
    let line = lines.first().ok_or("no line")?;
    assert!(value(line, "system.filesystem.limit").is_none());
    assert!(value(line, "system.filesystem.free").is_none());
    assert_eq!(line.get("metrics_failed"), Some(&Value::from(1)));
    Ok(())
}


#[tokio::test]
async fn omitted_mounts_travel_in_the_line() -> TestResult {
    let fixture = fixture()?;
    let many = Arc::new(ArcSwap::from_pointee(MetricsSettings {
        interval_seconds: INTERVAL,
        mounts: vec![PathBuf::from("/"); MAX_MOUNTS + 1],
    }));
    run_metrics(&many, &source_of(BIG_SPOOL), &fixture.env, 1, &quiet, &|| 0).await?;
    let lines = spooled(&fixture)?;
    assert_eq!(lines.first().and_then(|line| line.get("metrics_omitted")), Some(&Value::from(1)));
    Ok(())
}


#[test]
fn an_empty_sample_has_no_metric_keys() -> TestResult {
    let line: Value = serde_json::from_str(&metrics_line(&HostSample::default(), None))?;
    assert_eq!(line.get("metrics").and_then(Value::as_object).map(|found| found.len()), Some(0));
    assert_eq!(line.get("host").and_then(Value::as_object).map(|found| found.len()), Some(0));
    Ok(())
}


#[tokio::test]
async fn a_settings_swap_changes_the_pause_of_the_next_round() -> TestResult {
    let fixture = fixture()?;
    let shared = metrics_of(INTERVAL);
    let swapper = Arc::clone(&shared);
    let pauses = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&pauses);
    let pause = move |delay: Duration| -> PauseFuture {
        recorded.lock().push(delay);
        swapper.store(Arc::new(MetricsSettings {
            interval_seconds: SWAPPED_INTERVAL,
            ..MetricsSettings::default()
        }));
        Box::pin(async {})
    };
    run_metrics(&shared, &source_of(BIG_SPOOL), &fixture.env, ROUNDS_TWO, &pause, &|| 0).await?;
    assert_eq!(*pauses.lock(), vec![Duration::from_secs(INTERVAL), Duration::from_secs(SWAPPED_INTERVAL)]);
    Ok(())
}


#[tokio::test]
async fn max_runs_bounds_the_loop_and_a_zero_runs_nothing() -> TestResult {
    let fixture = fixture()?;
    let totals = run_metrics(&metrics_of(INTERVAL), &source_of(BIG_SPOOL), &fixture.env, ROUNDS, &quiet, &|| 0).await?;
    assert_eq!(totals.published, ROUNDS);
    let none = run_metrics(&metrics_of(INTERVAL), &source_of(BIG_SPOOL), &fixture.env, 0, &quiet, &|| 0).await?;
    assert_eq!(none, MetricsTotals::default());
    assert_eq!(spooled(&fixture)?.len() as u64, ROUNDS);
    Ok(())
}


#[tokio::test]
async fn a_clock_that_runs_backwards_or_far_ahead_never_makes_the_pause_negative() -> TestResult {
    let fixture = fixture()?;
    let pauses = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&pauses);
    let pause = move |delay: Duration| -> PauseFuture {
        recorded.lock().push(delay);
        Box::pin(async {})
    };
    let ticks = AtomicU64::new(TICK * TICK);
    let backwards = move || ticks.fetch_sub(TICK, Ordering::SeqCst);
    run_metrics(&metrics_of(INTERVAL), &source_of(BIG_SPOOL), &fixture.env, ROUNDS_TWO, &pause, &backwards).await?;
    let forwards_ticks = AtomicU64::new(0);
    let forwards = move || forwards_ticks.fetch_add(TICK, Ordering::SeqCst);
    run_metrics(&metrics_of(INTERVAL), &source_of(BIG_SPOOL), &fixture.env, ROUNDS_TWO, &pause, &forwards).await?;
    let seen = pauses.lock().clone();
    assert_eq!(seen.len(), FOUR_PAUSES);
    assert!(seen.iter().take(LEN_TWO).all(|delay| *delay == Duration::from_secs(INTERVAL)));
    assert!(seen.iter().skip(LEN_TWO).all(|delay| delay.is_zero()));
    Ok(())
}


#[tokio::test]
async fn a_full_spool_is_counted_and_the_loop_still_pauses() -> TestResult {
    let fixture = fixture()?;
    let pauses = Arc::new(Mutex::new(0));
    let counted = Arc::clone(&pauses);
    let pause = move |_: Duration| -> PauseFuture {
        *counted.lock() += 1;
        Box::pin(async {})
    };
    let totals = run_metrics(&metrics_of(INTERVAL), &source_of(TINY_SPOOL), &fixture.env, ROUNDS_TWO, &pause, &|| 0).await?;
    assert_eq!(
        totals,
        MetricsTotals {
            published: 0,
            spool_full: ROUNDS_TWO,
            too_long: 0
        }
    );
    assert_eq!(*pauses.lock(), ROUNDS_TWO);
    assert!(!fixture.env.spool.exists());
    Ok(())
}


#[tokio::test]
async fn a_line_over_the_limit_is_counted_not_spooled() -> TestResult {
    let fixture = fixture()?;
    let env = MetricsEnv {
        line_limit: TINY_LINE_LIMIT,
        ..fixture.env.clone()
    };
    let totals = run_metrics(&metrics_of(INTERVAL), &source_of(BIG_SPOOL), &env, ROUNDS_TWO, &quiet, &|| 0).await?;
    assert_eq!(
        totals,
        MetricsTotals {
            published: 0,
            spool_full: 0,
            too_long: ROUNDS_TWO
        }
    );
    assert!(!fixture.env.spool.exists());
    Ok(())
}


#[tokio::test]
async fn a_failing_spool_write_ends_the_loop() -> TestResult {
    let fixture = fixture()?;
    let env = MetricsEnv {
        spool: fixture.dir.path().join("absent/spool"),
        ..fixture.env.clone()
    };
    let outcome = run_metrics(&metrics_of(INTERVAL), &source_of(BIG_SPOOL), &env, ROUNDS_TWO, &quiet, &|| 0).await;
    assert!(matches!(outcome, Err(SourceError::Io(_))));
    Ok(())
}


#[test]
fn the_metric_settings_have_a_floor_a_ceiling_and_absolute_mounts() -> TestResult {
    assert!(invalid_metrics_settings(&MetricsSettings::default()).is_empty());
    let interval = |interval_seconds| MetricsSettings {
        interval_seconds,
        ..MetricsSettings::default()
    };
    assert_eq!(invalid_metrics_settings(&interval(BELOW_FLOOR)), vec!["metrics.interval_seconds"]);
    assert_eq!(invalid_metrics_settings(&interval(ABOVE_CEILING)), vec!["metrics.interval_seconds"]);
    assert!(invalid_metrics_settings(&interval(BELOW_FLOOR + 1)).is_empty());
    let relative = MetricsSettings {
        mounts: vec![PathBuf::from("data")],
        ..MetricsSettings::default()
    };
    assert_eq!(invalid_metrics_settings(&relative), vec!["metrics.mounts.path"]);
    let many = MetricsSettings {
        mounts: vec![PathBuf::from("/"); MAX_MOUNTS + 1],
        ..MetricsSettings::default()
    };
    assert_eq!(invalid_metrics_settings(&many), vec!["metrics.mounts"]);
    Ok(())
}
