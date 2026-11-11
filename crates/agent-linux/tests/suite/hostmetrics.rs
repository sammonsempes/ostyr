use crate::types::TestResult;
use agent_linux::capabilities::read_bounded;
use agent_linux::hostmetrics::{
    cpu_busy_ratio, meminfo_bytes, parse_boot_id, parse_cpu, parse_load, parse_number, parse_oom_kill, parse_uptime, read_sample, stat_mounts,
    statvfs_path, MAX_MOUNTS, MAX_PROC_BYTES,
};
use agent_linux::model::{CpuTimes, HostSample, LoadAverage, MountStat, MountSurvey};
use rustix::fs::{StatVfs, StatVfsMountFlags};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};


const BOOT_ID: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";


const SHORT_BOOT_ID: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4";


const NON_HEX_BOOT_ID: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4z";


const MISPLACED_DASH_BOOT_ID: &str = "0a1b2c3-d4e5f-4a6b-8c7d-9e0f1a2b3c4d";


const DASHLESS_BOOT_ID: &str = "0a1b2c3d04e5f-4a6b-8c7d-9e0f1a2b3c4d";


const STAT: &str = "cpu  100 10 50 800 40 5 6 7 0 0\ncpu0 100 10 50 800 40 5 6 7 0 0\nintr 1\n";


const MEMINFO: &str =
    "MemTotal:       16384 kB\nMemFree:         1000 kB\nMemAvailable:    8192 kB\nSwapTotal:       2048 kB\nSwapFree:        1024 kB\n";


const LOADAVG: &str = "0.25 0.50 0.75 1/234 5678\n";


const VMSTAT: &str = "nr_free_pages 1\noom_kill 3\n";


const UPTIME: &str = "1234.56 4321.00\n";


const BAD_BYTES: [u8; 2] = [0xff, 0xfe];


const EXPECTED_CPU: CpuTimes = CpuTimes {
    user: 100,
    nice: 10,
    system: 50,
    idle: 800,
    iowait: 40,
    irq: 5,
    softirq: 6,
    steal: 7,
};


const KILOBYTE: u64 = 1024;


const MEM_TOTAL_KB: u64 = 16_384;


const MEM_AVAILABLE_KB: u64 = 8192;


const SWAP_TOTAL_KB: u64 = 2048;


const SWAP_FREE_KB: u64 = 1024;


const LOAD_ONE: f64 = 0.25;


const LOAD_FIVE: f64 = 0.5;


const LOAD_FIFTEEN: f64 = 0.75;


const UPTIME_SECONDS: f64 = 1234.56;


const OOM_KILLS: u64 = 3;


const OVERFLOW_MEMINFO: &str = "MemTotal: 18446744073709551615 kB\n";


const MOUNT_PATHS: usize = 3;


const FRAGMENT_SIZE: u64 = 4096;


const BLOCKS: u64 = 100;


const FREE_BLOCKS: u64 = 40;


const AVAILABLE_BLOCKS: u64 = 30;


const RATIO_TOLERANCE: f64 = 1e-9;


const HALF: f64 = 0.5;


const FIRST_USER: u64 = 100;


const NEXT_USER: u64 = 150;


const NEXT_IDLE: u64 = 150;


const FIRST_IDLE: u64 = 100;


struct Tree {
    dir: TempDir,
}


fn tree(files: &[(&str, &[u8])]) -> Result<Tree, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    for (relative, content) in files {
        let path = dir.path().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
    }
    Ok(Tree { dir })
}


fn full_files() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("proc/stat", STAT.as_bytes()),
        ("proc/meminfo", MEMINFO.as_bytes()),
        ("proc/loadavg", LOADAVG.as_bytes()),
        ("proc/vmstat", VMSTAT.as_bytes()),
        ("proc/uptime", UPTIME.as_bytes()),
        ("proc/sys/kernel/random/boot_id", BOOT_ID.as_bytes()),
    ]
}


fn without(skip: &str) -> Vec<(&'static str, &'static [u8])> {
    full_files().into_iter().filter(|(relative, _)| *relative != skip).collect()
}


fn with(replaced: &str, content: &'static [u8]) -> Vec<(&'static str, &'static [u8])> {
    full_files()
        .into_iter()
        .map(|(relative, original)| (relative, if relative == replaced { content } else { original }))
        .collect()
}


fn sample_of(files: &[(&str, &[u8])]) -> Result<HostSample, Box<dyn std::error::Error>> {
    let built = tree(files)?;
    Ok(read_sample(built.dir.path(), read_bounded, &MountSurvey::default()))
}


fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc").join(name)
}


fn usage(blocks: u64) -> StatVfs {
    StatVfs {
        f_bsize: FRAGMENT_SIZE,
        f_frsize: FRAGMENT_SIZE,
        f_blocks: blocks,
        f_bfree: FREE_BLOCKS,
        f_bavail: AVAILABLE_BLOCKS,
        f_files: 0,
        f_ffree: 0,
        f_favail: 0,
        f_fsid: 0,
        f_flag: StatVfsMountFlags::empty(),
        f_namemax: 0,
    }
}


fn stat_ok(_path: &Path) -> rustix::io::Result<StatVfs> {
    Ok(usage(BLOCKS))
}


fn stat_overflow(_path: &Path) -> rustix::io::Result<StatVfs> {
    Ok(usage(u64::MAX))
}


fn stat_failing(_path: &Path) -> rustix::io::Result<StatVfs> {
    Err(rustix::io::Errno::NOENT)
}


fn stat_second_fails(path: &Path) -> rustix::io::Result<StatVfs> {
    if path.ends_with("bad") {
        stat_failing(path)
    } else {
        stat_ok(path)
    }
}


fn times(user: u64, idle: u64) -> CpuTimes {
    CpuTimes {
        user,
        idle,
        ..CpuTimes::default()
    }
}


#[test]
fn hand_made_tree_is_read_exactly() -> TestResult {
    let sample = sample_of(&full_files())?;
    assert_eq!(sample.cpu, Some(EXPECTED_CPU));
    assert_eq!(sample.mem_total_bytes, Some(MEM_TOTAL_KB * KILOBYTE));
    assert_eq!(sample.mem_available_bytes, Some(MEM_AVAILABLE_KB * KILOBYTE));
    assert_eq!(sample.swap_total_bytes, Some(SWAP_TOTAL_KB * KILOBYTE));
    assert_eq!(sample.swap_free_bytes, Some(SWAP_FREE_KB * KILOBYTE));
    assert_eq!(
        sample.load,
        Some(LoadAverage {
            one: LOAD_ONE,
            five: LOAD_FIVE,
            fifteen: LOAD_FIFTEEN
        })
    );
    assert_eq!(sample.oom_kill, Some(OOM_KILLS));
    assert_eq!(sample.boot_id.as_deref(), Some(BOOT_ID));
    assert_eq!(sample.uptime_seconds, Some(UPTIME_SECONDS));
    Ok(())
}


#[test]
fn ubuntu_capture_reads_every_field() -> TestResult {
    let sample = read_sample(&fixture("ubuntu2404"), read_bounded, &MountSurvey::default());
    assert!(sample.cpu.is_some());
    assert!(sample.mem_total_bytes.is_some());
    assert!(sample.mem_available_bytes.is_some());
    assert!(sample.swap_total_bytes.is_some());
    assert!(sample.swap_free_bytes.is_some());
    assert!(sample.load.is_some());
    assert!(sample.oom_kill.is_some());
    assert!(sample.boot_id.is_some());
    assert!(sample.uptime_seconds.is_some());
    Ok(())
}


#[test]
fn rocky8_capture_reads_every_field_and_an_old_kernel_vmstat_gives_no_oom_kill() -> TestResult {
    let vmstat = fs::read_to_string(fixture("rocky8").join("proc/vmstat"))?;
    let old_kernel: String = vmstat
        .lines()
        .filter(|line| !line.starts_with("oom_kill"))
        .map(|line| format!("{line}\n"))
        .collect();
    let stripped = sample_of(&[("proc/vmstat", old_kernel.as_bytes())])?;
    assert!(stripped.oom_kill.is_none());
    let sample = read_sample(&fixture("rocky8"), read_bounded, &MountSurvey::default());
    assert!(sample.oom_kill.is_some());
    assert!(sample.cpu.is_some());
    assert!(sample.mem_total_bytes.is_some());
    assert!(sample.mem_available_bytes.is_some());
    assert!(sample.swap_total_bytes.is_some());
    assert!(sample.swap_free_bytes.is_some());
    assert!(sample.load.is_some());
    assert!(sample.boot_id.is_some());
    assert!(sample.uptime_seconds.is_some());
    Ok(())
}


#[test]
fn missing_files_give_none_per_value() -> TestResult {
    let sample = sample_of(&without("proc/vmstat"))?;
    assert!(sample.oom_kill.is_none());
    assert!(sample.cpu.is_some());
    let empty = sample_of(&[])?;
    assert_eq!(empty, HostSample::default());
    Ok(())
}


#[test]
fn truncated_meminfo_keeps_the_other_values() -> TestResult {
    let sample = sample_of(&with("proc/meminfo", b"MemTotal:       16384 kB\nMemAvail"))?;
    assert_eq!(sample.mem_total_bytes, Some(MEM_TOTAL_KB * KILOBYTE));
    assert!(sample.mem_available_bytes.is_none());
    assert!(sample.swap_total_bytes.is_none());
    assert!(sample.cpu.is_some());
    Ok(())
}


#[test]
fn overflowing_meminfo_is_refused() -> TestResult {
    let sample = sample_of(&with("proc/meminfo", OVERFLOW_MEMINFO.as_bytes()))?;
    assert!(sample.mem_total_bytes.is_none());
    assert!(sample.oom_kill.is_some());
    assert_eq!(meminfo_bytes("MemTotal:\n", "MemTotal:"), None);
    assert_eq!(meminfo_bytes("MemTotal: lots kB\n", "MemTotal:"), None);
    Ok(())
}


#[test]
fn short_cpu_line_is_refused() -> TestResult {
    let sample = sample_of(&with("proc/stat", b"cpu  1 2 3 4\n"))?;
    assert!(sample.cpu.is_none());
    assert!(sample.load.is_some());
    assert_eq!(parse_cpu("intr 1\n"), None);
    assert_eq!(parse_cpu("cpu  1 2 3 4 5 6 7 x\n"), None);
    Ok(())
}


#[test]
fn non_utf8_loadavg_is_unknown() -> TestResult {
    let sample = sample_of(&with("proc/loadavg", &BAD_BYTES))?;
    assert!(sample.load.is_none());
    assert!(sample.cpu.is_some());
    Ok(())
}


#[test]
fn oversized_stat_is_unknown() -> TestResult {
    let big = vec![b'x'; usize::try_from(MAX_PROC_BYTES)? + 1];
    let built = tree(&without("proc/stat"))?;
    fs::write(built.dir.path().join("proc/stat"), &big)?;
    let sample = read_sample(built.dir.path(), read_bounded, &MountSurvey::default());
    assert!(sample.cpu.is_none());
    assert!(sample.mem_total_bytes.is_some());
    Ok(())
}


#[test]
fn bad_boot_ids_are_refused() -> TestResult {
    for bad in [SHORT_BOOT_ID, NON_HEX_BOOT_ID, MISPLACED_DASH_BOOT_ID, DASHLESS_BOOT_ID, ""] {
        assert_eq!(parse_boot_id(bad), None, "{bad}");
    }
    assert_eq!(parse_boot_id(&format!("{BOOT_ID}\n")).as_deref(), Some(BOOT_ID));
    Ok(())
}


#[test]
fn small_parsers_refuse_bad_input() -> TestResult {
    assert_eq!(parse_load("0.1 0.2\n"), None);
    assert_eq!(parse_load("0.1 NaN 0.3\n"), None);
    assert_eq!(parse_load("0.1 0.2 inf\n"), None);
    assert_eq!(parse_oom_kill("oom_kill\n"), None);
    assert_eq!(parse_oom_kill("oom_kill many\n"), None);
    assert_eq!(parse_oom_kill("nr_free_pages 1\n"), None);
    assert_eq!(parse_uptime(""), None);
    assert_eq!(parse_uptime("NaN 1\n"), None);
    assert_eq!(parse_number::<u64>("18446744073709551616"), None);
    assert_eq!(parse_number::<f64>("x"), None);
    Ok(())
}


#[test]
fn busy_ratio_of_a_normal_delta() -> TestResult {
    let ratio = cpu_busy_ratio(&times(FIRST_USER, FIRST_IDLE), &times(NEXT_USER, NEXT_IDLE)).ok_or("no ratio")?;
    assert!((ratio - HALF).abs() < RATIO_TOLERANCE);
    Ok(())
}


#[test]
fn busy_ratio_refuses_zero_delta_and_backwards_counters() -> TestResult {
    let same = times(FIRST_USER, FIRST_IDLE);
    assert_eq!(cpu_busy_ratio(&same, &same), None);
    assert_eq!(cpu_busy_ratio(&times(NEXT_USER, FIRST_IDLE), &times(FIRST_USER, NEXT_IDLE)), None);
    Ok(())
}


#[test]
fn mounts_are_measured_and_a_failure_is_counted() -> TestResult {
    let paths: Vec<PathBuf> = ["/", "/bad", "/data"].iter().map(PathBuf::from).collect();
    assert_eq!(paths.len(), MOUNT_PATHS);
    let survey = stat_mounts(&paths, stat_second_fails);
    assert_eq!(survey.failed, 1);
    assert_eq!(survey.omitted, 0);
    assert_eq!(
        survey.mounts.first(),
        Some(&MountStat {
            mount: "/".to_string(),
            total_bytes: BLOCKS * FRAGMENT_SIZE,
            free_bytes: FREE_BLOCKS * FRAGMENT_SIZE,
            available_bytes: AVAILABLE_BLOCKS * FRAGMENT_SIZE,
        })
    );
    assert_eq!(survey.mounts.len(), MOUNT_PATHS - 1);
    let carried = read_sample(&fixture("ubuntu2404"), read_bounded, &survey);
    assert_eq!(carried.survey, survey);
    Ok(())
}


#[test]
fn mounts_past_the_cap_are_counted_as_omitted() -> TestResult {
    let paths: Vec<PathBuf> = (0..=MAX_MOUNTS).map(|index| PathBuf::from(format!("/m{index}"))).collect();
    let survey = stat_mounts(&paths, stat_ok);
    assert_eq!(survey.mounts.len(), MAX_MOUNTS);
    assert_eq!(survey.omitted, 1);
    assert_eq!(survey.failed, 0);
    Ok(())
}


#[test]
fn huge_block_counts_saturate() -> TestResult {
    let survey = stat_mounts(&[PathBuf::from("/")], stat_overflow);
    assert_eq!(survey.mounts.first().map(|mount| mount.total_bytes), Some(u64::MAX));
    Ok(())
}


#[test]
fn the_real_statvfs_answers_for_root_and_fails_for_nothing() -> TestResult {
    let survey = stat_mounts(&[PathBuf::from("/"), PathBuf::from("/nonexistent-t252")], statvfs_path);
    assert_eq!(survey.mounts.len(), 1);
    assert_eq!(survey.failed, 1);
    Ok(())
}
