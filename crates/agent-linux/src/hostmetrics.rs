use crate::capabilities::{read_text, MAX_SMALL_BYTES};
use crate::model::{CpuTimes, HostSample, LoadAverage, MountStat, MountSurvey};
use crate::types::{ReadFn, StatFn};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::str::FromStr;


pub const MAX_PROC_BYTES: u64 = 1_048_576;


pub const MAX_MOUNTS: usize = 64;


pub const STAT_FILE: &str = "proc/stat";


pub const MEMINFO_FILE: &str = "proc/meminfo";


pub const LOADAVG_FILE: &str = "proc/loadavg";


pub const VMSTAT_FILE: &str = "proc/vmstat";


pub const BOOT_ID_FILE: &str = "proc/sys/kernel/random/boot_id";


pub const UPTIME_FILE: &str = "proc/uptime";


const BYTES_PER_KB: u64 = 1024;


const CPU_FIELDS: usize = 8;


const LOAD_FIELDS: usize = 3;


const BUSY_FIELDS: usize = 6;


const BOOT_ID_LENGTH: usize = 36;


const BOOT_ID_DASHES: [usize; 4] = [8, 13, 18, 23];


/// Parses a number, logging why it was refused; overflow and trailing text are refused.
pub fn parse_number<Number: FromStr>(text: &str) -> Option<Number>
where
    Number::Err: Display,
{
    text.parse()
        .inspect_err(|error| tracing::debug!(%error, text, "host metric field refused"))
        .ok()
}


pub fn parse_finite(text: &str) -> Option<f64> {
    parse_number::<f64>(text).filter(|value| value.is_finite())
}


pub fn parse_cpu(text: &str) -> Option<CpuTimes> {
    let line = text.lines().find(|line| line.split_whitespace().next() == Some("cpu"))?;
    let parsed: Option<Vec<u64>> = line.split_whitespace().skip(1).take(CPU_FIELDS).map(parse_number).collect();
    match parsed?.as_slice() {
        [user, nice, system, idle, iowait, irq, softirq, steal] => Some(CpuTimes {
            user: *user,
            nice: *nice,
            system: *system,
            idle: *idle,
            iowait: *iowait,
            irq: *irq,
            softirq: *softirq,
            steal: *steal,
        }),
        _ => None,
    }
}


/// A `Key:   value kB` line of `proc/meminfo` in bytes; `None` when absent, unparsable or overflowing.
pub fn meminfo_bytes(text: &str, key: &str) -> Option<u64> {
    let rest = text.lines().find_map(|line| line.strip_prefix(key))?;
    let kilobytes: Option<u64> = rest.split_whitespace().next().and_then(parse_number);
    kilobytes.and_then(|value| value.checked_mul(BYTES_PER_KB))
}


pub fn parse_load(text: &str) -> Option<LoadAverage> {
    let parsed: Option<Vec<f64>> = text.split_whitespace().take(LOAD_FIELDS).map(parse_finite).collect();
    match parsed?.as_slice() {
        [one, five, fifteen] => Some(LoadAverage {
            one: *one,
            five: *five,
            fifteen: *fifteen,
        }),
        _ => None,
    }
}


pub fn parse_oom_kill(text: &str) -> Option<u64> {
    let line = text.lines().find(|line| line.split_whitespace().next() == Some("oom_kill"))?;
    line.split_whitespace().nth(1).and_then(parse_number)
}


pub fn parse_uptime(text: &str) -> Option<f64> {
    text.split_whitespace().next().and_then(parse_finite)
}


/// A 36-character UUID text; anything else is not a boot id.
pub fn parse_boot_id(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let shaped = trimmed.chars().count() == BOOT_ID_LENGTH
        && trimmed.chars().enumerate().all(|(index, found)| {
            let dash = BOOT_ID_DASHES.contains(&index);
            (found == '-') == dash && (dash || found.is_ascii_hexdigit())
        });
    shaped.then(|| trimmed.to_string())
}


pub fn read_sample(root: &Path, read: ReadFn, survey: &MountSurvey) -> HostSample {
    let stat = read_text(root, STAT_FILE, read, MAX_PROC_BYTES);
    let meminfo = read_text(root, MEMINFO_FILE, read, MAX_SMALL_BYTES);
    let vmstat = read_text(root, VMSTAT_FILE, read, MAX_PROC_BYTES);
    let load = read_text(root, LOADAVG_FILE, read, MAX_SMALL_BYTES);
    let boot_id = read_text(root, BOOT_ID_FILE, read, MAX_SMALL_BYTES);
    let uptime = read_text(root, UPTIME_FILE, read, MAX_SMALL_BYTES);
    let memory = |key: &str| meminfo.as_deref().and_then(|text| meminfo_bytes(text, key));
    HostSample {
        cpu: stat.as_deref().and_then(parse_cpu),
        mem_total_bytes: memory("MemTotal:"),
        mem_available_bytes: memory("MemAvailable:"),
        swap_total_bytes: memory("SwapTotal:"),
        swap_free_bytes: memory("SwapFree:"),
        load: load.as_deref().and_then(parse_load),
        oom_kill: vmstat.as_deref().and_then(parse_oom_kill),
        boot_id: boot_id.as_deref().and_then(parse_boot_id),
        uptime_seconds: uptime.as_deref().and_then(parse_uptime),
        survey: survey.clone(),
    }
}


/// Busy time over total time between two readings; `None` when no time passed or a counter went backwards.
pub fn cpu_busy_ratio(previous: &CpuTimes, current: &CpuTimes) -> Option<f64> {
    let deltas = [
        current.user.checked_sub(previous.user),
        current.nice.checked_sub(previous.nice),
        current.system.checked_sub(previous.system),
        current.irq.checked_sub(previous.irq),
        current.softirq.checked_sub(previous.softirq),
        current.steal.checked_sub(previous.steal),
        current.idle.checked_sub(previous.idle),
        current.iowait.checked_sub(previous.iowait),
    ];
    let collected: Option<Vec<u64>> = deltas.into_iter().collect();
    let all = collected?;
    let (busy_part, idle_part) = all.split_at(BUSY_FIELDS);
    let busy: u64 = busy_part.iter().fold(0, |sum: u64, delta| sum.saturating_add(*delta));
    let total = idle_part.iter().fold(busy, |sum: u64, delta| sum.saturating_add(*delta));
    (total > 0).then(|| busy as f64 / total as f64)
}


/// The real call, for production: the file system statistics of a path.
pub fn statvfs_path(path: &Path) -> rustix::io::Result<rustix::fs::StatVfs> {
    rustix::fs::statvfs(path)
}


pub fn mount_stat(path: &Path, stat: StatFn) -> Option<MountStat> {
    let usage = stat(path)
        .inspect_err(|error| tracing::warn!(%error, path = %path.display(), "mount statistics unavailable"))
        .ok()?;
    Some(MountStat {
        mount: path.to_string_lossy().into_owned(),
        total_bytes: usage.f_blocks.saturating_mul(usage.f_frsize),
        free_bytes: usage.f_bfree.saturating_mul(usage.f_frsize),
        available_bytes: usage.f_bavail.saturating_mul(usage.f_frsize),
    })
}


/// At most `MAX_MOUNTS` paths are asked; the rest is counted in `omitted`, a failing path in `failed`.
pub fn stat_mounts(paths: &[PathBuf], stat: StatFn) -> MountSurvey {
    let outcomes: Vec<Option<MountStat>> = paths.iter().take(MAX_MOUNTS).map(|path| mount_stat(path, stat)).collect();
    let failed = outcomes.iter().filter(|outcome| outcome.is_none()).count() as u64;
    let omitted = paths.len().saturating_sub(MAX_MOUNTS) as u64;
    MountSurvey {
        mounts: outcomes.into_iter().flatten().collect(),
        failed,
        omitted,
    }
}
