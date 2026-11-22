use crate::error::SourceError;
use crate::hostmetrics::{cpu_busy_ratio, read_sample, stat_mounts};
use crate::model::{HostSample, MetricsEnv, MetricsMemory, MetricsSettings, MetricsTotals, MountStat, SourceSettings};
use crate::spool::append_within;
use crate::types::{SharedMetrics, SharedSource};
use crate::updates::{present, OUTCOME_OK, OUTCOME_SPOOL_FULL, SKIP_EVENT_TOO_LONG};
use agent_channel::types::{ClockFn, PauseFn};
use serde_json::{json, Map, Value};
use std::time::Duration;


pub const DATASET_HOST_METRICS: &str = "ostyr.host_metrics";


/// The CPU busy ratio, only between two samples of the same known boot; `None` on the first round, after a boot change and when the boot id is unknown.
pub fn busy_ratio(memory: &MetricsMemory, sample: &HostSample) -> Option<f64> {
    let same_boot = memory.boot_id.is_some() && memory.boot_id == sample.boot_id;
    let (previous, current) = memory.cpu.zip(sample.cpu)?;
    same_boot.then(|| cpu_busy_ratio(&previous, &current)).flatten()
}


/// One value per mount, each with its `mountpoint`; absent when no mount answered.
pub fn per_mount(mounts: &[MountStat], value: fn(&MountStat) -> u64) -> Option<Value> {
    (!mounts.is_empty()).then(|| {
        Value::Array(
            mounts
                .iter()
                .map(|mount| json!({"mountpoint": mount.mount, "value": value(mount)}))
                .collect(),
        )
    })
}


/// The ECS line of one sample: values that could not be read are absent keys, the mount survey counts always travel with it.
pub fn metrics_line(sample: &HostSample, ratio: Option<f64>) -> String {
    let load = sample.load.as_ref();
    let values: Map<String, Value> = present(vec![
        ("system.cpu.utilization", ratio.map(|value| json!(value))),
        ("system.memory.limit", sample.mem_total_bytes.map(|value| json!(value))),
        ("system.memory.available", sample.mem_available_bytes.map(|value| json!(value))),
        ("system.paging.limit", sample.swap_total_bytes.map(|value| json!(value))),
        ("system.paging.free", sample.swap_free_bytes.map(|value| json!(value))),
        ("system.cpu.load_average.1m", load.map(|found| json!(found.one))),
        ("system.cpu.load_average.5m", load.map(|found| json!(found.five))),
        ("system.cpu.load_average.15m", load.map(|found| json!(found.fifteen))),
        ("system.oom_kills", sample.oom_kill.map(|value| json!(value))),
        ("system.uptime", sample.uptime_seconds.map(|value| json!(value))),
        ("system.filesystem.limit", per_mount(&sample.survey.mounts, |mount| mount.total_bytes)),
        ("system.filesystem.free", per_mount(&sample.survey.mounts, |mount| mount.free_bytes)),
    ]);
    let host = present(vec![("boot_id", sample.boot_id.as_ref().map(|boot| json!(boot)))]);
    json!({
        "event": {"kind": "metric", "category": ["host"], "type": ["info"], "dataset": DATASET_HOST_METRICS},
        "host": host,
        "metrics": values,
        "metrics_omitted": sample.survey.omitted,
        "metrics_failed": sample.survey.failed,
    })
    .to_string()
}


/// One round on a blocking thread: read the sample, append its line within the spool bound; the outcome name and what the next round remembers.
pub fn metrics_round(
    env: &MetricsEnv,
    settings: &MetricsSettings,
    source: &SourceSettings,
    memory: &MetricsMemory,
) -> Result<(&'static str, MetricsMemory), SourceError> {
    let survey = stat_mounts(&settings.mounts, env.stat);
    let sample = read_sample(&env.root, env.read, &survey);
    let line = metrics_line(&sample, busy_ratio(memory, &sample));
    let next = MetricsMemory {
        boot_id: sample.boot_id,
        cpu: sample.cpu,
    };
    let outcome = if line.len() > env.line_limit {
        SKIP_EVENT_TOO_LONG
    } else if append_within(&env.lock, &env.spool, &env.sending, source.max_spool_bytes, &[line])? {
        OUTCOME_OK
    } else {
        OUTCOME_SPOOL_FULL
    };
    Ok((outcome, next))
}


/// The totals after one more round of this outcome.
pub fn counted(totals: MetricsTotals, outcome: &str) -> MetricsTotals {
    MetricsTotals {
        published: totals.published + u64::from(outcome == OUTCOME_OK),
        spool_full: totals.spool_full + u64::from(outcome == OUTCOME_SPOOL_FULL),
        too_long: totals.too_long + u64::from(outcome == SKIP_EVENT_TOO_LONG),
    }
}


/// Runs `max_runs` rounds, the first at start, each next one `interval_seconds` after the start of the previous; a refused line is counted and logged and the round still pauses, a failing spool write ends the agent.
pub async fn run_metrics(
    metrics: &SharedMetrics,
    source: &SharedSource,
    env: &MetricsEnv,
    max_runs: u64,
    pause: &PauseFn,
    monotonic: &ClockFn,
) -> Result<MetricsTotals, SourceError> {
    let mut totals = MetricsTotals::default();
    let mut memory = MetricsMemory::default();
    for _ in 0..max_runs {
        let (settings, source_settings) = (metrics.load_full(), source.load_full());
        let started = monotonic();
        let (owned, previous) = (env.clone(), memory.clone());
        let (snapshot, bound) = (settings.clone(), source_settings.clone());
        let (outcome, next) = tokio::task::spawn_blocking(move || metrics_round(&owned, &snapshot, &bound, &previous))
            .await?
            .inspect_err(|error| tracing::error!(%error, "host metrics not spooled, the agent stops"))?;
        if outcome != OUTCOME_OK {
            tracing::warn!(outcome, "host metrics line not spooled");
        }
        memory = next;
        totals = counted(totals, outcome);
        pause(Duration::from_secs(
            settings.interval_seconds.saturating_sub(monotonic().saturating_sub(started)),
        ))
        .await;
    }
    Ok(totals)
}
