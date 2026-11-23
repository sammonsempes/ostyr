mod common;


use common::types::TestResult;
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::cli::{run_cli, run_host_files, CliError};
use metrics_ingest::host::{host_rows, MAX_HOST_EVENT_BYTES, MAX_MOUNTS};
use metrics_ingest::model::{DropReason, HostCaller, Limits, MetricKind, Outcome, Refusal, SampleRow};
use metrics_ingest::run::run_host_insert;
use std::time::Duration;
use tempfile::tempdir;


const TENANT: &str = "a";


const STAMP: u64 = 1_700_000_000_000_000_000;


const ONE: u64 = 1;


const TWO: usize = 2;


const COUNT_TWO: u64 = 2;


const COUNT_FOUR: u64 = 4;


const ONE_F: f64 = 1.0;


const ZERO_F: f64 = 0.0;


const COUNT_THREE: u64 = 3;


const THREE: usize = 3;


const MANY_ENTRIES: usize = 10_000;


const FULL_EVENT_ROWS: usize = 14;


const BYTES_VALUE: f64 = 8_589_934_592.0;


const FS_LIMIT: f64 = 107_374_182_400.0;


const RATIO: f64 = 0.25;


const OOM: f64 = 3.0;


fn event_with(metrics: &str, stamp: &str, host: &str) -> String {
    format!(
        r#"{{"@timestamp":"{stamp}","ecs":{{"version":"8.11.0"}},"event":{{"kind":"metric","dataset":"ostyr.host_metrics"}},"host":{{"name":"{host}","boot_id":"3f2a0c1e-0000-4000-8000-000000000001"}},"tenant":"evil","metrics":{metrics},"metrics_omitted":0,"metrics_failed":1}}"#
    )
}


const AGENT: &str = "agent-7";


fn caller() -> HostCaller<'static> {
    HostCaller {
        tenant: TENANT,
        agent_id: AGENT,
        received_nanos: STAMP,
    }
}


fn convert(text: &str, limits: &Limits, state: &mut CardinalityState) -> Outcome {
    host_rows(text.as_bytes(), &caller(), limits, state)
}


fn simple(metrics: &str) -> Outcome {
    convert(
        &event_with(metrics, "2023-11-14T22:13:20Z", "web-1"),
        &Limits::default(),
        &mut CardinalityState::default(),
    )
}


fn find<'a>(outcome: &'a Outcome, name: &str) -> Result<&'a SampleRow, String> {
    outcome.rows.iter().find(|row| row.name == name).ok_or_else(|| format!("no row {name}"))
}


fn label<'a>(row: &'a SampleRow, key: &str) -> Option<&'a str> {
    row.labels.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str())
}


fn dropped(outcome: &Outcome, reason: DropReason) -> u64 {
    outcome.dropped.get(&reason).copied().unwrap_or(0)
}


const FULL_METRICS: &str = r#"{"system.cpu.utilization":0.25,"system.memory.limit":8589934592,"system.memory.available":4294967296,
"system.paging.limit":2147483648,"system.paging.free":1073741824,"system.cpu.load_average.1m":0.5,"system.cpu.load_average.5m":0.4,
"system.cpu.load_average.15m":0.3,"system.oom_kills":3,"system.uptime":3600,
"system.filesystem.limit":[{"mountpoint":"/","value":107374182400}],"system.filesystem.free":[{"mountpoint":"/","value":53687091200}]}"#;


#[test]
fn the_agent_example_converts_to_the_expected_rows() -> TestResult {
    let outcome = simple(FULL_METRICS);
    assert_eq!(outcome.refusal, None);
    assert_eq!(dropped(&outcome, DropReason::PayloadIdentityIgnored), COUNT_TWO);
    assert_eq!(outcome.dropped.len(), 1);
    assert_eq!(outcome.rows.len(), FULL_EVENT_ROWS);
    let ratio = find(&outcome, "system.cpu.utilization")?;
    assert_eq!(
        (ratio.unit.as_str(), ratio.kind, ratio.value, ratio.timestamp_nanos),
        ("1", MetricKind::Gauge, RATIO, STAMP)
    );
    assert_eq!(ratio.tenant, TENANT);
    assert_eq!(ratio.labels, vec![("host.id".to_string(), AGENT.to_string())]);
    let memory = find(&outcome, "system.memory.limit")?;
    assert_eq!((memory.unit.as_str(), memory.value), ("By", BYTES_VALUE));
    let oom = find(&outcome, "system.oom_kills")?;
    assert_eq!(
        (oom.unit.as_str(), oom.kind, oom.monotonic, oom.value),
        ("{process}", MetricKind::Counter, true, OOM)
    );
    assert_eq!(find(&outcome, "system.uptime")?.unit, "s");
    let limit = find(&outcome, "system.filesystem.limit")?;
    assert_eq!(limit.value, FS_LIMIT);
    assert_eq!(label(limit, "mountpoint"), Some("/"));
    assert_eq!(label(limit, "host.id"), Some(AGENT));
    let failed = find(&outcome, "ostyr.agent.metrics_failed")?;
    assert_eq!((failed.value, failed.unit.as_str()), (ONE_F, "{mount}"));
    assert_eq!(find(&outcome, "ostyr.agent.metrics_omitted")?.value, ZERO_F);
    Ok(())
}


#[test]
fn boot_id_and_an_agent_tenant_never_become_labels() -> TestResult {
    let outcome = simple(FULL_METRICS);
    assert!(outcome
        .rows
        .iter()
        .all(|row| row.tenant == TENANT && row.labels.iter().all(|(key, _)| key == "host.id" || key == "mountpoint")));
    Ok(())
}


#[test]
fn a_missing_metrics_block_still_gives_the_two_gap_gauges() -> TestResult {
    let text = r#"{"@timestamp":"2023-11-14T22:13:20Z","event":{"dataset":"ostyr.host_metrics"},"host":{"name":"h"}}"#;
    let outcome = convert(text, &Limits::default(), &mut CardinalityState::default());
    assert!(outcome.rows.is_empty());
    assert_eq!(outcome.refusal, None);
    Ok(())
}


#[test]
fn each_malformed_value_drops_only_its_row() -> TestResult {
    let metrics = r#"{"system.cpu.utilization":1.5,"system.memory.limit":1e309,"system.memory.available":-0,"system.paging.limit":"5",
"system.paging.free":-1,"system.uptime":null,"system.oom_kills":true,"system.cpu.load_average.1m":2}"#;
    let outcome = simple(metrics);
    assert_eq!(dropped(&outcome, DropReason::OutOfRange), COUNT_FOUR);
    assert_eq!(dropped(&outcome, DropReason::NotANumber), COUNT_THREE);
    assert!(find(&outcome, "system.cpu.load_average.1m").is_ok());
    assert!(find(&outcome, "system.memory.limit").is_err());
    Ok(())
}


#[test]
fn a_ratio_of_exactly_one_and_zero_are_kept() -> TestResult {
    assert_eq!(simple(r#"{"system.cpu.utilization":1}"#).rows.len(), THREE);
    assert_eq!(simple(r#"{"system.cpu.utilization":0}"#).rows.len(), THREE);
    Ok(())
}


#[test]
fn mount_entries_are_capped_before_they_are_built() -> TestResult {
    let entries = |count: usize| vec![r#"{"mountpoint":"/m","value":1}"#; count].join(",");
    let at_cap = simple(&format!(r#"{{"system.filesystem.limit":[{}]}}"#, entries(MAX_MOUNTS)));
    assert_eq!(dropped(&at_cap, DropReason::TooManyMounts), 0);
    let over = simple(&format!(r#"{{"system.filesystem.limit":[{}]}}"#, entries(MAX_MOUNTS + 1)));
    assert_eq!(dropped(&over, DropReason::TooManyMounts), ONE);
    assert!(find(&over, "system.filesystem.limit").is_err());
    let huge = simple(&format!(r#"{{"system.filesystem.free":[{}]}}"#, vec!["0"; MANY_ENTRIES].join(",")));
    assert_eq!(dropped(&huge, DropReason::TooManyMounts), ONE);
    Ok(())
}


#[test]
fn mountpoints_are_text_checked_and_distinct() -> TestResult {
    let metrics = "{\"system.filesystem.limit\":[{\"mountpoint\":\"/a\",\"value\":1},{\"mountpoint\":\"/a/\",\"value\":1},\
{\"mountpoint\":\"/a\\u200b\",\"value\":1},{\"mountpoint\":\"/b\\u0007\",\"value\":1}]}";
    let outcome = simple(metrics);
    let mounts: Vec<Option<&str>> = outcome
        .rows
        .iter()
        .filter(|row| row.name == "system.filesystem.limit")
        .map(|row| label(row, "mountpoint"))
        .collect();
    assert_eq!(mounts, vec![Some("/a"), Some("/a/")]);
    assert_eq!(dropped(&outcome, DropReason::ControlCharacter), COUNT_TWO);
    Ok(())
}


#[test]
fn malformed_mount_entries_are_dropped_one_by_one() -> TestResult {
    let metrics = r#"{"system.filesystem.limit":[5,{"mountpoint":"","value":1},{"value":1},{"mountpoint":"/x"},{"mountpoint":"/y","value":"1"},{"mountpoint":"/ok","value":2}],
"system.filesystem.free":{"not":"an array"}}"#;
    let outcome = simple(metrics);
    assert_eq!(dropped(&outcome, DropReason::MalformedMounts), COUNT_TWO);
    assert_eq!(dropped(&outcome, DropReason::EmptyName), COUNT_TWO);
    assert_eq!(dropped(&outcome, DropReason::MissingValue), 1);
    assert_eq!(dropped(&outcome, DropReason::NotANumber), 1);
    assert_eq!(outcome.rows.iter().filter(|row| label(row, "mountpoint") == Some("/ok")).count(), 1);
    Ok(())
}


#[test]
fn a_tenant_at_its_series_cap_drops_new_series_named() -> TestResult {
    let limits = Limits {
        max_series_per_tenant: TWO,
        ..Limits::default()
    };
    let mut state = CardinalityState::default();
    let outcome = convert(
        &event_with(
            r#"{"system.uptime":1,"system.oom_kills":1,"system.memory.limit":1}"#,
            "2023-11-14T22:13:20Z",
            "h",
        ),
        &limits,
        &mut state,
    );
    assert_eq!(outcome.rows.len(), TWO);
    assert_eq!(dropped(&outcome, DropReason::SeriesCap), COUNT_THREE);
    Ok(())
}


#[test]
fn a_rotating_agent_id_hits_the_value_cap() -> TestResult {
    let limits = Limits {
        max_values_per_label: TWO,
        ..Limits::default()
    };
    let mut state = CardinalityState::default();
    let text = event_with(r#"{"system.uptime":1}"#, "2023-11-14T22:13:20Z", "h");
    let outcomes: Vec<Outcome> = ["a1", "a2", "a3"]
        .iter()
        .map(|agent_id| {
            let rotating = HostCaller { agent_id, ..caller() };
            host_rows(text.as_bytes(), &rotating, &limits, &mut state)
        })
        .collect();
    let last = outcomes.last().map(|outcome| dropped(outcome, DropReason::LabelValueCap));
    assert_eq!(last, Some(COUNT_THREE));
    Ok(())
}


#[test]
fn a_payload_host_and_time_never_reach_a_row() -> TestResult {
    let nested = r#"{"@timestamp":"2001-01-01T00:00:00Z","event":{"dataset":"ostyr.host_metrics"},"host":{"name":"db-prod-1","id":"x","boot_id":"b"},
"metrics":{"system.uptime":1}}"#;
    let flat = r#"{"@timestamp":"2001-01-01T00:00:00Z","event":{"dataset":"ostyr.host_metrics"},"host.name":"db-prod-1","host.boot_id":"b","host.ip":"1",
"metrics":{"system.uptime":1}}"#;
    let limits = Limits::default();
    let seen = [(nested, COUNT_THREE), (flat, COUNT_THREE)].map(|(text, count)| (convert(text, &limits, &mut CardinalityState::default()), count));
    seen.iter().for_each(|(outcome, count)| {
        assert_eq!(dropped(outcome, DropReason::PayloadIdentityIgnored), *count);
        assert_eq!(outcome.rows.len(), 1);
        assert!(outcome
            .rows
            .iter()
            .all(|row| row.timestamp_nanos == STAMP && row.labels == vec![("host.id".to_string(), AGENT.to_string())]));
    });
    Ok(())
}


#[test]
fn an_unknown_metric_key_is_counted() -> TestResult {
    let outcome = simple(r#"{"system.uptime":1,"system.evil":9,"x":1}"#);
    assert_eq!(dropped(&outcome, DropReason::UnknownMetric), COUNT_TWO);
    assert_eq!(find(&outcome, "system.uptime")?.value, ONE_F);
    Ok(())
}


#[test]
fn an_unusable_event_is_refused_named() -> TestResult {
    let limits = Limits::default();
    let mut state = CardinalityState::default();
    let mut refusal = |text: String| convert(&text, &limits, &mut state).refusal;
    assert_eq!(refusal(r#"{"event":{"dataset":"other"}}"#.to_string()), Some(Refusal::NotHostMetrics));
    assert_eq!(refusal("{}".to_string()), Some(Refusal::NotHostMetrics));
    assert_eq!(refusal("not json".to_string()), Some(Refusal::BadEvent));
    assert_eq!(refusal(r#"{"event":5}"#.to_string()), Some(Refusal::BadEvent));
    assert_eq!(refusal(r#"{"host":5}"#.to_string()), Some(Refusal::BadEvent));
    assert_eq!(refusal(r#"{"metrics":5}"#.to_string()), Some(Refusal::BadEvent));
    let big = "x".repeat(MAX_HOST_EVENT_BYTES + 1);
    assert!(matches!(refusal(big), Some(Refusal::TooLarge { .. })));
    let hostile = HostCaller {
        agent_id: "h\u{200b}",
        ..caller()
    };
    let text = event_with("{}", "2023-11-14T22:13:20Z", "h");
    assert_eq!(host_rows(text.as_bytes(), &hostile, &limits, &mut state).refusal, Some(Refusal::BadHost));
    Ok(())
}


#[test]
fn the_cli_host_mode_checks_the_tenant_first_and_other_modes_are_usage() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("event.json");
    std::fs::write(&file, event_with("{}", "2023-11-14T22:13:20Z", "h"))?;
    let path = file.to_str().ok_or("path")?;
    let elapsed = || Duration::ZERO;
    let mut out = Vec::new();
    let refused = run_host_files("missing.yaml", path, "-x", AGENT, 0, &elapsed, &mut out);
    assert!(matches!(refused, Err(CliError::Run(_))));
    let args: Vec<String> = ["missing.yaml", path, "-x", "host", AGENT].iter().map(ToString::to_string).collect();
    assert!(matches!(run_cli(&args, 0, &elapsed, &mut out), Err(CliError::Run(_))));
    let other: Vec<String> = ["missing.yaml", path, "a", "other", AGENT].iter().map(ToString::to_string).collect();
    assert!(matches!(run_cli(&other, 0, &elapsed, &mut out), Err(CliError::Usage)));
    Ok(())
}


#[test]
fn every_new_drop_reason_has_a_fixed_name() -> TestResult {
    let names: Vec<String> = [
        DropReason::NotANumber,
        DropReason::OutOfRange,
        DropReason::TooManyMounts,
        DropReason::MalformedMounts,
        DropReason::PayloadIdentityIgnored,
        DropReason::UnknownMetric,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        names,
        vec![
            "not_a_number",
            "out_of_range",
            "too_many_mounts",
            "malformed_mounts",
            "payload_identity_ignored",
            "unknown_metric"
        ]
    );
    Ok(())
}


#[test]
fn a_host_event_without_rows_is_converted_for_the_caller_and_sends_nothing() -> TestResult {
    let dir = tempdir()?;
    let settings = dir.path().join("settings.yaml");
    std::fs::write(
        &settings,
        "url: http://127.0.0.1:1\nuser: ostyr\npassword_file: password\ndatabase: ostyr\ntable: t\n",
    )?;
    let event = r#"{"event":{"dataset":"ostyr.host_metrics"},"host":{"name":"spoof"}}"#;
    let elapsed = || Duration::ZERO;
    let report = run_host_insert(
        &settings,
        event.as_bytes(),
        TENANT,
        AGENT,
        &mut CardinalityState::default(),
        STAMP,
        &elapsed,
    )?;
    assert_eq!(
        (report.tenant.as_str(), report.rows, report.batches_sent, report.failed_batch),
        (TENANT, 0, 0, None)
    );
    assert_eq!(report.dropped.get(&DropReason::PayloadIdentityIgnored), Some(&ONE));
    Ok(())
}
