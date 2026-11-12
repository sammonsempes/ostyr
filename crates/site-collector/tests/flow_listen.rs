#[path = "support/types.rs"]
mod types;


use core_audit::log::{append, open_file_log};
use core_config::reload::{reload, ReloadContext, ReloadOutcome};
use site_collector::admission::admit_extra_record;
use site_collector::error::{ConfigError, ListenError};
use site_collector::flow::validate_flow_limits;
use site_collector::flow_listen::{encode_frame, flow_version, handle_flow_datagram, handle_flow_with};
use site_collector::flow_model::{FlowFrame, FlowLimits, MAX_EXPORTERS_PER_SOURCE_KEY, MAX_TEMPLATES_TOTAL, MAX_TEMPLATE_DATAGRAM_BYTES};
use site_collector::listen::{handle_datagram, open_runtime, prune_if_due, receive_buffer_len, sync_settings};
use site_collector::listen_model::{ListenerKind, ListenerSettings, Runtime, PRUNE_INTERVAL_MS};
use site_collector::listen_settings::{open_listener_engine, settings_state, validate_settings};
use site_collector::model::DropReason;
use site_collector::model::MAX_MESSAGE_BYTES;
use site_collector::spool::{open_spool, read_from, spool_stats};
use site_collector::spool_model::{Priority, SpoolConfig, MAX_FRAME_BYTES};
use site_collector::template::{evict_least_recent_exporter, set_declared};
use site_collector::template_model::TemplateCache;
use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use types::TestResult;


const V5: &[u8] = include_bytes!("fixtures/netflow/v5-softflowd.bin");


const V9: &[u8] = include_bytes!("fixtures/netflow/v9-softflowd.bin");


const IPFIX: &[u8] = include_bytes!("fixtures/netflow/ipfix-softflowd.bin");


const NOW: u64 = 1_000_000;


const FLOW_PORT: u16 = 2055;


const SEGMENTS: u64 = 16;


const REPLAY: usize = 1000;


const V5_RECORDS: u64 = 2;


const SOFTFLOWD_RECORDS: u64 = 8;


const TEMPLATE_ID: u16 = 300;


const SET_HEADER: usize = 4;


const FIELD_COUNT: u16 = 2;


const ELEMENT_SOURCE_PORT: u16 = 7;


const ELEMENT_DESTINATION_PORT: u16 = 11;


const PORT_FIELD_BYTES: u16 = 2;


const RECORD_BYTES: usize = 4;


const V9_VERSION: u16 = 9;


const V9_UPTIME: u32 = 100_000;


const V9_SECONDS: u32 = 1_700_000_000;


const KEY_CAP: usize = 2;


const EXPORTER_CAP: usize = 2;


const TOTAL_CAP: usize = 3;


const SMALL_TOTAL: usize = 2;


const PRUNE_AGE_SECONDS: u64 = 1;


const FILLER: u8 = 0xAB;


const GOLDEN_KEYS: usize = 18;


const GOLDEN_START: &str = "{\"v\":1,\"exporter\":\"10.0.0.1\",\"source\":";


const HOST_TWO: u8 = 2;


const FIRST_OCTET: u8 = 10;


const V6_PREFIX: u16 = 0x2001;


const V6_SECOND: u16 = 0xdb8;


const RATE: u64 = 1_000_000;


const SHARE: u64 = 99;


const UNKNOWN_SHARE: u64 = 50;


const SOURCES: usize = 4096;


const BATCH: usize = 500;


const THREE: u64 = 3;


const TWO: u64 = 2;


const LIMIT_SEVEN: usize = 7;


const HOST_THREE: u8 = 3;


const HOST_FOUR: u8 = 4;


const SEGMENT_FACTOR: u64 = 16;


fn word(value: u16) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}


fn long_word(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}


fn set(set_id: u16, body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(body.len() + SET_HEADER).unwrap_or(u16::MAX);
    [word(set_id), word(length), body.to_vec()].concat()
}


fn template_set(template_id: u16) -> Vec<u8> {
    let body = [
        word(template_id),
        word(FIELD_COUNT),
        word(ELEMENT_SOURCE_PORT),
        word(PORT_FIELD_BYTES),
        word(ELEMENT_DESTINATION_PORT),
        word(PORT_FIELD_BYTES),
    ]
    .concat();
    set(0, &body)
}


fn data_set(template_id: u16, records: usize) -> Vec<u8> {
    set(template_id, &vec![FILLER; records * RECORD_BYTES])
}


fn v9(domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
    [
        word(V9_VERSION),
        word(0),
        long_word(V9_UPTIME),
        long_word(V9_SECONDS),
        long_word(0),
        long_word(domain),
        sets.concat(),
    ]
    .concat()
}


fn v4_source(last: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(FIRST_OCTET, 0, 0, last)), FLOW_PORT)
}


fn v6_source(last: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(V6_PREFIX, V6_SECOND, 0, 1, 0, 0, 0, last)), FLOW_PORT)
}


fn flow_settings() -> ListenerSettings {
    ListenerSettings {
        listen: "127.0.0.1:0".to_owned(),
        kind: ListenerKind::Netflow,
        flow: FlowLimits::default(),
        tenant: "acme".to_owned(),
        rate_per_second: RATE,
        burst: RATE,
        source_share_percent: SHARE,
        unknown_share_percent: UNKNOWN_SHARE,
        max_sources: SOURCES,
        forward_batch_records: BATCH,
        drop_unknown: false,
        sources: Vec::new(),
        bind_failed: Arc::default(),
    }
}


fn runtime_in(dir: &Path, settings: ListenerSettings) -> Result<Runtime, Box<dyn std::error::Error>> {
    let spool_dir = dir.join("spool");
    fs::create_dir_all(&spool_dir)?;
    let spool = open_spool(
        &spool_dir,
        SpoolConfig {
            segment_max_bytes: MAX_FRAME_BYTES,
            total_max_bytes: MAX_FRAME_BYTES * SEGMENTS * SEGMENT_FACTOR,
        },
    )?;
    Ok(open_runtime(Arc::new(settings), spool)?)
}


fn frames(runtime: &Runtime) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(read_from(&runtime.spool, 0, REPLAY)?
        .iter()
        .map(|record| String::from_utf8_lossy(&record.payload).into_owned())
        .collect())
}


fn with_limits(flow: FlowLimits) -> ListenerSettings {
    ListenerSettings { flow, ..flow_settings() }
}


#[test]
fn v5_v9_and_ipfix_give_one_frame_per_record() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), flow_settings())?;
    handle_datagram(&mut runtime, v4_source(1), V5, NOW, 0);
    assert_eq!((runtime.stats.flows_accepted, runtime.stats.flow_records), (1, V5_RECORDS));
    handle_datagram(&mut runtime, v4_source(1), V9, NOW, 0);
    handle_flow_datagram(&mut runtime, v4_source(1), IPFIX, NOW);
    assert_eq!(runtime.stats.flows_accepted, THREE);
    assert_eq!(runtime.stats.flow_records, V5_RECORDS + TWO * SOFTFLOWD_RECORDS);
    assert_eq!(runtime.stats.received, THREE);
    let stored = frames(&runtime)?;
    assert_eq!(u64::try_from(stored.len())?, runtime.stats.flow_records);
    assert!(read_from(&runtime.spool, 0, REPLAY)?
        .iter()
        .all(|record| record.priority == Priority::Low));
    assert_eq!(spool_stats(&runtime.spool).next_sequence, runtime.stats.flow_records);
    Ok(())
}


#[test]
fn the_frame_shape_is_versioned_and_complete() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), flow_settings())?;
    handle_datagram(&mut runtime, v4_source(1), V5, NOW, 0);
    let stored = frames(&runtime)?;
    let first = stored.first().ok_or("no frame")?;
    assert!(first.starts_with(GOLDEN_START), "{first}");
    let parsed: serde_json::Value = serde_json::from_str(first)?;
    let keys: Vec<&String> = parsed.as_object().ok_or("not an object")?.keys().collect();
    assert_eq!(keys.len(), GOLDEN_KEYS);
    assert_eq!(parsed.get("v"), Some(&serde_json::json!(1)));
    Ok(())
}


#[test]
fn an_ipv4_mapped_exporter_is_recorded_as_ipv4() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), flow_settings())?;
    let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(FIRST_OCTET, 0, 0, 1).to_ipv6_mapped()), FLOW_PORT);
    handle_datagram(&mut runtime, mapped, V5, NOW, 0);
    let stored = frames(&runtime)?;
    assert!(stored.iter().all(|frame| frame.starts_with(GOLDEN_START)));
    Ok(())
}


#[test]
fn unsupported_short_and_templateless_datagrams_are_counted() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), flow_settings())?;
    handle_datagram(&mut runtime, v4_source(1), &[0, HOST_FOUR, 0, 0], NOW, 0);
    handle_datagram(&mut runtime, v4_source(1), &[1], NOW, 0);
    handle_datagram(&mut runtime, v4_source(1), &[], NOW, 0);
    assert_eq!(runtime.stats.dropped_parse, THREE);
    handle_datagram(&mut runtime, v4_source(1), &v9(0, &[data_set(TEMPLATE_ID, 1)]), NOW, 0);
    assert_eq!(runtime.stats.dropped_parse, HOST_FOUR as u64);
    assert_eq!((runtime.stats.flows_accepted, runtime.stats.flow_records), (0, 0));
    assert_eq!(flow_version(&[0, V9_VERSION as u8]), Some(V9_VERSION));
    assert_eq!(flow_version(&[0]), None);
    Ok(())
}


#[test]
fn data_only_datagrams_decode_with_the_cached_template() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), flow_settings())?;
    handle_datagram(&mut runtime, v4_source(1), &v9(0, &[template_set(TEMPLATE_ID)]), NOW, 0);
    assert_eq!(runtime.stats.flow_records, 0);
    handle_datagram(
        &mut runtime,
        v4_source(1),
        &v9(0, &[data_set(TEMPLATE_ID, usize::from(HOST_THREE))]),
        NOW,
        0,
    );
    assert_eq!(runtime.stats.flow_records, HOST_THREE as u64);
    handle_datagram(&mut runtime, v4_source(HOST_TWO), &v9(0, &[data_set(TEMPLATE_ID, 1)]), NOW, 0);
    assert_eq!(runtime.stats.flow_records, HOST_THREE as u64);
    Ok(())
}


#[test]
fn a_refused_source_never_touches_the_cache() -> TestResult {
    let dir = TempDir::new()?;
    let settings = ListenerSettings {
        drop_unknown: true,
        sources: vec![v4_source(HOST_TWO).ip()],
        ..flow_settings()
    };
    let mut runtime = runtime_in(dir.path(), settings)?;
    handle_datagram(&mut runtime, v4_source(1), &v9(0, &[template_set(TEMPLATE_ID)]), NOW, 0);
    assert_eq!(runtime.stats.dropped_unknown, 1);
    assert!(runtime.templates.exporters.is_empty());
    handle_datagram(&mut runtime, v4_source(HOST_TWO), &v9(0, &[template_set(TEMPLATE_ID)]), NOW, 0);
    assert_eq!(runtime.templates.exporters.len(), 1);
    Ok(())
}


#[test]
fn the_size_cap_is_the_template_datagram_cap() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), flow_settings())?;
    handle_datagram(&mut runtime, v4_source(1), &vec![0; MAX_TEMPLATE_DATAGRAM_BYTES + 1], NOW, 0);
    assert_eq!((runtime.stats.dropped_too_long, runtime.stats.dropped_parse), (1, 0));
    handle_datagram(&mut runtime, v4_source(1), &vec![0; MAX_TEMPLATE_DATAGRAM_BYTES], NOW, 0);
    assert_eq!((runtime.stats.dropped_too_long, runtime.stats.dropped_parse), (1, 1));
    assert_eq!(receive_buffer_len(ListenerKind::Netflow), MAX_TEMPLATE_DATAGRAM_BYTES + 1);
    assert_eq!(receive_buffer_len(ListenerKind::Syslog), MAX_MESSAGE_BYTES + 1);
    Ok(())
}


#[test]
fn exporters_per_source_key_are_capped_at_n_and_n_plus_one() -> TestResult {
    let dir = TempDir::new()?;
    let flow = FlowLimits {
        max_exporters_per_source_key: KEY_CAP,
        ..FlowLimits::default()
    };
    let mut runtime = runtime_in(dir.path(), with_limits(flow))?;
    let define = v9(0, &[template_set(TEMPLATE_ID)]);
    handle_datagram(&mut runtime, v4_source(1), &define, NOW, 0);
    (1..=KEY_CAP as u16).for_each(|last| handle_datagram(&mut runtime, v6_source(last), &define, NOW, 0));
    assert_eq!(runtime.templates.exporters.len(), KEY_CAP + 1);
    assert_eq!(runtime.templates.stats.refused_templates, 0);
    handle_datagram(&mut runtime, v6_source(HOST_THREE.into()), &define, NOW, 0);
    assert_eq!(runtime.templates.exporters.len(), KEY_CAP + 1);
    assert_eq!(runtime.templates.stats.refused_templates, 1);
    assert_eq!(runtime.templates.stats.evicted_exporters, 0);
    assert_eq!(runtime.stats.dropped_parse, 1);
    handle_datagram(&mut runtime, v6_source(1), &v9(0, &[data_set(TEMPLATE_ID, 1)]), NOW, 0);
    assert_eq!(runtime.stats.flow_records, 1);
    Ok(())
}


#[test]
fn an_undeclared_exporter_never_evicts_a_declared_one() -> TestResult {
    let dir = TempDir::new()?;
    let flow = FlowLimits {
        max_template_exporters: EXPORTER_CAP,
        ..FlowLimits::default()
    };
    let settings = ListenerSettings {
        sources: vec![v4_source(1).ip(), v4_source(HOST_TWO).ip()],
        ..with_limits(flow)
    };
    let mut runtime = runtime_in(dir.path(), settings)?;
    let define = v9(0, &[template_set(TEMPLATE_ID)]);
    handle_datagram(&mut runtime, v4_source(1), &define, NOW, 0);
    handle_datagram(&mut runtime, v4_source(HOST_THREE), &define, NOW, 0);
    handle_datagram(&mut runtime, v4_source(HOST_FOUR), &define, NOW, 0);
    let held: Vec<IpAddr> = runtime.templates.exporters.keys().copied().collect();
    assert_eq!(held, vec![v4_source(1).ip(), v4_source(HOST_FOUR).ip()]);
    assert_eq!(runtime.templates.stats.evicted_exporters, 1);
    handle_datagram(&mut runtime, v4_source(HOST_TWO), &define, NOW, 0);
    let after_declared: Vec<IpAddr> = runtime.templates.exporters.keys().copied().collect();
    assert_eq!(after_declared, vec![v4_source(1).ip(), v4_source(HOST_TWO).ip()]);
    handle_datagram(&mut runtime, v4_source(HOST_THREE), &define, NOW, 0);
    let still: Vec<IpAddr> = runtime.templates.exporters.keys().copied().collect();
    assert_eq!(still, after_declared);
    assert_eq!(runtime.templates.stats.refused_templates, 1);
    assert_eq!(runtime.templates.stats.evicted_exporters, TWO);
    Ok(())
}


#[test]
fn a_declared_exporter_evicts_the_least_recent_declared_one_when_no_undeclared_is_left() -> TestResult {
    let dir = TempDir::new()?;
    let flow = FlowLimits {
        max_template_exporters: EXPORTER_CAP,
        ..FlowLimits::default()
    };
    let settings = ListenerSettings {
        sources: vec![v4_source(1).ip(), v4_source(HOST_TWO).ip(), v4_source(HOST_THREE).ip()],
        ..with_limits(flow)
    };
    let mut runtime = runtime_in(dir.path(), settings)?;
    let define = v9(0, &[template_set(TEMPLATE_ID)]);
    [1, HOST_TWO, HOST_THREE]
        .into_iter()
        .for_each(|last| handle_datagram(&mut runtime, v4_source(last), &define, NOW, 0));
    let held: Vec<IpAddr> = runtime.templates.exporters.keys().copied().collect();
    assert_eq!(held, vec![v4_source(HOST_TWO).ip(), v4_source(HOST_THREE).ip()]);
    Ok(())
}


#[test]
fn the_total_template_cap_holds_at_n_and_n_plus_one() -> TestResult {
    let dir = TempDir::new()?;
    let flow = FlowLimits {
        max_templates_total: TOTAL_CAP,
        ..FlowLimits::default()
    };
    let mut runtime = runtime_in(dir.path(), with_limits(flow))?;
    let two = v9(0, &[template_set(TEMPLATE_ID), template_set(TEMPLATE_ID + 1)]);
    let one = v9(0, &[template_set(TEMPLATE_ID)]);
    handle_datagram(&mut runtime, v4_source(1), &two, NOW, 0);
    handle_datagram(&mut runtime, v4_source(HOST_TWO), &one, NOW, 0);
    assert_eq!(runtime.templates.templates.len(), TOTAL_CAP);
    assert_eq!(runtime.templates.stats.evicted_exporters, 0);
    handle_datagram(&mut runtime, v4_source(HOST_THREE), &one, NOW, 0);
    assert_eq!(runtime.templates.templates.len(), SMALL_TOTAL);
    assert_eq!(runtime.templates.stats.evicted_exporters, 1);
    assert!(!runtime.templates.exporters.contains_key(&v4_source(1).ip()));
    Ok(())
}


#[test]
fn a_lone_exporter_cannot_exceed_the_total_cap() -> TestResult {
    let dir = TempDir::new()?;
    let flow = FlowLimits {
        max_templates_total: SMALL_TOTAL,
        ..FlowLimits::default()
    };
    let mut runtime = runtime_in(dir.path(), with_limits(flow))?;
    let three = v9(
        0,
        &[
            template_set(TEMPLATE_ID),
            template_set(TEMPLATE_ID + 1),
            template_set(TEMPLATE_ID + FIELD_COUNT),
        ],
    );
    handle_datagram(&mut runtime, v4_source(1), &three, NOW, 0);
    assert_eq!(runtime.templates.templates.len(), SMALL_TOTAL);
    assert_eq!(runtime.templates.stats.refused_templates, 1);
    assert_eq!(runtime.templates.stats.evicted_exporters, 0);
    Ok(())
}


#[test]
fn the_prune_tick_expires_templates_of_a_flow_listener_only() -> TestResult {
    let dir = TempDir::new()?;
    let flow = FlowLimits {
        max_template_age_seconds: PRUNE_AGE_SECONDS,
        ..FlowLimits::default()
    };
    let mut runtime = runtime_in(dir.path(), with_limits(flow.clone()))?;
    handle_datagram(&mut runtime, v4_source(1), &v9(0, &[template_set(TEMPLATE_ID)]), 0, 0);
    prune_if_due(&mut runtime, PRUNE_INTERVAL_MS);
    assert!(runtime.templates.templates.is_empty());
    assert_eq!(runtime.templates.stats.expired_templates, 1);
    let other = TempDir::new()?;
    let mut syslog = runtime_in(
        other.path(),
        ListenerSettings {
            kind: ListenerKind::Syslog,
            ..with_limits(flow)
        },
    )?;
    syslog.templates.exporters.insert(
        v4_source(1).ip(),
        site_collector::template_model::ExporterState { last_used: 0, templates: 1 },
    );
    prune_if_due(&mut syslog, PRUNE_INTERVAL_MS);
    assert_eq!(syslog.templates.exporters.len(), 1);
    Ok(())
}


fn failing_encoder(_frame: &FlowFrame) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::from_str::<Vec<u8>>("x")
}


fn oversized_encoder(_frame: &FlowFrame) -> Result<Vec<u8>, serde_json::Error> {
    Ok(vec![0; MAX_FRAME_BYTES as usize])
}


#[test]
fn encode_and_spool_failures_are_counted_per_record() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), flow_settings())?;
    handle_flow_with(&mut runtime, v4_source(1), V5, NOW, failing_encoder);
    assert_eq!((runtime.stats.spool_errors, runtime.stats.flow_records), (V5_RECORDS, 0));
    handle_flow_with(&mut runtime, v4_source(1), V5, NOW, oversized_encoder);
    assert_eq!((runtime.stats.spool_errors, runtime.stats.flow_records), (TWO * V5_RECORDS, 0));
    handle_flow_with(&mut runtime, v4_source(1), V5, NOW, encode_frame);
    assert_eq!(runtime.stats.flow_records, V5_RECORDS);
    Ok(())
}


#[test]
fn flow_limits_are_validated_with_their_ceilings() -> TestResult {
    let broken = [
        FlowLimits {
            max_exporters_per_source_key: 0,
            ..FlowLimits::default()
        },
        FlowLimits {
            max_exporters_per_source_key: MAX_EXPORTERS_PER_SOURCE_KEY + 1,
            ..FlowLimits::default()
        },
        FlowLimits {
            max_templates_total: 0,
            ..FlowLimits::default()
        },
        FlowLimits {
            max_templates_total: MAX_TEMPLATES_TOTAL + 1,
            ..FlowLimits::default()
        },
    ];
    assert!(broken
        .iter()
        .all(|limits| validate_flow_limits(limits) == Err(ConfigError::BadFlowTemplateLimit)));
    let ceilings = FlowLimits {
        max_exporters_per_source_key: MAX_EXPORTERS_PER_SOURCE_KEY,
        max_templates_total: MAX_TEMPLATES_TOTAL,
        ..FlowLimits::default()
    };
    assert!(validate_flow_limits(&ceilings).is_ok());
    assert!(matches!(
        validate_settings(&with_limits(broken[0].clone())),
        Err(ListenError::Limits(ConfigError::BadFlowTemplateLimit))
    ));
    assert_eq!(FlowLimits::default().max_exporters_per_source_key, HOST_FOUR as usize);
    Ok(())
}


fn write_kind(path: &Path, kind: &str) -> std::io::Result<()> {
    fs::write(
        path,
        format!("listen: \"127.0.0.1:0\"\ntenant: acme\nkind: {kind}\nflow:\n  max_templates_total: {LIMIT_SEVEN}\n"),
    )
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "collector".to_owned(),
        tenant: "acme".to_owned(),
        module: "site-collector".to_owned(),
        target: "settings".to_owned(),
        request_id: "test".to_owned(),
    }
}


#[test]
fn a_kind_change_on_reload_is_refused_and_audited() -> TestResult {
    let dir = TempDir::new()?;
    let file = dir.path().join("listener.yaml");
    let audit = dir.path().join("audit.log");
    write_kind(&file, "netflow")?;
    let log = open_file_log(&audit)?;
    let (engine, shared) = open_listener_engine(file.clone(), Box::new(move |entry| append(&log, entry)), context())?;
    assert_eq!(shared.kind, ListenerKind::Netflow);
    let spool_dir = dir.path().join("spool");
    fs::create_dir_all(&spool_dir)?;
    let spool = open_spool(
        &spool_dir,
        SpoolConfig {
            segment_max_bytes: MAX_FRAME_BYTES,
            total_max_bytes: MAX_FRAME_BYTES * SEGMENTS,
        },
    )?;
    let mut runtime = open_runtime(core_config::reload::current_config(&engine), spool)?;
    assert_eq!(runtime.applied.flow.max_templates_total, LIMIT_SEVEN);
    assert!(settings_state(&runtime.applied).contains_key("listener.kind"));
    write_kind(&file, "syslog")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert!(fs::read_to_string(&audit)?.contains("refused"));
    sync_settings(&mut runtime, &engine);
    assert_eq!(runtime.applied.kind, ListenerKind::Netflow);
    Ok(())
}


#[test]
fn the_plain_least_recent_eviction_removes_one_whole_exporter() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), flow_settings())?;
    let define = v9(0, &[template_set(TEMPLATE_ID)]);
    handle_datagram(&mut runtime, v4_source(1), &define, NOW, 0);
    handle_datagram(&mut runtime, v4_source(HOST_TWO), &define, NOW, 0);
    assert_eq!(evict_least_recent_exporter(&mut runtime.templates), 1);
    let held: Vec<IpAddr> = runtime.templates.exporters.keys().copied().collect();
    assert_eq!(held, vec![v4_source(HOST_TWO).ip()]);
    Ok(())
}


const HOSTILE_TEMPLATES: u16 = 1000;


const STEP_BOUND: u64 = 4;


const SMALL_FLEET: u8 = 3;


const LARGE_FLEET: u8 = 100;


const BUDGET_BURST: u64 = 4;


const BUDGET_RECORDS: usize = 10;


const NEWCOMER_HOST: u8 = 200;


fn many_templates(count: u16) -> Vec<u8> {
    let body: Vec<u8> = (0..count)
        .flat_map(|offset| [word(TEMPLATE_ID + offset), word(1), word(ELEMENT_SOURCE_PORT), word(PORT_FIELD_BYTES)].concat())
        .collect();
    set(0, &body)
}


fn indexes_agree(cache: &TemplateCache) -> bool {
    cache.undeclared_lru.len() + cache.declared_lru.len() == cache.exporters.len() && cache.per_key.values().sum::<usize>() == cache.exporters.len()
}


fn hostile_limits(flow: FlowLimits) -> FlowLimits {
    FlowLimits {
        max_templates_per_exporter: usize::from(HOSTILE_TEMPLATES),
        ..flow
    }
}


fn key_refusal_cost(fleet: u8) -> Result<(u64, u64, u64), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let flow = hostile_limits(FlowLimits {
        max_exporters_per_source_key: KEY_CAP,
        ..FlowLimits::default()
    });
    let mut runtime = runtime_in(dir.path(), with_limits(flow))?;
    let define = v9(0, &[template_set(TEMPLATE_ID)]);
    (1..=fleet).for_each(|last| handle_datagram(&mut runtime, v4_source(last), &define, NOW, 0));
    (1..=KEY_CAP as u16).for_each(|last| handle_datagram(&mut runtime, v6_source(last), &define, NOW, 0));
    let before = runtime.templates.stats;
    handle_datagram(
        &mut runtime,
        v6_source(HOST_THREE.into()),
        &v9(0, &[many_templates(HOSTILE_TEMPLATES)]),
        NOW,
        0,
    );
    assert!(indexes_agree(&runtime.templates));
    assert_eq!(runtime.templates.exporters.len(), usize::from(fleet) + KEY_CAP);
    let stats = runtime.templates.stats;
    Ok((
        stats.index_steps - before.index_steps,
        stats.refused_templates - before.refused_templates,
        runtime.stats.dropped_parse,
    ))
}


#[test]
fn a_refused_newcomer_costs_a_bounded_lookup_whatever_the_exporter_count() -> TestResult {
    let (small_steps, small_refused, small_parse) = key_refusal_cost(SMALL_FLEET)?;
    let (large_steps, large_refused, large_parse) = key_refusal_cost(LARGE_FLEET)?;
    assert_eq!(small_steps, large_steps);
    assert!(large_steps <= STEP_BOUND);
    assert_eq!((small_refused, large_refused), (HOSTILE_TEMPLATES.into(), HOSTILE_TEMPLATES.into()));
    assert_eq!((small_parse, large_parse), (1, 1));
    Ok(())
}


fn declared_refusal_cost(fleet: u8) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let flow = hostile_limits(FlowLimits {
        max_template_exporters: usize::from(fleet),
        ..FlowLimits::default()
    });
    let settings = ListenerSettings {
        sources: (1..=fleet).map(|last| v4_source(last).ip()).collect(),
        ..with_limits(flow)
    };
    let mut runtime = runtime_in(dir.path(), settings)?;
    let define = v9(0, &[template_set(TEMPLATE_ID)]);
    (1..=fleet).for_each(|last| handle_datagram(&mut runtime, v4_source(last), &define, NOW, 0));
    let before = runtime.templates.stats;
    handle_datagram(
        &mut runtime,
        v4_source(NEWCOMER_HOST),
        &v9(0, &[many_templates(HOSTILE_TEMPLATES)]),
        NOW,
        0,
    );
    assert!(indexes_agree(&runtime.templates));
    assert_eq!(runtime.templates.exporters.len(), usize::from(fleet));
    assert_eq!(runtime.templates.stats.evicted_exporters, 0);
    let stats = runtime.templates.stats;
    Ok((stats.index_steps - before.index_steps, stats.refused_templates - before.refused_templates))
}


#[test]
fn an_undeclared_newcomer_facing_declared_exporters_costs_a_bounded_lookup() -> TestResult {
    let (small_steps, small_refused) = declared_refusal_cost(SMALL_FLEET)?;
    let (large_steps, large_refused) = declared_refusal_cost(LARGE_FLEET)?;
    assert_eq!(small_steps, large_steps);
    assert!(large_steps <= STEP_BOUND);
    assert_eq!((small_refused, large_refused), (HOSTILE_TEMPLATES.into(), HOSTILE_TEMPLATES.into()));
    Ok(())
}


fn budget_settings(sources: Vec<IpAddr>) -> ListenerSettings {
    ListenerSettings {
        rate_per_second: 1,
        burst: BUDGET_BURST,
        sources,
        ..flow_settings()
    }
}


fn many_records() -> Vec<u8> {
    v9(0, &[template_set(TEMPLATE_ID), data_set(TEMPLATE_ID, BUDGET_RECORDS)])
}


#[test]
fn an_undeclared_source_records_are_bounded_by_its_buckets_and_stored_low() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), budget_settings(Vec::new()))?;
    handle_datagram(&mut runtime, v4_source(1), &many_records(), NOW, 0);
    assert_eq!(runtime.stats.flow_records, TWO);
    assert_eq!(runtime.stats.flow_records_over_budget, (BUDGET_RECORDS as u64) - TWO);
    let stored = read_from(&runtime.spool, 0, REPLAY)?;
    assert_eq!(stored.len(), TWO as usize);
    assert!(stored.iter().all(|record| record.priority == Priority::Low));
    Ok(())
}


#[test]
fn a_declared_source_gets_its_own_bucket_and_high_priority() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), budget_settings(vec![v4_source(1).ip()]))?;
    handle_datagram(&mut runtime, v4_source(1), &many_records(), NOW, 0);
    assert_eq!(runtime.stats.flow_records, THREE);
    assert_eq!(runtime.stats.flow_records_over_budget, (BUDGET_RECORDS as u64) - THREE);
    let stored = read_from(&runtime.spool, 0, REPLAY)?;
    assert!(stored.iter().all(|record| record.priority == Priority::High));
    Ok(())
}


#[test]
fn an_untracked_source_is_refused_an_extra_record() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), budget_settings(Vec::new()))?;
    assert_eq!(
        admit_extra_record(&mut runtime.collector, v4_source(1).ip(), NOW),
        Err(DropReason::SourceTableFull)
    );
    Ok(())
}


#[test]
fn a_change_of_declared_sources_moves_exporters_between_the_indexes() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), flow_settings())?;
    let define = v9(0, &[template_set(TEMPLATE_ID)]);
    [1, HOST_TWO]
        .into_iter()
        .for_each(|last| handle_datagram(&mut runtime, v4_source(last), &define, NOW, 0));
    assert_eq!(
        (runtime.templates.undeclared_lru.len(), runtime.templates.declared_lru.len()),
        (TWO as usize, 0)
    );
    set_declared(&mut runtime.templates, BTreeSet::from([v4_source(1).ip()]));
    assert_eq!((runtime.templates.undeclared_lru.len(), runtime.templates.declared_lru.len()), (1, 1));
    assert!(indexes_agree(&runtime.templates));
    Ok(())
}


#[test]
fn evicting_one_of_two_exporters_of_a_key_keeps_the_key_count() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), flow_settings())?;
    let define = v9(0, &[template_set(TEMPLATE_ID)]);
    [1, HOST_TWO]
        .into_iter()
        .for_each(|last| handle_datagram(&mut runtime, v6_source(last.into()), &define, NOW, 0));
    assert_eq!(runtime.templates.per_key.values().copied().collect::<Vec<usize>>(), vec![TWO as usize]);
    assert_eq!(evict_least_recent_exporter(&mut runtime.templates), 1);
    assert_eq!(runtime.templates.per_key.values().copied().collect::<Vec<usize>>(), vec![1]);
    assert!(indexes_agree(&runtime.templates));
    Ok(())
}
