#![cfg(unix)]

#[path = "support/logging.rs"]
mod logging;
#[path = "support/types.rs"]
mod types;


use logging::captured;
use serde_json::{json, Value};
use site_collector::dirfs::open_directory;
use site_collector::error::{FlowFrameError, ForwardError};
use site_collector::flow_frame::{decode_flow_frame, single_flow_batch};
use site_collector::flow_listen::encode_frame;
use site_collector::flow_model::{FlowFrame, FlowLimits, FlowRecord, FLOW_FRAME_VERSION, MAX_FLOW_FRAME_BYTES};
use site_collector::forward::{event_line, forward_error_kind, forward_once, is_unknown_version, read_cursor, write_cursor};
use site_collector::forward_model::{ForwardLimits, ForwardReport};
use site_collector::listen::handle_datagram;
use site_collector::listen_model::{ListenerKind, ListenerSettings, Runtime};
use site_collector::spool::{append, open_spool, sync_range};
use site_collector::spool_model::{Priority, SpoolConfig, MAX_FRAME_BYTES};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use time::OffsetDateTime;
use types::TestResult;


const V5: &[u8] = include_bytes!("fixtures/netflow/v5-softflowd.bin");


const V9: &[u8] = include_bytes!("fixtures/netflow/v9-softflowd.bin");


const IPFIX: &[u8] = include_bytes!("fixtures/netflow/ipfix-softflowd.bin");


const NOW_SECONDS: i64 = 1_800_000_000;


const NOW_MS: i64 = 1_800_000_000_000;


const NOW_MONOTONIC: u64 = 1_000_000;


const FLOW_PORT: u16 = 2055;


const RATE: u64 = 1_000_000;


const SHARE: u64 = 99;


const UNKNOWN_SHARE: u64 = 50;


const SOURCES: usize = 4096;


const BATCH: usize = 500;


const SEGMENTS: u64 = 256;


const MANY: usize = 100;


const ONE_MIB: u64 = 1 << 20;


const V5_RECORDS: usize = 2;


const SOFTFLOWD_RECORDS: usize = 8;


const THREE: u64 = 3;


const TEST_NET_FIRST: u8 = 192;


const TEST_NET_SECOND: u8 = 2;


const EXPORTER_HOST: u8 = 10;


const OUTPUT_INTERFACE: u32 = 2;


const PACKETS: u64 = 3;


const OCTETS: u64 = 400;


const SOURCE_PORT: u16 = 1234;


const DESTINATION_PORT: u16 = 53;


const UDP: u8 = 17;


const PORT_OVERFLOW: u32 = 65_536;


const FRACTION: f64 = 1.5;


const ALL_ONES: u16 = 0xffff;


const TWICE: usize = 2;


const UNKNOWN_FRAME_VERSION: u64 = 2;


const OVER_BOUND: usize = MAX_FLOW_FRAME_BYTES + 1;


const FLOW_MS_BEFORE: i64 = 1000;


const GOLDEN_LINE: &str = r#"{"@timestamp":"2027-01-15T08:00:00Z","ecs":{"version":"8.11"},"event":{"kind":"event","category":["network"],"type":["connection"],"dataset":"collector.netflow","module":"collector","start":"2027-01-15T07:59:59Z","end":"2027-01-15T08:00:00Z"},"source":{"ip":"10.0.0.1","port":1234,"bytes":400,"packets":3},"destination":{"ip":"10.0.0.2","port":53},"network":{"transport":"udp"},"labels":{"collector_epoch":"EPOCH","collector_index":"0","collector_sequence":"0","netflow_engine":"0/0","netflow_exporter_ip":"192.0.2.10"}}"#;


struct Fixture {
    runtime: Runtime,
    agent_spool: PathBuf,
    root: TempDir,
}


fn now() -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS)
}


fn settings(kind: ListenerKind) -> ListenerSettings {
    ListenerSettings {
        listen: "127.0.0.1:0".to_owned(),
        kind,
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


fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let spool_dir = root.path().join("spool");
    fs::create_dir(&spool_dir)?;
    let spool = open_spool(
        &spool_dir,
        SpoolConfig {
            segment_max_bytes: MAX_FRAME_BYTES,
            total_max_bytes: MAX_FRAME_BYTES * SEGMENTS,
        },
    )?;
    let runtime = site_collector::listen::open_runtime(Arc::new(settings(ListenerKind::Netflow)), spool)?;
    let agent_spool = root.path().join("agent.spool");
    Ok(Fixture { runtime, agent_spool, root })
}


fn limits(kind: ListenerKind) -> ForwardLimits {
    ForwardLimits {
        kind,
        max_records: MANY,
        agent_spool_max_bytes: ONE_MIB,
    }
}


fn forward(fixture: &mut Fixture, kind: ListenerKind) -> Result<ForwardReport, Box<dyn std::error::Error>> {
    Ok(forward_once(
        &mut fixture.runtime.spool,
        &fixture.agent_spool,
        &limits(kind),
        now()?,
        write_cursor,
        sync_range,
    )?)
}


fn lines_of(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    fs::read_to_string(path)?.lines().map(|line| Ok(serde_json::from_str(line)?)).collect()
}


fn exporter() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(TEST_NET_FIRST, 0, TEST_NET_SECOND, EXPORTER_HOST)), FLOW_PORT)
}


fn frame_value() -> Value {
    json!({
        "v": 1,
        "exporter": "192.0.2.10",
        "source": "10.0.0.1",
        "destination": "10.0.0.2",
        "next_hop": "0.0.0.0",
        "input_interface": 1,
        "output_interface": OUTPUT_INTERFACE,
        "packets": PACKETS,
        "octets": OCTETS,
        "start_unix_ms": NOW_MS - FLOW_MS_BEFORE,
        "end_unix_ms": NOW_MS,
        "source_port": SOURCE_PORT,
        "destination_port": DESTINATION_PORT,
        "tcp_flags": 0,
        "protocol": UDP,
        "tos": 0,
        "source_as": 0,
        "destination_as": 0
    })
}


fn good_frame() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&frame_value())
}


fn frame_with(key: &str, value: Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut frame = frame_value();
    if let Some(object) = frame.as_object_mut() {
        object.insert(key.to_owned(), value);
    }
    serde_json::to_vec(&frame)
}


fn frame_without(key: &str) -> Result<Vec<u8>, serde_json::Error> {
    let mut frame = frame_value();
    if let Some(object) = frame.as_object_mut() {
        object.remove(key);
    }
    serde_json::to_vec(&frame)
}


fn feed(fixture: &mut Fixture, payloads: &[&[u8]]) -> TestResult {
    payloads
        .iter()
        .try_for_each(|payload| append(&mut fixture.runtime.spool, Priority::Low, payload).map(|_| ()))?;
    Ok(())
}


fn spool_handle(fixture: &Fixture) -> Result<site_collector::types::DirHandle, Box<dyn std::error::Error>> {
    Ok(open_directory(&fixture.root.path().join("spool"))?)
}


#[test]
fn v5_v9_and_ipfix_datagrams_reach_the_agent_spool_as_netflow_events() -> TestResult {
    let mut fixture = fixture()?;
    handle_datagram(&mut fixture.runtime, exporter(), V5, NOW_MONOTONIC, 0);
    handle_datagram(&mut fixture.runtime, exporter(), V9, NOW_MONOTONIC, 0);
    handle_datagram(&mut fixture.runtime, exporter(), IPFIX, NOW_MONOTONIC, 0);
    let report = forward(&mut fixture, ListenerKind::Netflow)?;
    let expected = V5_RECORDS + TWICE * SOFTFLOWD_RECORDS;
    assert_eq!(
        (report.forwarded, report.skipped_unparsable, report.skipped_unknown_version),
        (expected as u64, 0, 0)
    );
    let events = lines_of(&fixture.agent_spool)?;
    assert_eq!(events.len(), expected);
    assert!(events.iter().all(|event| {
        event.pointer("/event/dataset").and_then(Value::as_str) == Some("collector.netflow")
            && event.pointer("/event/module").and_then(Value::as_str) == Some("collector")
            && event.pointer("/labels/netflow_exporter_ip").and_then(Value::as_str) == Some("192.0.2.10")
    }));
    let mut sequences: Vec<&str> = events
        .iter()
        .filter_map(|event| event.pointer("/labels/collector_sequence").and_then(Value::as_str))
        .collect();
    sequences.sort_unstable();
    sequences.dedup();
    assert_eq!(sequences.len(), expected);
    Ok(())
}


#[test]
fn a_frame_gives_the_golden_event() -> TestResult {
    let mut fixture = fixture()?;
    feed(&mut fixture, &[&good_frame()?])?;
    forward(&mut fixture, ListenerKind::Netflow)?;
    let line = fs::read_to_string(&fixture.agent_spool)?;
    let epoch = fixture.runtime.spool.epoch.clone();
    assert_eq!(line.trim_end(), GOLDEN_LINE.replace("EPOCH", &epoch));
    Ok(())
}


#[test]
fn a_poison_frame_is_skipped_counted_and_passed_by_the_cursor() -> TestResult {
    let mut fixture = fixture()?;
    let good = good_frame()?;
    feed(&mut fixture, &[&good, b"{not json", &good])?;
    let report = forward(&mut fixture, ListenerKind::Netflow)?;
    assert_eq!(
        (report.forwarded, report.skipped_unparsable, report.skipped_unknown_version),
        (TWICE as u64, 1, 0)
    );
    assert_eq!(lines_of(&fixture.agent_spool)?.len(), TWICE);
    assert_eq!(read_cursor(&spool_handle(&fixture)?)?, THREE);
    assert_eq!(forward(&mut fixture, ListenerKind::Netflow)?, ForwardReport::default());
    Ok(())
}


#[test]
fn an_unknown_version_is_refused_and_counted_apart() -> TestResult {
    let mut fixture = fixture()?;
    let good = good_frame()?;
    feed(&mut fixture, &[&frame_with("v", json!(UNKNOWN_FRAME_VERSION))?, &good])?;
    let report = forward(&mut fixture, ListenerKind::Netflow)?;
    assert_eq!((report.forwarded, report.skipped_unparsable, report.skipped_unknown_version), (1, 0, 1));
    Ok(())
}


const MARKER: &str = "SECRETMARK";


const MALFORMED_FRAMES: u64 = 3;


#[test]
fn a_skipped_frame_is_logged_without_any_frame_text() -> TestResult {
    let mut fixture = fixture()?;
    let long_marker = MARKER.repeat(MANY);
    feed(
        &mut fixture,
        &[
            &frame_with("protocol", json!(MARKER))?,
            &frame_with("source_port", json!(long_marker))?,
            &frame_with("exporter", json!(MARKER))?,
            &frame_with("v", json!(UNKNOWN_FRAME_VERSION))?,
        ],
    )?;
    let (outcome, log) = captured(|| forward(&mut fixture, ListenerKind::Netflow));
    let report = outcome?;
    assert_eq!((report.skipped_unparsable, report.skipped_unknown_version), (MALFORMED_FRAMES, 1));
    assert!(log.contains("spooled records skipped"), "{log}");
    assert!(
        log.contains("sequence 0: the flow frame is not a strict flow record (Data, line 0, column 0)"),
        "{log}"
    );
    assert!(!log.contains(MARKER), "{log}");
    assert_eq!(
        forward_error_kind(&ForwardError::Io(std::io::Error::other(MARKER))),
        "forward input/output failure"
    );
    let unknown = ForwardError::Frame(FlowFrameError::UnknownVersion(UNKNOWN_FRAME_VERSION));
    assert_eq!(forward_error_kind(&unknown), "the flow frame has version 2, not a known one");
    Ok(())
}


#[test]
fn an_oversized_payload_is_refused_before_parsing() -> TestResult {
    let mut fixture = fixture()?;
    let mut padded = good_frame()?;
    padded.resize(OVER_BOUND, b' ');
    assert!(matches!(decode_flow_frame(&padded), Err(FlowFrameError::TooLarge(OVER_BOUND))));
    feed(&mut fixture, &[&padded, &good_frame()?])?;
    let report = forward(&mut fixture, ListenerKind::Netflow)?;
    assert_eq!((report.forwarded, report.skipped_unparsable), (1, 1));
    Ok(())
}


#[test]
fn the_largest_possible_frame_fits_the_bound() -> TestResult {
    let wide = IpAddr::V6(Ipv6Addr::new(
        ALL_ONES, ALL_ONES, ALL_ONES, ALL_ONES, ALL_ONES, ALL_ONES, ALL_ONES, ALL_ONES,
    ));
    let record = FlowRecord {
        source: wide,
        destination: wide,
        next_hop: wide,
        input_interface: u32::MAX,
        output_interface: u32::MAX,
        packets: u64::MAX,
        octets: u64::MAX,
        start_unix_ms: i64::MIN,
        end_unix_ms: i64::MIN,
        source_port: u16::MAX,
        destination_port: u16::MAX,
        tcp_flags: u8::MAX,
        protocol: u8::MAX,
        tos: u8::MAX,
        source_as: u32::MAX,
        destination_as: u32::MAX,
    };
    let payload = encode_frame(&FlowFrame {
        version: FLOW_FRAME_VERSION,
        exporter: wide,
        record: &record,
    })?;
    assert!(payload.len() <= MAX_FLOW_FRAME_BYTES, "{}", payload.len());
    let (decoded_exporter, decoded) = decode_flow_frame(&payload)?;
    assert_eq!((decoded_exporter, decoded.clone()), (wide, record));
    assert_eq!(single_flow_batch(decoded).records.len(), 1);
    Ok(())
}


#[test]
fn the_decode_is_strict() -> TestResult {
    assert!(matches!(decode_flow_frame(b"[]"), Err(FlowFrameError::Json(_))));
    assert!(matches!(decode_flow_frame(&frame_without("v")?), Err(FlowFrameError::MissingVersion)));
    assert!(matches!(
        decode_flow_frame(&frame_with("v", json!("1"))?),
        Err(FlowFrameError::MissingVersion)
    ));
    assert!(matches!(
        decode_flow_frame(&frame_without("exporter")?),
        Err(FlowFrameError::MissingExporter)
    ));
    assert!(matches!(
        decode_flow_frame(&frame_with("exporter", json!("not-an-ip"))?),
        Err(FlowFrameError::Json(_))
    ));
    assert!(matches!(
        decode_flow_frame(&frame_with("tenant", json!("other"))?),
        Err(FlowFrameError::Json(_))
    ));
    assert!(matches!(
        decode_flow_frame(&frame_with("source", json!("999.1.1.1"))?),
        Err(FlowFrameError::Json(_))
    ));
    assert!(matches!(
        decode_flow_frame(&frame_with("source_port", json!(PORT_OVERFLOW))?),
        Err(FlowFrameError::Json(_))
    ));
    assert!(matches!(
        decode_flow_frame(&frame_with("packets", json!(-1))?),
        Err(FlowFrameError::Json(_))
    ));
    assert!(matches!(
        decode_flow_frame(&frame_with("protocol", json!(FRACTION))?),
        Err(FlowFrameError::Json(_))
    ));
    assert!(matches!(decode_flow_frame(&frame_without("octets")?), Err(FlowFrameError::Json(_))));
    assert!(decode_flow_frame(&good_frame()?).is_ok());
    Ok(())
}


#[test]
fn the_kind_comes_from_the_settings_not_the_frame() -> TestResult {
    let mut fixture = fixture()?;
    feed(&mut fixture, &[&good_frame()?, b"<34>1 2026-11-10T10:00:00Z router1 sshd - - - hello"])?;
    let as_syslog = forward(&mut fixture, ListenerKind::Syslog)?;
    assert_eq!((as_syslog.forwarded, as_syslog.skipped_unparsable), (1, 1));
    assert_eq!(
        lines_of(&fixture.agent_spool)?
            .first()
            .and_then(|event| event.pointer("/event/module").cloned()),
        Some(json!("syslog"))
    );
    Ok(())
}


#[test]
fn a_syslog_payload_under_a_netflow_kind_is_malformed() -> TestResult {
    let error = event_line(
        &site_collector::spool_model::Record {
            priority: Priority::Low,
            sequence: 0,
            payload: b"<34>1 2026-11-10T10:00:00Z router1 sshd - - - hello".to_vec(),
        },
        ListenerKind::Netflow,
        "ab",
        now()?,
    );
    let refused = error.err().ok_or("accepted")?;
    assert!(!is_unknown_version(&refused));
    assert!(matches!(refused, ForwardError::Frame(FlowFrameError::Json(_))));
    assert!(is_unknown_version(&ForwardError::Frame(FlowFrameError::UnknownVersion(
        UNKNOWN_FRAME_VERSION
    ))));
    Ok(())
}
