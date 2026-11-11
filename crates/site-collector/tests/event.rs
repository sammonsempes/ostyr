#[path = "support/types.rs"]
mod types;


use core_export::ecs::{to_json, EcsEvent};
use serde_json::Value;
use site_collector::event::{clamp_flow_ms, flow_events, flow_time, kind_name, transport_name, trap_event, version_name};
use site_collector::event_model::{MAX_FLOW_AGE_MS, MAX_FLOW_SKEW_MS, MAX_TRAP_OID_BYTES, MAX_VARBIND_LABEL_BYTES};
use site_collector::flow::parse_netflow_v5;
use site_collector::flow_model::{FlowBatch, FlowLimits, FlowRecord};
use site_collector::model::{TrapKind, TrapLimits, TrapRecord, TrapVarbind, TrapVersion};
use site_collector::snmp::parse_trap;
use std::net::{IpAddr, Ipv4Addr};
use time::OffsetDateTime;
use types::TestResult;


const NOW_SECONDS: i64 = 1_794_429_120;


const NOW_MS: i64 = NOW_SECONDS * 1000;


const EPOCH: &str = "00112233445566778899aabbccddeeff";


const SEQUENCE: u64 = 7;


const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));


const CLAIMED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 99);


const BIG_VALUE: usize = 10_000;


const PROTOCOL_TCP: u8 = 6;


const PROTOCOL_UDP: u8 = 17;


const PROTOCOL_ICMP: u8 = 1;


const PROTOCOL_GRE: u8 = 47;


const OMITTED: usize = 5;


const UPTIME: u32 = 4242;


const DAY_MS: i64 = 86_400_000;


const TWO: usize = 2;


const FLOW_SOURCE: Ipv4Addr = Ipv4Addr::LOCALHOST;


const FLOW_DESTINATION: Ipv4Addr = Ipv4Addr::BROADCAST;


const FLOW_PACKETS: u32 = 3;


const FLOW_OCTETS: u32 = 300;


const FLOW_PORT: u16 = 4000;


const DNS_PORT: u16 = 53;


const ENGINE_ID: u8 = 2;


const MS_PER_SECOND: i64 = 1000;


const ONE_SECOND_MS: i64 = 1000;


const HALF_SECOND_MS: i64 = 500;


const TWO_SECONDS_MS: i64 = 2000;


const SECS_START: usize = 8;


const SECS_END: usize = 12;


const GOLDEN_TRAP: &str = r#"{"@timestamp":"2026-11-11T20:32:00Z","ecs":{"version":"8.11"},"event":{"kind":"event","code":"1.3.6.1.6.3.1.1.5.3","dataset":"collector.snmp_trap","module":"collector"},"source":{"ip":"192.0.2.10"},"labels":{"collector_epoch":"00112233445566778899aabbccddeeff","collector_sequence":"7","snmp_kind":"trap_v2","snmp_uptime_ticks":"59607","snmp_varbind_0":"1.3.6.1.2.1.2.2.1.1.7=7","snmp_varbind_1":"1.3.6.1.2.1.2.2.1.2.7=eth0","snmp_varbind_2":"1.3.6.1.2.1.2.2.1.3.7=6","snmp_version":"v2c"}}"#;


const GOLDEN_FLOW: &str = r#"{"@timestamp":"2026-11-11T20:31:54.274Z","ecs":{"version":"8.11"},"event":{"kind":"event","category":["network"],"type":["connection"],"dataset":"collector.netflow","module":"collector","start":"2026-11-11T20:31:54.269Z","end":"2026-11-11T20:31:54.274Z"},"source":{"ip":"127.0.0.1","port":47103,"bytes":126,"packets":2},"destination":{"ip":"127.0.0.53","port":53},"network":{"transport":"udp"},"labels":{"collector_epoch":"00112233445566778899aabbccddeeff","collector_index":"0","collector_sequence":"7","netflow_engine":"0/0","netflow_exporter_ip":"192.0.2.10"}}
{"@timestamp":"2026-11-11T20:31:54.274Z","ecs":{"version":"8.11"},"event":{"kind":"event","category":["network"],"type":["connection"],"dataset":"collector.netflow","module":"collector","start":"2026-11-11T20:31:54.269Z","end":"2026-11-11T20:31:54.274Z"},"source":{"ip":"127.0.0.53","port":53,"bytes":170,"packets":2},"destination":{"ip":"127.0.0.1","port":47103},"network":{"transport":"udp"},"labels":{"collector_epoch":"00112233445566778899aabbccddeeff","collector_index":"1","collector_sequence":"7","netflow_engine":"0/0","netflow_exporter_ip":"192.0.2.10"}}"#;


fn now() -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS)
}


fn record_with(varbinds: Vec<TrapVarbind>) -> TrapRecord {
    TrapRecord {
        version: TrapVersion::V2c,
        kind: TrapKind::TrapV2,
        trap_oid: "1.3.6.1.6.3.1.1.5.4".to_owned(),
        agent_address: None,
        uptime_ticks: UPTIME,
        varbinds,
        varbinds_omitted: 0,
    }
}


fn varbind(value: String) -> TrapVarbind {
    TrapVarbind {
        oid: "1.3.6.1.2.1.2.2.1.1.2".to_owned(),
        value,
    }
}


fn flow_at(start_ms: i64, end_ms: i64, protocol: u8) -> FlowRecord {
    FlowRecord {
        source: FLOW_SOURCE,
        destination: FLOW_DESTINATION,
        next_hop: FLOW_SOURCE,
        input_interface: 1,
        output_interface: 0,
        packets: FLOW_PACKETS,
        octets: FLOW_OCTETS,
        start_unix_ms: start_ms,
        end_unix_ms: end_ms,
        source_port: FLOW_PORT,
        destination_port: DNS_PORT,
        tcp_flags: 0,
        protocol,
        tos: 0,
        source_as: 0,
        destination_as: 0,
    }
}


fn batch_of(records: Vec<FlowRecord>) -> FlowBatch {
    FlowBatch {
        export_unix_ms: NOW_MS,
        exporter_uptime_ms: 0,
        sequence: 0,
        engine_type: 1,
        engine_id: ENGINE_ID,
        sampling_mode: 0,
        sampling_interval: 0,
        records,
    }
}


fn json_of(event: &EcsEvent) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&to_json(event)?)?)
}


fn text(json: &Value, pointer: &str) -> Option<String> {
    json.pointer(pointer)
        .map(|value| value.as_str().map_or_else(|| value.to_string(), str::to_owned))
}


fn label<'a>(event: &'a EcsEvent, name: &str) -> Option<&'a str> {
    event.labels.get(name).map(String::as_str)
}


#[test]
fn golden_trap() -> TestResult {
    let datagram = std::fs::read(format!("{}/tests/fixtures/snmp/v2c_trap.bin", env!("CARGO_MANIFEST_DIR")))?;
    let record = parse_trap(&datagram, &TrapLimits::default())?;
    let event = trap_event(&record, PEER, EPOCH, SEQUENCE, now()?);
    assert_eq!(to_json(&event)?, GOLDEN_TRAP);
    Ok(())
}


#[test]
fn golden_flow() -> TestResult {
    let datagram = std::fs::read(format!("{}/tests/fixtures/netflow/v5-softflowd.bin", env!("CARGO_MANIFEST_DIR")))?;
    let batch = parse_netflow_v5(&datagram, &FlowLimits::default())?;
    let events = flow_events(&batch, PEER, EPOCH, SEQUENCE, now()?);
    assert_eq!(events.len(), TWO);
    let lines = events.iter().map(to_json).collect::<Result<Vec<_>, _>>()?;
    assert_eq!(lines.join("\n"), GOLDEN_FLOW);
    Ok(())
}


#[test]
fn community_never_reaches_the_event() -> TestResult {
    let datagram = std::fs::read(format!("{}/tests/fixtures/snmp/v2c_trap.bin", env!("CARGO_MANIFEST_DIR")))?;
    assert!(datagram.windows("public".len()).any(|window| window == b"public"));
    let record = parse_trap(&datagram, &TrapLimits::default())?;
    let text = to_json(&trap_event(&record, PEER, EPOCH, SEQUENCE, now()?))?;
    assert!(!text.contains("public"));
    Ok(())
}


#[test]
fn claimed_agent_address_never_becomes_the_source() -> TestResult {
    let mut record = record_with(Vec::new());
    record.version = TrapVersion::V1;
    record.kind = TrapKind::TrapV1;
    record.agent_address = Some(CLAIMED);
    let event = trap_event(&record, PEER, EPOCH, SEQUENCE, now()?);
    let json = json_of(&event)?;
    assert_eq!(text(&json, "/source/ip"), Some("192.0.2.10".to_owned()));
    assert_eq!(label(&event, "snmp_agent_address_claimed"), Some("198.51.100.99"));
    assert_eq!(label(&event, "snmp_version"), Some("v1"));
    assert_eq!(label(&event, "snmp_kind"), Some("trap_v1"));
    assert!(label(&event, "snmp_varbinds_omitted").is_none());
    assert!(label(&event, "snmp_varbind_0").is_none());
    assert!(label(
        &trap_event(&record_with(Vec::new()), PEER, EPOCH, SEQUENCE, now()?),
        "snmp_agent_address_claimed"
    )
    .is_none());
    Ok(())
}


#[test]
fn omitted_varbinds_are_a_visible_label() -> TestResult {
    let mut record = record_with(vec![varbind("1".to_owned())]);
    record.varbinds_omitted = OMITTED;
    let event = trap_event(&record, PEER, EPOCH, SEQUENCE, now()?);
    assert_eq!(label(&event, "snmp_varbinds_omitted"), Some("5"));
    assert_eq!(label(&event, "snmp_varbind_0"), Some("1.3.6.1.2.1.2.2.1.1.2=1"));
    Ok(())
}


#[test]
fn hostile_varbinds_are_cut_and_escaped() -> TestResult {
    let fake = r#"","source":{"ip":"1.2.3.4"}"#;
    let record = record_with(vec![
        varbind("a\u{1b}[31mred\0nul".to_owned()),
        varbind("x".repeat(BIG_VALUE)),
        varbind(fake.to_owned()),
    ]);
    let event = trap_event(&record, PEER, EPOCH, SEQUENCE, now()?);
    let first = label(&event, "snmp_varbind_0").ok_or("no label")?;
    assert!(first.ends_with("=a[31mrednul"));
    let second = label(&event, "snmp_varbind_1").ok_or("no label")?;
    assert!(second.len() < MAX_VARBIND_LABEL_BYTES + "[+99999 bytes cut]".len());
    assert!(second.contains("bytes cut]"));
    let line = to_json(&event)?;
    assert!(!line.contains('\u{1b}') && !line.contains("\\u001b") && !line.contains("\\u0000"));
    let json: Value = serde_json::from_str(&line)?;
    assert_eq!(text(&json, "/source/ip"), Some("192.0.2.10".to_owned()));
    assert_eq!(text(&json, "/labels/snmp_varbind_2"), Some(format!("1.3.6.1.2.1.2.2.1.1.2={fake}")));
    Ok(())
}


#[test]
fn trap_oid_is_cut() -> TestResult {
    let mut record = record_with(Vec::new());
    record.trap_oid = "1.".repeat(MAX_TRAP_OID_BYTES);
    let event = trap_event(&record, PEER, EPOCH, SEQUENCE, now()?);
    assert!(event.event.code.ok_or("no code")?.contains("bytes cut]"));
    Ok(())
}


#[test]
fn names_cover_every_variant() -> TestResult {
    assert_eq!(version_name(TrapVersion::V1), "v1");
    assert_eq!(version_name(TrapVersion::V2c), "v2c");
    assert_eq!(kind_name(TrapKind::TrapV1), "trap_v1");
    assert_eq!(kind_name(TrapKind::TrapV2), "trap_v2");
    assert_eq!(kind_name(TrapKind::Inform), "inform");
    Ok(())
}


#[test]
fn protocol_table() -> TestResult {
    assert_eq!(transport_name(PROTOCOL_TCP), "tcp");
    assert_eq!(transport_name(PROTOCOL_UDP), "udp");
    assert_eq!(transport_name(PROTOCOL_ICMP), "icmp");
    assert_eq!(transport_name(PROTOCOL_GRE), "47");
    Ok(())
}


#[test]
fn clamp_boundaries() -> TestResult {
    assert_eq!(clamp_flow_ms(NOW_MS - MAX_FLOW_AGE_MS, NOW_MS), (NOW_MS - MAX_FLOW_AGE_MS, false));
    assert_eq!(clamp_flow_ms(NOW_MS - MAX_FLOW_AGE_MS - 1, NOW_MS), (NOW_MS, true));
    assert_eq!(clamp_flow_ms(NOW_MS + MAX_FLOW_SKEW_MS, NOW_MS), (NOW_MS + MAX_FLOW_SKEW_MS, false));
    assert_eq!(clamp_flow_ms(NOW_MS + MAX_FLOW_SKEW_MS + 1, NOW_MS), (NOW_MS, true));
    assert_eq!(clamp_flow_ms(i64::MIN, i64::MAX), (i64::MAX, true));
    assert_eq!(
        flow_time(NOW_MS + DAY_MS, NOW_MS, now()?).unix_timestamp(),
        NOW_SECONDS + DAY_MS / MS_PER_SECOND
    );
    Ok(())
}


#[test]
fn old_and_future_times_are_clamped_and_labelled() -> TestResult {
    let batch = batch_of(vec![
        flow_at(0, 0, PROTOCOL_UDP),
        flow_at(NOW_MS - ONE_SECOND_MS, NOW_MS - HALF_SECOND_MS, PROTOCOL_TCP),
        flow_at(NOW_MS, i64::from(u32::MAX) * MS_PER_SECOND, PROTOCOL_ICMP),
    ]);
    let events = flow_events(&batch, PEER, EPOCH, SEQUENCE, now()?);
    let first = events.first().ok_or("no event")?;
    assert_eq!(label(first, "flow_time_clamped"), Some("true"));
    assert_eq!(first.timestamp.unix_timestamp(), NOW_SECONDS);
    assert_eq!(first.event.start.ok_or("start")?.unix_timestamp(), NOW_SECONDS);
    let second = events.get(1).ok_or("no event")?;
    assert!(label(second, "flow_time_clamped").is_none());
    assert_eq!(second.timestamp.unix_timestamp(), NOW_SECONDS - 1);
    let third = events.get(TWO).ok_or("no event")?;
    assert_eq!(label(third, "flow_time_clamped"), Some("true"));
    assert_eq!(third.event.end.ok_or("end")?.unix_timestamp(), NOW_SECONDS);
    assert_eq!(label(third, "collector_index"), Some("2"));
    Ok(())
}


#[test]
fn hostile_export_times_from_the_parser_are_clamped() -> TestResult {
    let datagram = std::fs::read(format!("{}/tests/fixtures/netflow/v5-softflowd.bin", env!("CARGO_MANIFEST_DIR")))?;
    let secs_range = SECS_START..SECS_END;
    [0u32, u32::MAX].into_iter().try_for_each(|secs| -> TestResult {
        let mut bytes = datagram.clone();
        bytes.splice(secs_range.clone(), secs.to_be_bytes());
        let batch = parse_netflow_v5(&bytes, &FlowLimits::default())?;
        flow_events(&batch, PEER, EPOCH, SEQUENCE, now()?)
            .iter()
            .try_for_each(|event| -> TestResult {
                assert_eq!(label(event, "flow_time_clamped"), Some("true"));
                assert_eq!(event.timestamp.unix_timestamp(), NOW_SECONDS);
                Ok(())
            })
    })
}


#[test]
fn flow_event_fields() -> TestResult {
    let batch = batch_of(vec![flow_at(NOW_MS - TWO_SECONDS_MS, NOW_MS - ONE_SECOND_MS, PROTOCOL_TCP)]);
    let event = flow_events(&batch, PEER, EPOCH, SEQUENCE, now()?).into_iter().next().ok_or("no event")?;
    let json = json_of(&event)?;
    assert_eq!(text(&json, "/source/ip"), Some("127.0.0.1".to_owned()));
    assert_eq!(text(&json, "/destination/ip"), Some("255.255.255.255".to_owned()));
    assert_eq!(text(&json, "/network/transport"), Some("tcp".to_owned()));
    assert_eq!(text(&json, "/source/bytes"), Some("300".to_owned()));
    assert_eq!(text(&json, "/labels/netflow_exporter_ip"), Some("192.0.2.10".to_owned()));
    assert_eq!(text(&json, "/labels/netflow_engine"), Some("1/2".to_owned()));
    assert_eq!(text(&json, "/event/dataset"), Some("collector.netflow".to_owned()));
    Ok(())
}
