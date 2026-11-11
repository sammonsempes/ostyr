#[path = "support/types.rs"]
mod types;


use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use site_collector::error::ConfigError;
use site_collector::flow::{absolute_ms, export_time_ms, parse_netflow_v5, read_record, read_records, skip, validate_flow_limits};
use site_collector::flow_model::{FlowDrop, FlowLimits, FLOW_HEADER_BYTES, FLOW_RECORD_BYTES, MAX_FLOW_DATAGRAM_BYTES, MAX_FLOW_RECORDS};
use site_collector::listen::count_reason;
use site_collector::listen_model::ListenerStats;
use site_collector::model::DropReason;
use std::net::Ipv4Addr;
use types::TestResult;


const SECS: u32 = 1_700_000_000;


const NANOS: u32 = 250_000_000;


const UPTIME: u32 = 100_000;


const FIRST_STAMP: u32 = 90_000;


const LAST_STAMP: u32 = 99_000;


const SEQUENCE: u32 = 77;


const SAMPLING_FIELD: u16 = 0x4064;


const SAMPLING_INTERVAL: u16 = 0x64;


const TWO: u16 = 2;


const TWO_RECORDS: usize = 2;


const THIRTY: u16 = 30;


const THIRTY_ONE: u16 = 31;


const THIRTY_ONE_RECORDS: usize = 31;


const THIRTY_FIRST_MINUS_ONE: usize = 30;


const MISSING_RECORD_COUNT: usize = 29;


const VERSION: u16 = 5;


const OTHER_VERSIONS: [u16; 4] = [9, 10, 7, 0];


const SRC_PORT: u16 = 40000;


const DST_PORT: u16 = 443;


const PACKETS: u32 = 11;


const OCTETS: u32 = 2222;


const TCP_FLAGS: u8 = 0x1b;


const PROTOCOL_TCP: u8 = 6;


const TOS: u8 = 0x10;


const AS_NUMBER: u16 = 65000;


const NEXT_AS_NUMBER: u16 = 65001;


const INTERFACES: (u16, u16) = (3, 4);


const ENGINE: (u8, u8) = (1, 2);


const MILLIS_PER_SECOND: i64 = 1000;


const NANOS_AS_MILLIS: i64 = 250;


const TEN_SECONDS: i64 = 10_000;


const ONE_SECOND: i64 = 1000;


const MAX_NANOS_MILLIS: i64 = 999;


const NANOS_BELOW_MILLI: u32 = 999_999;


const NANOS_ONE_MILLI: u32 = 1_000_000;


const FUZZ_ROUNDS: usize = 100_000;


const FUZZ_MAX_LEN: usize = 1500;


const FUZZ_SEED: u64 = 285;


const FUZZ_SHAPED_ODDS: f64 = 0.5;


const VERSION_BYTES: usize = 2;


const FIXTURE: &[u8] = include_bytes!("fixtures/netflow/v5-softflowd.bin");


const FIXTURE_SEQUENCE: u32 = 96;


const FIXTURE_EXPORT_MS: i64 = 1_794_429_117_397;


const FIXTURE_UPTIME: u32 = 70_265;


const FIXTURE_START_MS: i64 = 1_794_429_114_269;


const FIXTURE_END_MS: i64 = 1_794_429_114_274;


const FIXTURE_PORT: u16 = 47103;


const DNS_PORT: u16 = 53;


const PROTOCOL_UDP: u8 = 17;


const FIXTURE_QUERY: (u32, u32) = (2, 126);


const FIXTURE_ANSWER: (u32, u32) = (2, 170);


const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);


const DESTINATION: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);


const NEXT_HOP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 254);


const PAD_BYTES: usize = 4;


const PARSE_DROPS: u64 = 2;


const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);


const RESOLVER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 53);


fn header(count: u16, uptime: u32, secs: u32, nsecs: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&uptime.to_be_bytes());
    bytes.extend_from_slice(&secs.to_be_bytes());
    bytes.extend_from_slice(&nsecs.to_be_bytes());
    bytes.extend_from_slice(&SEQUENCE.to_be_bytes());
    bytes.push(ENGINE.0);
    bytes.push(ENGINE.1);
    bytes.extend_from_slice(&SAMPLING_FIELD.to_be_bytes());
    bytes
}


fn record(first: u32, last: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&SOURCE.octets());
    bytes.extend_from_slice(&DESTINATION.octets());
    bytes.extend_from_slice(&NEXT_HOP.octets());
    bytes.extend_from_slice(&INTERFACES.0.to_be_bytes());
    bytes.extend_from_slice(&INTERFACES.1.to_be_bytes());
    bytes.extend_from_slice(&PACKETS.to_be_bytes());
    bytes.extend_from_slice(&OCTETS.to_be_bytes());
    bytes.extend_from_slice(&first.to_be_bytes());
    bytes.extend_from_slice(&last.to_be_bytes());
    bytes.extend_from_slice(&SRC_PORT.to_be_bytes());
    bytes.extend_from_slice(&DST_PORT.to_be_bytes());
    bytes.extend_from_slice(&[0, TCP_FLAGS, PROTOCOL_TCP, TOS]);
    bytes.extend_from_slice(&AS_NUMBER.to_be_bytes());
    bytes.extend_from_slice(&NEXT_AS_NUMBER.to_be_bytes());
    bytes.extend_from_slice(&[0; PAD_BYTES]);
    bytes
}


fn datagram(count: u16, records: usize, first: u32, last: u32) -> Vec<u8> {
    let mut bytes = header(count, UPTIME, SECS, NANOS);
    (0..records).for_each(|_| bytes.extend_from_slice(&record(first, last)));
    bytes
}


fn plain(count: u16, records: usize) -> Vec<u8> {
    datagram(count, records, FIRST_STAMP, LAST_STAMP)
}


#[test]
fn golden_fields() -> TestResult {
    let batch = parse_netflow_v5(&plain(1, 1), &FlowLimits::default())?;
    assert_eq!(batch.sequence, SEQUENCE);
    assert_eq!((batch.engine_type, batch.engine_id), ENGINE);
    assert_eq!((batch.sampling_mode, batch.sampling_interval), (1, SAMPLING_INTERVAL));
    assert_eq!(batch.exporter_uptime_ms, UPTIME);
    assert_eq!(batch.export_unix_ms, i64::from(SECS) * MILLIS_PER_SECOND + NANOS_AS_MILLIS);
    let flow = batch.records.first().ok_or("no record")?;
    assert_eq!(flow.source, SOURCE);
    assert_eq!(flow.destination, DESTINATION);
    assert_eq!(flow.next_hop, NEXT_HOP);
    assert_eq!((flow.input_interface, flow.output_interface), INTERFACES);
    assert_eq!((flow.packets, flow.octets), (PACKETS, OCTETS));
    assert_eq!(flow.start_unix_ms, batch.export_unix_ms - TEN_SECONDS);
    assert_eq!(flow.end_unix_ms, batch.export_unix_ms - ONE_SECOND);
    assert_eq!((flow.source_port, flow.destination_port), (SRC_PORT, DST_PORT));
    assert_eq!((flow.tcp_flags, flow.protocol, flow.tos), (TCP_FLAGS, PROTOCOL_TCP, TOS));
    assert_eq!((flow.source_as, flow.destination_as), (AS_NUMBER, NEXT_AS_NUMBER));
    Ok(())
}


#[test]
fn thirty_records_parse() -> TestResult {
    let bytes = plain(THIRTY, MAX_FLOW_RECORDS);
    assert_eq!(bytes.len(), MAX_FLOW_DATAGRAM_BYTES);
    assert_eq!(parse_netflow_v5(&bytes, &FlowLimits::default())?.records.len(), MAX_FLOW_RECORDS);
    Ok(())
}


#[test]
fn length_off_by_one_each_way() -> TestResult {
    let exact = plain(TWO, TWO_RECORDS);
    let mut longer = exact.clone();
    longer.push(0);
    let shorter = exact.get(..exact.len() - 1).ok_or("short")?;
    assert_eq!(parse_netflow_v5(&longer, &FlowLimits::default()), Err(FlowDrop::Malformed));
    assert_eq!(parse_netflow_v5(shorter, &FlowLimits::default()), Err(FlowDrop::Malformed));
    Ok(())
}


#[test]
fn trailing_bytes_and_missing_records_refused() -> TestResult {
    let limits = FlowLimits::default();
    assert_eq!(parse_netflow_v5(&plain(1, TWO_RECORDS), &limits), Err(FlowDrop::Malformed));
    assert_eq!(parse_netflow_v5(&plain(THIRTY, MISSING_RECORD_COUNT), &limits), Err(FlowDrop::Malformed));
    Ok(())
}


#[test]
fn count_zero_and_thirty_one_refused() -> TestResult {
    let limits = FlowLimits::default();
    assert_eq!(parse_netflow_v5(&plain(0, 0), &limits), Err(FlowDrop::Malformed));
    assert_eq!(parse_netflow_v5(&plain(THIRTY_ONE, THIRTY_ONE_RECORDS), &limits), Err(FlowDrop::TooLarge));
    assert_eq!(
        parse_netflow_v5(&plain(THIRTY_ONE, THIRTY_FIRST_MINUS_ONE), &limits),
        Err(FlowDrop::Malformed)
    );
    Ok(())
}


#[test]
fn count_thirty_one_in_a_max_sized_datagram_is_malformed() -> TestResult {
    let mut bytes = plain(THIRTY_ONE, MAX_FLOW_RECORDS);
    assert_eq!(bytes.len(), MAX_FLOW_DATAGRAM_BYTES);
    assert_eq!(parse_netflow_v5(&bytes, &FlowLimits::default()), Err(FlowDrop::Malformed));
    bytes.push(0);
    assert_eq!(parse_netflow_v5(&bytes, &FlowLimits::default()), Err(FlowDrop::TooLarge));
    Ok(())
}


#[test]
fn other_versions_are_unsupported() -> TestResult {
    OTHER_VERSIONS.iter().try_for_each(|version| -> TestResult {
        let mut bytes = plain(1, 1);
        bytes.splice(0..VERSION_BYTES, version.to_be_bytes());
        assert_eq!(parse_netflow_v5(&bytes, &FlowLimits::default()), Err(FlowDrop::Unsupported));
        Ok(())
    })
}


#[test]
fn record_cap_below_count_is_too_large() -> TestResult {
    let limits = FlowLimits { max_records_per_datagram: 1 };
    assert_eq!(parse_netflow_v5(&plain(TWO, TWO_RECORDS), &limits), Err(FlowDrop::TooLarge));
    assert!(parse_netflow_v5(&plain(1, 1), &limits).is_ok());
    Ok(())
}


#[test]
fn limits_validation() -> TestResult {
    assert_eq!(FlowLimits::default().max_records_per_datagram, MAX_FLOW_RECORDS);
    assert!(validate_flow_limits(&FlowLimits::default()).is_ok());
    assert!(validate_flow_limits(&FlowLimits { max_records_per_datagram: 1 }).is_ok());
    assert_eq!(
        validate_flow_limits(&FlowLimits { max_records_per_datagram: 0 }),
        Err(ConfigError::BadMaxFlowRecords)
    );
    assert_eq!(
        validate_flow_limits(&FlowLimits {
            max_records_per_datagram: MAX_FLOW_RECORDS + 1
        }),
        Err(ConfigError::BadMaxFlowRecords)
    );
    Ok(())
}


#[test]
fn every_prefix_is_refused() -> TestResult {
    let full = plain(TWO, TWO_RECORDS);
    (0..full.len()).try_for_each(|length| -> TestResult {
        let prefix = full.get(..length).ok_or("prefix")?;
        assert!(parse_netflow_v5(prefix, &FlowLimits::default()).is_err());
        Ok(())
    })
}


#[test]
fn start_after_end_is_kept() -> TestResult {
    let batch = parse_netflow_v5(&datagram(1, 1, LAST_STAMP, FIRST_STAMP), &FlowLimits::default())?;
    let flow = batch.records.first().ok_or("no record")?;
    assert!(flow.start_unix_ms > flow.end_unix_ms);
    Ok(())
}


#[test]
fn hostile_time_fields_are_defined() -> TestResult {
    let mut bytes = header(1, 0, u32::MAX, u32::MAX);
    bytes.extend_from_slice(&record(u32::MAX, u32::MAX));
    let batch = parse_netflow_v5(&bytes, &FlowLimits::default())?;
    let flow = batch.records.first().ok_or("no record")?;
    assert_eq!(batch.export_unix_ms, i64::from(u32::MAX) * MILLIS_PER_SECOND + MAX_NANOS_MILLIS);
    assert_eq!(flow.start_unix_ms, batch.export_unix_ms - 1);
    assert_eq!(absolute_ms(0, 0, u32::MAX), -1);
    assert_eq!(absolute_ms(0, 0, 1), -i64::from(u32::MAX));
    assert_eq!(export_time_ms(0, NANOS_BELOW_MILLI), 0);
    assert_eq!(export_time_ms(1, NANOS_ONE_MILLI), MILLIS_PER_SECOND + 1);
    Ok(())
}


#[test]
fn record_readers_refuse_short_input() -> TestResult {
    let bytes = record(1, 1);
    let mut short: &[u8] = bytes.get(..FLOW_RECORD_BYTES - 1).ok_or("short")?;
    assert_eq!(read_record(&mut short, 0, 0), Err(FlowDrop::Malformed));
    let mut empty: &[u8] = &[];
    assert_eq!(skip(&mut empty, 1), Err(FlowDrop::Malformed));
    let mut one: &[u8] = &[0];
    assert!(skip(&mut one, 1).is_ok());
    let mut one_record: &[u8] = &bytes;
    assert_eq!(read_records(&mut one_record, TWO_RECORDS, 0, 0), Err(FlowDrop::Malformed));
    let mut full: &[u8] = &bytes;
    assert!(read_record(&mut full, 0, 0).is_ok());
    assert!(full.is_empty());
    Ok(())
}


#[test]
fn drops_map_and_count() -> TestResult {
    assert_eq!(DropReason::from(FlowDrop::TooLarge), DropReason::FlowTooLarge);
    assert_eq!(DropReason::from(FlowDrop::Malformed), DropReason::FlowMalformed);
    assert_eq!(DropReason::from(FlowDrop::Unsupported), DropReason::FlowUnsupported);
    let mut stats = ListenerStats::default();
    count_reason(&mut stats, DropReason::FlowTooLarge);
    count_reason(&mut stats, DropReason::FlowMalformed);
    count_reason(&mut stats, DropReason::FlowUnsupported);
    assert_eq!((stats.dropped_too_long, stats.dropped_parse), (1, PARSE_DROPS));
    assert!(!DropReason::FlowTooLarge.to_string().is_empty());
    assert!(!FlowDrop::Unsupported.to_string().is_empty());
    assert!(!ConfigError::BadMaxFlowRecords.to_string().is_empty());
    Ok(())
}


#[test]
fn random_datagrams_never_panic() -> TestResult {
    let mut rng = StdRng::seed_from_u64(FUZZ_SEED);
    let limits = FlowLimits::default();
    let accepted = (0..FUZZ_ROUNDS).try_fold(0usize, |total, _| -> Result<usize, Box<dyn std::error::Error>> {
        let length = rng.gen_range(0..=FUZZ_MAX_LEN);
        let mut bytes: Vec<u8> = (0..length).map(|_| rng.gen()).collect();
        let prefix = bytes.len().min(VERSION_BYTES);
        if rng.gen_bool(FUZZ_SHAPED_ODDS) {
            bytes.splice(0..prefix, VERSION.to_be_bytes().into_iter().take(prefix));
        }
        Ok(total + usize::from(parse_netflow_v5(&bytes, &limits).is_ok()))
    })?;
    assert!(accepted <= FUZZ_ROUNDS);
    Ok(())
}


#[test]
fn live_fixture_parses() -> TestResult {
    let batch = parse_netflow_v5(FIXTURE, &FlowLimits::default())?;
    assert_eq!(FIXTURE.len(), FLOW_HEADER_BYTES + FLOW_RECORD_BYTES * batch.records.len());
    assert_eq!((batch.sequence, batch.records.len()), (FIXTURE_SEQUENCE, TWO_RECORDS));
    assert_eq!((batch.export_unix_ms, batch.exporter_uptime_ms), (FIXTURE_EXPORT_MS, FIXTURE_UPTIME));
    let query = batch.records.first().ok_or("no record")?;
    let answer = batch.records.get(1).ok_or("no answer")?;
    assert_eq!((query.source, query.destination), (LOOPBACK, RESOLVER));
    assert_eq!(
        (query.source_port, query.destination_port, query.protocol),
        (FIXTURE_PORT, DNS_PORT, PROTOCOL_UDP)
    );
    assert_eq!((query.packets, query.octets), FIXTURE_QUERY);
    assert_eq!((query.start_unix_ms, query.end_unix_ms), (FIXTURE_START_MS, FIXTURE_END_MS));
    assert_eq!((answer.source, answer.destination), (RESOLVER, LOOPBACK));
    assert_eq!((answer.packets, answer.octets), FIXTURE_ANSWER);
    Ok(())
}
