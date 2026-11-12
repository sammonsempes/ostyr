#[path = "support/types.rs"]
mod types;


use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use site_collector::error::ConfigError;
use site_collector::flow::validate_flow_limits;
use site_collector::flow_model::{FlowDrop, FlowLimits, MAX_TEMPLATE_DATAGRAM_BYTES};
use site_collector::listen::count_reason;
use site_collector::listen_model::ListenerStats;
use site_collector::model::DropReason;
use site_collector::template::{
    age_limit_ms, evict_least_recent_exporter, expire_exporter, is_expired, lookup_template, prune_expired, store_template, withdraw_scope,
};
use site_collector::template_model::{Template, TemplateCache, TemplateKey};
use site_collector::template_parse::{address, parse_ipfix, parse_netflow_v9, unsigned};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use types::TestResult;


const SECS: u32 = 1_700_000_000;


const UPTIME: u32 = 100_000;


const DOMAIN: u32 = 7;


const NOW: u64 = 1_000_000;


const TEMPLATE_ID: u16 = 300;


const SECOND_TEMPLATE_ID: u16 = 301;


const FUZZ_ROUNDS: usize = 100_000;


const FUZZ_SEED: u64 = 296;


const FUZZ_MAX_BODY: usize = 60;


const FAKE_EXPORTERS: u32 = 100_000;


const RSS_GROWTH_LIMIT_KB: u64 = 65_536;


const HONEST_EVERY: u32 = 100;


const FIELD_COUNT_HUGE: u16 = 65_535;


const FULL_FIELDS: [(u16, u16); 16] = [
    (1, 8),
    (2, 4),
    (4, 1),
    (5, 1),
    (6, 1),
    (7, 2),
    (11, 2),
    (8, 4),
    (12, 4),
    (15, 4),
    (10, 4),
    (14, 2),
    (16, 4),
    (17, 2),
    (21, 4),
    (22, 4),
];


const NUM_100000_U64: u64 = 100_000;


const NUM_10000_I64: i64 = 10_000;


const NUM_10000_U64: u64 = 10_000;


const NUM_10001_U64: u64 = 10_001;


const NUM_1000_I64: i64 = 1000;


const NUM_100_U16: u16 = 100;


const NUM_10500_U64: u64 = 10_500;


const NUM_1099511627776_I64: i64 = 1_099_511_627_776;


const NUM_1099511627777_I64: i64 = 1_099_511_627_777;


const NUM_10_U16: u16 = 10;


const NUM_10_U64: u64 = 10;


const NUM_10_U8: u8 = 10;


const NUM_10_USIZE: usize = 10;


const NUM_11_U32: u32 = 11;


const NUM_11_U64: u64 = 11;


const NUM_12_USIZE: usize = 12;


const NUM_1501: usize = 1501;


const NUM_1501_U16: u16 = 1501;


const NUM_150_U16: u16 = 150;


const NUM_151_U16: u16 = 151;


const NUM_152_U16: u16 = 152;


const NUM_153_U16: u16 = 153;


const NUM_16: usize = 16;


const NUM_168_U8: u8 = 168;


const NUM_16_U16: u16 = 16;


const NUM_1700000001000_I64: i64 = 1_700_000_001_000;


const NUM_1700000001_U32: u32 = 1_700_000_001;


const NUM_1700000002000_I64: i64 = 1_700_000_002_000;


const NUM_1700000002_U32: u32 = 1_700_000_002;


const NUM_192_U8: u8 = 192;


const NUM_2: usize = 2;


const NUM_20: usize = 20;


const NUM_200_U8: u8 = 200;


const NUM_2048_U64: u64 = 2048;


const NUM_20_USIZE: usize = 20;


const NUM_25: usize = 25;


const NUM_254_U8: u8 = 254;


const NUM_255_U8: u8 = 255;


const NUM_256_U64: u64 = 256;


const NUM_257: usize = 257;


const NUM_27_U16: u16 = 27;


const NUM_28_U16: u16 = 28;


const NUM_29305_U32: u32 = 29_305;


const NUM_2_U16: u16 = 2;


const NUM_2_U32: u32 = 2;


const NUM_2_U64: u64 = 2;


const NUM_2_U8: u8 = 2;


const NUM_3: usize = 3;


const NUM_300: usize = 300;


const NUM_300_U16: u16 = 300;


const NUM_301_U16: u16 = 301;


const NUM_302_U16: u16 = 302;


const NUM_303_U16: u16 = 303;


const NUM_3_U16: u16 = 3;


const NUM_3_U32: u32 = 3;


const NUM_3_U64: u64 = 3;


const NUM_3_U8: u8 = 3;


const NUM_4: usize = 4;


const NUM_40000_U16: u16 = 40_000;


const NUM_4097: usize = 4097;


const NUM_40_U8: u8 = 40;


const NUM_443_U16: u16 = 443;


const NUM_44_U8: u8 = 44;


const NUM_4_U16: u16 = 4;


const NUM_4_U32: u32 = 4;


const NUM_4_U64: u64 = 4;


const NUM_4_U8: u8 = 4;


const NUM_4_USIZE: usize = 4;


const NUM_5000_U64: u64 = 5000;


const NUM_53_U16: u16 = 53;


const NUM_5_U32: u32 = 5;


const NUM_5_U64: u64 = 5;


const NUM_5_U8: u8 = 5;


const NUM_60000_U16: u16 = 60_000;


const NUM_62_U16: u16 = 62;


const NUM_64512_U16: u16 = 64_512;


const NUM_64512_U32: u32 = 64_512;


const NUM_65: usize = 65;


const NUM_65000_U32: u32 = 65_000;


const NUM_65535_U16: u16 = 65_535;


const NUM_65_U16: u16 = 65;


const NUM_6_U16: u16 = 6;


const NUM_6_U64: u64 = 6;


const NUM_6_U8: u8 = 6;


const NUM_6_USIZE: usize = 6;


const NUM_7_U16: u16 = 7;


const NUM_8099_U16: u16 = 8099;


const NUM_80_U16: u16 = 80;


const NUM_85_U16: u16 = 85;


const NUM_86401_U64: u64 = 86_401;


const NUM_86_U16: u16 = 86;


const NUM_8_U16: u16 = 8;


const NUM_8_U32: u32 = 8;


const NUM_8_USIZE: usize = 8;


const NUM_90000_U32: u32 = 90_000;


const NUM_9000_U64: u64 = 9000;


const NUM_96_U16: u16 = 96;


const NUM_99000_U32: u32 = 99_000;


const NUM_9999_U16: u16 = 9999;


const NUM_9_U16: u16 = 9;


const NUM_9_U64: u64 = 9;


const NUM_9_U8: u8 = 9;


const NUM_HEX00_U8: u8 = 0x00;


const NUM_HEX01FF_U16: u16 = 0x01ff;


const NUM_HEX08_U8: u8 = 0x08;


const NUM_HEX0A000000_U32: u32 = 0x0a00_0000;


const NUM_HEX10_U8: u8 = 0x10;


const NUM_HEX1B_U8: u8 = 0x1b;


const NUM_HEX2001_U16: u16 = 0x2001;


const NUM_HEX8001_U16: u16 = 0x8001;


const NUM_HEXDB8_U16: u16 = 0xdb8;


const NUM_HEXFFFF_U16: u16 = 0xFFFF;


const NUM_HEXFF_U8: u8 = 0xff;


fn exporter(last: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(NUM_HEX0A000000_U32 + last))
}


fn word(value: u16) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}


fn long_word(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}


fn set(set_id: u16, body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(body.len() + NUM_4).unwrap_or(u16::MAX);
    [word(set_id), word(length), body.to_vec()].concat()
}


fn template_record(template_id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    let count = u16::try_from(fields.len()).unwrap_or(u16::MAX);
    let specs: Vec<u8> = fields
        .iter()
        .flat_map(|(element, length)| [word(*element), word(*length)].concat())
        .collect();
    [word(template_id), word(count), specs].concat()
}


fn v9_datagram(domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
    [
        word(NUM_9_U16),
        word(0),
        long_word(UPTIME),
        long_word(SECS),
        long_word(NUM_5_U32),
        long_word(domain),
        sets.concat(),
    ]
    .concat()
}


fn ipfix_datagram(domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
    let body = sets.concat();
    let length = u16::try_from(body.len() + NUM_16).unwrap_or(u16::MAX);
    [
        word(NUM_10_U16),
        word(length),
        long_word(SECS),
        long_word(NUM_5_U32),
        long_word(domain),
        body,
    ]
    .concat()
}


fn parse_v9(datagram: &[u8], cache: &mut TemplateCache) -> Result<site_collector::flow_model::FlowBatch, FlowDrop> {
    parse_netflow_v9(datagram, exporter(1), cache, NOW, &FlowLimits::default())
}


fn parse_ipfix_default(datagram: &[u8], cache: &mut TemplateCache) -> Result<site_collector::flow_model::FlowBatch, FlowDrop> {
    parse_ipfix(datagram, exporter(1), cache, NOW, &FlowLimits::default())
}


fn full_record() -> Vec<u8> {
    [
        vec![0, 0, 0, 0, 0, 0, NUM_HEX08_U8, NUM_HEX00_U8],
        long_word(NUM_11_U32),
        vec![NUM_6_U8, NUM_HEX10_U8, NUM_HEX1B_U8],
        word(NUM_40000_U16),
        word(NUM_443_U16),
        vec![NUM_10_U8, 0, 0, 1],
        vec![NUM_192_U8, NUM_168_U8, 1, NUM_2_U8],
        vec![NUM_10_U8, 0, 0, NUM_254_U8],
        long_word(NUM_3_U32),
        word(NUM_4_U16),
        long_word(NUM_65000_U32),
        word(NUM_64512_U16),
        long_word(NUM_99000_U32),
        long_word(NUM_90000_U32),
    ]
    .concat()
}


fn full_v9() -> Vec<u8> {
    let templates = set(0, &template_record(TEMPLATE_ID, &FULL_FIELDS));
    let data = set(TEMPLATE_ID, &[full_record(), vec![0]].concat());
    v9_datagram(DOMAIN, &[templates, data])
}


#[test]
fn v9_template_then_data_decodes_every_field() -> TestResult {
    let mut cache = TemplateCache::default();
    let batch = parse_v9(&full_v9(), &mut cache)?;
    let flow = batch.records.first().ok_or("no record")?;
    assert_eq!(batch.records.len(), 1);
    assert_eq!((batch.sequence, batch.exporter_uptime_ms), (NUM_5_U32, UPTIME));
    assert_eq!(batch.export_unix_ms, i64::from(SECS) * NUM_1000_I64);
    assert_eq!((flow.octets, flow.packets), (NUM_2048_U64, NUM_11_U64));
    assert_eq!((flow.protocol, flow.tos, flow.tcp_flags), (NUM_6_U8, NUM_HEX10_U8, NUM_HEX1B_U8));
    assert_eq!((flow.source_port, flow.destination_port), (NUM_40000_U16, NUM_443_U16));
    assert_eq!(flow.source, IpAddr::V4(Ipv4Addr::new(NUM_10_U8, 0, 0, 1)));
    assert_eq!(flow.destination, IpAddr::V4(Ipv4Addr::new(NUM_192_U8, NUM_168_U8, 1, NUM_2_U8)));
    assert_eq!(flow.next_hop, IpAddr::V4(Ipv4Addr::new(NUM_10_U8, 0, 0, NUM_254_U8)));
    assert_eq!((flow.input_interface, flow.output_interface), (NUM_3_U32, NUM_4_U32));
    assert_eq!((flow.source_as, flow.destination_as), (NUM_65000_U32, NUM_64512_U32));
    assert_eq!(flow.start_unix_ms, i64::from(SECS) * NUM_1000_I64 - NUM_10000_I64);
    assert_eq!(flow.end_unix_ms, i64::from(SECS) * NUM_1000_I64 - NUM_1000_I64);
    assert_eq!(cache.templates.len(), 1);
    let second = parse_v9(&v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &full_record())]), &mut cache)?;
    assert_eq!(second.records.len(), 1);
    Ok(())
}


#[test]
fn ipv6_totals_times_and_unknown_elements() -> TestResult {
    let fields = [
        (NUM_27_U16, NUM_16_U16),
        (NUM_28_U16, NUM_16_U16),
        (NUM_62_U16, NUM_16_U16),
        (NUM_85_U16, NUM_8_U16),
        (NUM_86_U16, NUM_8_U16),
        (NUM_150_U16, NUM_4_U16),
        (NUM_151_U16, NUM_4_U16),
        (NUM_9999_U16, NUM_3_U16),
        (NUM_8_U16, NUM_3_U16),
    ];
    let source = Ipv6Addr::LOCALHOST.octets();
    let destination = Ipv6Addr::new(NUM_HEX2001_U16, NUM_HEXDB8_U16, 0, 0, 0, 0, 0, 1).octets();
    let record = [
        source.to_vec(),
        destination.to_vec(),
        destination.to_vec(),
        vec![0, 0, 0, 0, 0, 0, 1, 0],
        vec![0, 0, 0, 0, 0, 0, 0, NUM_9_U8],
        long_word(NUM_1700000001_U32),
        long_word(NUM_1700000002_U32),
        vec![1, NUM_2_U8, NUM_3_U8],
        vec![1, NUM_2_U8, NUM_3_U8],
    ]
    .concat();
    let datagram = v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &fields)), set(TEMPLATE_ID, &record)]);
    let mut cache = TemplateCache::default();
    let batch = parse_v9(&datagram, &mut cache)?;
    let flow = batch.records.first().ok_or("no record")?;
    assert_eq!(flow.source, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(
        flow.destination,
        IpAddr::V6(Ipv6Addr::new(NUM_HEX2001_U16, NUM_HEXDB8_U16, 0, 0, 0, 0, 0, 1))
    );
    assert_eq!(flow.next_hop, flow.destination);
    assert_eq!((flow.octets, flow.packets), (NUM_256_U64, NUM_9_U64));
    assert_eq!((flow.start_unix_ms, flow.end_unix_ms), (NUM_1700000001000_I64, NUM_1700000002000_I64));
    Ok(())
}


#[test]
fn ipfix_enterprise_variable_and_millisecond_times() -> TestResult {
    let enterprise = [word(NUM_HEX8001_U16), word(NUM_2_U16), long_word(NUM_29305_U32)].concat();
    let specs = [
        word(NUM_8_U16),
        word(NUM_4_U16),
        enterprise,
        word(NUM_96_U16),
        word(NUM_HEXFFFF_U16),
        word(NUM_152_U16),
        word(NUM_8_U16),
        word(NUM_153_U16),
        word(NUM_8_U16),
        word(NUM_7_U16),
        word(NUM_2_U16),
        word(NUM_6_U16),
        word(NUM_2_U16),
    ]
    .concat();
    let template = [word(TEMPLATE_ID), word(NUM_7_U16), specs].concat();
    let long_text = vec![b'x'; NUM_300];
    let record = |text: &[u8], lead: Vec<u8>| {
        [
            vec![NUM_10_U8, 1, 1, 1],
            vec![NUM_9_U8, NUM_9_U8],
            lead,
            text.to_vec(),
            vec![0, 0, 1, 0, 0, 0, 0, 0],
            vec![0, 0, 1, 0, 0, 0, 0, 1],
            word(NUM_53_U16),
            word(NUM_HEX01FF_U16),
        ]
        .concat()
    };
    let short = record(b"ab", vec![NUM_2_U8]);
    let long = record(&long_text, [vec![NUM_255_U8], word(NUM_300_U16)].concat());
    let data = [short, long].concat();
    let datagram = ipfix_datagram(DOMAIN, &[set(NUM_2_U16, &template), set(TEMPLATE_ID, &data)]);
    let mut cache = TemplateCache::default();
    let batch = parse_ipfix_default(&datagram, &mut cache)?;
    assert_eq!(batch.records.len(), NUM_2);
    let flow = batch.records.first().ok_or("no record")?;
    assert_eq!(flow.source, IpAddr::V4(Ipv4Addr::new(NUM_10_U8, 1, 1, 1)));
    assert_eq!((flow.start_unix_ms, flow.end_unix_ms), (NUM_1099511627776_I64, NUM_1099511627777_I64));
    assert_eq!((flow.source_port, flow.tcp_flags), (NUM_53_U16, NUM_HEXFF_U8));
    assert_eq!(batch.exporter_uptime_ms, 0);
    Ok(())
}


#[test]
fn unknown_template_is_counted_and_never_buffered() -> TestResult {
    let mut cache = TemplateCache::default();
    let data = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &full_record())]);
    assert_eq!(parse_v9(&data, &mut cache), Err(FlowDrop::NoTemplate));
    assert_eq!(parse_v9(&data, &mut cache), Err(FlowDrop::NoTemplate));
    assert_eq!(cache.stats.no_template_sets, NUM_2_U64);
    parse_v9(&v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &FULL_FIELDS))]), &mut cache)?;
    assert!(cache.templates.len() == 1);
    let mixed = v9_datagram(DOMAIN, &[set(SECOND_TEMPLATE_ID, &[0; NUM_8_USIZE]), set(TEMPLATE_ID, &full_record())]);
    assert_eq!(parse_v9(&mixed, &mut cache)?.records.len(), 1);
    assert_eq!(cache.stats.no_template_sets, NUM_3_U64);
    Ok(())
}


#[test]
fn cache_is_keyed_by_exporter_domain_and_id() -> TestResult {
    let mut cache = TemplateCache::default();
    let defined = v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &FULL_FIELDS))]);
    parse_netflow_v9(&defined, exporter(1), &mut cache, NOW, &FlowLimits::default())?;
    let data = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &full_record())]);
    let other_exporter = parse_netflow_v9(&data, exporter(NUM_2_U32), &mut cache, NOW, &FlowLimits::default());
    assert_eq!(other_exporter, Err(FlowDrop::NoTemplate));
    let other_domain = parse_netflow_v9(
        &v9_datagram(DOMAIN + 1, &[set(TEMPLATE_ID, &full_record())]),
        exporter(1),
        &mut cache,
        NOW,
        &FlowLimits::default(),
    );
    assert_eq!(other_domain, Err(FlowDrop::NoTemplate));
    assert!(parse_netflow_v9(&data, exporter(1), &mut cache, NOW, &FlowLimits::default()).is_ok());
    Ok(())
}


#[test]
fn redefinition_replaces_and_withdrawal_removes() -> TestResult {
    let mut cache = TemplateCache::default();
    parse_v9(&full_v9(), &mut cache)?;
    let redefined = v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &[(NUM_7_U16, NUM_2_U16)]))]);
    parse_v9(&redefined, &mut cache)?;
    let old_layout = parse_v9(&v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &full_record())]), &mut cache)?;
    assert_eq!(old_layout.records.len(), NUM_25);
    let new_layout = parse_v9(&v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &word(NUM_80_U16))]), &mut cache)?;
    assert_eq!(new_layout.records.first().ok_or("none")?.source_port, NUM_80_U16);
    assert_eq!(cache.templates.len(), 1);
    let withdraw = ipfix_datagram(DOMAIN, &[set(NUM_2_U16, &template_record(TEMPLATE_ID, &[]))]);
    parse_ipfix_default(&withdraw, &mut cache)?;
    assert!(cache.templates.is_empty() && cache.exporters.is_empty());
    let absent = ipfix_datagram(DOMAIN, &[set(NUM_2_U16, &template_record(TEMPLATE_ID, &[]))]);
    assert!(parse_ipfix_default(&absent, &mut cache).is_ok());
    Ok(())
}


#[test]
fn withdraw_all_removes_one_domain_only() -> TestResult {
    let mut cache = TemplateCache::default();
    let defs = set(
        NUM_2_U16,
        &[
            template_record(TEMPLATE_ID, &[(NUM_7_U16, NUM_2_U16)]),
            template_record(SECOND_TEMPLATE_ID, &[(NUM_7_U16, NUM_2_U16)]),
        ]
        .concat(),
    );
    parse_ipfix_default(&ipfix_datagram(DOMAIN, std::slice::from_ref(&defs)), &mut cache)?;
    parse_ipfix_default(&ipfix_datagram(DOMAIN + 1, &[defs]), &mut cache)?;
    assert_eq!(cache.templates.len(), NUM_4);
    parse_ipfix_default(&ipfix_datagram(DOMAIN, &[set(NUM_2_U16, &template_record(NUM_2_U16, &[]))]), &mut cache)?;
    assert_eq!(cache.templates.len(), NUM_2);
    assert_eq!(cache.exporters.get(&exporter(1)).map(|state| state.templates), Some(NUM_2));
    assert_eq!(withdraw_scope(&mut cache, exporter(1), DOMAIN + 1), NUM_2);
    assert!(cache.exporters.is_empty());
    Ok(())
}


#[test]
fn per_exporter_cap_refuses_new_templates_but_not_redefinition() -> TestResult {
    let limits = FlowLimits {
        max_templates_per_exporter: NUM_2,
        ..FlowLimits::default()
    };
    let mut cache = TemplateCache::default();
    let define = |id: u16| v9_datagram(DOMAIN, &[set(0, &template_record(id, &[(NUM_7_U16, NUM_2_U16)]))]);
    parse_netflow_v9(&define(NUM_300_U16), exporter(1), &mut cache, NOW, &limits)?;
    parse_netflow_v9(&define(NUM_301_U16), exporter(1), &mut cache, NOW, &limits)?;
    assert_eq!(
        parse_netflow_v9(&define(NUM_302_U16), exporter(1), &mut cache, NOW, &limits),
        Err(FlowDrop::TemplateRefused)
    );
    assert_eq!(cache.stats.refused_templates, 1);
    assert_eq!(cache.templates.len(), NUM_2);
    assert!(parse_netflow_v9(&define(NUM_300_U16), exporter(1), &mut cache, NOW, &limits).is_ok());
    assert!(parse_netflow_v9(&define(NUM_300_U16), exporter(NUM_2_U32), &mut cache, NOW, &limits).is_ok());
    let both = v9_datagram(
        DOMAIN,
        &[
            set(0, &template_record(NUM_303_U16, &[(NUM_7_U16, NUM_2_U16)])),
            set(NUM_300_U16, &word(1)),
        ],
    );
    assert_eq!(parse_netflow_v9(&both, exporter(1), &mut cache, NOW, &limits)?.records.len(), 1);
    let three = set(
        0,
        &[
            template_record(NUM_300_U16, &[(NUM_7_U16, NUM_2_U16)]),
            template_record(NUM_301_U16, &[(NUM_7_U16, NUM_2_U16)]),
            template_record(NUM_302_U16, &[(NUM_7_U16, NUM_2_U16)]),
        ]
        .concat(),
    );
    let refused = parse_netflow_v9(&v9_datagram(DOMAIN, &[three]), exporter(NUM_3_U32), &mut cache, NOW, &limits);
    assert_eq!(refused, Err(FlowDrop::TemplateRefused));
    assert!(!cache.exporters.contains_key(&exporter(NUM_3_U32)));
    Ok(())
}


#[test]
fn exporter_cap_evicts_least_recently_used_first() -> TestResult {
    let limits = FlowLimits {
        max_template_exporters: NUM_3,
        ..FlowLimits::default()
    };
    let mut cache = TemplateCache::default();
    let define = v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &[(NUM_7_U16, NUM_2_U16)]))]);
    let data = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &word(1))]);
    (1..=NUM_3_U32).try_for_each(|peer_index| parse_netflow_v9(&define, exporter(peer_index), &mut cache, NOW, &limits).map(|_| ()))?;
    parse_netflow_v9(&data, exporter(1), &mut cache, NOW, &limits)?;
    parse_netflow_v9(&define, exporter(NUM_4_U32), &mut cache, NOW, &limits)?;
    assert_eq!(cache.stats.evicted_exporters, 1);
    let alive: Vec<IpAddr> = cache.exporters.keys().copied().collect();
    assert_eq!(alive, vec![exporter(1), exporter(NUM_3_U32), exporter(NUM_4_U32)]);
    parse_netflow_v9(&define, exporter(NUM_5_U32), &mut cache, NOW, &limits)?;
    let alive_later: Vec<IpAddr> = cache.exporters.keys().copied().collect();
    assert_eq!(alive_later, vec![exporter(1), exporter(NUM_4_U32), exporter(NUM_5_U32)]);
    assert_eq!(cache.stats.evicted_exporters, NUM_2_U64);
    assert_eq!(cache.templates.len(), NUM_3);
    let mut empty = TemplateCache::default();
    assert_eq!(evict_least_recent_exporter(&mut empty), 0);
    assert_eq!(empty.stats.evicted_exporters, 0);
    Ok(())
}


#[test]
fn templates_expire_with_the_injected_clock() -> TestResult {
    let limits = FlowLimits {
        max_template_age_seconds: NUM_10_U64,
        ..FlowLimits::default()
    };
    assert_eq!(age_limit_ms(&limits), NUM_10000_U64);
    let mut cache = TemplateCache::default();
    let define = v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &[(NUM_7_U16, NUM_2_U16)]))]);
    let data = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &word(1))]);
    parse_netflow_v9(&define, exporter(1), &mut cache, NOW, &limits)?;
    assert!(parse_netflow_v9(&data, exporter(1), &mut cache, NOW + NUM_10000_U64, &limits).is_ok());
    assert_eq!(
        parse_netflow_v9(&data, exporter(1), &mut cache, NOW + NUM_10001_U64, &limits),
        Err(FlowDrop::NoTemplate)
    );
    assert_eq!(cache.stats.expired_templates, 1);
    assert!(cache.exporters.is_empty());
    parse_netflow_v9(&define, exporter(1), &mut cache, NOW, &limits)?;
    parse_netflow_v9(&define, exporter(NUM_2_U32), &mut cache, NOW + NUM_9000_U64, &limits)?;
    assert_eq!(prune_expired(&mut cache, NOW + NUM_10500_U64, age_limit_ms(&limits)), 1);
    assert_eq!(cache.exporters.len(), 1);
    let backwards = parse_netflow_v9(&data, exporter(NUM_2_U32), &mut cache, 0, &limits);
    assert!(backwards.is_ok());
    let key = TemplateKey {
        exporter: exporter(NUM_2_U32),
        domain: DOMAIN,
        template_id: TEMPLATE_ID,
    };
    assert!(lookup_template(&mut cache, &key, NOW + NUM_9000_U64, NUM_10000_U64).is_some());
    parse_netflow_v9(&define, exporter(NUM_3_U32), &mut cache, NOW, &limits)?;
    let key_three = TemplateKey {
        exporter: exporter(NUM_3_U32),
        ..key
    };
    assert!(lookup_template(&mut cache, &key_three, NOW + NUM_100000_U64, NUM_10000_U64).is_none());
    assert_eq!(expire_exporter(&mut cache, exporter(NUM_2_U32), NOW + NUM_100000_U64, NUM_10000_U64), 1);
    assert_eq!(cache.stats.expired_templates, NUM_4_U64);
    let fresh = Template {
        fields: Vec::new(),
        min_record_bytes: 1,
        refreshed_ms: NUM_5_U64,
    };
    assert!(!is_expired(&fresh, NUM_4_U64, 0));
    assert!(is_expired(&fresh, NUM_6_U64, 0));
    Ok(())
}


#[test]
fn expiry_frees_the_per_exporter_slot_before_a_new_template() -> TestResult {
    let limits = FlowLimits {
        max_templates_per_exporter: 1,
        max_template_age_seconds: 1,
        ..FlowLimits::default()
    };
    let mut cache = TemplateCache::default();
    parse_netflow_v9(
        &v9_datagram(DOMAIN, &[set(0, &template_record(NUM_300_U16, &[(NUM_7_U16, NUM_2_U16)]))]),
        exporter(1),
        &mut cache,
        NOW,
        &limits,
    )?;
    let later = v9_datagram(DOMAIN, &[set(0, &template_record(NUM_301_U16, &[(NUM_7_U16, NUM_2_U16)]))]);
    assert!(parse_netflow_v9(&later, exporter(1), &mut cache, NOW + NUM_5000_U64, &limits).is_ok());
    assert_eq!(cache.templates.len(), 1);
    Ok(())
}


#[test]
fn hostile_templates_are_refused() -> TestResult {
    let mut cache = TemplateCache::default();
    let huge_count = [word(TEMPLATE_ID), word(FIELD_COUNT_HUGE)].concat();
    assert_eq!(
        parse_v9(&v9_datagram(DOMAIN, &[set(0, &huge_count)]), &mut cache),
        Err(FlowDrop::TemplateRefused)
    );
    assert_eq!(cache.stats.refused_templates, 1);
    let over_fields: Vec<(u16, u16)> = (0..NUM_65).map(|_| (NUM_7_U16, NUM_2_U16)).collect();
    assert_eq!(
        parse_v9(&v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &over_fields))]), &mut cache),
        Err(FlowDrop::TemplateRefused)
    );
    let huge_record = v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &[(NUM_7_U16, NUM_65535_U16)]))]);
    assert_eq!(parse_v9(&huge_record, &mut cache), Err(FlowDrop::TemplateRefused));
    let ipfix_huge = ipfix_datagram(DOMAIN, &[set(NUM_2_U16, &template_record(TEMPLATE_ID, &[(NUM_7_U16, NUM_60000_U16)]))]);
    assert_eq!(parse_ipfix_default(&ipfix_huge, &mut cache), Err(FlowDrop::TemplateRefused));
    let zero_length = v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &[(NUM_7_U16, 0)]))]);
    assert_eq!(parse_v9(&zero_length, &mut cache), Err(FlowDrop::TemplateRefused));
    assert!(cache.templates.is_empty());
    assert_eq!(cache.stats.refused_templates, NUM_5_U64);
    let many: Vec<u8> = (0..NUM_65_U16)
        .flat_map(|offset| template_record(NUM_300_U16 + offset, &[(NUM_7_U16, NUM_2_U16)]))
        .collect();
    assert_eq!(
        parse_v9(&v9_datagram(DOMAIN, &[set(0, &many)]), &mut cache),
        Err(FlowDrop::TemplateRefused)
    );
    let refused_with_records = v9_datagram(
        DOMAIN,
        &[
            set(0, &template_record(TEMPLATE_ID, &[(NUM_7_U16, NUM_2_U16)])),
            set(0, &template_record(SECOND_TEMPLATE_ID, &[(NUM_7_U16, 0)])),
            set(TEMPLATE_ID, &word(NUM_9_U16)),
        ],
    );
    assert_eq!(parse_v9(&refused_with_records, &mut cache)?.records.len(), 1);
    Ok(())
}


#[test]
fn malformed_structures_are_refused_whole() -> TestResult {
    let mut cache = TemplateCache::default();
    let good = full_v9();
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(parse_v9(&trailing, &mut cache), Err(FlowDrop::Malformed));
    let mut short_set = v9_datagram(DOMAIN, &[]);
    short_set.extend_from_slice(&[0, 0, 0, NUM_3_U8, 0, 0, 0, 0]);
    assert_eq!(parse_v9(&short_set, &mut cache), Err(FlowDrop::Malformed));
    let mut overrun = v9_datagram(DOMAIN, &[]);
    overrun.extend_from_slice(&[1, NUM_44_U8, 0, NUM_40_U8, 0, 0, 0, 0]);
    assert_eq!(parse_v9(&overrun, &mut cache), Err(FlowDrop::Malformed));
    let reserved_id = v9_datagram(DOMAIN, &[set(0, &template_record(NUM_100_U16, &[(NUM_7_U16, NUM_2_U16)]))]);
    assert_eq!(parse_v9(&reserved_id, &mut cache), Err(FlowDrop::Malformed));
    let ipfix_reserved = ipfix_datagram(DOMAIN, &[set(NUM_2_U16, &template_record(NUM_2_U16, &[(NUM_7_U16, NUM_2_U16)]))]);
    assert_eq!(parse_ipfix_default(&ipfix_reserved, &mut cache), Err(FlowDrop::Malformed));
    let v9_two = v9_datagram(DOMAIN, &[set(0, &template_record(NUM_2_U16, &[]))]);
    assert_eq!(parse_v9(&v9_two, &mut cache), Err(FlowDrop::Malformed));
    let truncated_template = v9_datagram(
        DOMAIN,
        &[set(0, &[word(NUM_300_U16), word(NUM_3_U16), word(NUM_7_U16), word(NUM_2_U16)].concat())],
    );
    assert_eq!(parse_v9(&truncated_template, &mut cache), Err(FlowDrop::Malformed));
    let enterprise_cut = ipfix_datagram(
        DOMAIN,
        &[set(
            NUM_2_U16,
            &[word(NUM_300_U16), word(1), word(NUM_HEX8001_U16), word(NUM_2_U16)].concat(),
        )],
    );
    assert_eq!(parse_ipfix_default(&enterprise_cut, &mut cache), Err(FlowDrop::Malformed));
    parse_v9(
        &v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &[(1, NUM_8_U16)]))]),
        &mut cache,
    )?;
    let padded_too_much = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &[0; NUM_12_USIZE])]);
    assert_eq!(parse_v9(&padded_too_much, &mut cache), Err(FlowDrop::Malformed));
    Ok(())
}


#[test]
fn padding_up_to_three_bytes_is_accepted() -> TestResult {
    let mut cache = TemplateCache::default();
    parse_v9(
        &v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &[(1, NUM_8_U16)]))]),
        &mut cache,
    )?;
    let padded = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &[0, 0, 0, 0, 0, 0, 0, NUM_5_U8, 0, 0, 0])]);
    assert_eq!(parse_v9(&padded, &mut cache)?.records.len(), 1);
    let empty_data = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &[])]);
    assert!(parse_v9(&empty_data, &mut cache)?.records.is_empty());
    Ok(())
}


#[test]
fn variable_length_elements_are_bounded() -> TestResult {
    let mut cache = TemplateCache::default();
    let template = set(NUM_2_U16, &template_record(TEMPLATE_ID, &[(NUM_96_U16, NUM_HEXFFFF_U16)]));
    parse_ipfix_default(&ipfix_datagram(DOMAIN, &[template]), &mut cache)?;
    let over_cap = [vec![NUM_255_U8], word(NUM_1501_U16), vec![0; NUM_1501]].concat();
    assert_eq!(
        parse_ipfix_default(&ipfix_datagram(DOMAIN, &[set(TEMPLATE_ID, &over_cap)]), &mut cache),
        Err(FlowDrop::Malformed)
    );
    let past_set = [vec![NUM_200_U8], vec![0; NUM_10_USIZE]].concat();
    assert_eq!(
        parse_ipfix_default(&ipfix_datagram(DOMAIN, &[set(TEMPLATE_ID, &past_set)]), &mut cache),
        Err(FlowDrop::Malformed)
    );
    let cut_prefix = vec![NUM_255_U8, 0];
    assert_eq!(
        parse_ipfix_default(&ipfix_datagram(DOMAIN, &[set(TEMPLATE_ID, &cut_prefix)]), &mut cache),
        Err(FlowDrop::Malformed)
    );
    let v9_marker = v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &[(NUM_96_U16, NUM_HEXFFFF_U16)]))]);
    assert_eq!(parse_v9(&v9_marker, &mut cache), Err(FlowDrop::TemplateRefused));
    Ok(())
}


#[test]
fn header_checks() -> TestResult {
    let mut cache = TemplateCache::default();
    assert_eq!(parse_v9(&ipfix_datagram(DOMAIN, &[]), &mut cache), Err(FlowDrop::Unsupported));
    assert_eq!(parse_ipfix_default(&v9_datagram(DOMAIN, &[]), &mut cache), Err(FlowDrop::Unsupported));
    let mut wrong_length = ipfix_datagram(DOMAIN, &[set(NUM_2_U16, &[])]);
    wrong_length.push(0);
    assert_eq!(parse_ipfix_default(&wrong_length, &mut cache), Err(FlowDrop::Malformed));
    let huge = vec![0; MAX_TEMPLATE_DATAGRAM_BYTES + 1];
    assert_eq!(parse_v9(&huge, &mut cache), Err(FlowDrop::TooLarge));
    assert_eq!(parse_ipfix_default(&huge, &mut cache), Err(FlowDrop::TooLarge));
    assert!(parse_v9(&v9_datagram(DOMAIN, &[]), &mut cache)?.records.is_empty());
    Ok(())
}


#[test]
fn skipped_sets_are_ignored_by_length() -> TestResult {
    let mut cache = TemplateCache::default();
    let datagram = v9_datagram(
        DOMAIN,
        &[set(1, &[0; NUM_12_USIZE]), set(NUM_100_U16, &[1, NUM_2_U8, NUM_3_U8, NUM_4_U8])],
    );
    assert!(parse_v9(&datagram, &mut cache)?.records.is_empty());
    let ipfix = ipfix_datagram(DOMAIN, &[set(NUM_3_U16, &[0; NUM_12_USIZE])]);
    assert!(parse_ipfix_default(&ipfix, &mut cache)?.records.is_empty());
    Ok(())
}


#[test]
fn record_cap_refuses_a_flood_of_records() -> TestResult {
    let limits = FlowLimits {
        max_template_records_per_datagram: NUM_3,
        ..FlowLimits::default()
    };
    let mut cache = TemplateCache::default();
    parse_netflow_v9(
        &v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &[(NUM_7_U16, NUM_2_U16)]))]),
        exporter(1),
        &mut cache,
        NOW,
        &limits,
    )?;
    let at_cap = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &[0; NUM_6_USIZE])]);
    assert_eq!(parse_netflow_v9(&at_cap, exporter(1), &mut cache, NOW, &limits)?.records.len(), NUM_3);
    let over = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &[0; NUM_8_USIZE])]);
    assert_eq!(parse_netflow_v9(&over, exporter(1), &mut cache, NOW, &limits), Err(FlowDrop::TooLarge));
    let across = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &[0; NUM_4_USIZE]), set(TEMPLATE_ID, &[0; NUM_4_USIZE])]);
    assert_eq!(parse_netflow_v9(&across, exporter(1), &mut cache, NOW, &limits), Err(FlowDrop::TooLarge));
    Ok(())
}


#[test]
fn every_truncated_prefix_off_a_set_boundary_is_refused() -> TestResult {
    let v9 = full_v9();
    let ipfix = ipfix_datagram(
        DOMAIN,
        &[
            set(NUM_2_U16, &template_record(TEMPLATE_ID, &FULL_FIELDS)),
            set(TEMPLATE_ID, &[full_record(), vec![0]].concat()),
        ],
    );
    let first_set_end = NUM_20 + NUM_4 + NUM_4 + FULL_FIELDS.len() * NUM_4;
    let results: Vec<bool> = (0..v9.len())
        .map(|length| {
            let mut cache = TemplateCache::default();
            let prefix = v9.get(..length).unwrap_or(&[]);
            parse_v9(prefix, &mut cache).is_ok()
        })
        .collect();
    let accepted: Vec<usize> = results.iter().enumerate().filter(|(_, ok)| **ok).map(|(length, _)| length).collect();
    assert_eq!(accepted, vec![NUM_20_USIZE, first_set_end]);
    let ipfix_accepted = (0..ipfix.len())
        .filter(|length| {
            let mut cache = TemplateCache::default();
            parse_ipfix_default(ipfix.get(..*length).unwrap_or(&[]), &mut cache).is_ok()
        })
        .count();
    assert_eq!(ipfix_accepted, 0);
    Ok(())
}


#[test]
fn seeded_random_sets_never_panic() -> TestResult {
    let mut random = StdRng::seed_from_u64(FUZZ_SEED);
    let limits = FlowLimits {
        max_template_exporters: NUM_4,
        max_templates_per_exporter: NUM_4,
        ..FlowLimits::default()
    };
    let mut cache = TemplateCache::default();
    let handled = (0..FUZZ_ROUNDS)
        .map(|round| {
            let set_count = random.gen_range(1..=NUM_3);
            let mut sets: Vec<Vec<u8>> = (0..set_count)
                .map(|_| {
                    let body: Vec<u8> = (0..random.gen_range(0..=FUZZ_MAX_BODY)).map(|_| random.gen()).collect();
                    let set_id = match random.gen_range(0..NUM_4) {
                        0 => random.gen_range(0..=NUM_3_U16),
                        1 => random.gen(),
                        _ => TEMPLATE_ID,
                    };
                    set(set_id, &body)
                })
                .collect();
            if round % NUM_2 == 0 {
                sets.insert(0, set(0, &template_record(TEMPLATE_ID, &FULL_FIELDS)));
            }
            let peer = exporter(random.gen_range(0..NUM_8_U32));
            let first = parse_netflow_v9(&v9_datagram(DOMAIN, &sets), peer, &mut cache, round as u64, &limits);
            let second = parse_ipfix(&ipfix_datagram(DOMAIN, &sets), peer, &mut cache, round as u64, &limits);
            usize::from(first.is_ok() || first.is_err()) + usize::from(second.is_ok() || second.is_err())
        })
        .sum::<usize>();
    assert_eq!(handled, FUZZ_ROUNDS * NUM_2);
    assert!(cache.exporters.len() <= NUM_4);
    Ok(())
}


fn resident_kilobytes() -> Result<u64, Box<dyn std::error::Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:")).ok_or("no VmRSS")?;
    Ok(line.split_whitespace().nth(1).ok_or("no value")?.parse()?)
}


#[test]
fn a_flood_of_fake_exporters_stays_within_the_caps() -> TestResult {
    let limits = FlowLimits::default();
    let mut cache = TemplateCache::default();
    let define = v9_datagram(DOMAIN, &[set(0, &template_record(TEMPLATE_ID, &[(NUM_7_U16, NUM_2_U16)]))]);
    let data = v9_datagram(DOMAIN, &[set(TEMPLATE_ID, &word(1))]);
    let honest = exporter(0);
    parse_netflow_v9(&define, honest, &mut cache, NOW, &limits)?;
    let before = resident_kilobytes()?;
    (1..=FAKE_EXPORTERS).try_for_each(|peer_index| {
        parse_netflow_v9(&define, exporter(peer_index), &mut cache, NOW, &limits)?;
        if peer_index % HONEST_EVERY == 0 {
            parse_netflow_v9(&data, honest, &mut cache, NOW, &limits)?;
        }
        Ok::<(), FlowDrop>(())
    })?;
    let after = resident_kilobytes()?;
    assert!(after.saturating_sub(before) < RSS_GROWTH_LIMIT_KB);
    assert_eq!(cache.exporters.len(), limits.max_template_exporters);
    assert_eq!(cache.templates.len(), limits.max_template_exporters);
    assert!(cache.exporters.contains_key(&honest));
    assert_eq!(
        cache.stats.evicted_exporters,
        u64::from(FAKE_EXPORTERS) + 1 - limits.max_template_exporters as u64
    );
    Ok(())
}


#[test]
fn store_template_direct_and_helpers() -> TestResult {
    let mut cache = TemplateCache::default();
    let limits = FlowLimits::default();
    let key = TemplateKey {
        exporter: exporter(1),
        domain: 1,
        template_id: TEMPLATE_ID,
    };
    let template = Template {
        fields: Vec::new(),
        min_record_bytes: 1,
        refreshed_ms: 0,
    };
    store_template(&mut cache, key, template.clone(), &limits)?;
    store_template(&mut cache, key, template, &limits)?;
    assert_eq!(cache.templates.len(), 1);
    assert_eq!(unsigned(&[1, 0]), NUM_256_U64);
    assert_eq!(unsigned(&[]), 0);
    assert_eq!(
        address(&[1, NUM_2_U8, NUM_3_U8, NUM_4_U8]),
        Some(IpAddr::V4(Ipv4Addr::new(1, NUM_2_U8, NUM_3_U8, NUM_4_U8)))
    );
    assert_eq!(address(&[1, NUM_2_U8]), None);
    Ok(())
}


#[test]
fn limits_validation_and_drop_reasons() -> TestResult {
    assert!(validate_flow_limits(&FlowLimits::default()).is_ok());
    let broken = [
        FlowLimits {
            max_templates_per_exporter: 0,
            ..FlowLimits::default()
        },
        FlowLimits {
            max_template_exporters: NUM_4097,
            ..FlowLimits::default()
        },
        FlowLimits {
            max_fields_per_template: NUM_257,
            ..FlowLimits::default()
        },
        FlowLimits {
            max_record_bytes: 0,
            ..FlowLimits::default()
        },
        FlowLimits {
            max_template_age_seconds: NUM_86401_U64,
            ..FlowLimits::default()
        },
        FlowLimits {
            max_template_records_per_datagram: MAX_TEMPLATE_DATAGRAM_BYTES + 1,
            ..FlowLimits::default()
        },
    ];
    broken
        .iter()
        .for_each(|limits| assert_eq!(validate_flow_limits(limits), Err(ConfigError::BadFlowTemplateLimit)));
    assert_eq!(DropReason::from(FlowDrop::NoTemplate), DropReason::FlowNoTemplate);
    assert_eq!(DropReason::from(FlowDrop::TemplateRefused), DropReason::FlowTemplateRefused);
    let mut stats = ListenerStats::default();
    count_reason(&mut stats, DropReason::FlowNoTemplate);
    count_reason(&mut stats, DropReason::FlowTemplateRefused);
    assert_eq!(stats.dropped_parse, NUM_2_U64);
    assert!(!DropReason::FlowNoTemplate.to_string().is_empty());
    assert!(!FlowDrop::TemplateRefused.to_string().is_empty());
    assert!(!ConfigError::BadFlowTemplateLimit.to_string().is_empty());
    Ok(())
}


const V9_FIXTURE: &[u8] = include_bytes!("fixtures/netflow/v9-softflowd.bin");


const IPFIX_FIXTURE: &[u8] = include_bytes!("fixtures/netflow/ipfix-softflowd.bin");


const FIXTURE_RECORDS: usize = 8;


const FIXTURE_PACKETS: u64 = 36;


const FIXTURE_OCTETS: u64 = 3652;


#[test]
fn softflowd_v9_and_ipfix_goldens_decode_template_and_data() -> TestResult {
    let mut cache = TemplateCache::default();
    let v9 = parse_v9(V9_FIXTURE, &mut cache)?;
    assert_eq!(v9.records.len(), FIXTURE_RECORDS);
    assert_eq!(v9.records.iter().map(|flow| flow.packets).sum::<u64>(), FIXTURE_PACKETS);
    assert_eq!(v9.records.iter().map(|flow| flow.octets).sum::<u64>(), FIXTURE_OCTETS);
    assert!(v9.records.iter().any(|flow| flow.source.is_ipv6()));
    assert!(v9
        .records
        .iter()
        .any(|flow| flow.protocol == NUM_6_U8 && flow.destination_port == NUM_8099_U16));
    assert!(cache.templates.len() >= NUM_2);
    let mut ipfix_cache = TemplateCache::default();
    let ipfix = parse_ipfix_default(IPFIX_FIXTURE, &mut ipfix_cache)?;
    assert_eq!(ipfix.records.len(), FIXTURE_RECORDS);
    assert_eq!(ipfix.records.iter().map(|flow| flow.packets).sum::<u64>(), FIXTURE_PACKETS);
    assert_eq!(ipfix.records.iter().map(|flow| flow.octets).sum::<u64>(), FIXTURE_OCTETS);
    assert!(ipfix.records.iter().all(|flow| flow.start_unix_ms <= flow.end_unix_ms));
    Ok(())
}
