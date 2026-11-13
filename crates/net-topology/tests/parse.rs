#[path = "common/reader.rs"]
mod reader;
#[path = "common/types.rs"]
mod types;


use net_topology::error::ParseError;
use net_topology::limits::Limits;
use net_topology::lldp::{normal_mac, parse_buffer, parse_lldpd};
use net_topology::model::{IdSubtype, NeighbourId, Parsed};
use reader::FailingReader;
use types::TestResult;


const NOW: i64 = 1_700_000_000;


const HOST: &str = "server";


const MAC_ID: &str = r#"[{"type":"mac","value":"52:54:00:AA:BB:CC"}]"#;


const NAME_LIST: &str = r#"[{"value":"switch-1"}]"#;


const LONG_TEXT_BYTES: usize = 10_000;


const NEST_DEPTH: usize = 200;


const FLOOD: usize = 100_000;


const WIDE_INTERFACES: usize = 1_000;


const WIDE_NEIGHBOURS: usize = 100;


const SMALL_LIMIT: u64 = 8;


const CAPABILITY_FLOOD: usize = 17;


const GOOD_NEIGHBOURS: usize = 2;


const SMALL_COUNT: usize = 2;


fn chassis_with(id: &str, name: &str, capability: &str) -> String {
    format!(r#"{{"id":{id},"name":{name},"capability":{capability}}}"#)
}


fn port_with(id: &str) -> String {
    format!(r#"{{"id":{id}}}"#)
}


fn document(local: &str, chassis: &str, port: &str) -> String {
    format!(r#"{{"lldp":[{{"interface":[{{"name":{local},"chassis":[{chassis}],"port":[{port}]}}]}}]}}"#)
}


fn good_document() -> String {
    document(r#""eth0""#, &chassis_with(MAC_ID, NAME_LIST, "[]"), &port_with(MAC_ID))
}


fn parse_text(text: &str) -> Result<Parsed, ParseError> {
    parse_lldpd(text.as_bytes(), HOST, NOW, &Limits::default())
}


fn parse_limited(text: &str, limits: &Limits) -> Result<Parsed, ParseError> {
    parse_lldpd(text.as_bytes(), HOST, NOW, limits)
}


fn mac(value: &str) -> NeighbourId {
    NeighbourId {
        subtype: IdSubtype::Mac,
        value: value.to_owned(),
    }
}


fn skip_counts(parsed: &Parsed) -> (usize, usize, usize) {
    (parsed.observations.len(), parsed.skipped.unparsable, parsed.skipped.bad_field)
}


#[test]
fn a_neighbour_becomes_an_observation_with_a_normalised_mac() -> TestResult {
    let parsed = parse_text(&good_document())?;
    let observation = parsed.observations.first().ok_or("no observation")?;
    assert_eq!(parsed.observations.len(), 1);
    assert_eq!(observation.local_host, HOST);
    assert_eq!(observation.local_port, "eth0");
    assert_eq!(observation.remote_chassis, mac("52:54:00:aa:bb:cc"));
    assert_eq!(observation.remote_port, mac("52:54:00:aa:bb:cc"));
    assert_eq!(observation.remote_name.as_deref(), Some("switch-1"));
    assert_eq!(observation.seen, NOW);
    assert_eq!(skip_counts(&parsed), (1, 0, 0));
    Ok(())
}


#[test]
fn every_id_subtype_is_read() -> TestResult {
    let cases = [
        (r#"[{"type":"ip","value":"192.168.0.1"}]"#, IdSubtype::Ip, "192.168.0.1"),
        (r#"[{"type":"ip","value":"FE80:0:0:0:0:0:0:1"}]"#, IdSubtype::Ip, "fe80::1"),
        (r#"[{"type":"ifname","value":"Gi0/1"}]"#, IdSubtype::IfName, "Gi0/1"),
        (r#"[{"type":"ifalias","value":"uplink"}]"#, IdSubtype::IfAlias, "uplink"),
        (r#"[{"type":"local","value":"7"}]"#, IdSubtype::Local, "7"),
        (r#"[{"type":"chassis","value":"stack-1"}]"#, IdSubtype::Chassis, "stack-1"),
        (r#"[{"type":"port","value":"p1"}]"#, IdSubtype::Port, "p1"),
    ];
    cases.iter().try_for_each(|(id, subtype, value)| -> TestResult {
        let parsed = parse_text(&document(r#""eth0""#, &chassis_with(id, "[]", "[]"), &port_with(id)))?;
        let observation = parsed.observations.first().ok_or("no observation")?;
        assert_eq!(observation.remote_chassis.subtype, *subtype);
        assert_eq!(observation.remote_chassis.value, *value);
        assert_eq!(observation.remote_name, None);
        assert_eq!(skip_counts(&parsed), (1, 0, 0));
        Ok(())
    })
}


#[test]
fn an_empty_report_has_no_observation() -> TestResult {
    ["{\"lldp\":[{}]}", "{\"lldp\":[]}", "{\"lldp\":[{\"interface\":[]}]}"]
        .iter()
        .try_for_each(|text| -> TestResult {
            assert_eq!(skip_counts(&parse_text(text)?), (0, 0, 0));
            Ok(())
        })
}


#[test]
fn an_unreadable_source_is_a_read_error() -> TestResult {
    let outcome = parse_lldpd(FailingReader, HOST, NOW, &Limits::default());
    assert!(matches!(outcome, Err(ParseError::Read(_))));
    Ok(())
}


#[test]
fn a_report_above_the_byte_cap_is_refused_and_one_at_the_cap_is_read() -> TestResult {
    let text = "{\"lldp\":[]}";
    let at_cap = Limits {
        max_bytes: u64::try_from(text.len())?,
        ..Limits::default()
    };
    assert!(parse_limited(text, &at_cap).is_ok());
    let below = Limits {
        max_bytes: SMALL_LIMIT,
        ..Limits::default()
    };
    assert!(matches!(parse_limited(text, &below), Err(ParseError::TooLarge { max: SMALL_LIMIT })));
    Ok(())
}


#[test]
fn a_hostile_local_host_name_is_refused_before_reading() -> TestResult {
    let cases = ["", "-host", "ho\nst", "ho\u{202e}st"];
    cases.iter().for_each(|host| {
        assert!(matches!(
            parse_lldpd(FailingReader, host, NOW, &Limits::default()),
            Err(ParseError::InvalidHost)
        ))
    });
    Ok(())
}


#[test]
fn a_buffer_with_a_hostile_host_is_refused() -> TestResult {
    let outcome = parse_buffer(b"{}", "-host", NOW, &Limits::default());
    assert!(matches!(outcome, Err(ParseError::InvalidHost)));
    Ok(())
}


#[test]
fn malformed_documents_are_refused_without_echoing_input() -> TestResult {
    let cases = [
        "not json".to_owned(),
        "{\"lldp\":[{\"interface\":\"SECRET\"}]}".to_owned(),
        "{\"lldp\":{\"interface\":{}}}".to_owned(),
        "{\"lldp\":[5]}".to_owned(),
        "{}".to_owned(),
    ];
    cases.iter().try_for_each(|text| -> TestResult {
        let error = parse_text(text).err().ok_or("accepted")?;
        let shown = error.to_string();
        assert!(matches!(error, ParseError::Malformed { .. }), "{shown}");
        assert!(!shown.contains("SECRET"));
        Ok(())
    })
}


#[test]
fn deep_nesting_yields_no_neighbour_and_no_overflow() -> TestResult {
    let nest = format!("{}{}", "[".repeat(NEST_DEPTH), "]".repeat(NEST_DEPTH));
    let documents = [
        format!("{{\"lldp\":{nest}}}"),
        nest.clone(),
        format!("{{\"lldp\":[{{\"interface\":[{nest}]}}]}}"),
        format!("{{\"lldp\":[{{\"interface\":[{{\"name\":\"eth0\",\"chassis\":[{nest}],\"port\":[{nest}]}}]}}]}}"),
        document(r#""eth0""#, &chassis_with(&nest, &nest, &nest), &port_with(&nest)),
    ];
    documents.iter().try_for_each(|text| -> TestResult {
        match parse_text(text) {
            Ok(parsed) => assert_eq!((parsed.observations.len(), parsed.skipped.unparsable + parsed.skipped.bad_field), (0, 1)),
            Err(error) => assert!(matches!(error, ParseError::Malformed { .. })),
        }
        Ok(())
    })
}


#[test]
fn the_single_object_json_form_is_refused_as_malformed() -> TestResult {
    let plain = include_bytes!("fixtures/lldpd-json.json");
    let error = parse_lldpd(plain.as_slice(), HOST, NOW, &Limits::default()).err().ok_or("accepted")?;
    assert!(matches!(error, ParseError::Malformed { .. }));
    Ok(())
}


#[test]
fn the_live_json0_fixture_is_one_link_to_the_client() -> TestResult {
    let live = include_bytes!("fixtures/lldpd-json0.json");
    let parsed = parse_lldpd(live.as_slice(), HOST, NOW, &Limits::default())?;
    let observation = parsed.observations.first().ok_or("no observation")?;
    assert_eq!(skip_counts(&parsed), (1, 0, 0));
    assert_eq!(observation.local_port, "vx0");
    assert_eq!(observation.remote_chassis, mac("52:54:00:a6:c9:ce"));
    assert_eq!(observation.remote_port, mac("b2:c8:e3:64:f6:ff"));
    assert_eq!(observation.remote_name.as_deref(), Some("client"));
    Ok(())
}


#[test]
fn counts_above_a_cap_refuse_the_whole_report() -> TestResult {
    let two_blocks = "{\"lldp\":[{},{}]}";
    assert!(matches!(
        parse_text(two_blocks),
        Err(ParseError::TooMany {
            list: "lldp",
            count: SMALL_COUNT,
            ..
        })
    ));
    let small = Limits {
        max_interfaces: 1,
        max_neighbours_per_interface: 1,
        ..Limits::default()
    };
    let two_interfaces = "{\"lldp\":[{\"interface\":[{},{}]}]}";
    assert!(matches!(
        parse_limited(two_interfaces, &small),
        Err(ParseError::TooMany {
            list: "interface",
            count: SMALL_COUNT,
            max: 1
        })
    ));
    let two_chassis = "{\"lldp\":[{\"interface\":[{\"chassis\":[{},{}],\"port\":[{}]}]}]}";
    assert!(matches!(
        parse_limited(two_chassis, &small),
        Err(ParseError::TooMany { list: "chassis", .. })
    ));
    let two_ports = "{\"lldp\":[{\"interface\":[{\"chassis\":[{}],\"port\":[{},{}]}]}]}";
    assert!(matches!(parse_limited(two_ports, &small), Err(ParseError::TooMany { list: "port", .. })));
    Ok(())
}


#[test]
fn a_flood_of_neighbours_and_a_wide_report_are_refused() -> TestResult {
    let empty = vec!["{}"; FLOOD].join(",");
    let flood = format!("{{\"lldp\":[{{\"interface\":[{{\"name\":\"eth0\",\"chassis\":[{empty}],\"port\":[{empty}]}}]}}]}}");
    assert!(matches!(
        parse_text(&flood),
        Err(ParseError::TooMany {
            list: "chassis",
            count: FLOOD,
            ..
        })
    ));
    let neighbours = vec!["{}"; WIDE_NEIGHBOURS].join(",");
    let interface = format!("{{\"name\":\"eth0\",\"chassis\":[{neighbours}],\"port\":[{neighbours}]}}");
    let wide = format!("{{\"lldp\":[{{\"interface\":[{}]}}]}}", vec![interface; WIDE_INTERFACES].join(","));
    assert!(matches!(
        parse_text(&wide),
        Err(ParseError::TooMany {
            list: "interface",
            count: WIDE_INTERFACES,
            ..
        })
    ));
    let within = format!("{{\"lldp\":[{{\"interface\":[{{\"name\":\"eth0\",\"chassis\":[{neighbours}],\"port\":[{neighbours}]}}]}}]}}");
    assert!(matches!(
        parse_text(&within),
        Err(ParseError::TooMany {
            list: "chassis",
            count: WIDE_NEIGHBOURS,
            ..
        })
    ));
    Ok(())
}


#[test]
fn structural_damage_inside_an_interface_skips_it_and_counts() -> TestResult {
    let cases = [
        "{\"lldp\":[{\"interface\":[5]}]}",
        "{\"lldp\":[{\"interface\":[{\"chassis\":\"x\",\"port\":[]}]}]}",
        "{\"lldp\":[{\"interface\":[{\"chassis\":[],\"port\":{}}]}]}",
        "{\"lldp\":[{\"interface\":[{\"chassis\":[{}],\"port\":[]}]}]}",
    ];
    cases.iter().try_for_each(|text| -> TestResult {
        assert_eq!(skip_counts(&parse_text(text)?), (0, 1, 0));
        Ok(())
    })
}


#[test]
fn a_malformed_neighbour_is_counted_and_never_fails_the_document() -> TestResult {
    let long = "x".repeat(LONG_TEXT_BYTES);
    let capabilities = format!("[{}]", vec!["{}"; CAPABILITY_FLOOD].join(","));
    let good_chassis = chassis_with(MAC_ID, NAME_LIST, "[]");
    let good_port = port_with(MAC_ID);
    let bad_cases: Vec<(String, (usize, usize, usize))> = vec![
        (document(r#""eth0""#, "5", &good_port), (0, 1, 0)),
        (document(r#""eth0""#, &good_chassis, "5"), (0, 1, 0)),
        (document(r#""eth0""#, &chassis_with(MAC_ID, NAME_LIST, "{}"), &good_port), (0, 0, 1)),
        (
            document(r#""eth0""#, &chassis_with(MAC_ID, NAME_LIST, &capabilities), &good_port),
            (0, 0, 1),
        ),
        (document("null", &good_chassis, &good_port), (0, 0, 1)),
        (document(r#""et\nh0""#, &good_chassis, &good_port), (0, 0, 1)),
        (document(&format!("\"{long}\""), &good_chassis, &good_port), (0, 0, 1)),
        (
            document(
                r#""eth0""#,
                &chassis_with(r#"[{"type":"mac","value":"zz:54:00:aa:bb:cc"}]"#, NAME_LIST, "[]"),
                &good_port,
            ),
            (0, 0, 1),
        ),
        (
            document(
                r#""eth0""#,
                &chassis_with(r#"[{"type":"mac","value":"52-54-00-aa-bb-cc"}]"#, NAME_LIST, "[]"),
                &good_port,
            ),
            (0, 0, 1),
        ),
        (
            document(
                r#""eth0""#,
                &chassis_with(r#"[{"type":"mac","value":"52:54:00:aa:bb"}]"#, NAME_LIST, "[]"),
                &good_port,
            ),
            (0, 0, 1),
        ),
        (
            document(
                r#""eth0""#,
                &chassis_with(r#"[{"type":"ip","value":"300.1.1.1"}]"#, NAME_LIST, "[]"),
                &good_port,
            ),
            (0, 0, 1),
        ),
        (
            document(
                r#""eth0""#,
                &good_chassis,
                &port_with(&format!(r#"[{{"type":"ifname","value":"{long}"}}]"#)),
            ),
            (0, 0, 1),
        ),
        (
            document(r#""eth0""#, &good_chassis, &port_with(r#"[{"type":"ifname","value":"-rf"}]"#)),
            (0, 0, 1),
        ),
        (
            document(r#""eth0""#, &good_chassis, &port_with(r#"[{"type":"ifname","value":""}]"#)),
            (0, 0, 1),
        ),
        (
            document(r#""eth0""#, &good_chassis, &port_with(r#"[{"type":"bogus","value":"x"}]"#)),
            (0, 0, 1),
        ),
        (document(r#""eth0""#, &good_chassis, &port_with(r#"[{"value":"x"}]"#)), (0, 0, 1)),
        (document(r#""eth0""#, &good_chassis, &port_with(r#"[{"type":"ifname"}]"#)), (0, 0, 1)),
        (document(r#""eth0""#, &good_chassis, &port_with(r#"[5]"#)), (0, 1, 0)),
        (document(r#""eth0""#, &good_chassis, &port_with("[]")), (0, 0, 1)),
        (document(r#""eth0""#, &good_chassis, &port_with("{}")), (0, 0, 1)),
        (document(r#""eth0""#, &good_chassis, "{}"), (0, 0, 1)),
        (
            document(r#""eth0""#, &chassis_with(MAC_ID, r#"[{"value":"a\u202eb"}]"#, "[]"), &good_port),
            (0, 0, 1),
        ),
        (
            document(r#""eth0""#, &chassis_with(MAC_ID, r#"[{"value":"a\nb"}]"#, "[]"), &good_port),
            (0, 0, 1),
        ),
        (document(r#""eth0""#, &chassis_with(MAC_ID, r#"[{}]"#, "[]"), &good_port), (0, 0, 1)),
        (document(r#""eth0""#, &chassis_with(MAC_ID, r#"[5]"#, "[]"), &good_port), (0, 1, 0)),
        (
            document(r#""eth0""#, &chassis_with(MAC_ID, r#"[{"value":"a"},{"value":"b"}]"#, "[]"), &good_port),
            (0, 0, 1),
        ),
        (document(r#""eth0""#, &chassis_with(MAC_ID, "{}", "[]"), &good_port), (0, 0, 1)),
    ];
    bad_cases.iter().try_for_each(|(text, expected)| -> TestResult {
        let parsed = parse_text(text)?;
        assert_eq!(skip_counts(&parsed), *expected, "{text}");
        Ok(())
    })
}


#[test]
fn a_bad_neighbour_does_not_hide_a_good_one() -> TestResult {
    let good = format!("{{\"id\":{MAC_ID},\"name\":{NAME_LIST}}}");
    let bad = "5";
    let chassis = format!("{good},{bad},{good}");
    let ports = format!("{{\"id\":{MAC_ID}}},{{\"id\":{MAC_ID}}},{{\"id\":{MAC_ID}}}");
    let text = format!("{{\"lldp\":[{{\"interface\":[{{\"name\":\"eth0\",\"chassis\":[{chassis}],\"port\":[{ports}]}}]}}]}}");
    assert_eq!(skip_counts(&parse_text(&text)?), (GOOD_NEIGHBOURS, 1, 0));
    Ok(())
}


#[test]
fn mac_text_is_lowercased_and_checked() -> TestResult {
    assert_eq!(normal_mac("AA:bb:00:11:22:3F").as_deref(), Some("aa:bb:00:11:22:3f"));
    assert_eq!(normal_mac("aa:bb:00:11:22"), None);
    assert_eq!(normal_mac("a:bbb:cc:dd:ee:ff"), None);
    assert_eq!(normal_mac("aa:bb:00:11:22:3g"), None);
    assert_eq!(normal_mac("aabb.0011.223f.."), None);
    Ok(())
}
