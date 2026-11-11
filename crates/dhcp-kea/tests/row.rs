#[path = "common/types.rs"]
mod types;


use core_export::ecs::to_json;
use dhcp_kea::error::{HeaderError, RowError};
use dhcp_kea::header::{parse_header, Family, MAX_COLUMNS};
use dhcp_kea::row::{convert_row, hostname_fields, normalise_mac, valid_hostname, HOSTNAME_RAW_LABEL, MAX_HOSTNAME_CHARS, MAX_LABEL_CHARS};
use serde_json::Value;
use types::TestResult;


const V4_24: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context";


const V4_26: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id";


const V4_SHUFFLED: &str = "state,hostname,expire,pool_id,subnet_id,valid_lifetime,address,extra,hwaddr";


const V6_26: &str = "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,hwtype,hwaddr_source,state,user_context,pool_id";


const ROW_24: &str = "192.168.1.10,aa:bb:cc:dd:ee:ff,01:aa:bb:cc:dd:ee:ff,3600,1700003600,7,0,0,pc1.example.,0,";


const ROW_26: &str = "192.168.1.10,aa:bb:cc:dd:ee:ff,01:aa:bb:cc:dd:ee:ff,3600,1700003600,7,0,0,pc1.example.,0,,3";


const ROW_SHUFFLED: &str = "0,pc1.example,1700003600,3,7,3600,192.168.1.10,x,aa:bb:cc:dd:ee:ff";


const ROW_V6: &str = "2001:db8::1,00:01:00:01:aa:bb,3600,1700003600,7,0,0,1,0,0,0,srv.example.,,0,0,0,,";


const ROW_24_START: i64 = 1_700_000_000;


const ROW_24_END: i64 = 1_700_003_600;


const SHUFFLED_COLUMNS: usize = 9;


const SHUFFLED_ADDRESS: usize = 6;


const V6_HWADDR: usize = 12;


const LAST_LABEL: usize = 61;


const LONG_HOST: usize = 10_000;


const BOGUS_COLUMNS: usize = 100_000;


const FAR_FUTURE: &str = "9000000000000000";


const HOST_PREFIX: &str = "192.168.1.10,aa:bb:cc:dd:ee:ff,01,3600,1700003600,7,0,0,";


const HOST_SUFFIX: &str = ",0,";


fn event_json(header: &str, row: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let columns = parse_header(header)?;
    let converted = convert_row(&columns, row)?;
    Ok(serde_json::from_str(&to_json(&converted.event)?)?)
}


fn at<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value.pointer(pointer).and_then(Value::as_str).unwrap_or("<absent>")
}


fn v4_row(host: &str) -> String {
    format!("{HOST_PREFIX}{host}{HOST_SUFFIX}")
}


fn failure(header: &str, row: &str) -> Result<String, Box<dyn std::error::Error>> {
    let columns = parse_header(header)?;
    Ok(convert_row(&columns, row).err().ok_or("the row was accepted")?.to_string())
}


#[test]
fn v4_row_of_kea_2_4_is_mapped() -> TestResult {
    let event = event_json(V4_24, ROW_24)?;
    assert_eq!(at(&event, "/source/ip"), "192.168.1.10");
    assert_eq!(at(&event, "/source/mac"), "AA-BB-CC-DD-EE-FF");
    assert_eq!(at(&event, "/host/hostname"), "pc1.example");
    assert_eq!(at(&event, "/event/start"), "2023-11-14T22:13:20Z");
    assert_eq!(at(&event, "/event/end"), "2023-11-14T23:13:20Z");
    assert_eq!(at(&event, "/@timestamp"), "2023-11-14T22:13:20Z");
    assert_eq!(at(&event, "/event/action"), "lease-assigned");
    assert_eq!(at(&event, "/event/module"), "kea");
    assert_eq!(at(&event, "/event/dataset"), "kea.lease");
    assert_eq!(at(&event, "/labels/subnet_id"), "7");
    assert!(event.pointer("/labels/duid").is_none() && event.pointer(&format!("/labels/{HOSTNAME_RAW_LABEL}")).is_none());
    Ok(())
}


#[test]
fn the_lease_key_is_ordered_by_creation_time_first() -> TestResult {
    let converted = convert_row(&parse_header(V4_24)?, ROW_24)?;
    assert_eq!(
        converted.key,
        (ROW_24_START, ROW_24_END, "192.168.1.10".to_string(), "AA-BB-CC-DD-EE-FF".to_string())
    );
    Ok(())
}


#[test]
fn pool_id_and_shuffled_columns_give_the_same_event() -> TestResult {
    let reference = event_json(V4_24, ROW_24)?;
    assert_eq!(event_json(V4_26, ROW_26)?, reference);
    assert_eq!(event_json(V4_SHUFFLED, ROW_SHUFFLED)?, reference);
    Ok(())
}


#[test]
fn v6_row_has_duid_and_no_mac() -> TestResult {
    let columns = parse_header(V6_26)?;
    assert_eq!(columns.family, Family::V6);
    let event = event_json(V6_26, ROW_V6)?;
    assert_eq!(at(&event, "/source/ip"), "2001:db8::1");
    assert!(event.pointer("/source/mac").is_none());
    assert_eq!(at(&event, "/labels/duid"), "00:01:00:01:aa:bb");
    assert_eq!(at(&event, "/host/hostname"), "srv.example");
    Ok(())
}


#[test]
fn v6_hwaddr_is_used_when_present_and_refused_when_bad() -> TestResult {
    let with_mac = ROW_V6.replace(",srv.example.,,", ",srv.example.,aa:bb:cc:dd:ee:ff,");
    assert_eq!(at(&event_json(V6_26, &with_mac)?, "/source/mac"), "AA-BB-CC-DD-EE-FF");
    let bad_mac = ROW_V6.replace(",srv.example.,,", ",srv.example.,zz,");
    assert_eq!(failure(V6_26, &bad_mac)?, RowError::Mac.to_string());
    let no_duid = ROW_V6.replace("00:01:00:01:aa:bb", "");
    assert!(event_json(V6_26, &no_duid)?.pointer("/labels/duid").is_none());
    Ok(())
}


#[test]
fn state_decides_the_action() -> TestResult {
    let actions = [
        ("0", "lease-assigned"),
        ("1", "lease-declined"),
        ("2", "lease-expired-reclaimed"),
        ("7", "lease-state-7"),
    ];
    actions.iter().try_for_each(|(state, action)| -> TestResult {
        let row = ROW_24.replace(",pc1.example.,0,", &format!(",pc1.example.,{state},"));
        assert_eq!(at(&event_json(V4_24, &row)?, "/event/action"), *action);
        Ok(())
    })
}


#[test]
fn rows_outside_the_grammar_are_refused_by_reason() -> TestResult {
    let cases = [
        (ROW_24.replace("192.168.1.10", "2001:db8::1"), "address"),
        (ROW_24.replace("192.168.1.10", "999.1.1.1"), "address"),
        (ROW_24.replace("aa:bb:cc:dd:ee:ff,01", "aa:bb:cc:dd:ee,01"), "hwaddr"),
        (ROW_24.replace("aa:bb:cc:dd:ee:ff,01", "aa:bb:cc:dd:ee:fg,01"), "hwaddr"),
        (ROW_24.replace("aa:bb:cc:dd:ee:ff,01", ",01"), "hwaddr"),
        (ROW_24.replace("aa:bb:cc:dd:ee:ff,01", "aaa:bb:cc:dd:ee:ff,01"), "hwaddr"),
        (ROW_24.replace("1700003600", "soon"), "expire"),
        (ROW_24.replace("1700003600", "99999999999999999999"), "expire"),
        (ROW_24.replace(",3600,", ",-1,"), "valid_lifetime"),
        (ROW_24.replace(",3600,", ",1700003601,"), "lifetime-range"),
        (ROW_24.replace("1700003600", FAR_FUTURE).replace(",3600,", ",1,"), "lifetime-range"),
        (
            ROW_24.replace("1700003600", FAR_FUTURE).replace(",3600,", ",8999999999999000,"),
            "lifetime-range",
        ),
        (ROW_24.replace(",7,", ",seven,"), "subnet_id"),
        (ROW_24.replace("example.,0,", "example.,x,"), "state"),
        ("192.168.1.10,aa:bb:cc:dd:ee:ff".to_string(), "column-count"),
        (format!("{ROW_24},extra"), "column-count"),
        (String::new(), "column-count"),
    ];
    cases.iter().try_for_each(|(row, reason)| -> TestResult {
        assert_eq!(failure(V4_24, row)?, *reason, "row {row}");
        Ok(())
    })
}


#[test]
fn hostnames_follow_the_dns_grammar() -> TestResult {
    let long_label = "a".repeat(MAX_LABEL_CHARS + 1);
    let max_name = format!(
        "{}.{}.{}.{}",
        "a".repeat(MAX_LABEL_CHARS),
        "b".repeat(MAX_LABEL_CHARS),
        "c".repeat(MAX_LABEL_CHARS),
        "d".repeat(LAST_LABEL)
    );
    assert_eq!(max_name.len(), MAX_HOSTNAME_CHARS);
    let too_long_name = format!("{max_name}.{}", "e".repeat(MAX_LABEL_CHARS));
    assert_eq!(valid_hostname("Pc_1.example."), Some("Pc_1.example".to_string()));
    assert_eq!(valid_hostname("my-host1"), Some("my-host1".to_string()));
    assert_eq!(valid_hostname(&max_name), Some(max_name.clone()));
    let refused = ["", ".", "-rf", "rf-", "a..b", "a b", "caf\u{e9}", &long_label, &too_long_name];
    assert!(refused.iter().all(|text| valid_hostname(text).is_none()));
    assert_eq!(hostname_fields(""), (None, None));
    assert_eq!(hostname_fields("pc1"), (Some("pc1".to_string()), None));
    Ok(())
}


#[test]
fn a_hostile_hostname_goes_to_a_cleaned_label() -> TestResult {
    let long = "h".repeat(LONG_HOST);
    let hostile = ["-rf", "nul\0byte", "ansi\u{1b}[31mred", "cr\rlf", "sep\u{2028}arator", long.as_str()];
    hostile.iter().try_for_each(|name| -> TestResult {
        let event = event_json(V4_24, &v4_row(name))?;
        let raw = event
            .pointer(&format!("/labels/{HOSTNAME_RAW_LABEL}"))
            .and_then(Value::as_str)
            .ok_or("no raw label")?
            .to_string();
        assert!(event.pointer("/host").is_none(), "no hostname for {name}");
        assert!(
            !raw.is_empty() && !raw.chars().any(|found| found.is_control() || found == '\u{2028}'),
            "label of {name}"
        );
        Ok(())
    })?;
    let long_event = event_json(V4_24, &v4_row(&long))?;
    let cut = long_event
        .pointer(&format!("/labels/{HOSTNAME_RAW_LABEL}"))
        .and_then(Value::as_str)
        .ok_or("no raw label")?;
    assert!(cut.ends_with(&format!("[cut, {LONG_HOST} chars]")));
    assert!(cut.len() < LONG_HOST);
    Ok(())
}


#[test]
fn mac_is_normalised_to_ecs_form() -> TestResult {
    assert_eq!(normalise_mac("aa:bb:cc:dd:ee:ff"), Some("AA-BB-CC-DD-EE-FF".to_string()));
    assert_eq!(normalise_mac("0a-1B-2c-3D-4e-5F"), Some("0A-1B-2C-3D-4E-5F".to_string()));
    assert_eq!(normalise_mac("aa:bb:cc:dd:ee:ff:00"), None);
    assert_eq!(normalise_mac(""), None);
    Ok(())
}


#[test]
fn the_header_decides_the_columns() -> TestResult {
    let columns = parse_header(V4_SHUFFLED)?;
    assert_eq!(
        (columns.family, columns.count, columns.address, columns.state),
        (Family::V4, SHUFFLED_COLUMNS, SHUFFLED_ADDRESS, 0)
    );
    assert_eq!(columns.duid, None);
    assert_eq!(parse_header(V6_26)?.hwaddr, Some(V6_HWADDR));
    Ok(())
}


#[test]
fn a_missing_required_column_is_named() -> TestResult {
    let required = ["address", "hwaddr", "expire", "valid_lifetime", "hostname", "state", "subnet_id"];
    required.iter().for_each(|name| {
        let header = V4_24.split(',').filter(|column| column != name).collect::<Vec<&str>>().join(",");
        let message = parse_header(&header).err().map(|error| error.to_string());
        assert!(message.is_some_and(|text| text.contains(&format!("`{name}`"))), "{name}");
    });
    let v6_without_duid_and_hwaddr = V6_26.replace("duid,", "").replace("hwaddr,", "");
    assert!(matches!(parse_header(&v6_without_duid_and_hwaddr), Err(HeaderError::Missing("hwaddr"))));
    Ok(())
}


#[test]
fn a_repeated_column_or_too_many_columns_refuse_the_file() -> TestResult {
    assert!(matches!(
        parse_header(&format!("{V4_24},address")),
        Err(HeaderError::Duplicate("address"))
    ));
    assert!(matches!(parse_header(&format!("{V6_26},duid")), Err(HeaderError::Duplicate("duid"))));
    assert!(matches!(parse_header(&format!("{V6_26},hwaddr")), Err(HeaderError::Duplicate("hwaddr"))));
    let many = vec!["x"; BOGUS_COLUMNS].join(",");
    assert!(matches!(parse_header(&many), Err(HeaderError::TooManyColumns { max }) if max == MAX_COLUMNS));
    let at_cap = format!("{V4_24},{}", vec!["x"; MAX_COLUMNS - V4_24.split(',').count()].join(","));
    assert!(parse_header(&at_cap).is_ok());
    Ok(())
}


#[test]
fn a_v6_file_without_a_hwaddr_column_has_no_mac() -> TestResult {
    let header = V6_26.replace("hwaddr,", "");
    let row = ROW_V6.replace(",srv.example.,,", ",srv.example.,");
    let event = event_json(&header, &row)?;
    assert!(event.pointer("/source/mac").is_none());
    assert_eq!(at(&event, "/source/ip"), "2001:db8::1");
    Ok(())
}
