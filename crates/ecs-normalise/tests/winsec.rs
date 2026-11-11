#[path = "common/types.rs"]
mod types;


use core_export::ecs::{to_json, EcsEvent};
use ecs_normalise::cli::run_reporting;
use ecs_normalise::error::{NormaliseError, WinSecError};
use ecs_normalise::stream::{normalise_stream_format, Counts, Format};
use ecs_normalise::sysmon_input::{MAX_EVENT_BYTES, MAX_FIELDS};
use ecs_normalise::winsec::{normalise_security, WIN_KINDS};
use serde_json::Value;
use sigma_sql::compile::{compile_rule, SqlOptions};
use sigma_sql::mapping::parse_mapping;
use std::error::Error;
use std::process::ExitCode;
use types::TestResult;


const CASES: [(&str, &str); 16] = [
    (include_str!("fixtures/winsec_4624.xml"), include_str!("snapshots/winsec_4624.json")),
    (
        include_str!("fixtures/winsec_4624_dash.xml"),
        include_str!("snapshots/winsec_4624_dash.json"),
    ),
    (
        include_str!("fixtures/winsec_4624_ipv6.xml"),
        include_str!("snapshots/winsec_4624_ipv6.json"),
    ),
    (include_str!("fixtures/winsec_4625.xml"), include_str!("snapshots/winsec_4625.json")),
    (include_str!("fixtures/winsec_4634.xml"), include_str!("snapshots/winsec_4634.json")),
    (include_str!("fixtures/winsec_4647.xml"), include_str!("snapshots/winsec_4647.json")),
    (include_str!("fixtures/winsec_4648.xml"), include_str!("snapshots/winsec_4648.json")),
    (include_str!("fixtures/winsec_4672.xml"), include_str!("snapshots/winsec_4672.json")),
    (include_str!("fixtures/winsec_4720.xml"), include_str!("snapshots/winsec_4720.json")),
    (include_str!("fixtures/winsec_4726.xml"), include_str!("snapshots/winsec_4726.json")),
    (include_str!("fixtures/winsec_4740.xml"), include_str!("snapshots/winsec_4740.json")),
    (include_str!("fixtures/winsec_4768.xml"), include_str!("snapshots/winsec_4768.json")),
    (include_str!("fixtures/winsec_4769.xml"), include_str!("snapshots/winsec_4769.json")),
    (include_str!("fixtures/winsec_4771.xml"), include_str!("snapshots/winsec_4771.json")),
    (include_str!("fixtures/winsec_4776.xml"), include_str!("snapshots/winsec_4776.json")),
    (include_str!("fixtures/winsec_json.json"), include_str!("snapshots/winsec_json.json")),
];


const FAILED_4625: &str = include_str!("fixtures/winsec_4625.xml");


const UNKNOWN: &str = include_str!("fixtures/winsec_9999.xml");


const OK_4776: &str = include_str!("fixtures/winsec_4776_ok.xml");


const MAPPING: &str = include_str!("rules/winsec_mapping.yaml");


const RULE: &str = include_str!("rules/windows_failed_logon.yml");


const PROVIDER: &str = "Microsoft-Windows-Security-Auditing";


const LONG_NAME: usize = 10_000;


const MEDIUM_NAME: usize = 1_000;


const SHOWN: usize = 256;


const REPEATS: usize = 1_000;


const PROCESSED: u64 = 2;


const TWO: u64 = 2;


const PAIR: usize = 2;


const UNKNOWN_ID: u32 = 9999;


fn render(provider: &str, channel: &str, id: &str, data: &str) -> String {
    format!(
        "<Event><System><Provider Name=\"{provider}\"/><EventID>{id}</EventID><TimeCreated SystemTime=\"2026-11-03T10:00:00Z\"/>\
         <Channel>{channel}</Channel><Computer>H</Computer></System><EventData>{data}</EventData></Event>"
    )
}


fn security(id: &str, data: &str) -> String {
    render(PROVIDER, "Security", id, data)
}


fn json_of(text: &str) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(&to_json(&normalise_security(text)?)?)?)
}


fn error_of(text: &str) -> Result<WinSecError, Box<dyn Error>> {
    match normalise_security(text) {
        Ok(_) => Err(format!("expected an error for {text}").into()),
        Err(error) => Ok(error),
    }
}


fn text_at(event: &Value, pointer: &str) -> Option<String> {
    event.pointer(pointer).and_then(Value::as_str).map(String::from)
}


#[test]
fn every_event_id_matches_its_snapshot() -> TestResult {
    CASES.iter().try_for_each(|(fixture, snapshot)| {
        let json = format!("{}\n", to_json(&normalise_security(fixture)?)?);
        assert_eq!(&json, snapshot);
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn every_mapped_id_has_a_fixture() -> TestResult {
    let codes: Vec<Option<String>> = CASES
        .iter()
        .map(|(fixture, _)| json_of(fixture).map(|event| text_at(&event, "/event/code")))
        .collect::<Result<_, _>>()?;
    assert!(WIN_KINDS.iter().all(|kind| codes.contains(&Some(kind.id.to_string()))));
    Ok(())
}


#[test]
fn outcome_category_and_type_follow_the_table() -> TestResult {
    let failed = json_of(FAILED_4625)?;
    assert_eq!(text_at(&failed, "/event/outcome").as_deref(), Some("failure"));
    assert_eq!(text_at(&failed, "/labels/failure_status").as_deref(), Some("0xC000006D"));
    assert_eq!(text_at(&failed, "/labels/sub_status").as_deref(), Some("0xC000006A"));
    assert_eq!(text_at(&failed, "/labels/logon_type").as_deref(), Some("3"));
    let created = json_of(&security("4720", r#"<Data Name="TargetUserName">n</Data>"#))?;
    assert_eq!(created.pointer("/event/category"), Some(&serde_json::json!(["authentication", "iam"])));
    assert_eq!(text_at(&created, "/event/type/0").as_deref(), Some("creation"));
    let ntlm_ok = json_of(OK_4776)?;
    assert_eq!(text_at(&ntlm_ok, "/event/outcome").as_deref(), Some("success"));
    assert!(ntlm_ok.pointer("/labels/failure_status").is_none());
    let no_status = json_of(&security("4768", r#"<Data Name="TargetUserName">n</Data>"#))?;
    assert!(no_status.pointer("/event/outcome").is_none());
    let kerberos = json_of(&security("4771", r#"<Data Name="Status">0x18</Data>"#))?;
    assert_eq!(text_at(&kerberos, "/event/outcome").as_deref(), Some("failure"));
    assert_eq!(text_at(&kerberos, "/event/provider").as_deref(), Some(PROVIDER));
    Ok(())
}


#[test]
fn source_addresses_are_parsed_never_copied() -> TestResult {
    let dash = json_of(&security("4624", r#"<Data Name="IpAddress">-</Data><Data Name="IpPort">-</Data>"#))?;
    assert!(dash.pointer("/source").is_none());
    let hostile = "1.2.3.4; rm -rf";
    let injected = json_of(&security(
        "4624",
        &format!(r#"<Data Name="IpAddress">{hostile}</Data><Data Name="IpPort">80; x</Data>"#),
    ))?;
    assert!(injected.pointer("/source").is_none());
    assert!(!serde_json::to_string(&injected)?.contains("rm -rf"));
    let mapped = json_of(&security("4624", r#"<Data Name="IpAddress">::ffff:1.2.3.4</Data>"#))?;
    assert!(mapped.pointer("/source/ip").is_some());
    let loopback = json_of(&security("4624", r#"<Data Name="IpAddress">::1</Data>"#))?;
    assert_eq!(text_at(&loopback, "/source/ip").as_deref(), Some("::1"));
    Ok(())
}


#[test]
fn hostile_user_names_are_cleaned_and_cut_visibly() -> TestResult {
    let name = format!("a\nb\u{202E}c{}", "x".repeat(MEDIUM_NAME));
    let event = json_of(&security("4624", &format!(r#"<Data Name="TargetUserName">{name}</Data>"#)))?;
    let shown = text_at(&event, "/user/name").ok_or("no user.name")?;
    assert!(!shown.contains('\n') && !shown.contains('\u{202E}'));
    assert!(shown.contains('\u{FFFD}'));
    assert!(shown.ends_with("[cut, 1005 chars]"));
    assert_eq!(shown.chars().count(), SHOWN + "[cut, 1005 chars]".chars().count());
    let padded = json_of(&security("4624", r#"<Data Name="TargetUserName">admin </Data>"#))?;
    assert_ne!(text_at(&padded, "/user/name").as_deref(), Some("admin"));
    let huge = format!(r#"<Data Name="TargetUserName">{}</Data>"#, "y".repeat(LONG_NAME));
    assert!(matches!(error_of(&security("4624", &huge))?, WinSecError::Event(_)));
    Ok(())
}


#[test]
fn only_the_security_auditing_provider_on_the_security_channel_is_accepted() -> TestResult {
    let sysmon = render("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", "4624", "");
    assert!(matches!(error_of(&sysmon)?, WinSecError::Provider(_)));
    let other = render("Evil\nProvider", "Security", "4624", "");
    assert!(matches!(error_of(&other)?, WinSecError::Provider(_)));
    assert!(matches!(error_of(&render(PROVIDER, "System", "4624", ""))?, WinSecError::Channel(_)));
    let bare = "<Event><System><EventID>4624</EventID></System><EventData></EventData></Event>";
    assert!(matches!(error_of(bare)?, WinSecError::Provider(_)));
    let no_channel = format!(r#"<Event><System><Provider Name="{PROVIDER}"/><EventID>4624</EventID></System><EventData/></Event>"#);
    assert!(matches!(error_of(&no_channel)?, WinSecError::Channel(_)));
    let plain = r#"{"System":{"Provider":"Microsoft-Windows-Sysmon","EventID":4624,"Channel":"Security"},"EventData":{}}"#;
    assert!(matches!(error_of(plain)?, WinSecError::Provider(_)));
    let plain_ok = format!(
        r#"{{"System":{{"Provider":"{PROVIDER}","EventID":4624,"Channel":"Security","TimeCreated":{{"SystemTime":"2026-11-03T10:00:00Z"}}}},"EventData":{{}}}}"#
    );
    assert!(normalise_security(&plain_ok).is_ok());
    Ok(())
}


#[test]
fn limits_and_hostile_xml_are_refused_or_inert() -> TestResult {
    let big = "x".repeat(MAX_EVENT_BYTES + 1);
    assert!(matches!(error_of(&big)?, WinSecError::Event(_)));
    let distinct: String = (0..=MAX_FIELDS).map(|index| format!(r#"<Data Name="f{index}">v</Data>"#)).collect();
    assert!(matches!(error_of(&security("4624", &distinct))?, WinSecError::Event(_)));
    let repeated = r#"<Data Name="TargetUserName">r</Data>"#.repeat(REPEATS);
    assert_eq!(text_at(&json_of(&security("4624", &repeated))?, "/user/name").as_deref(), Some("r"));
    let entity = format!(
        "<!DOCTYPE e [<!ENTITY boom \"BOOM\">]>{}",
        security("4624", r#"<Data Name="TargetUserName">&boom;</Data>"#)
    );
    assert!(matches!(error_of(&entity)?, WinSecError::Event(_)));
    let doctype = format!(
        "<!DOCTYPE e [<!ENTITY boom \"BOOM\">]>{}",
        security("4624", r#"<Data Name="TargetUserName">n</Data>"#)
    );
    assert_eq!(text_at(&json_of(&doctype)?, "/user/name").as_deref(), Some("n"));
    Ok(())
}


#[test]
fn numbers_and_statuses_follow_their_grammar() -> TestResult {
    let big = json_of(&security("4624", r#"<Data Name="LogonType">99999999999999999999</Data>"#))?;
    assert!(big.pointer("/labels/logon_type").is_none());
    let statuses = ["0x", "0x123456789", "0xZZ", "nothex", "0x+1"];
    statuses.iter().try_for_each(|status| {
        let event = json_of(&security(
            "4625",
            &format!(r#"<Data Name="Status">{status}</Data><Data Name="SubStatus">{status}</Data>"#),
        ))?;
        assert!(event.pointer("/labels/failure_status").is_none());
        assert!(event.pointer("/labels/sub_status").is_none());
        Ok::<(), Box<dyn Error>>(())
    })?;
    let upper = json_of(&security("4776", r#"<Data Name="Status">0X1F</Data>"#))?;
    assert_eq!(text_at(&upper, "/event/outcome").as_deref(), Some("failure"));
    Ok(())
}


#[test]
fn identity_and_time_details() -> TestResult {
    let blank = json_of(&security("4624", r#"<Data Name="TargetUserName"></Data>"#))?;
    assert!(blank.pointer("/user").is_none());
    let nameless = json_of(&security("4624", r#"<Data Name="TargetUserName">-</Data>"#))?;
    assert!(nameless.pointer("/user").is_none());
    let no_host = "<Event><System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/><EventID>4634</EventID>\
        <TimeCreated SystemTime=\"2026-11-03T10:00:00Z\"/><Channel>Security</Channel><Computer></Computer></System><EventData/></Event>";
    assert!(json_of(no_host)?.pointer("/host/name").is_none());
    let no_time = no_host.replace("<TimeCreated SystemTime=\"2026-11-03T10:00:00Z\"/>", "");
    assert!(matches!(error_of(&no_time)?, WinSecError::Event(_)));
    let bad_time = no_host.replace("2026-11-03T10:00:00Z", "yesterday");
    assert!(matches!(error_of(&bad_time)?, WinSecError::Event(_)));
    assert!(matches!(error_of(UNKNOWN)?, WinSecError::Unknown(UNKNOWN_ID)));
    assert!(error_of(UNKNOWN)?.to_string().contains("9999"));
    assert!(error_of("")?.to_string().starts_with("invalid event"));
    Ok(())
}


#[test]
fn a_sigma_rule_for_failed_logons_matches_the_normalised_event() -> TestResult {
    let mapping = parse_mapping(MAPPING)?;
    let sql = compile_rule(RULE, &mapping, &SqlOptions::default())?;
    let event: EcsEvent = normalise_security(FAILED_4625)?;
    let json: Value = serde_json::from_str(&to_json(&event)?)?;
    assert_eq!(text_at(&json, "/event/category/0").as_deref(), Some("authentication"));
    assert_eq!(text_at(&json, "/host/os/type").as_deref(), Some("windows"));
    let columns: Vec<&str> = sql.split('`').skip(1).step_by(PAIR).collect();
    assert!(columns.contains(&"event.code") && columns.contains(&"user.name") && columns.contains(&"source.ip"));
    columns
        .iter()
        .filter(|column| **column != "event.id" && **column != "events")
        .try_for_each(|column| {
            json.pointer(&format!("/{}", column.replace('.', "/")))
                .map(|_| ())
                .ok_or_else(|| format!("the normalised event lacks {column}"))
        })?;
    assert_eq!(text_at(&json, "/event/code").as_deref(), Some("4625"));
    assert!(sql.contains("4625") && sql.contains("10.0.0.9"));
    Ok(())
}


#[test]
fn the_stream_counts_processed_unknown_and_malformed_lines() -> TestResult {
    let one = FAILED_4625.trim_end();
    let input = format!(
        "{one}\n{one}\n{}\nnot xml at all <\n{}\n",
        UNKNOWN.trim_end(),
        render("Other", "Security", "4624", "")
    );
    let mut reader = input.as_bytes();
    let mut out = Vec::new();
    let counts = normalise_stream_format(&mut reader, &mut out, Format::WinSecurity)?;
    assert_eq!(
        counts,
        Counts {
            processed: PROCESSED,
            malformed: TWO,
            unknown: 1,
            duplicate: 0
        }
    );
    assert_eq!(String::from_utf8(out)?.lines().count(), TWO as usize);
    Ok(())
}


#[test]
fn the_cli_accepts_the_winsec_format() -> TestResult {
    let input = format!("{}\n", FAILED_4625.trim_end());
    let mut reader = input.as_bytes();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_reporting(&["--format", "winsec"], &mut reader, &mut out, &mut err)?;
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    assert_eq!(String::from_utf8(err)?, "processed=1 malformed=0 unknown=0\n");
    assert_eq!("winsec".parse::<Format>()?, Format::WinSecurity);
    assert!(matches!("x".parse::<Format>(), Err(NormaliseError::UnknownFormat(_))));
    let wrapped = NormaliseError::WinSecurity(WinSecError::Unknown(1));
    assert!(wrapped.to_string().starts_with("invalid Windows Security event"));
    Ok(())
}
