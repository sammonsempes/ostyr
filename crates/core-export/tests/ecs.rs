#[path = "common/types.rs"]
mod types;


use core_export::ecs::{blank_event, to_json, EndpointFields, EventFields, FileFields, HostFields, ProcessFields, UserFields, ECS_VERSION};
use core_export::error::ExportError;
use time::OffsetDateTime;
use types::TestResult;


const FIXED_UNIX: i64 = 1_700_000_000;


const YEAR_BEFORE_COMMON_ERA: i64 = -62_198_755_200;


const SOURCE_PORT: u16 = 51_000;


const DESTINATION_PORT: u16 = 443;


const PROCESS_ID: u32 = 4242;


const FILE_SIZE: u64 = 2048;


const SEVERITY: u32 = 3;


const SEQUENCE: u64 = 7;


const FULL_SNAPSHOT: &str = concat!(
    r#"{"@timestamp":"2023-11-14T22:13:20Z","ecs":{"version":"8.11"},"#,
    r#""event":{"kind":"event","category":["process","network"],"action":"start","outcome":"success","dataset":"edr.process","#,
    r#""module":"edr","severity":3,"sequence":7},"message":"hello","#,
    r#""host":{"name":"srv1","id":"h-1","ip":["10.0.0.1"]},"user":{"name":"root","id":"0","domain":"local"},"#,
    r#""source":{"ip":"10.0.0.1","port":51000,"domain":"a.example"},"destination":{"ip":"10.0.0.2","port":443,"domain":"b.example"},"#,
    r#""process":{"pid":4242,"name":"curl","executable":"/usr/bin/curl","command_line":"curl x"},"#,
    r#""file":{"path":"/tmp/a","name":"a","size":2048},"labels":{"tenant":"acme"}}"#
);


fn text(value: &str) -> Option<String> {
    Some(value.to_string())
}


#[test]
fn full_event_matches_the_ecs_snapshot() -> TestResult {
    let mut event = blank_event(OffsetDateTime::from_unix_timestamp(FIXED_UNIX)?);
    event.event = EventFields {
        kind: text("event"),
        category: vec!["process".to_string(), "network".to_string()],
        action: text("start"),
        outcome: text("success"),
        dataset: text("edr.process"),
        module: text("edr"),
        severity: Some(SEVERITY),
        sequence: Some(SEQUENCE),
    };
    event.message = text("hello");
    event.host = Some(HostFields {
        name: text("srv1"),
        id: text("h-1"),
        ip: vec!["10.0.0.1".to_string()],
    });
    event.user = Some(UserFields {
        name: text("root"),
        id: text("0"),
        domain: text("local"),
    });
    event.source = Some(EndpointFields {
        ip: text("10.0.0.1"),
        port: Some(SOURCE_PORT),
        domain: text("a.example"),
    });
    event.destination = Some(EndpointFields {
        ip: text("10.0.0.2"),
        port: Some(DESTINATION_PORT),
        domain: text("b.example"),
    });
    event.process = Some(ProcessFields {
        pid: Some(PROCESS_ID),
        name: text("curl"),
        executable: text("/usr/bin/curl"),
        command_line: text("curl x"),
    });
    event.file = Some(FileFields {
        path: text("/tmp/a"),
        name: text("a"),
        size: Some(FILE_SIZE),
    });
    event.labels.insert("tenant".to_string(), "acme".to_string());
    assert_eq!(to_json(&event)?, FULL_SNAPSHOT);
    Ok(())
}


#[test]
fn blank_event_keeps_only_the_mandatory_fields() -> TestResult {
    let event = blank_event(OffsetDateTime::from_unix_timestamp(FIXED_UNIX)?);
    assert_eq!(
        to_json(&event)?,
        format!(r#"{{"@timestamp":"2023-11-14T22:13:20Z","ecs":{{"version":"{ECS_VERSION}"}},"event":{{}}}}"#)
    );
    Ok(())
}


#[test]
fn a_timestamp_outside_rfc3339_is_an_error() -> TestResult {
    let event = blank_event(OffsetDateTime::from_unix_timestamp(YEAR_BEFORE_COMMON_ERA)?);
    assert!(matches!(to_json(&event), Err(ExportError::Serialize(_))));
    Ok(())
}
