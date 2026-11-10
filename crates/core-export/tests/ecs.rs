#[path = "common/types.rs"]
mod types;


use core_export::ecs::{
    blank_event, to_json, DnsFields, DnsQuestion, EndpointFields, EventFields, FileFields, HashFields, HostFields, HttpBodyFields, HttpFields,
    HttpRequestFields, HttpResponseFields, JaHash, NetworkFields, OsFields, ParentFields, PeFields, ProcessFields, RegistryFields, RuleFields,
    TlsClientFields, TlsFields, TlsServerFields, UrlFields, UserAgentFields, UserFields, ECS_VERSION,
};
use core_export::error::ExportError;
use time::OffsetDateTime;
use types::TestResult;


const FIXED_UNIX: i64 = 1_700_000_000;


const YEAR_BEFORE_COMMON_ERA: i64 = -62_198_755_200;


const SOURCE_PORT: u16 = 51_000;


const DESTINATION_PORT: u16 = 443;


const PROCESS_ID: u32 = 4242;


const BYTES: u64 = 10;


const PACKETS: u64 = 2;


const STATUS: u64 = 200;


const BODY_BYTES: u64 = 5;


const FILE_SIZE: u64 = 2048;


const SEVERITY: u32 = 3;


const SEQUENCE: u64 = 7;


const FULL_SNAPSHOT: &str = concat!(
    r#"{"@timestamp":"2023-11-14T22:13:20Z","ecs":{"version":"8.11"},"#,
    r#""event":{"kind":"event","category":["process","network"],"type":["start"],"action":"start","outcome":"success","dataset":"edr.process","#,
    r#""module":"edr","severity":3,"sequence":7},"message":"hello","#,
    r#""host":{"name":"srv1","id":"h-1","ip":["10.0.0.1"],"os":{"type":"linux"}},"user":{"name":"root","id":"0","domain":"local"},"#,
    r#""source":{"ip":"10.0.0.1","port":51000,"domain":"a.example"},"destination":{"ip":"10.0.0.2","port":443,"domain":"b.example"},"#,
    r#""network":{"transport":"tcp","direction":"egress"},"#,
    r#""process":{"pid":4242,"name":"curl","executable":"/usr/bin/curl","command_line":"curl x","args":["x"],"working_directory":"/tmp","#,
    r#""parent":{"pid":1,"executable":"/sbin/init","command_line":"init"}},"#,
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
        code: None,
        category: vec!["process".to_string(), "network".to_string()],
        types: vec!["start".to_string()],
        action: text("start"),
        outcome: text("success"),
        dataset: text("edr.process"),
        module: text("edr"),
        severity: Some(SEVERITY),
        sequence: Some(SEQUENCE),
        ..EventFields::default()
    };
    event.message = text("hello");
    event.host = Some(HostFields {
        name: text("srv1"),
        id: text("h-1"),
        ip: vec!["10.0.0.1".to_string()],
        os: Some(OsFields { kind: text("linux") }),
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
        ..EndpointFields::default()
    });
    event.destination = Some(EndpointFields {
        ip: text("10.0.0.2"),
        port: Some(DESTINATION_PORT),
        domain: text("b.example"),
        ..EndpointFields::default()
    });
    event.network = Some(NetworkFields {
        transport: text("tcp"),
        direction: text("egress"),
        ..NetworkFields::default()
    });
    event.process = Some(ProcessFields {
        pid: Some(PROCESS_ID),
        name: text("curl"),
        executable: text("/usr/bin/curl"),
        command_line: text("curl x"),
        args: vec!["x".to_string()],
        working_directory: text("/tmp"),
        parent: Some(ParentFields {
            pid: Some(1),
            executable: text("/sbin/init"),
            command_line: text("init"),
            ..ParentFields::default()
        }),
        ..ProcessFields::default()
    });
    event.file = Some(FileFields {
        path: text("/tmp/a"),
        name: text("a"),
        size: Some(FILE_SIZE),
        ..FileFields::default()
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


#[test]
fn windows_endpoint_groups_are_serialised_nested() -> TestResult {
    let mut event = blank_event(OffsetDateTime::from_unix_timestamp(FIXED_UNIX)?);
    event.event.code = text("1");
    event.process = Some(ProcessFields {
        entity_id: text("{g}"),
        hash: Some(HashFields {
            md5: text("a"),
            sha1: text("b"),
            sha256: text("c"),
        }),
        pe: Some(PeFields {
            original_file_name: text("x.exe"),
        }),
        parent: Some(ParentFields {
            entity_id: text("{p}"),
            ..ParentFields::default()
        }),
        ..ProcessFields::default()
    });
    event.file = Some(FileFields {
        hash: Some(HashFields::default()),
        ..FileFields::default()
    });
    event.registry = Some(RegistryFields { path: text("HKLM\\k") });
    event.dns = Some(DnsFields {
        question: DnsQuestion {
            name: text("a.test"),
            kind: None,
        },
        kind: None,
        response_code: None,
        resolved_ip: vec!["10.0.0.1".to_string()],
    });
    event.sysmon.insert("Key".to_string(), "v".to_string());
    assert_eq!(
        to_json(&event)?,
        concat!(
            r#"{"@timestamp":"2023-11-14T22:13:20Z","ecs":{"version":"8.11"},"event":{"code":"1"},"#,
            r#""process":{"entity_id":"{g}","hash":{"md5":"a","sha1":"b","sha256":"c"},"#,
            r#""pe":{"original_file_name":"x.exe"},"parent":{"entity_id":"{p}"}},"#,
            r#""file":{"hash":{}},"registry":{"path":"HKLM\\k"},"#,
            r#""dns":{"question":{"name":"a.test"},"resolved_ip":["10.0.0.1"]},"sysmon":{"Key":"v"}}"#
        )
    );
    Ok(())
}


#[test]
fn network_telemetry_groups_are_serialised_when_set() -> TestResult {
    let mut event = blank_event(OffsetDateTime::from_unix_timestamp(FIXED_UNIX)?);
    event.event = EventFields {
        start: Some(OffsetDateTime::from_unix_timestamp(FIXED_UNIX)?),
        end: Some(OffsetDateTime::from_unix_timestamp(FIXED_UNIX + 1)?),
        ..EventFields::default()
    };
    event.source = Some(EndpointFields {
        bytes: Some(BYTES),
        packets: Some(PACKETS),
        ..EndpointFields::default()
    });
    event.network = Some(NetworkFields {
        protocol: text("http"),
        community_id: text("1:abc"),
        ..NetworkFields::default()
    });
    event.url = Some(UrlFields {
        domain: text("a.test"),
        path: text("/p"),
        original: text("/p?q"),
    });
    event.http = Some(HttpFields {
        version: text("HTTP/1.1"),
        request: Some(HttpRequestFields { method: text("GET") }),
        response: Some(HttpResponseFields {
            status_code: Some(STATUS),
            body: Some(HttpBodyFields { bytes: Some(BODY_BYTES) }),
        }),
    });
    event.tls = Some(TlsFields {
        version: text("TLS 1.3"),
        client: Some(TlsClientFields {
            server_name: text("a.test"),
            ja3: Some(JaHash { hash: text("j3") }),
        }),
        server: Some(TlsServerFields {
            subject: text("CN=a"),
            issuer: text("CN=b"),
            not_after: text("2027"),
            ja3s: Some(JaHash { hash: text("js") }),
        }),
    });
    event.rule = Some(RuleFields {
        id: text("1"),
        name: text("n"),
        category: text("c"),
    });
    event.user_agent = Some(UserAgentFields { original: text("curl") });
    let expected = concat!(
        r#"{"@timestamp":"2023-11-14T22:13:20Z","ecs":{"version":"8.11"},"#,
        r#""event":{"start":"2023-11-14T22:13:20Z","end":"2023-11-14T22:13:21Z"},"#,
        r#""source":{"bytes":10,"packets":2},"network":{"protocol":"http","community_id":"1:abc"},"#,
        r#""url":{"domain":"a.test","path":"/p","original":"/p?q"},"#,
        r#""http":{"version":"HTTP/1.1","request":{"method":"GET"},"response":{"status_code":200,"body":{"bytes":5}}},"#,
        r#""tls":{"version":"TLS 1.3","client":{"server_name":"a.test","ja3":{"hash":"j3"}},"#,
        r#""server":{"subject":"CN=a","issuer":"CN=b","not_after":"2027","ja3s":{"hash":"js"}}},"#,
        r#""rule":{"id":"1","name":"n","category":"c"},"user_agent":{"original":"curl"}}"#
    );
    let json = to_json(&event)?;
    assert_eq!(json, expected);
    Ok(())
}
