#[path = "common/capture.rs"]
mod capture;
#[path = "common/types.rs"]
mod types;


use capture::{Capture, ANCHOR};
use chrono::{TimeZone, Utc};
use core_pg::scope::{tenant_scope, TenantScope};
use oncall::alert::{Cell, FailureReason, Outcome, Param, Statement};
use oncall::channel::{load_channel, parse_channel, redacted_target, validate_channel};
use oncall::error::{OncallError, StoreError};
use oncall::limits::{
    MAX_CHANNELS, MAX_CHANNEL_NAME_BYTES, MAX_NAME_LEN, MAX_PATH_LEN, MAX_TARGET_LEN, MAX_VALUE_LEN, NTFY_BODY_LEN, NTFY_SUBJECT_LEN, SLACK_BODY_LEN,
    SMS_BODY_LEN, SMS_SUBJECT_LEN, SMTP_BODY_LEN, SMTP_SUBJECT_LEN, TEAMS_BODY_LEN, WEBHOOK_BODY_LEN,
};
use oncall::model::{AlertNotice, Channel, ChannelKind, Message};
use oncall::notify::notify;
use oncall::render::render;
use oncall::store::{record_notification, NOTIFY_SQL};
use oncall::types::Row;
use std::collections::BTreeMap;
use std::future::ready;
use std::sync::{Arc, LazyLock};
use tracing::Dispatch;
use types::TestResult;


const CHANNEL_YAML: &str = include_str!("fixtures/channel.yaml");


const SECRET_QUERY: &str = "token=hunter2";


const THREE: usize = 3;


const ESCAPE_FACTOR: usize = 2;


const LONG_VALUE: usize = 250;


const TENANT: &str = "acme";


fn channel(name: &str, kind: ChannelKind, target: &str) -> Channel {
    Channel {
        name: name.to_string(),
        tenant: TENANT.to_string(),
        kind,
        target: target.to_string(),
        secret_file: None,
    }
}


fn alert(name: &str) -> AlertNotice {
    AlertNotice {
        tenant: TENANT.to_string(),
        name: name.to_string(),
        labels: BTreeMap::from([("host".to_string(), "web-1".to_string())]),
        annotations: BTreeMap::from([("summary".to_string(), "disk *full*".to_string())]),
    }
}


fn refused(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    parse_channel(text, "c.yaml")
        .map(|_| String::new())
        .or_else(|error| Ok(error.to_string()))
}


#[test]
fn a_channel_file_is_loaded() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("pager.yaml");
    std::fs::write(&path, CHANNEL_YAML)?;
    let loaded = load_channel(&path)?;
    assert_eq!(loaded.kind, ChannelKind::Webhook);
    assert_eq!(loaded.secret_file.as_deref(), Some("/etc/ostyr/secrets/pager-token"));
    assert_eq!(redacted_target(&loaded), "https://hooks.example.com");
    assert_eq!(redacted_target(&channel("m", ChannelKind::Smtp, "a@example.com")), "<address>");
    Ok(())
}


#[test]
fn an_inline_secret_is_a_parse_error_with_file_and_line() -> TestResult {
    let message = refused(&format!("{CHANNEL_YAML}token: abc\n"))?;
    assert!(message.contains("c.yaml"));
    assert!(message.contains("unknown field"));
    assert!(!message.contains("abc"));
    Ok(())
}


#[test]
fn http_and_bad_targets_are_refused() -> TestResult {
    let http = "name: a\ntenant: acme\nkind: slack\ntarget: http://hooks.example.com/x\n";
    assert!(refused(http)?.contains("https"));
    let junk = "name: a\ntenant: acme\nkind: ntfy\ntarget: not a url\n";
    assert!(refused(junk)?.contains("https"));
    Ok(())
}


#[test]
fn smtp_addresses_are_checked() -> TestResult {
    let good = "name: a\ntenant: acme\nkind: smtp\ntarget: oncall@example.com\n";
    assert_eq!(refused(good)?, "");
    [
        "nobody",
        "@example.com",
        "a@",
        "a@b@c",
        "a b@example.com",
        "a\\u0000b@example.com",
        "a@example.com\\r\\nBcc: x@y.z",
    ]
    .iter()
    .try_for_each(|target| -> TestResult {
        let text = format!("name: a\ntenant: acme\nkind: smtp\ntarget: \"{target}\"\n");
        assert!(refused(&text)?.contains("address"), "{target}");
        Ok(())
    })
}


#[test]
fn bounds_on_fields_are_enforced() -> TestResult {
    let mut long_target = channel(
        "a",
        ChannelKind::Webhook,
        &format!("https://example.com/{}", "a".repeat(MAX_TARGET_LEN as usize)),
    );
    assert!(matches!(validate_channel(&long_target), Err(OncallError::OutOfBounds { .. })));
    long_target.target = "https://example.com".to_string();
    long_target.secret_file = Some(String::new());
    assert!(matches!(validate_channel(&long_target), Err(OncallError::OutOfBounds { .. })));
    long_target.secret_file = Some("p".repeat(MAX_PATH_LEN as usize + 1));
    assert!(matches!(validate_channel(&long_target), Err(OncallError::OutOfBounds { .. })));
    long_target.secret_file = Some("/run/secret".to_string());
    validate_channel(&long_target)?;
    long_target.name = String::new();
    assert!(validate_channel(&long_target).is_err());
    Ok(())
}


#[test]
fn crlf_in_subject_or_address_is_refused() -> TestResult {
    let smtp = channel("mail", ChannelKind::Smtp, "oncall@example.com");
    assert!(matches!(
        render(&alert("down\r\nBcc: evil@example.com"), &smtp),
        Err(OncallError::HeaderInjection { field: "subject" })
    ));
    assert!(matches!(
        render(&alert("down\nx"), &smtp),
        Err(OncallError::HeaderInjection { field: "subject" })
    ));
    let bad_address = channel("mail", ChannelKind::Smtp, "a@example.com\r\nBcc: x@y.z");
    assert!(matches!(
        render(&alert("down"), &bad_address),
        Err(OncallError::HeaderInjection { field: "address" })
    ));
    let mut other_tenant = alert("down");
    other_tenant.tenant = "ac\nme".to_string();
    assert!(render(&other_tenant, &smtp).is_err());
    Ok(())
}


fn long_alert() -> AlertNotice {
    let mut long = alert(&"n".repeat(SMTP_BODY_LEN));
    long.annotations = (0..SMTP_BODY_LEN).map(|i| (format!("k{i:05}"), "v".repeat(LONG_VALUE))).collect();
    long
}


#[test]
fn every_kind_is_bounded() -> TestResult {
    let long = long_alert();
    let cases = [
        (ChannelKind::Smtp, SMTP_SUBJECT_LEN, SMTP_BODY_LEN),
        (ChannelKind::Ntfy, NTFY_SUBJECT_LEN, NTFY_BODY_LEN),
        (ChannelKind::Sms, SMS_SUBJECT_LEN, SMS_BODY_LEN),
    ];
    cases.iter().try_for_each(|(kind, subject_len, body_len)| -> TestResult {
        let target = if *kind == ChannelKind::Smtp {
            "a@example.com"
        } else {
            "https://example.com"
        };
        let message = render(&long, &channel("c", *kind, target))?;
        assert_eq!(message.subject.chars().count(), *subject_len);
        assert_eq!(message.body.chars().count(), *body_len);
        Ok(())
    })?;
    let teams = render(&long, &channel("t", ChannelKind::Teams, "https://example.com"))?;
    assert!(teams.body.chars().count() <= TEAMS_BODY_LEN * ESCAPE_FACTOR);
    let slack = render(&long, &channel("s", ChannelKind::Slack, "https://example.com"))?;
    assert!(slack.body.chars().count() <= SLACK_BODY_LEN * ESCAPE_FACTOR);
    let hook = render(&long, &channel("w", ChannelKind::Webhook, "https://example.com"))?;
    assert!(hook.body.chars().count() <= WEBHOOK_BODY_LEN * ESCAPE_FACTOR);
    Ok(())
}


#[test]
fn text_is_escaped_for_the_target_format() -> TestResult {
    let hostile = AlertNotice {
        tenant: TENANT.to_string(),
        name: "a \"quote\" [link](x)".to_string(),
        labels: BTreeMap::from([("k".to_string(), "line1\r\nlabel x: y \"q\" \\".to_string())]),
        annotations: BTreeMap::new(),
    };
    let hook = render(&hostile, &channel("w", ChannelKind::Webhook, "https://example.com"))?;
    let parsed: serde_json::Value = serde_json::from_str(&hook.body)?;
    assert_eq!(parsed.get("tenant").and_then(|value| value.as_str()), Some(TENANT));
    assert_eq!(
        parsed.get("text").and_then(|value| value.as_str()),
        Some("label k: line1  label x: y \"q\" \\\n")
    );
    let teams = render(&hostile, &channel("t", ChannelKind::Teams, "https://example.com"))?;
    assert_eq!(teams.subject, "\\[acme\\] a \"quote\" \\[link\\]\\(x\\)");
    let slack = render(&alert("x"), &channel("s", ChannelKind::Slack, "https://example.com"))?;
    assert!(slack.body.contains("disk *full*"));
    let injected = AlertNotice {
        tenant: TENANT.to_string(),
        name: "<!channel> <https://evil.example|click> a&b".to_string(),
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
    };
    let slack_injected = render(&injected, &channel("s", ChannelKind::Slack, "https://example.com"))?;
    assert_eq!(
        slack_injected.subject,
        "[acme] &lt;!channel&gt; &lt;https://evil.example|click&gt; a&amp;b"
    );
    let plain = render(&alert("x"), &channel("m", ChannelKind::Smtp, "a@example.com"))?;
    assert!(plain.body.contains("disk *full*"));
    Ok(())
}


#[test]
fn one_failing_sender_does_not_stop_the_others() -> TestResult {
    let channels = [
        channel("one", ChannelKind::Smtp, "a@example.com"),
        channel("two", ChannelKind::Webhook, "https://example.com/hook?token=hunter2"),
        channel("three", ChannelKind::Ntfy, "https://ntfy.example.com/topic"),
    ];
    let mut sent: Vec<String> = Vec::new();
    let capture = Capture(Arc::default());
    LazyLock::force(&ANCHOR);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer({
                let sink = capture.clone();
                move || sink.clone()
            })
            .finish(),
    );
    let failures = tracing::dispatcher::with_default(&dispatch, || {
        notify(&alert("down"), &channels, &mut |target: &Channel, _message: &Message| {
            sent.push(target.name.clone());
            if target.name == "two" {
                Err(format!("POST {} refused", target.target))
            } else {
                Ok(())
            }
        })
    })?;
    assert_eq!(sent.len(), THREE);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures.first().map(|failure| failure.channel.as_str()), Some("two"));
    let logs = String::from_utf8(capture.0.lock().map_err(|error| error.to_string())?.clone())?;
    assert!(logs.contains("two"));
    let reasons: String = failures.iter().map(|failure| format!("{:?}", failure.reason)).collect();
    assert!(!reasons.contains(SECRET_QUERY));
    assert!(!logs.contains(SECRET_QUERY));
    assert!(!logs.contains("/hook"));
    Ok(())
}


#[test]
fn sender_text_never_reaches_reasons_or_logs() -> TestResult {
    let target = "https://Example.com:443?token=hunter2";
    let parsed = url::Url::parse(target)?;
    let channels = [channel("hook", ChannelKind::Webhook, target)];
    let capture = Capture(Arc::default());
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer({
                let sink = capture.clone();
                move || sink.clone()
            })
            .finish(),
    );
    let failures = tracing::dispatcher::with_default(&dispatch, || {
        notify(&alert("down"), &channels, &mut |_: &Channel, _: &Message| {
            Err(format!("POST {parsed} failed\nFORGED line"))
        })
    })?;
    let logs = String::from_utf8(capture.0.lock().map_err(|error| error.to_string())?.clone())?;
    let reasons: String = failures.iter().map(|failure| format!("{:?}", failure.reason)).collect();
    assert!(!reasons.contains("hunter2") && !logs.contains("hunter2"));
    assert!(!logs.contains("FORGED"));
    assert!(failures.iter().all(|failure| failure.channel == "hook"));
    Ok(())
}


#[test]
fn an_unvalidated_channel_is_refused_by_notify() -> TestResult {
    let mut calls: Vec<String> = Vec::new();
    let failures = notify(
        &alert("down"),
        &[channel("plain", ChannelKind::Webhook, "http://example.com/x")],
        &mut |_: &Channel, _: &Message| {
            calls.push(String::new());
            Ok(())
        },
    )?;
    assert!(calls.is_empty());
    assert!(failures.iter().all(|failure| failure.reason == FailureReason::InvalidMessage));
    Ok(())
}


#[test]
fn long_keys_names_and_tenants_are_truncated() -> TestResult {
    let mut long = alert(&"n".repeat(MAX_VALUE_LEN as usize * THREE));
    long.annotations = BTreeMap::from([("k".repeat(MAX_VALUE_LEN as usize * THREE), "v".to_string())]);
    let message = render(&long, &channel("m", ChannelKind::Smtp, "a@example.com"))?;
    assert!(message.subject.chars().count() <= MAX_VALUE_LEN as usize + MAX_NAME_LEN as usize);
    assert!(!message.body.contains(&"k".repeat(MAX_VALUE_LEN as usize + 1)));
    long.tenant = "t".repeat(MAX_NAME_LEN as usize * THREE);
    let hook = render(&long, &channel("w", ChannelKind::Webhook, "https://example.com"))?;
    let parsed: serde_json::Value = serde_json::from_str(&hook.body)?;
    assert_eq!(
        parsed.get("tenant").and_then(|value| value.as_str()).map(|text| text.chars().count()),
        Some(MAX_NAME_LEN as usize)
    );
    Ok(())
}


#[test]
fn a_render_error_is_a_failure_of_that_channel() -> TestResult {
    let failures = notify(
        &alert("bad\nname"),
        &[channel("m", ChannelKind::Smtp, "a@example.com")],
        &mut |_: &Channel, _: &Message| Ok(()),
    )?;
    assert_eq!(failures.len(), 1);
    assert!(failures.iter().all(|failure| failure.reason == FailureReason::InvalidMessage));
    Ok(())
}


#[test]
fn a_channel_of_another_tenant_is_refused() -> TestResult {
    let mut foreign = channel("foreign", ChannelKind::Smtp, "a@example.com");
    foreign.tenant = "globex".to_string();
    let mut calls: Vec<String> = Vec::new();
    let failures = notify(&alert("down"), &[foreign], &mut |_: &Channel, _: &Message| {
        calls.push(String::new());
        Ok(())
    })?;
    assert!(calls.is_empty());
    assert_eq!(failures.len(), 1);
    assert!(failures.iter().all(|failure| failure.reason == FailureReason::OtherTenant));
    Ok(())
}


#[test]
fn too_many_channels_are_refused() -> TestResult {
    let channels = vec![channel("c", ChannelKind::Smtp, "a@example.com"); MAX_CHANNELS as usize + 1];
    assert!(matches!(
        notify(&alert("down"), &channels, &mut |_: &Channel, _: &Message| Ok(())),
        Err(OncallError::OutOfBounds { .. })
    ));
    Ok(())
}


#[test]
fn an_empty_tenant_and_a_missing_file_are_refused() -> TestResult {
    let no_tenant = "name: a\ntenant: \"\"\nkind: smtp\ntarget: a@example.com\n";
    assert!(refused(no_tenant)?.contains("channel tenant"));
    let directory = tempfile::tempdir()?;
    assert!(load_channel(&directory.path().join("absent.yaml")).is_err());
    Ok(())
}


#[test]
fn one_channel_name_rule_applies_on_load() -> TestResult {
    let max = "a".repeat(MAX_CHANNEL_NAME_BYTES);
    let wide = "\u{e9}".repeat(MAX_CHANNEL_NAME_BYTES);
    let long = "a".repeat(MAX_CHANNEL_NAME_BYTES + 1);
    let refused_names = [
        "ops ",
        " ops",
        "a  b",
        "a\u{a0}b",
        "\u{e9}quipe",
        "a\u{2028}b",
        "a\u{3164}b",
        "a\u{202e}b",
        "a\tb",
        "a\0b",
        "",
        long.as_str(),
        wide.as_str(),
    ];
    refused_names.iter().try_for_each(|name| {
        let text = CHANNEL_YAML.replacen("name: pager-webhook", &format!("name: {}", serde_json::to_string(name)?), 1);
        let message = refused(&text)?;
        assert!(message.contains("channel name"), "{name:?}: {message}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    parse_channel(&CHANNEL_YAML.replacen("name: pager-webhook", &format!("name: {max}"), 1), "c.yaml")?;
    refused_names.iter().try_for_each(|name| {
        let mut loaded = channel(name, ChannelKind::Smtp, "a@example.com");
        assert!(validate_channel(&loaded).is_err(), "{name:?}");
        assert_eq!(
            validate_channel(&loaded).err().map(|error| error.to_string()),
            Some("the setting `channel name` is not valid".to_string())
        );
        loaded.name = max.clone();
        validate_channel(&loaded)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}


#[tokio::test]
async fn a_refused_channel_name_does_not_stop_the_valid_channel() -> TestResult {
    let channels = [
        channel("\u{e9}quipe", ChannelKind::Smtp, "a@example.com"),
        channel("ops ", ChannelKind::Smtp, "c@example.com"),
        channel("a  b", ChannelKind::Smtp, "d@example.com"),
        channel("ops", ChannelKind::Smtp, "b@example.com"),
    ];
    let mut sent: Vec<String> = Vec::new();
    let failures = notify(&alert("down"), &channels, &mut |target: &Channel, _: &Message| {
        sent.push(target.name.clone());
        Ok(())
    })?;
    assert_eq!(sent, ["ops"]);
    assert_eq!(failures.len(), THREE);
    assert!(failures.iter().all(|failure| failure.reason == FailureReason::InvalidMessage));
    let scope = tenant_scope(TENANT)?;
    let now = Utc.timestamp_opt(0, 0).single().ok_or("time")?;
    let mut statements: Vec<Statement> = Vec::new();
    let mut exec = |_: &TenantScope, statement: Statement| {
        let answer: Row = vec![Cell::Int(1)];
        statements.push(statement);
        ready(Ok::<Vec<Row>, StoreError>(vec![answer]))
    };
    let name = sent.first().ok_or("nothing sent")?;
    let seq = record_notification(&mut exec, &scope, 1, name, &Outcome::Sent, now).await?;
    assert_eq!(seq, 1);
    assert_eq!(statements.len(), 1);
    let recorded = statements.first().ok_or("no statement")?;
    assert_eq!(recorded.sql, NOTIFY_SQL);
    assert_eq!(
        recorded.params,
        [
            Param::Int(1),
            Param::Text("ops".to_string()),
            Param::Text("sent".to_string()),
            Param::OptText(None),
            Param::Time(Some(now))
        ]
    );
    Ok(())
}
