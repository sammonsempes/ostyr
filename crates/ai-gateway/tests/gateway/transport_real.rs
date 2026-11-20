use crate::budget_pg::real_chat;
use crate::common::{chain, completion, settings, MARKER};
use crate::numbers::{KEY_MODE, KIB, STATUS_SERVER_ERROR};
use crate::servers::{closed_port, held_server, http_reply, plain_server, tls_server, ANNOUNCED_BODY, PARTIAL_BODY};
use crate::types::TestResult;
use ai_gateway::error::AiError;
use ai_gateway::limits::{MIN_TIMEOUT_SECONDS, STATUS_OK};
use ai_gateway::settings::AiSettings;
use ai_gateway::transport::{body_error, ca_certificate, ureq_error};
use rcgen::string::Ia5String;
use rcgen::SanType;
use serde_json::json;
use std::error::Error;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use ureq::Error as UreqError;


const ESCAPE: char = '\u{1b}';


const LONG_NAME_BYTES: usize = 40_000;


fn endpoint(base_url: String, ca_file: Option<PathBuf>) -> AiSettings {
    AiSettings {
        base_url,
        ca_file,
        timeout_seconds: MIN_TIMEOUT_SECONDS,
        ..settings("x")
    }
}


async fn call(used: &AiSettings) -> Result<Result<ai_gateway::model::Answer, AiError>, Box<dyn Error>> {
    real_chat(used, "i", &json!({"a": 1})).await
}


fn loopback() -> Vec<SanType> {
    vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))]
}


#[tokio::test(flavor = "multi_thread")]
async fn a_plain_loopback_endpoint_answers_and_sees_the_bearer_and_the_body() -> TestResult {
    let server = plain_server(http_reply(STATUS_OK, &completion("over http")))?;
    let mut used = settings("x");
    used.base_url = format!("http://127.0.0.1:{}", server.port);
    let directory = tempfile::tempdir()?;
    let key = directory.path().join("key");
    fs::write(&key, "  sk-live.1_2  \n")?;
    fs::set_permissions(&key, fs::Permissions::from_mode(KEY_MODE))?;
    used.api_key_file = Some(key);
    let answer = real_chat(&used, "instructions", &json!({"a": 1})).await??;
    let seen = server.request.join().map_err(|_panic| "server panicked")??.to_ascii_lowercase();
    assert_eq!(answer.content, "over http");
    assert!(seen.starts_with("post /v1/chat/completions"));
    assert!(seen.lines().any(|line| line.trim_end() == "authorization: bearer sk-live.1_2"), "{seen}");
    assert!(seen.contains("content-type: application/json"));
    assert!(seen.contains("\"model\":\"test-model:1\""));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_error_status_over_the_wire_is_a_fixed_error() -> TestResult {
    let server = plain_server(http_reply(STATUS_SERVER_ERROR, MARKER.as_bytes()))?;
    let mut used = settings("x");
    used.base_url = format!("http://127.0.0.1:{}", server.port);
    let error = real_chat(&used, "i", &json!({"a": 1})).await?.err().ok_or("accepted")?;
    assert!(matches!(error, AiError::Status { status: STATUS_SERVER_ERROR }));
    assert!(!chain(&error).contains(MARKER));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_never_answers_ends_at_the_deadline() -> TestResult {
    let held = held_server(Vec::new())?;
    let used = endpoint(format!("http://127.0.0.1:{}", held.port), None);
    let error = call(&used).await?.err().ok_or("answered")?;
    held.release.send(())?;
    assert!(matches!(error, AiError::Timeout));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_stalls_ends_at_the_deadline_in_either_phase() -> TestResult {
    let announced = format!("HTTP/1.1 200 X\r\nContent-Length: {ANNOUNCED_BODY}\r\nConnection: close\r\n\r\n");
    let held = held_server([announced.as_bytes(), PARTIAL_BODY].concat())?;
    let used = endpoint(format!("http://127.0.0.1:{}", held.port), None);
    let error = call(&used).await?.err().ok_or("read")?;
    held.release.send(())?;
    assert!(matches!(error, AiError::Timeout));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_closed_port_is_a_connect_error() -> TestResult {
    let used = endpoint(format!("http://127.0.0.1:{}", closed_port()?), None);
    let got = call(&used).await?.err();
    assert!(
        matches!(
            got,
            Some(AiError::Io {
                kind: io::ErrorKind::ConnectionRefused
            })
        ),
        "{got:?}"
    );
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_private_ca_is_trusted_through_the_ca_file() -> TestResult {
    let tls = tls_server(loopback(), http_reply(STATUS_OK, &completion("over tls")))?;
    let directory = tempfile::tempdir()?;
    let ca = directory.path().join("ca.pem");
    fs::write(&ca, &tls.ca_pem)?;
    let mut used = settings("x");
    used.base_url = format!("https://127.0.0.1:{}", tls.served.port);
    used.ca_file = Some(ca);
    let answer = real_chat(&used, "i", &json!({"a": 1})).await??;
    assert_eq!(answer.content, "over tls");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_untrusted_certificate_is_a_fixed_tls_error() -> TestResult {
    let tls = tls_server(loopback(), http_reply(STATUS_OK, b"{}"))?;
    let used = endpoint(format!("https://127.0.0.1:{}", tls.served.port), None);
    let got = call(&used).await?.err();
    assert!(matches!(got, Some(AiError::Tls)), "{got:?}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_san_list_never_reaches_an_error() -> TestResult {
    let long = "a".repeat(LONG_NAME_BYTES);
    let names = vec![
        SanType::DnsName(Ia5String::try_from(format!("{MARKER}.example"))?),
        SanType::URI(Ia5String::try_from(format!("urn:{MARKER}{ESCAPE}[31m{long}"))?),
    ];
    let tls = tls_server(names, http_reply(STATUS_OK, b"{}"))?;
    let directory = tempfile::tempdir()?;
    let ca = directory.path().join("ca.pem");
    fs::write(&ca, &tls.ca_pem)?;
    let used = endpoint(format!("https://127.0.0.1:{}", tls.served.port), Some(ca));
    let error = call(&used).await?.err().ok_or("accepted")?;
    let shown = chain(&error);
    assert!(matches!(error, AiError::Tls), "{error:?}");
    assert!(!shown.contains(MARKER) && !shown.contains(ESCAPE) && !shown.contains("u{1b}"));
    assert!(shown.len() < KIB);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_ca_file_is_refused_before_any_connection() -> TestResult {
    let directory = tempfile::tempdir()?;
    let garbage = directory.path().join("garbage.pem");
    fs::write(&garbage, "not a certificate")?;
    assert!(matches!(ca_certificate(&garbage), Err(AiError::CaFile)));
    assert!(matches!(ca_certificate(&directory.path().join("absent.pem")), Err(AiError::CaFile)));
    let used = endpoint("https://127.0.0.1:1".to_owned(), Some(garbage));
    assert!(matches!(call(&used).await?, Err(AiError::CaFile)));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn every_ureq_error_class_maps_to_a_fixed_variant() -> TestResult {
    assert!(matches!(ureq_error(&UreqError::Timeout(ureq::Timeout::Global)), AiError::Timeout));
    assert!(matches!(ureq_error(&UreqError::Tls("x")), AiError::Tls));
    assert!(matches!(ureq_error(&UreqError::HostNotFound), AiError::Connect));
    assert!(matches!(ureq_error(&UreqError::ConnectionFailed), AiError::Connect));
    let io_error = ureq_error(&UreqError::Io(io::Error::new(io::ErrorKind::ConnectionReset, MARKER)));
    assert!(matches!(
        io_error,
        AiError::Io {
            kind: io::ErrorKind::ConnectionReset
        }
    ));
    assert!(!chain(&io_error).contains(MARKER));
    let other = ureq_error(&UreqError::BadUri(MARKER.to_owned()));
    assert!(matches!(other, AiError::Protocol));
    assert!(!chain(&other).contains(MARKER));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_read_error_keeps_its_kind_or_unwraps_a_ureq_error() -> TestResult {
    assert!(matches!(
        body_error(io::Error::new(io::ErrorKind::BrokenPipe, MARKER)),
        AiError::Io {
            kind: io::ErrorKind::BrokenPipe
        }
    ));
    assert!(matches!(
        body_error(io::Error::other(UreqError::Timeout(ureq::Timeout::Global))),
        AiError::Timeout
    ));
    let tls = body_error(io::Error::new(io::ErrorKind::InvalidData, rustls::Error::General(MARKER.to_owned())));
    assert!(matches!(tls, AiError::Tls));
    assert!(!chain(&tls).contains(MARKER));
    Ok(())
}
