use crate::common::{chain, completion, settings, MARKER};
use crate::numbers::{CONNECT_TIMEOUT_SECONDS, KEY_MODE, KIB, STATUS_SERVER_ERROR};
use crate::servers::{closed_port, held_server, http_reply, plain_server, tls_server, ANNOUNCED_BODY, PARTIAL_BODY};
use crate::types::TestResult;
use ai_gateway::chat::{chat, production_deps};
use ai_gateway::error::AiError;
use ai_gateway::limits::STATUS_OK;
use ai_gateway::model::HttpRequest;
use ai_gateway::response::read_body;
use ai_gateway::transport::{body_error, ca_certificate, ureq_error, ureq_transport};
use rcgen::string::Ia5String;
use rcgen::SanType;
use serde_json::json;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use ureq::Error as UreqError;
use zeroize::Zeroizing;


const SHORT: Duration = Duration::from_millis(100);


const ESCAPE: char = '\u{1b}';


const LONG_NAME_BYTES: usize = 40_000;


fn request(url: String, ca_file: Option<PathBuf>) -> HttpRequest {
    HttpRequest {
        url,
        authorization: Some(Zeroizing::new("Bearer sk-live".to_owned())),
        body: b"{\"model\":\"m\"}".to_vec(),
        timeout: Duration::from_secs(CONNECT_TIMEOUT_SECONDS),
        ca_file,
    }
}


fn loopback() -> Vec<SanType> {
    vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))]
}


#[test]
fn a_plain_loopback_endpoint_answers_and_sees_the_bearer_and_the_body() -> TestResult {
    let server = plain_server(http_reply(STATUS_OK, &completion("over http")))?;
    let mut used = settings("x");
    used.base_url = format!("http://127.0.0.1:{}", server.port);
    let directory = tempfile::tempdir()?;
    let key = directory.path().join("key");
    fs::write(&key, "sk-live\n")?;
    fs::set_permissions(&key, fs::Permissions::from_mode(KEY_MODE))?;
    used.api_key_file = Some(key);
    let answer = chat(&used, "instructions", &json!({"a": 1}), &production_deps())?;
    let seen = server.request.join().map_err(|_panic| "server panicked")??.to_ascii_lowercase();
    assert_eq!(answer.content, "over http");
    assert!(seen.starts_with("post /v1/chat/completions"));
    assert!(seen.contains("authorization: bearer sk-live"));
    assert!(seen.contains("content-type: application/json"));
    assert!(seen.contains("\"model\":\"test-model:1\""));
    Ok(())
}


#[test]
fn an_error_status_over_the_wire_is_a_fixed_error() -> TestResult {
    let server = plain_server(http_reply(STATUS_SERVER_ERROR, MARKER.as_bytes()))?;
    let mut used = settings("x");
    used.base_url = format!("http://127.0.0.1:{}", server.port);
    let error = chat(&used, "i", &json!({"a": 1}), &production_deps()).err().ok_or("accepted")?;
    assert!(matches!(error, AiError::Status { status: STATUS_SERVER_ERROR }));
    assert!(!chain(&error).contains(MARKER));
    Ok(())
}


#[test]
fn a_peer_that_never_answers_ends_at_the_deadline() -> TestResult {
    let held = held_server(Vec::new())?;
    let mut call = request(format!("http://127.0.0.1:{}/v1/chat/completions", held.port), None);
    call.timeout = SHORT;
    let error = ureq_transport(&call).err().ok_or("answered")?;
    held.release.send(())?;
    assert!(matches!(error, AiError::Timeout));
    Ok(())
}


#[test]
fn a_body_that_stalls_ends_at_the_deadline_in_either_phase() -> TestResult {
    let announced = format!("HTTP/1.1 200 X\r\nContent-Length: {ANNOUNCED_BODY}\r\nConnection: close\r\n\r\n");
    let held = held_server([announced.as_bytes(), PARTIAL_BODY].concat())?;
    let mut call = request(format!("http://127.0.0.1:{}/v1/chat/completions", held.port), None);
    call.timeout = SHORT;
    let error = ureq_transport(&call).and_then(|reply| read_body(reply, KIB)).err().ok_or("read")?;
    held.release.send(())?;
    assert!(matches!(error, AiError::Timeout));
    Ok(())
}


#[test]
fn a_closed_port_is_a_connect_error() -> TestResult {
    let call = request(format!("http://127.0.0.1:{}/v1/chat/completions", closed_port()?), None);
    let got = ureq_transport(&call).err();
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


#[test]
fn a_private_ca_is_trusted_through_the_ca_file() -> TestResult {
    let tls = tls_server(loopback(), http_reply(STATUS_OK, &completion("over tls")))?;
    let directory = tempfile::tempdir()?;
    let ca = directory.path().join("ca.pem");
    fs::write(&ca, &tls.ca_pem)?;
    let mut used = settings("x");
    used.base_url = format!("https://127.0.0.1:{}", tls.served.port);
    used.ca_file = Some(ca);
    let answer = chat(&used, "i", &json!({"a": 1}), &production_deps())?;
    assert_eq!(answer.content, "over tls");
    Ok(())
}


#[test]
fn an_untrusted_certificate_is_a_fixed_tls_error() -> TestResult {
    let tls = tls_server(loopback(), http_reply(STATUS_OK, b"{}"))?;
    let call = request(format!("https://127.0.0.1:{}/v1/chat/completions", tls.served.port), None);
    let got = ureq_transport(&call).err();
    assert!(matches!(got, Some(AiError::Tls)), "{got:?}");
    Ok(())
}


#[test]
fn a_hostile_san_list_never_reaches_an_error() -> TestResult {
    let long = "a".repeat(LONG_NAME_BYTES);
    let names = vec![
        SanType::DnsName(Ia5String::try_from(format!("{MARKER}.example"))?),
        SanType::URI(Ia5String::try_from(format!("urn:{MARKER}{ESCAPE}[31m{long}"))?),
    ];
    let tls = tls_server(names, http_reply(STATUS_OK, b"{}"))?;
    let directory = tempfile::tempdir()?;
    let ca = directory.path().join("ca.pem");
    fs::write(&ca, &tls.ca_pem)?;
    let call = request(format!("https://127.0.0.1:{}/v1/chat/completions", tls.served.port), Some(ca));
    let error = ureq_transport(&call).err().ok_or("accepted")?;
    let shown = chain(&error);
    assert!(matches!(error, AiError::Tls), "{error:?}");
    assert!(!shown.contains(MARKER) && !shown.contains(ESCAPE) && !shown.contains("u{1b}"));
    assert!(shown.len() < KIB);
    Ok(())
}


#[test]
fn an_unusable_ca_file_is_refused_before_any_connection() -> TestResult {
    let directory = tempfile::tempdir()?;
    let garbage = directory.path().join("garbage.pem");
    fs::write(&garbage, "not a certificate")?;
    assert!(matches!(ca_certificate(&garbage), Err(AiError::CaFile)));
    assert!(matches!(ca_certificate(&directory.path().join("absent.pem")), Err(AiError::CaFile)));
    let call = request("https://127.0.0.1:1/v1/chat/completions".to_owned(), Some(garbage));
    assert!(matches!(ureq_transport(&call), Err(AiError::CaFile)));
    Ok(())
}


#[test]
fn every_ureq_error_class_maps_to_a_fixed_variant() -> TestResult {
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


#[test]
fn a_read_error_keeps_its_kind_or_unwraps_a_ureq_error() -> TestResult {
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
