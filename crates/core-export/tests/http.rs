#[path = "common/http_sink.rs"]
mod http_sink;
#[path = "common/pki.rs"]
mod pki;
#[path = "common/types.rs"]
mod types;


use core_export::error::ExportError;
use core_export::http::{build_agent, post_json};
use types::TestResult;


const STATUS_OK: u16 = 200;


const STATUS_ERROR: u16 = 500;


#[test]
fn a_post_carries_the_body_and_the_bearer_token() -> TestResult {
    let http_sink::HttpSink { port, bodies } = http_sink::spawn_http_sink(None, vec![STATUS_OK, STATUS_OK])?;
    let agent = build_agent(None)?;
    let url = format!("http://127.0.0.1:{port}/hook");
    post_json(&agent, &url, Some("tok"), "[1]").map_err(|error| error.to_string())?;
    post_json(&agent, &url, None, "[2]").map_err(|error| error.to_string())?;
    let received = bodies.join().map_err(|_panic| "sink thread panicked")??;
    assert_eq!(
        received,
        vec![("bearer tok".to_string(), "[1]".to_string()), (String::new(), "[2]".to_string())]
    );
    Ok(())
}


#[test]
fn a_rejecting_receiver_is_an_error() -> TestResult {
    let http_sink::HttpSink { port, bodies } = http_sink::spawn_http_sink(None, vec![STATUS_ERROR])?;
    let agent = build_agent(None)?;
    assert!(post_json(&agent, &format!("http://127.0.0.1:{port}/hook"), None, "[1]").is_err());
    bodies.join().map_err(|_panic| "sink thread panicked")??;
    Ok(())
}


#[test]
fn an_unreachable_receiver_is_an_error() -> TestResult {
    let agent = build_agent(None)?;
    assert!(post_json(&agent, "http://127.0.0.1:1/hook", None, "[1]").is_err());
    Ok(())
}


#[test]
fn https_works_with_the_private_ca_and_fails_without_it() -> TestResult {
    let authority = pki::test_pki()?;
    let http_sink::HttpSink { port, bodies } = http_sink::spawn_http_sink(Some(authority.server_config.clone()), vec![STATUS_OK, STATUS_OK])?;
    let url = format!("https://localhost:{port}/hook");
    post_json(&build_agent(Some(authority.ca_pem.as_bytes()))?, &url, None, "[1]").map_err(|error| error.to_string())?;
    assert!(post_json(&build_agent(None)?, &url, None, "[2]").is_err());
    assert!(bodies.join().map_err(|_panic| "sink thread panicked")?.is_err());
    Ok(())
}


#[test]
fn a_bad_ca_bundle_is_rejected() -> TestResult {
    assert!(matches!(build_agent(Some(b"not a pem")), Err(ExportError::Certificate(_))));
    Ok(())
}
