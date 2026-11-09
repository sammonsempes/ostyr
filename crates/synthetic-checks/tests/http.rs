#[path = "common/server.rs"]
mod server;
#[path = "common/types.rs"]
mod types;


use server::{ca_signed, finish, self_signed, serve, Behaviour, HOST};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::Command;
use std::time::Duration;
use synthetic_checks::http::{fetch_with_roots, http_fetch, load_roots, tls_handshake};
use synthetic_checks::probe::{FetchCaps, HttpRequest};
use synthetic_checks::target::guard_address;
use tempfile::tempdir;
use types::TestResult;


const LEFT: Duration = Duration::from_secs(10);


const OK: u16 = 200;


const FOUND: u16 = 302;


const TWO: usize = 2;


const OVER_CA_FILE: usize = 1_048_577;


const OVER_CA_COUNT: usize = 65;


const TEN: usize = 10;


const CERT_CAP: usize = 16_384;


const BODY_LARGE: usize = 1024;


const LOCATION_LARGE: usize = 2048;


const HUNDRED: usize = 100;


const SHORT: Duration = Duration::from_millis(300);


const BODY_CAP: usize = 4;


const LOCATION_CAP: usize = 10;


const LONG_LOCATION: &str = "http://example.org/a/very/long/location";


const BAD_ROOT: &[u8] = &[1, 2, 3];


const CHILD_TARGET: &str = "OSTYR_PROXY_CHILD_TARGET";


const PROXY_VARIABLES: [&str; 3] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"];


fn caps() -> FetchCaps {
    FetchCaps {
        body_bytes: BODY_LARGE,
        certificates: TEN,
        certificate_bytes: CERT_CAP,
        location_bytes: LOCATION_LARGE,
    }
}


fn request(address: SocketAddr, tls: bool) -> Result<HttpRequest, Box<dyn std::error::Error>> {
    let loopback = "127.0.0.0/8".parse()?;
    Ok(HttpRequest {
        address: guard_address(address.ip(), &[loopback])?,
        host: HOST.to_string(),
        port: address.port(),
        tls,
        path_and_query: "/p?q=1".to_string(),
    })
}


fn reply(status_line: &str, extra_header: &str, body: &str) -> Behaviour {
    Behaviour::Reply(
        format!(
            "HTTP/1.1 {status_line}\r\n{extra_header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    )
}


#[test]
fn a_plain_response_gives_status_and_body() -> TestResult {
    let served = serve(None, reply("200 OK", "", "hello"), 1)?;
    let response = http_fetch(&request(served.address, false)?, LEFT, caps(), &[])?;
    assert_eq!(response.status, OK);
    assert_eq!(response.body, b"hello");
    assert_eq!(response.location, None);
    assert!(response.certificate_chain.is_empty());
    assert_eq!(response.certificate_verified, None);
    assert_eq!(finish(served)?, vec!["GET /p?q=1 HTTP/1.1".to_string()]);
    Ok(())
}


#[test]
fn a_body_over_the_cap_is_cut_at_one_byte_past_it() -> TestResult {
    let served = serve(None, reply("200 OK", "", &"x".repeat(HUNDRED)), 1)?;
    let small = FetchCaps {
        body_bytes: BODY_CAP,
        ..caps()
    };
    let response = http_fetch(&request(served.address, false)?, LEFT, small, &[])?;
    assert_eq!(response.body.len(), BODY_CAP + 1);
    finish(served)?;
    Ok(())
}


#[test]
fn a_redirect_is_reported_and_not_followed() -> TestResult {
    let served = serve(None, reply("302 Found", "Location: /next\r\n", ""), 1)?;
    let response = http_fetch(&request(served.address, false)?, LEFT, caps(), &[])?;
    assert_eq!(response.status, FOUND);
    assert_eq!(response.location.as_deref(), Some("/next"));
    assert_eq!(finish(served)?.len(), 1);
    Ok(())
}


#[test]
fn a_location_over_the_cap_is_cut_just_above_it() -> TestResult {
    let header = format!("Location: {LONG_LOCATION}\r\n");
    let served = serve(None, reply("302 Found", &header, ""), 1)?;
    let small = FetchCaps {
        location_bytes: LOCATION_CAP,
        ..caps()
    };
    let response = http_fetch(&request(served.address, false)?, LEFT, small, &[])?;
    assert_eq!(response.location.as_deref(), LONG_LOCATION.get(..=LOCATION_CAP));
    finish(served)?;
    Ok(())
}


#[test]
fn a_self_signed_leaf_is_captured_and_marked_unverified() -> TestResult {
    let pki = self_signed()?;
    let served = serve(Some(pki.config.clone()), reply("200 OK", "", "secret body"), TWO)?;
    let response = http_fetch(&request(served.address, true)?, LEFT, caps(), &[])?;
    assert_eq!(response.certificate_chain, vec![pki.leaf_der.clone()]);
    assert_eq!(response.certificate_verified, Some(false));
    assert_eq!(response.status, 0);
    assert_eq!(response.location, None);
    assert!(response.body.is_empty());
    let seen = finish(served)?;
    assert_eq!(seen.len(), TWO);
    assert_eq!(seen.get(1).map(String::as_str), Some("HEAD / HTTP/1.1"));
    Ok(())
}


#[test]
fn a_chain_to_a_trusted_ca_is_captured_and_marked_verified() -> TestResult {
    let pki = ca_signed()?;
    let served = serve(Some(pki.config.clone()), reply("200 OK", "", "fine"), 1)?;
    let response = http_fetch(&request(served.address, true)?, LEFT, caps(), std::slice::from_ref(&pki.ca_der))?;
    assert_eq!(response.certificate_chain, vec![pki.leaf_der.clone()]);
    assert_eq!(response.certificate_verified, Some(true));
    assert_eq!(response.body, b"fine");
    assert_eq!(finish(served)?, vec!["GET /p?q=1 HTTP/1.1".to_string()]);
    Ok(())
}


#[test]
fn a_certificate_above_the_byte_cap_is_an_error() -> TestResult {
    let pki = ca_signed()?;
    let served = serve(Some(pki.config.clone()), reply("200 OK", "", ""), 1)?;
    let small = FetchCaps {
        certificate_bytes: TEN,
        ..caps()
    };
    let error = http_fetch(&request(served.address, true)?, LEFT, small, std::slice::from_ref(&pki.ca_der))
        .err()
        .ok_or("expected an error")?;
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    finish(served)?;
    Ok(())
}


#[test]
fn a_zero_certificate_cap_captures_nothing() -> TestResult {
    let pki = ca_signed()?;
    let served = serve(Some(pki.config.clone()), reply("200 OK", "", ""), 1)?;
    let none = FetchCaps { certificates: 0, ..caps() };
    let response = http_fetch(&request(served.address, true)?, LEFT, none, std::slice::from_ref(&pki.ca_der))?;
    assert!(response.certificate_chain.is_empty());
    finish(served)?;
    Ok(())
}


#[test]
fn an_unparseable_root_is_an_error() -> TestResult {
    let served = serve(None, reply("200 OK", "", ""), 0)?;
    assert!(http_fetch(&request(served.address, true)?, LEFT, caps(), &[BAD_ROOT.to_vec()]).is_err());
    finish(served)?;
    Ok(())
}


#[test]
fn a_refused_connection_keeps_its_error() -> TestResult {
    let closed = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    assert!(http_fetch(&request(closed, false)?, LEFT, caps(), &[]).is_err());
    assert!(http_fetch(&request(closed, true)?, LEFT, caps(), &[]).is_err());
    Ok(())
}


#[test]
fn a_server_that_never_answers_times_out() -> TestResult {
    let served = serve(None, Behaviour::Hang, 1)?;
    let error = http_fetch(&request(served.address, false)?, SHORT, caps(), &[])
        .err()
        .ok_or("expected a timeout")?;
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(finish(served)?, vec!["hung".to_string()]);
    Ok(())
}


#[test]
fn a_tls_server_that_never_answers_times_out_without_a_second_connection() -> TestResult {
    let served = serve(None, Behaviour::Hang, 1)?;
    let error = http_fetch(&request(served.address, true)?, SHORT, caps(), &[])
        .err()
        .ok_or("expected a timeout")?;
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(finish(served)?.len(), 1);
    Ok(())
}


#[test]
fn proxy_child() -> TestResult {
    match std::env::var(CHILD_TARGET) {
        Ok(target) => {
            let response = http_fetch(&request(target.parse()?, false)?, LEFT, caps(), &[])?;
            assert_eq!(response.body, b"direct");
            Ok(())
        }
        Err(_) => Ok(()),
    }
}


#[test]
fn proxy_variables_are_ignored() -> TestResult {
    let proxy = TcpListener::bind("127.0.0.1:0")?;
    proxy.set_nonblocking(true)?;
    let proxy_url = format!("http://{}", proxy.local_addr()?);
    let served = serve(None, reply("200 OK", "", "direct"), 1)?;
    let mut child = Command::new(std::env::current_exe()?);
    child.args(["--exact", "proxy_child"]).env(CHILD_TARGET, served.address.to_string());
    PROXY_VARIABLES.iter().for_each(|name| {
        child.env(name, &proxy_url);
    });
    assert!(child.output()?.status.success());
    assert_eq!(proxy.accept().err().map(|error| error.kind()), Some(ErrorKind::WouldBlock));
    assert_eq!(finish(served)?.len(), 1);
    Ok(())
}


#[test]
fn the_handshake_returns_the_self_signed_leaf() -> TestResult {
    let pki = self_signed()?;
    let served = serve(Some(pki.config.clone()), reply("200 OK", "", ""), TWO)?;
    let chain = tls_handshake(served.address, HOST, LEFT, TEN, CERT_CAP)?;
    assert_eq!(chain, vec![pki.leaf_der.clone()]);
    let seen = finish(served)?;
    assert_eq!(seen.get(1).map(String::as_str), Some("HEAD / HTTP/1.1"));
    Ok(())
}


#[test]
fn the_handshake_to_a_closed_port_fails() -> TestResult {
    let closed = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    assert!(tls_handshake(closed, HOST, LEFT, TEN, CERT_CAP).is_err());
    assert_eq!(closed.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    Ok(())
}


fn write_ca(name: &str, content: &[u8]) -> Result<(tempfile::TempDir, String), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let path = directory.path().join(name);
    std::fs::write(&path, content)?;
    let text = path.to_str().ok_or("path")?.to_string();
    Ok((directory, text))
}


#[test]
fn no_ca_file_means_no_extra_root() -> TestResult {
    assert!(load_roots(None)?.is_empty());
    Ok(())
}


#[test]
fn a_pem_bundle_is_read_into_der_roots() -> TestResult {
    let pki = ca_signed()?;
    let (_directory, path) = write_ca("ca.pem", pki.ca_pem.as_bytes())?;
    assert_eq!(load_roots(Some(&path))?, vec![pki.ca_der.clone()]);
    Ok(())
}


#[test]
fn a_missing_ca_file_is_an_error() -> TestResult {
    let (directory, path) = write_ca("ca.pem", b"")?;
    let missing = format!("{path}.absent");
    assert!(load_roots(Some(&missing)).is_err());
    drop(directory);
    Ok(())
}


#[test]
fn a_ca_file_above_the_byte_cap_is_an_error() -> TestResult {
    let (_directory, path) = write_ca("ca.pem", &vec![b'a'; OVER_CA_FILE])?;
    let error = load_roots(Some(&path)).err().ok_or("expected an error")?;
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    Ok(())
}


#[test]
fn a_broken_pem_block_is_an_error() -> TestResult {
    let (_directory, path) = write_ca("ca.pem", b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")?;
    assert!(load_roots(Some(&path)).is_err());
    Ok(())
}


#[test]
fn too_many_ca_certificates_are_an_error() -> TestResult {
    let pki = ca_signed()?;
    let (_directory, path) = write_ca("ca.pem", pki.ca_pem.repeat(OVER_CA_COUNT).as_bytes())?;
    let error = load_roots(Some(&path)).err().ok_or("expected an error")?;
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    Ok(())
}


#[test]
fn the_bound_fetch_trusts_the_loaded_roots() -> TestResult {
    let pki = ca_signed()?;
    let served = serve(Some(pki.config.clone()), reply("200 OK", "", "fine"), 1)?;
    let roots = vec![pki.ca_der.clone()];
    let fetch = fetch_with_roots(&roots);
    let response = fetch(&request(served.address, true)?, LEFT, caps())?;
    assert_eq!(response.certificate_verified, Some(true));
    finish(served)?;
    Ok(())
}
