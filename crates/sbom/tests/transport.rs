#![cfg(unix)]
#[path = "common/tls_sink.rs"]
mod tls_sink;
#[path = "common/types.rs"]
mod types;


use sbom::error::StoreError;
use sbom::model::{HttpRequest, StoreMethod};
use sbom::store_settings::StoreSettings;
use sbom::transport::{agent_transport, build_agent, open_https_store, redact, send};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::tempdir;
use tls_sink::{spawn_sink, test_pki, SERVER_NAME};
use types::TestResult;


const STATUS_OK: u16 = 200;


const STATUS_MISSING: u16 = 404;


const PRIVATE_MODE: u32 = 0o600;


const TOTAL_MILLIS: u64 = 5000;


const OVERSIZE_CA: usize = 1_048_577;


const BOUND: usize = 10;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const BODY: usize = 100;


const CLOSED_PORT: u16 = 1;


fn settings(directory: &Path, ca_file: Option<&Path>) -> Result<StoreSettings, Box<dyn std::error::Error>> {
    let access = directory.join("access");
    let secret = directory.join("secret");
    fs::write(&access, "AKIDEXAMPLE\n")?;
    fs::write(&secret, "SECRETEXAMPLE\n")?;
    fs::set_permissions(&access, fs::Permissions::from_mode(PRIVATE_MODE))?;
    fs::set_permissions(&secret, fs::Permissions::from_mode(PRIVATE_MODE))?;
    Ok(StoreSettings {
        endpoint: "https://localhost:9000".to_owned(),
        bucket: "sboms".to_owned(),
        region: "us-east-1".to_owned(),
        ca_file: ca_file.map(Path::to_path_buf),
        access_key_file: access,
        secret_key_file: secret,
        connect_millis: TOTAL_MILLIS,
        read_millis: TOTAL_MILLIS,
        total_millis: TOTAL_MILLIS,
    })
}


fn request(method: StoreMethod, url: String, body: &[u8], max_response: usize) -> HttpRequest {
    HttpRequest {
        method,
        url,
        body: body.to_vec(),
        max_response,
    }
}


fn sent(agent: &ureq::Agent, http_request: &HttpRequest) -> Result<sbom::model::HttpResponse, String> {
    send(agent, http_request).map_err(|error| error.to_string())
}


#[test]
fn get_and_put_travel_over_tls_with_the_private_ca() -> TestResult {
    let directory = tempdir()?;
    let pki = test_pki()?;
    let ca_path = directory.path().join("ca.pem");
    fs::write(&ca_path, &pki.ca_pem)?;
    let sink = spawn_sink(pki.server_config.clone(), vec![(STATUS_OK, b"hello".to_vec()), (STATUS_OK, Vec::new())])?;
    let agent = build_agent(&settings(directory.path(), Some(&ca_path))?)?;
    let base = format!("https://{SERVER_NAME}:{}/sboms/key?X-Amz-Signature=abc", sink.port);
    let got = sent(&agent, &request(StoreMethod::Get, base.clone(), b"", BODY))?;
    let put = (agent_transport(agent))(&request(StoreMethod::Put, base, b"payload", 0)).map_err(|error| error.to_string())?;
    assert_eq!((got.status, got.body), (STATUS_OK, b"hello".to_vec()));
    assert_eq!((put.status, put.body), (STATUS_OK, Vec::new()));
    let seen = sink.seen.join().map_err(|_panic| "sink panicked")??;
    assert!(seen.first().ok_or("none")?.request_line.starts_with("GET /sboms/key?"));
    assert!(seen.get(1).ok_or("none")?.request_line.starts_with("PUT /sboms/key?"));
    assert_eq!(seen.get(1).ok_or("none")?.body, b"payload");
    Ok(())
}


#[test]
fn the_body_is_cut_at_the_bound_and_a_status_is_not_an_error() -> TestResult {
    let directory = tempdir()?;
    let pki = test_pki()?;
    let ca_path = directory.path().join("ca.pem");
    fs::write(&ca_path, &pki.ca_pem)?;
    let sink = spawn_sink(
        pki.server_config.clone(),
        vec![(STATUS_OK, vec![b'x'; BODY]), (STATUS_MISSING, b"nope".to_vec())],
    )?;
    let agent = build_agent(&settings(directory.path(), Some(&ca_path))?)?;
    let url = format!("https://{SERVER_NAME}:{}/k", sink.port);
    let long = sent(&agent, &request(StoreMethod::Get, url.clone(), b"", BOUND))?;
    let missing = sent(&agent, &request(StoreMethod::Get, url, b"", BODY))?;
    assert_eq!(long.body.len(), BOUND);
    assert_eq!(missing.status, STATUS_MISSING);
    sink.seen.join().map_err(|_panic| "sink panicked")??;
    Ok(())
}


#[test]
fn a_server_with_an_unknown_ca_is_refused() -> TestResult {
    let directory = tempdir()?;
    let pki = test_pki()?;
    let sink = spawn_sink(pki.server_config.clone(), vec![(STATUS_OK, Vec::new())])?;
    let agent = build_agent(&settings(directory.path(), None)?)?;
    let url = format!("https://{SERVER_NAME}:{}/k", sink.port);
    assert!(send(&agent, &request(StoreMethod::Get, url, b"", BODY)).is_err());
    assert!(sink.seen.join().map_err(|_panic| "sink panicked")?.is_err());
    Ok(())
}


#[test]
fn plain_http_and_bad_urls_are_refused_without_quoting_the_url() -> TestResult {
    let directory = tempdir()?;
    let agent = build_agent(&settings(directory.path(), None)?)?;
    let plain = send(
        &agent,
        &request(StoreMethod::Get, "http://127.0.0.1:1/k?X-Amz-Signature=topsecret".to_owned(), b"", BODY),
    );
    assert_eq!(plain.err().ok_or("accepted")?.to_string(), "the request URL was refused");
    let bad = send(&agent, &request(StoreMethod::Get, "not a url topsecret".to_owned(), b"", BODY));
    assert!(!bad.err().ok_or("accepted")?.to_string().contains("topsecret"));
    let closed = send(
        &agent,
        &request(StoreMethod::Put, format!("https://127.0.0.1:{CLOSED_PORT}/k"), b"x", BODY),
    );
    assert_ne!(closed.err().ok_or("accepted")?.to_string(), "the request URL was refused");
    assert!(redact(ureq::Error::Timeout(ureq::Timeout::Global)).to_string().contains("timeout"));
    Ok(())
}


#[test]
fn the_ca_file_is_checked() -> TestResult {
    let directory = tempdir()?;
    let big = directory.path().join("big.pem");
    fs::write(&big, vec![b'a'; OVERSIZE_CA])?;
    let binary = directory.path().join("binary.pem");
    fs::write(&binary, NOT_UTF8)?;
    let garbage = directory.path().join("garbage.pem");
    fs::write(&garbage, "not a certificate")?;
    let missing = directory.path().join("missing.pem");
    let refusal = |path: &Path| -> Result<StoreError, Box<dyn std::error::Error>> {
        Ok(build_agent(&settings(directory.path(), Some(path))?).err().ok_or("accepted")?)
    };
    assert!(matches!(refusal(&big)?, StoreError::CaTooLarge));
    assert!(matches!(refusal(&binary)?, StoreError::File(_)));
    assert!(matches!(refusal(&garbage)?, StoreError::Certificate(_)));
    assert!(matches!(refusal(&missing)?, StoreError::Signing(_)));
    Ok(())
}


#[test]
fn a_relative_ca_file_is_a_settings_error_naming_it() -> TestResult {
    let directory = tempdir()?;
    let relative = settings(directory.path(), Some(Path::new("ca.pem")))?;
    assert!(matches!(open_https_store(&relative), Err(StoreError::Settings("ca_file"))));
    Ok(())
}


#[test]
fn the_https_store_opens_from_settings() -> TestResult {
    let directory = tempdir()?;
    let pki = test_pki()?;
    let ca_path = directory.path().join("ca.pem");
    fs::write(&ca_path, &pki.ca_pem)?;
    let store = open_https_store(&settings(directory.path(), Some(&ca_path))?)?;
    assert_eq!(store.bucket.name(), "sboms");
    Ok(())
}


#[test]
fn a_ca_bundle_is_used_whole_and_other_pem_items_are_skipped() -> TestResult {
    let directory = tempdir()?;
    let pki = test_pki()?;
    let bundle = directory.path().join("bundle.pem");
    let key_block = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
    fs::write(&bundle, format!("{}{key_block}{}", pki.ca_pem, pki.ca_pem))?;
    assert!(build_agent(&settings(directory.path(), Some(&bundle))?).is_ok());
    let only_key = directory.path().join("key.pem");
    fs::write(&only_key, key_block)?;
    let refused = build_agent(&settings(directory.path(), Some(&only_key))?).err().ok_or("accepted")?;
    assert!(matches!(refused, StoreError::Certificate(_)));
    Ok(())
}


#[test]
fn a_malformed_pem_block_is_a_certificate_error() -> TestResult {
    let directory = tempdir()?;
    let broken = directory.path().join("broken.pem");
    fs::write(&broken, "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")?;
    let refused = build_agent(&settings(directory.path(), Some(&broken))?).err().ok_or("accepted")?;
    assert!(matches!(refused, StoreError::Certificate(_)));
    Ok(())
}
