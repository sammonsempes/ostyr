#[path = "common/reader.rs"]
mod reader;
#[path = "common/stand_in.rs"]
mod stand_in;
#[path = "common/types.rs"]
mod types;


use reader::FailingReader;
use siem_ingest::error::InsertClass;
use stand_in::{reply, spawn_stand_in, Reply, Seen, StandIn, SERVER_NAME};
use std::error::Error;
use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use types::TestResult;
use virt_inventory::error::FetchError;
use virt_inventory::fetch::{build_agent, endpoint, fetch_inventory, get_body, read_body, remaining, token_header, PERMISSIONS_PATH, RESOURCES_PATH};
use virt_inventory::inventory::{inventory_degraded_nodes, inventory_items, Inventory};
use virt_inventory::limits::Limits;
use virt_inventory::settings::FetchSettings;


const TOKEN: &str = "auditor@pve!lab=0a1b2c3d-1111-2222-3333-444455556666";


const AUDITOR: &[u8] = include_bytes!("fixtures/permissions-auditor.json");


const ADMIN: &[u8] = include_bytes!("fixtures/permissions-admin.json");


const RESOURCES: &[u8] = include_bytes!("fixtures/resources-before.json");


const UNKNOWN: &[u8] = include_bytes!("fixtures/resources-unknown.json");


const OK: u16 = 200;


const TWO: usize = 2;


const SMALL_MAX: u64 = 1024;


const STATUS_ERROR: u16 = 500;


const STATUS_REDIRECT: u16 = 302;


const STATUS_DENIED: u16 = 401;


const TIMEOUT_MS: u64 = 30_000;


const PERMISSIONS_LINE: &str = "GET /api2/json/access/permissions HTTP/1.1";


const RESOURCES_LINE: &str = "GET /api2/json/cluster/resources HTTP/1.1";


struct Rig {
    _directory: TempDir,
    settings: FetchSettings,
}


fn settings_for(directory: &Path, port: u16, ca_pem: &str, limits: Limits) -> Result<FetchSettings, Box<dyn Error>> {
    fs::write(directory.join("ca.pem"), ca_pem)?;
    fs::write(directory.join("token"), format!("{TOKEN}\n"))?;
    Ok(FetchSettings {
        api_url: format!("https://{SERVER_NAME}:{port}"),
        ca_file: directory.join("ca.pem"),
        token_file: directory.join("token"),
        tenant: "acme".to_owned(),
        cluster: "pve-1".to_owned(),
        timeout_ms: TIMEOUT_MS,
        limits,
    })
}


fn rig(stand_in: &StandIn, limits: Limits) -> Result<Rig, Box<dyn Error>> {
    let directory = tempdir()?;
    let settings = settings_for(directory.path(), stand_in.port, &stand_in.ca_pem, limits)?;
    Ok(Rig {
        _directory: directory,
        settings,
    })
}


fn chain_text(error: &dyn Error) -> String {
    std::iter::successors(Some(error), |cause| (*cause).source())
        .map(|cause| format!("{cause} {cause:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}


struct Run {
    outcome: Result<Inventory, FetchError>,
    seen: Vec<Seen>,
}


fn run(replies: Vec<Reply>, limits: Limits) -> Result<Run, Box<dyn Error>> {
    let stand_in = spawn_stand_in(replies)?;
    let rigged = rig(&stand_in, limits)?;
    let outcome = fetch_inventory(&rigged.settings);
    let seen = stand_in.seen.join().map_err(|_| "stand-in panicked")??;
    Ok(Run { outcome, seen })
}


fn request_lines(seen: &[Seen]) -> Vec<&str> {
    seen.iter().map(|entry| entry.request_line.as_str()).collect()
}


fn limits_with(max_bytes: u64) -> Limits {
    Limits {
        max_bytes,
        ..Limits::default()
    }
}


fn refusal(outcome: Result<Inventory, FetchError>) -> Result<FetchError, Box<dyn Error>> {
    outcome.err().ok_or_else(|| "an inventory was returned".into())
}


#[test]
fn a_read_only_token_gives_the_inventory_and_sends_the_header() -> TestResult {
    let Run { outcome, seen } = run(vec![reply(OK, AUDITOR), reply(OK, RESOURCES)], Limits::default())?;
    let inventory = outcome?;
    assert_eq!(request_lines(&seen), vec![PERMISSIONS_LINE, RESOURCES_LINE]);
    assert!(seen
        .iter()
        .all(|entry| entry.authorization.as_deref() == Some(format!("PVEAPIToken={TOKEN}").as_str())));
    assert!(!inventory_items(&inventory).is_empty());
    assert!(inventory_degraded_nodes(&inventory).is_empty());
    Ok(())
}


#[test]
fn a_writable_token_is_refused_and_the_resources_are_never_requested() -> TestResult {
    let Run { outcome, seen } = run(vec![reply(OK, ADMIN)], Limits::default())?;
    let error = refusal(outcome)?;
    assert!(matches!(error, FetchError::WritableCredential(_)));
    assert_eq!(request_lines(&seen), vec![PERMISSIONS_LINE]);
    assert!(!chain_text(&error).contains(TOKEN));
    Ok(())
}


#[test]
fn a_server_error_on_the_resources_gives_no_inventory() -> TestResult {
    let Run { outcome, seen } = run(vec![reply(OK, AUDITOR), reply(STATUS_ERROR, RESOURCES)], Limits::default())?;
    let error = refusal(outcome)?;
    assert!(matches!(error, FetchError::Status(STATUS_ERROR)));
    assert_eq!(seen.len(), TWO);
    assert!(!chain_text(&error).contains(TOKEN));
    Ok(())
}


#[test]
fn a_refused_permissions_request_gives_no_inventory() -> TestResult {
    let Run { outcome, seen } = run(vec![reply(STATUS_DENIED, b"{}")], Limits::default())?;
    assert!(matches!(refusal(outcome)?, FetchError::Status(STATUS_DENIED)));
    assert_eq!(request_lines(&seen), vec![PERMISSIONS_LINE]);
    Ok(())
}


#[test]
fn a_resources_body_over_max_bytes_is_refused_and_the_limit_is_exact() -> TestResult {
    let max = AUDITOR.len() as u64;
    let Run { outcome: fits, .. } = run(
        vec![reply(OK, AUDITOR), reply(OK, RESOURCES)],
        limits_with(RESOURCES.len().max(AUDITOR.len()) as u64),
    )?;
    assert!(fits.is_ok());
    let Run { outcome, .. } = run(vec![reply(OK, AUDITOR), reply(OK, &vec![b' '; AUDITOR.len() + 1])], limits_with(max))?;
    let error = refusal(outcome)?;
    assert!(matches!(error, FetchError::TooLarge { max: limit } if limit == max));
    Ok(())
}


#[test]
fn an_endless_permissions_body_is_cut_at_the_limit() -> TestResult {
    let endless = Reply {
        status: OK,
        extra: "",
        body: Vec::new(),
        endless: true,
    };
    let Run { outcome, seen } = run(vec![endless], limits_with(SMALL_MAX))?;
    assert!(matches!(refusal(outcome)?, FetchError::TooLarge { max: SMALL_MAX }));
    assert_eq!(seen.len(), 1);
    Ok(())
}


#[test]
fn a_redirect_is_not_followed() -> TestResult {
    let redirect = Reply {
        status: STATUS_REDIRECT,
        extra: "location: https://localhost:1/other\r\n",
        body: Vec::new(),
        endless: false,
    };
    let Run { outcome, seen } = run(vec![reply(OK, AUDITOR), redirect], Limits::default())?;
    assert!(matches!(refusal(outcome)?, FetchError::Status(STATUS_REDIRECT)));
    assert_eq!(request_lines(&seen), vec![PERMISSIONS_LINE, RESOURCES_LINE]);
    Ok(())
}


#[test]
fn a_hostile_body_with_a_token_shaped_string_never_reaches_an_error() -> TestResult {
    let hostile = format!("{{\"data\": {TOKEN} }}");
    let Run { outcome: on_permissions, .. } = run(vec![reply(OK, hostile.as_bytes())], Limits::default())?;
    let first = refusal(on_permissions)?;
    assert!(matches!(first, FetchError::Permissions(_)));
    let Run { outcome: on_resources, .. } = run(vec![reply(OK, AUDITOR), reply(OK, hostile.as_bytes())], Limits::default())?;
    let second = refusal(on_resources)?;
    assert!(matches!(second, FetchError::Resources(_)));
    assert!(!chain_text(&first).contains(TOKEN));
    assert!(!chain_text(&second).contains(TOKEN));
    Ok(())
}


#[test]
fn a_stalled_pvestatd_answer_is_flagged_degraded() -> TestResult {
    let Run { outcome, .. } = run(vec![reply(OK, AUDITOR), reply(OK, UNKNOWN)], Limits::default())?;
    assert_eq!(inventory_degraded_nodes(&outcome?), ["pve".to_owned()]);
    Ok(())
}


#[test]
fn settings_are_checked_before_any_file_or_request() -> TestResult {
    let stand_in = spawn_stand_in(Vec::new())?;
    let mut rigged = rig(&stand_in, Limits::default())?;
    rigged.settings.api_url = format!("http://{SERVER_NAME}:{}", stand_in.port);
    assert!(matches!(refusal(fetch_inventory(&rigged.settings))?, FetchError::Url));
    assert!(stand_in.seen.join().map_err(|_| "stand-in panicked")??.is_empty());
    Ok(())
}


#[test]
fn unusable_files_are_refused_without_the_token_in_the_text() -> TestResult {
    let stand_in = spawn_stand_in(Vec::new())?;
    let mut rigged = rig(&stand_in, Limits::default())?;
    let directory = rigged._directory.path().to_owned();
    let good = rigged.settings.clone();
    rigged.settings.ca_file = directory.join("missing-ca.pem");
    assert!(matches!(refusal(fetch_inventory(&rigged.settings))?, FetchError::CaFile(_)));
    fs::write(directory.join("bad-ca.pem"), "not a certificate")?;
    rigged.settings.ca_file = directory.join("bad-ca.pem");
    assert!(matches!(refusal(fetch_inventory(&rigged.settings))?, FetchError::Agent(_)));
    rigged.settings.ca_file = good.ca_file.clone();
    rigged.settings.token_file = directory.join("missing-token");
    assert!(matches!(refusal(fetch_inventory(&rigged.settings))?, FetchError::TokenFile(_)));
    fs::write(directory.join("bad-token"), format!("{TOKEN}\nx"))?;
    rigged.settings.token_file = directory.join("bad-token");
    let shaped = refusal(fetch_inventory(&rigged.settings))?;
    assert!(matches!(shaped, FetchError::TokenShape));
    assert!(!chain_text(&shaped).contains(TOKEN));
    Ok(())
}


#[test]
fn a_closed_port_is_a_transport_failure() -> TestResult {
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let directory = tempdir()?;
    let stand_in = spawn_stand_in(Vec::new())?;
    let settings = settings_for(directory.path(), port, &stand_in.ca_pem, Limits::default())?;
    let error = refusal(fetch_inventory(&settings))?;
    assert!(matches!(error, FetchError::Transport(InsertClass::Unavailable)));
    assert!(!chain_text(&error).contains(TOKEN));
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing() -> TestResult {
    let stand_in = spawn_stand_in(Vec::new())?;
    let rigged = rig(&stand_in, Limits::default())?;
    let agent = build_agent(&rigged.settings)?;
    let outcome = get_body(&agent, &endpoint(&rigged.settings, PERMISSIONS_PATH), "x", SMALL_MAX, Duration::ZERO);
    assert!(matches!(outcome, Err(FetchError::Transport(InsertClass::Timeout))));
    assert!(remaining(std::time::Instant::now()).is_zero());
    Ok(())
}


#[test]
fn the_endpoint_drops_a_trailing_slash() -> TestResult {
    let directory = tempdir()?;
    let mut settings = settings_for(directory.path(), 1, "x", Limits::default())?;
    settings.api_url = "https://pve.example:8006/".to_owned();
    assert_eq!(
        endpoint(&settings, RESOURCES_PATH),
        "https://pve.example:8006/api2/json/cluster/resources"
    );
    Ok(())
}


#[test]
fn a_failing_body_read_is_refused() -> TestResult {
    assert!(matches!(read_body(&mut FailingReader, SMALL_MAX), Err(FetchError::Body(_))));
    assert_eq!(read_body(&mut &b"abc"[..], SMALL_MAX)?, b"abc");
    Ok(())
}


#[test]
fn the_token_must_be_an_ascii_allowlist_with_user_and_secret() -> TestResult {
    assert_eq!(token_header(TOKEN.as_bytes())?.as_str(), format!("PVEAPIToken={TOKEN}"));
    let refused: &[&[u8]] = &[
        b"auditor@pve=secret",
        b"auditor@pve!lab",
        b"a!b=c\r\nX: y",
        b"a!b=c d",
        b"a!b=\xc3\xa9",
        b"a!b=\xff",
    ];
    refused
        .iter()
        .try_for_each(|token| match token_header(token) {
            Err(FetchError::TokenShape) => Ok(()),
            _ => Err(format!("{token:?} was accepted")),
        })
        .map_err(Into::into)
}
