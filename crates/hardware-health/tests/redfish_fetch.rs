#[path = "standin/mod.rs"]
mod standin;
#[path = "common/types.rs"]
mod types;


use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use core_pg::scope::tenant_scope;
use hardware_health::error::{DiscoverError, FetchError, GetError};
use hardware_health::limits::{default_redfish_limits, MAX_ID_BYTES, MAX_MEMBERS};
use hardware_health::model::{BlindReason, DeviceReport, FetchSession, Health, RedfishDevice, RoleCheck};
use hardware_health::redfish::parse_redfish;
use hardware_health::redfish_assess::assess_redfish;
use hardware_health::redfish_fetch::{basic_header, build_agent, fetch_document, get_body, is_member_path, member_paths, poll_device, role_in};
use standin::{reply, requests, start, Reply, Standin};
use std::error::Error;
use std::net::TcpListener;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use types::TestResult;


const CHASSIS: &str = include_str!("fixtures/lab-redfish-chassis.json");


const THERMAL: &str = include_str!("fixtures/lab-redfish-thermal.json");


const POWER: &str = include_str!("fixtures/lab-redfish-power.json");


const SYSTEM: &str = include_str!("fixtures/lab-redfish-system.json");


const STATUS_OK: u16 = 200;


const STATUS_NOT_FOUND: u16 = 404;


const STATUS_FOUND: u16 = 302;


const STATUS_ERROR: u16 = 500;


const BODY_CASES: usize = 5;


const COLLECTION_CASES: usize = 3;


const HUGE_DECLARED: usize = 1_000_000;


const SHORT_DECLARED: usize = 100;


const LEFT_SECONDS: u64 = 10;


const PASSWORD_PAD: usize = 2000;


const DEEP: usize = 40;


const PASSWORD: &str = "hunter2-secret";


const USER: &str = "monitor";


const LONG_TIMEOUT_MS: u64 = 20_000;


const SHORT_TIMEOUT_MS: u64 = 300;


const MEMBER_COUNT: usize = 1_000_000;


const MEMORY_LIMIT: &str = "--as=1073741824";


const MEMORY_ENV: &str = "T425_MEMORY_CHILD";


const CHASSIS_COLLECTION: &str = r#"{"Members@odata.count":1,"Members":[{"@odata.id":"/redfish/v1/Chassis/1U"}]}"#;


const SYSTEMS_COLLECTION: &str = r#"{"Members@odata.count":1,"Members":[{"@odata.id":"/redfish/v1/Systems/437XR1138R2"}]}"#;


const ACCOUNTS_COLLECTION: &str = r#"{"Members":[{"@odata.id":"/redfish/v1/AccountService/Accounts/1"}]}"#;


const READ_ONLY: &str = r#"{"UserName":"monitor","RoleId":"ReadOnly"}"#;


const ADMIN: &str = r#"{"UserName":"monitor","RoleId":"Administrator"}"#;


const ACCOUNT_PATH: &str = "/redfish/v1/AccountService/Accounts/1";


const THERMAL_PATH: &str = "/redfish/v1/Chassis/1U/Thermal";


const CHASSIS_PATH: &str = "/redfish/v1/Chassis/1U";


pub struct Rig {
    pub dir: TempDir,
    pub standin: Standin,
    pub device: RedfishDevice,
}


fn mockup(_method: &str, path: &str) -> Reply {
    match path {
        "/redfish/v1/Chassis" => reply(STATUS_OK, CHASSIS_COLLECTION),
        CHASSIS_PATH => reply(STATUS_OK, CHASSIS),
        THERMAL_PATH => reply(STATUS_OK, THERMAL),
        "/redfish/v1/Chassis/1U/Power" => reply(STATUS_OK, POWER),
        "/redfish/v1/Systems" => reply(STATUS_OK, SYSTEMS_COLLECTION),
        "/redfish/v1/Systems/437XR1138R2" => reply(STATUS_OK, SYSTEM),
        "/redfish/v1/AccountService/Accounts" => reply(STATUS_OK, ACCOUNTS_COLLECTION),
        ACCOUNT_PATH => reply(STATUS_OK, READ_ONLY),
        _ => reply(STATUS_NOT_FOUND, "{}"),
    }
}


fn rig_with(handler: impl Fn(&str, &str) -> Reply + Send + Sync + 'static, timeout_ms: u64) -> Result<Rig, Box<dyn Error>> {
    let standin = start(handler)?;
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("ca.pem"), &standin.ca_pem)?;
    std::fs::write(dir.path().join("password"), format!("{PASSWORD}\n"))?;
    let device = RedfishDevice {
        name: "bmc1".to_owned(),
        base_url: format!("https://127.0.0.1:{}", standin.port),
        ca_file: Some(dir.path().join("ca.pem").display().to_string()),
        insecure_skip_verify: false,
        username: USER.to_owned(),
        password_file: dir.path().join("password").display().to_string(),
        timeout_ms,
    };
    Ok(Rig { dir, standin, device })
}


fn rig(handler: impl Fn(&str, &str) -> Reply + Send + Sync + 'static) -> Result<Rig, Box<dyn Error>> {
    rig_with(handler, LONG_TIMEOUT_MS)
}


fn poll(rig: &Rig) -> Result<DeviceReport, Box<dyn Error>> {
    Ok(poll_device(&rig.device, &tenant_scope("acme")?, &default_redfish_limits())?)
}


fn poll_error(rig: &Rig) -> Result<FetchError, Box<dyn Error>> {
    Ok(poll_device(&rig.device, &tenant_scope("acme")?, &default_redfish_limits())
        .err()
        .ok_or("accepted")?)
}


fn blind(field: &str) -> Health {
    Health::BlindSpot(BlindReason::UnreadableHealthField(field.to_owned()))
}


fn only_gets(rig: &Rig) -> bool {
    let log = requests(&rig.standin);
    !log.is_empty() && log.iter().all(|entry| entry.starts_with("GET ") && entry.ends_with("auth=true"))
}


fn file_verdict() -> Result<Health, Box<dyn Error>> {
    let mut readers = [CHASSIS, THERMAL, POWER, SYSTEM].map(str::as_bytes);
    let [chassis, thermal, power, system] = &mut readers;
    let report = parse_redfish(Some(chassis), Some(thermal), Some(power), Some(system), &default_redfish_limits())?;
    Ok(assess_redfish(&report))
}


fn chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |inner| (*inner).source())
        .map(|inner| format!("{inner} {inner:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}


fn session_for(rig: &Rig, deadline: Instant) -> Result<FetchSession, Box<dyn Error>> {
    Ok(FetchSession {
        agent: build_agent(&rig.device)?,
        auth: basic_header(USER, PASSWORD.as_bytes()),
        base: rig.device.base_url.clone(),
        deadline,
        max_bytes: default_redfish_limits().max_bytes,
    })
}


fn session(rig: &Rig) -> Result<FetchSession, Box<dyn Error>> {
    session_for(rig, Instant::now() + Duration::from_millis(LONG_TIMEOUT_MS))
}


fn with_override(path: &'static str, answer: fn() -> Reply) -> impl Fn(&str, &str) -> Reply + Send + Sync + 'static {
    move |method, requested| if requested == path { answer() } else { mockup(method, requested) }
}


fn not_found() -> Reply {
    reply(STATUS_NOT_FOUND, "{}")
}


fn redirect() -> Reply {
    Reply {
        location: Some("https://127.0.0.1:9/elsewhere".to_owned()),
        ..reply(STATUS_FOUND, "")
    }
}


fn oversized() -> Reply {
    let padding = "a".repeat(default_redfish_limits().max_bytes as usize);
    reply(STATUS_OK, &format!(r#"{{"pad":"{padding}"}}"#))
}


fn array_body() -> Reply {
    reply(STATUS_OK, "[]")
}


#[test]
fn the_four_documents_are_fetched_and_give_the_file_verdict() -> TestResult {
    let rig = rig(mockup)?;
    let report = poll(&rig)?;
    assert_eq!(report.health, file_verdict()?);
    assert_eq!(report.health, Health::Degraded(vec!["power supply 0 warning".to_owned()]));
    assert_eq!((report.device.as_str(), report.tenant.as_str()), ("bmc1", "acme"));
    assert!(!report.unverified_tls);
    assert_eq!(report.role, RoleCheck::NotAdministrator);
    assert!(only_gets(&rig));
    let log = requests(&rig.standin).join("\n");
    [
        CHASSIS_PATH,
        THERMAL_PATH,
        "/redfish/v1/Chassis/1U/Power",
        "/redfish/v1/Systems/437XR1138R2",
    ]
    .iter()
    .for_each(|path| assert!(log.contains(path), "{path} not requested"));
    Ok(())
}


#[test]
fn a_missing_thermal_document_is_a_blind_spot() -> TestResult {
    let rig = rig(with_override(THERMAL_PATH, not_found))?;
    assert_eq!(poll(&rig)?.health, blind("thermal document"));
    assert!(only_gets(&rig));
    Ok(())
}


#[test]
fn a_redirect_is_not_followed() -> TestResult {
    let rig = rig(with_override(CHASSIS_PATH, redirect))?;
    assert_eq!(poll(&rig)?.health, blind("chassis document"));
    assert!(!requests(&rig.standin).iter().any(|entry| entry.contains("elsewhere")));
    Ok(())
}


#[test]
fn a_body_over_the_limit_is_a_blind_spot() -> TestResult {
    let rig = rig(with_override(THERMAL_PATH, oversized))?;
    assert_eq!(poll(&rig)?.health, blind("thermal document"));
    Ok(())
}


#[test]
fn a_document_that_is_not_an_object_is_refused() -> TestResult {
    let rig = rig(with_override(THERMAL_PATH, array_body))?;
    assert_eq!(poll(&rig)?.health, blind("document refused"));
    Ok(())
}


fn hostile_chassis(id: &'static str) -> impl Fn(&str, &str) -> Reply + Send + Sync + 'static {
    move |method, path| {
        if path == "/redfish/v1/Chassis" {
            reply(STATUS_OK, &format!(r#"{{"Members":[{{"@odata.id":"{id}"}}]}}"#))
        } else {
            mockup(method, path)
        }
    }
}


#[test]
fn a_hostile_member_id_is_refused_and_never_requested() -> TestResult {
    let ids = [
        "/redfish/v1/Chassis/../../x",
        "/redfish/v1/Chassis/..",
        "/redfish/v1/Chassis/%2e%2e",
        "/redfish/v1/Systems/437XR1138R2",
        "/redfish/v1/Chassis/",
        "/redfish/v1/Chassis/a/b",
        "https://127.0.0.1:9/redfish/v1/Chassis/1U",
    ];
    ids.iter().try_for_each(|id| -> TestResult {
        let rig = rig(hostile_chassis(id))?;
        assert_eq!(poll(&rig)?.health, blind("chassis document"), "{id}");
        assert!(!requests(&rig.standin)
            .iter()
            .any(|entry| entry.contains("..") || entry.contains("%2e") || entry.contains(":9")));
        Ok(())
    })
}


#[test]
fn an_administrator_credential_is_refused_before_any_document() -> TestResult {
    let rig = rig(|method, path| {
        if path == ACCOUNT_PATH {
            reply(STATUS_OK, ADMIN)
        } else {
            mockup(method, path)
        }
    })?;
    let report = poll(&rig)?;
    assert_eq!(report.role, RoleCheck::Administrator);
    assert_eq!(report.health, blind("administrator credential"));
    assert!(!requests(&rig.standin)
        .iter()
        .any(|entry| entry.contains("Thermal") || entry.contains("Systems")));
    Ok(())
}


#[test]
fn an_unreadable_role_is_reported_unknown_and_the_poll_goes_on() -> TestResult {
    let bodies: [(u16, &'static str); BODY_CASES] = [
        (STATUS_NOT_FOUND, "{}"),
        (STATUS_OK, r#"{"UserName":"other","RoleId":"Administrator"}"#),
        (STATUS_OK, r#"{"UserName":"monitor"}"#),
        (STATUS_OK, "[]"),
        (STATUS_OK, r#"{"UserName":"monitor","RoleId":5}"#),
    ];
    bodies.into_iter().try_for_each(|(status, body)| -> TestResult {
        let rig = rig(move |method, path| {
            if path == ACCOUNT_PATH {
                reply(status, body)
            } else {
                mockup(method, path)
            }
        })?;
        let report = poll(&rig)?;
        assert_eq!(report.role, RoleCheck::Unknown, "{body}");
        assert_eq!(report.health, file_verdict()?);
        Ok(())
    })
}


#[test]
fn an_unreadable_accounts_collection_is_unknown() -> TestResult {
    let collections: [(u16, &'static str); COLLECTION_CASES] = [
        (STATUS_NOT_FOUND, "{}"),
        (STATUS_OK, r#"{"Members":[{"@odata.id":"/redfish/v1/Systems/1"}]}"#),
        (STATUS_OK, "{}"),
    ];
    collections.into_iter().try_for_each(|(status, body)| -> TestResult {
        let rig = rig(move |method, path| {
            if path == "/redfish/v1/AccountService/Accounts" {
                reply(status, body)
            } else {
                mockup(method, path)
            }
        })?;
        assert_eq!(poll(&rig)?.role, RoleCheck::Unknown);
        Ok(())
    })
}


#[test]
fn an_insecure_device_is_flagged_and_a_wrong_ca_is_a_blind_spot() -> TestResult {
    let mut insecure = rig(mockup)?;
    insecure.device.ca_file = None;
    insecure.device.insecure_skip_verify = true;
    let report = poll(&insecure)?;
    assert!(report.unverified_tls);
    assert_eq!(report.health, file_verdict()?);
    let mut wrong = rig(mockup)?;
    let other = rig(mockup)?;
    std::fs::write(wrong.dir.path().join("ca.pem"), &other.standin.ca_pem)?;
    wrong.device.timeout_ms = LONG_TIMEOUT_MS;
    let refused = poll(&wrong)?;
    assert!(!refused.unverified_tls);
    assert_eq!(refused.health, blind("chassis document"));
    Ok(())
}


#[test]
fn an_http_declaration_is_refused_before_any_connection() -> TestResult {
    let mut rig = rig(mockup)?;
    rig.device.base_url = format!("http://127.0.0.1:{}", rig.standin.port);
    let error = poll_error(&rig)?;
    assert!(error.to_string().contains("base_url"));
    assert!(requests(&rig.standin).is_empty());
    Ok(())
}


#[test]
fn a_slow_device_is_cut_at_the_injected_deadline() -> TestResult {
    let rig = rig(|_, _| Reply {
        declared: HUGE_DECLARED,
        hold: true,
        ..reply(STATUS_OK, "{")
    })?;
    let short = session_for(&rig, Instant::now() + Duration::from_millis(SHORT_TIMEOUT_MS))?;
    assert!(fetch_document(&short, CHASSIS_PATH, "chassis").is_none());
    assert!(requests(&rig.standin).iter().any(|entry| entry.contains(CHASSIS_PATH)));
    Ok(())
}


#[test]
fn every_get_failure_class_is_named() -> TestResult {
    let rig = rig(|_, path| match path {
        "/short" => Reply {
            declared: SHORT_DECLARED,
            ..reply(STATUS_OK, "{")
        },
        "/big" => oversized(),
        _ => reply(STATUS_ERROR, "{}"),
    })?;
    let live = session(&rig)?;
    let left = Duration::from_secs(LEFT_SECONDS);
    assert!(matches!(
        get_body(&live, &format!("{}/x", live.base), left),
        Err(GetError::Status(STATUS_ERROR))
    ));
    assert!(matches!(get_body(&live, &format!("{}/short", live.base), left), Err(GetError::Body(_))));
    assert!(matches!(get_body(&live, &format!("{}/big", live.base), left), Err(GetError::Oversized)));
    let expired = session_for(&rig, Instant::now())?;
    assert!(fetch_document(&expired, "/x", "x").is_none());
    assert_eq!(GetError::Expired.to_string(), "deadline reached");
    let closed = TcpListener::bind("127.0.0.1:0")?;
    let mut dead = rig.device.clone();
    dead.base_url = format!("https://127.0.0.1:{}", closed.local_addr()?.port());
    drop(closed);
    let unreachable = FetchSession {
        base: dead.base_url.clone(),
        ..session(&rig)?
    };
    let failure = get_body(&unreachable, &format!("{}/x", unreachable.base), left)
        .err()
        .ok_or("connected")?;
    assert!(matches!(failure, GetError::Transport(_)));
    assert!(!chain(&failure).contains(PASSWORD));
    Ok(())
}


#[test]
fn the_password_never_reaches_an_error_text() -> TestResult {
    let secret_file = |name: &str, content: String| -> Result<(Rig, String), Box<dyn Error>> {
        let rig = rig(mockup)?;
        let path = rig.dir.path().join(name).display().to_string();
        std::fs::write(&path, content)?;
        Ok((rig, path))
    };
    let (mut big, big_path) = secret_file("big", format!("{PASSWORD}{}", "x".repeat(PASSWORD_PAD)))?;
    big.device.password_file = big_path;
    let too_big = poll_error(&big)?;
    assert!(matches!(too_big, FetchError::Password(_)));
    let (mut junk, junk_path) = secret_file("junk.pem", PASSWORD.to_owned())?;
    junk.device.ca_file = Some(junk_path);
    let bad_ca = poll_error(&junk)?;
    assert!(matches!(bad_ca, FetchError::CaInvalid(_)));
    let mut missing = rig(mockup)?;
    missing.device.password_file = missing.dir.path().join("absent").display().to_string();
    let no_password = poll_error(&missing)?;
    let mut no_ca = rig(mockup)?;
    no_ca.device.ca_file = Some(no_ca.dir.path().join("absent.pem").display().to_string());
    let missing_ca = poll_error(&no_ca)?;
    assert!(matches!(missing_ca, FetchError::CaFile(_)));
    let encoded = STANDARD.encode(format!("{USER}:{PASSWORD}"));
    let ok_rig = rig(mockup)?;
    let report = poll(&ok_rig)?;
    [
        chain(&too_big),
        chain(&bad_ca),
        chain(&no_password),
        chain(&missing_ca),
        format!("{report:?}"),
    ]
    .iter()
    .for_each(|text| assert!(!text.contains(PASSWORD) && !text.contains(&encoded), "{text}"));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_password_file_must_be_a_regular_file_and_a_symlink_is_followed() -> TestResult {
    let mut rig = rig(mockup)?;
    rig.device.password_file = rig.dir.path().display().to_string();
    assert!(matches!(poll_error(&rig)?, FetchError::Password(_)));
    let link = rig.dir.path().join("link");
    std::os::unix::fs::symlink(rig.dir.path().join("password"), &link)?;
    rig.device.password_file = link.display().to_string();
    assert_eq!(poll(&rig)?.health, file_verdict()?);
    Ok(())
}


#[test]
fn the_basic_header_is_standard_basic_auth() -> TestResult {
    assert_eq!(basic_header("Aladdin", b"open sesame").as_str(), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    Ok(())
}


#[test]
fn member_paths_count_before_building_and_refuse_every_odd_shape() -> TestResult {
    let prefix = "/redfish/v1/Chassis/";
    let numbers = format!(r#"{{"Members":[{}1]}}"#, "1,".repeat(MAX_MEMBERS));
    assert!(matches!(member_paths(numbers.as_bytes(), prefix), Err(DiscoverError::TooMany { .. })));
    let ok = format!(
        r#"{{"Members":[{}{{"@odata.id":"/redfish/v1/Chassis/z"}}]}}"#,
        r#"{"@odata.id":"/redfish/v1/Chassis/a"},"#.repeat(MAX_MEMBERS - 1)
    );
    assert_eq!(member_paths(ok.as_bytes(), prefix)?.len(), MAX_MEMBERS);
    assert!(matches!(member_paths(b"{}", prefix), Err(DiscoverError::NoMembers)));
    assert!(matches!(member_paths(br#"{"Members":{}}"#, prefix), Err(DiscoverError::Malformed { .. })));
    assert!(matches!(
        member_paths(br#"{"Members":[1]}"#, prefix),
        Err(DiscoverError::Malformed { .. })
    ));
    assert!(matches!(member_paths(b"[", prefix), Err(DiscoverError::Malformed { .. })));
    assert!(matches!(member_paths(br#"{"Members":[{}]}"#, prefix), Err(DiscoverError::BadId)));
    let deep = format!("{}{}", "[".repeat(DEEP), "]".repeat(DEEP));
    assert!(matches!(member_paths(deep.as_bytes(), prefix), Err(DiscoverError::TooDeep)));
    assert_eq!(DiscoverError::TooDeep.to_string(), "document nesting is deeper than the limit");
    Ok(())
}


#[test]
fn the_member_path_grammar_is_ascii_one_segment() -> TestResult {
    let prefix = "/redfish/v1/Chassis/";
    let long = format!("{prefix}{}", "a".repeat(MAX_ID_BYTES));
    assert!(is_member_path("/redfish/v1/Chassis/1U", prefix));
    assert!(is_member_path("/redfish/v1/Chassis/a.b_c-d", prefix));
    [
        "/redfish/v1/Chassis/",
        "/redfish/v1/Chassis/.",
        "/redfish/v1/Chassis/..",
        "/redfish/v1/Chassis/a/b",
        "/redfish/v1/Chassis/%2e",
        "/x",
        "",
        "/redfish/v1/Chassis/é",
    ]
    .iter()
    .for_each(|id| assert!(!is_member_path(id, prefix), "{id}"));
    assert!(!is_member_path(&long, prefix));
    Ok(())
}


#[test]
fn a_role_is_read_only_for_the_configured_user() -> TestResult {
    assert_eq!(role_in(READ_ONLY.as_bytes(), USER)?, Some(RoleCheck::NotAdministrator));
    assert_eq!(role_in(ADMIN.as_bytes(), USER)?, Some(RoleCheck::Administrator));
    assert_eq!(role_in(ADMIN.as_bytes(), "other")?, None);
    assert_eq!(role_in(br#"{"UserName":"monitor"}"#, USER)?, Some(RoleCheck::Unknown));
    Ok(())
}


#[test]
fn a_hostile_collection_is_refused_under_a_memory_limit() -> TestResult {
    let output = std::process::Command::new("prlimit")
        .arg(MEMORY_LIMIT)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--exact", "memory_limited_child", "--test-threads=1"])
        .env(MEMORY_ENV, "1")
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"), "the child test did not run");
    Ok(())
}


#[test]
fn memory_limited_child() -> TestResult {
    if std::env::var_os(MEMORY_ENV).is_some() {
        let members = format!(r#"{{"Members":[{}{{}}]}}"#, "{},".repeat(MEMBER_COUNT));
        let hostile = rig(move |method, path| {
            if path == "/redfish/v1/Chassis" {
                reply(STATUS_OK, &members)
            } else {
                mockup(method, path)
            }
        })?;
        assert_eq!(poll(&hostile)?.health, blind("chassis document"));
    }
    Ok(())
}
