#[path = "common/api.rs"]
mod api;
#[path = "common/api/types.rs"]
mod apitypes;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/types.rs"]
mod types;


use api::{
    answer, review_answer, review_of, rig, seen_of, settings_for, start, write_file, Answer, Rig, Seen, BAD_REQUEST, CREATED, NOT_FOUND, OK, TOKEN,
};
use apitypes::Handler;
use fixtures::{list, node, pod, set};
use k8s_inventory::access::{check_read_only, read_permissions, review_body, write_permissions, REVIEW_MAX_BYTES, WRITE_TARGETS, WRITE_VERBS};
use k8s_inventory::error::{FetchError, InventoryError, ParseError};
use k8s_inventory::fetch::{bearer_of, fetch_inventory, fetch_with, get_reply, new_agent, open_session, post_reply, Session, NODES_PATH, PODS_PATH};
use k8s_inventory::inventory::{inventory_cluster, inventory_nodes, inventory_pods, inventory_skipped_pods, Inventory};
use k8s_inventory::limits::{CEILING_PAGES, CEILING_TOTAL_ITEMS, DEFAULT_MAX_ITEMS};
use k8s_inventory::settings::{
    check_api_url, default_timeout_ms, load_settings, validate_settings, FetchSettings, CEILING_PAGE_BYTES, CEILING_RUN_BYTES, DEFAULT_TIMEOUT_MS,
    MAX_TIMEOUT_MS, MAX_URL_BYTES, MIN_TIMEOUT_MS,
};
use serde_json::{json, Value};
use std::error::Error;
use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use types::TestResult;


const OVER: usize = 1;


const TWO: usize = 2;


const CASES: usize = 12;


const THREE: usize = 3;


const FOUR: usize = 4;


const PAD_SLACK: usize = 200;


const NINETEEN: usize = 19;


const TWENTY: usize = 20;


const STATUS_GONE: u16 = 410;


const STATUS_SERVER_ERROR: u16 = 500;


const STATUS_FOUND: u16 = 302;


const STATUS_FORBIDDEN: u16 = 403;


const SMALL_PAGE: u64 = 2_048;


const SMALL_RUN: u64 = 5_000;


const TWO_PAGES: usize = 2;


const MEBIBYTE: usize = 1_048_576;


const HOSTILE_BODY: usize = 8_388_608;


const GIBIBYTE: &str = "--as=1073741824";


const CHILD_ENV: &str = "K8S_FETCH_MEMORY_CHILD";


const CHILD_TEST: &str = "memory_child_refuses_hostile_pages";


const RUN_BYTES_HOSTILE: u64 = 2_621_440;


const TRACE_TOKEN: &str = "TRACE-ONLY-TOKEN-9f3c71";


#[derive(Clone, Copy)]
pub struct Scenario {
    allow: fn(&str, &str) -> bool,
    pods: fn(&Seen) -> Answer,
    nodes: fn(&Seen) -> Answer,
}


fn page(kind: &str, items: Vec<Value>, next: &str) -> Answer {
    answer(OK, json!({"kind": kind, "metadata": {"continue": next}, "items": items}).to_string())
}


fn view_only(verb: &str, _resource: &str) -> bool {
    verb == "list"
}


fn edit_role(verb: &str, resource: &str) -> bool {
    matches!(verb, "list" | "create" | "update") && matches!(resource, "pods" | "nodes")
}


fn nothing(_verb: &str, _resource: &str) -> bool {
    false
}


fn only_wildcard(verb: &str, _resource: &str) -> bool {
    verb == "*" || verb == "list"
}


fn no_node_list(verb: &str, resource: &str) -> bool {
    verb == "list" && resource == "pods"
}


fn three_pod_pages(seen: &Seen) -> Answer {
    if seen.target.contains("continue=t2") {
        page("PodList", vec![pod("p3", "p3")], "")
    } else if seen.target.contains("continue=t1") {
        page("PodList", vec![pod("p2", "p2")], "t2")
    } else {
        page("PodList", vec![pod("p1", "p1")], "t1=")
    }
}


fn one_node(_seen: &Seen) -> Answer {
    answer(OK, String::from_utf8_lossy(&list("NodeList", vec![node("n1", "n1")])).into_owned())
}


fn gone_on_second(seen: &Seen) -> Answer {
    if seen.target.contains("continue=") {
        answer(STATUS_GONE, "expired".to_owned())
    } else {
        page("PodList", vec![pod("p1", "p1")], "t1")
    }
}


fn server_error(_seen: &Seen) -> Answer {
    answer(STATUS_SERVER_ERROR, "SECRET-SERVER-TEXT".to_owned())
}


fn forbidden(_seen: &Seen) -> Answer {
    answer(STATUS_FORBIDDEN, "SECRET-SERVER-TEXT".to_owned())
}


fn endless_tokens(_seen: &Seen) -> Answer {
    page("PodList", vec![pod("p1", "p1")], "again")
}


fn wrong_kind(_seen: &Seen) -> Answer {
    page("SecretList", vec![], "")
}


fn padded_page(size: usize, next: &str) -> Answer {
    let pad = "x".repeat(size);
    answer(
        OK,
        json!({"kind": "PodList", "metadata": {"continue": next}, "items": [], "pad": pad}).to_string(),
    )
}


fn large_pages(_seen: &Seen) -> Answer {
    padded_page(SMALL_PAGE as usize - PAD_SLACK, "more")
}


fn handler(scenario: Scenario) -> Handler {
    Arc::new(move |seen: &Seen| {
        if seen.method == "POST" {
            review_of(seen).map_or_else(
                || answer(BAD_REQUEST, String::new()),
                |(verb, resource)| review_answer((scenario.allow)(&verb, &resource)),
            )
        } else if seen.target.starts_with(PODS_PATH) {
            (scenario.pods)(seen)
        } else if seen.target.starts_with(NODES_PATH) {
            (scenario.nodes)(seen)
        } else {
            answer(NOT_FOUND, String::new())
        }
    })
}


fn standard() -> Scenario {
    Scenario {
        allow: view_only,
        pods: three_pod_pages,
        nodes: one_node,
    }
}


fn run(rig: &Rig) -> Result<Inventory, FetchError> {
    let mut session = open_session(&rig.settings)?;
    fetch_with(&mut session, &rig.settings)
}


fn requests(rig: &Rig) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    Ok(seen_of(&rig.stub)?.into_iter().map(|seen| (seen.method, seen.target)).collect())
}


fn lists_sent(rig: &Rig) -> Result<usize, Box<dyn Error>> {
    Ok(requests(rig)?.iter().filter(|(method, _)| method == "GET").count())
}


fn chain(error: &dyn Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    (0..TWENTY).for_each(|_| {
        if let Some(cause) = source {
            text.push_str(&format!(" | {cause}"));
            source = cause.source();
        }
    });
    text
}


#[test]
fn a_view_token_lists_three_pages_with_exactly_the_previous_token_and_merges_them() -> TestResult {
    let rig = rig(handler(standard()))?;
    let inventory = run(&rig)?;
    assert_eq!(inventory_pods(&inventory).len(), THREE);
    assert_eq!(inventory_nodes(&inventory).len(), 1);
    assert_eq!(inventory_cluster(&inventory), "prod-1");
    let seen = seen_of(&rig.stub)?;
    let lists = seen
        .iter()
        .filter(|entry| entry.method == "GET")
        .map(|entry| entry.target.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        lists,
        vec![
            "/api/v1/pods?limit=512",
            "/api/v1/pods?limit=512&continue=t1%3D",
            "/api/v1/pods?limit=512&continue=t2",
            "/api/v1/nodes?limit=512"
        ]
    );
    assert_eq!(seen.len(), NINETEEN + FOUR);
    assert!(seen.iter().all(|entry| entry.authorization == format!("Bearer {TOKEN}")));
    assert!(seen.iter().take(NINETEEN).all(|entry| entry.method == "POST"));
    Ok(())
}


#[test]
fn a_page_size_setting_is_the_limit_sent() -> TestResult {
    let mut rig = rig(handler(standard()))?;
    rig.settings.page_size = Some(TWO_PAGES);
    run(&rig)?;
    assert!(requests(&rig)?.iter().any(|(_, target)| target == "/api/v1/pods?limit=2"));
    Ok(())
}


#[test]
fn a_writable_token_is_refused_before_any_list() -> TestResult {
    let rig = rig(handler(Scenario {
        allow: edit_role,
        ..standard()
    }))?;
    let refused = run(&rig).err().ok_or("a writable token ran")?;
    assert!(matches!(
        refused,
        FetchError::WritableCredential {
            verb: "create",
            resource: "pods"
        }
    ));
    assert_eq!(lists_sent(&rig)?, 0);
    let wild = self::rig(handler(Scenario {
        allow: only_wildcard,
        ..standard()
    }))?;
    assert!(matches!(
        run(&wild).err().ok_or("a wildcard token ran")?,
        FetchError::WritableCredential { verb: "*", resource: "*" }
    ));
    assert_eq!(lists_sent(&wild)?, 0);
    Ok(())
}


#[test]
fn a_token_that_cannot_list_is_refused_and_every_permission_is_asked() -> TestResult {
    let rig = rig(handler(Scenario {
        allow: no_node_list,
        ..standard()
    }))?;
    assert!(matches!(run(&rig).err().ok_or("ran")?, FetchError::MissingRead { resource: "nodes" }));
    assert_eq!(lists_sent(&rig)?, 0);
    let all = write_permissions();
    assert_eq!(all.len(), WRITE_VERBS.len() * WRITE_TARGETS.len() + 1);
    assert_eq!(read_permissions().len(), TWO);
    let body = review_body(all.last().ok_or("none")?);
    assert!(body.contains(r#""verb":"*""#) && body.contains(r#""resource":"*""#));
    let denied = self::rig(handler(Scenario {
        allow: nothing,
        ..standard()
    }))?;
    assert!(matches!(run(&denied).err().ok_or("ran")?, FetchError::MissingRead { resource: "pods" }));
    Ok(())
}


#[test]
fn a_bad_review_answer_is_refused_without_its_text() -> TestResult {
    let broken: Handler = Arc::new(|_| answer(CREATED, "{\"status\":{\"reason\":\"SECRET-SERVER-TEXT\"}}".to_owned()));
    let rig = rig(broken)?;
    let error = run(&rig).err().ok_or("ran")?;
    assert!(matches!(error, FetchError::ReviewMalformed { .. }));
    assert!(!error.to_string().contains("SECRET"));
    let failing: Handler = Arc::new(|_| answer(STATUS_SERVER_ERROR, String::new()));
    assert!(matches!(
        run(&self::rig(failing)?).err().ok_or("ran")?,
        FetchError::Status { status: STATUS_SERVER_ERROR }
    ));
    let big: Handler = Arc::new(|_| answer(OK, " ".repeat(REVIEW_MAX_BYTES as usize + OVER)));
    assert!(matches!(
        run(&self::rig(big)?).err().ok_or("ran")?,
        FetchError::TooLarge { max: REVIEW_MAX_BYTES }
    ));
    let plain_ok: Handler = Arc::new(|_| answer(OK, "{\"status\":{\"allowed\":false}}".to_owned()));
    assert!(matches!(
        run(&self::rig(plain_ok)?).err().ok_or("ran")?,
        FetchError::MissingRead { resource: "pods" }
    ));
    Ok(())
}


#[test]
fn a_410_mid_run_is_incomplete_and_gives_no_inventory() -> TestResult {
    let rig = rig(handler(Scenario {
        pods: gone_on_second,
        ..standard()
    }))?;
    assert!(matches!(run(&rig).err().ok_or("ran")?, FetchError::Parse(ParseError::Incomplete)));
    Ok(())
}


#[test]
fn a_500_or_403_or_wrong_kind_gives_no_inventory_and_only_the_status_number() -> TestResult {
    let rig = rig(handler(Scenario {
        pods: server_error,
        ..standard()
    }))?;
    let error = run(&rig).err().ok_or("ran")?;
    assert!(matches!(error, FetchError::Status { status: STATUS_SERVER_ERROR }));
    assert!(!chain(&error).contains("SECRET"));
    let denied = self::rig(handler(Scenario {
        nodes: forbidden,
        ..standard()
    }))?;
    assert!(matches!(
        run(&denied).err().ok_or("ran")?,
        FetchError::Status { status: STATUS_FORBIDDEN }
    ));
    let kind = self::rig(handler(Scenario {
        pods: wrong_kind,
        ..standard()
    }))?;
    assert!(matches!(run(&kind).err().ok_or("ran")?, FetchError::Parse(ParseError::WrongKind { .. })));
    Ok(())
}


#[test]
fn endless_tokens_stop_at_max_pages_as_incomplete() -> TestResult {
    let mut rig = rig(handler(Scenario {
        pods: endless_tokens,
        ..standard()
    }))?;
    rig.settings.max_pages = Some(THREE);
    assert!(matches!(run(&rig).err().ok_or("ran")?, FetchError::Parse(ParseError::Incomplete)));
    let pod_lists = requests(&rig)?.iter().filter(|(_, target)| target.starts_with(PODS_PATH)).count();
    assert_eq!(pod_lists, THREE);
    Ok(())
}


#[test]
fn a_page_over_max_bytes_is_refused_and_the_run_budget_is_enforced() -> TestResult {
    let mut rig = rig(handler(Scenario {
        pods: large_pages,
        ..standard()
    }))?;
    rig.settings.max_bytes = Some(SMALL_PAGE / TWO_PAGES as u64);
    assert!(matches!(
        run(&rig).err().ok_or("ran")?,
        FetchError::TooLarge { max } if max == SMALL_PAGE / TWO_PAGES as u64
    ));
    let mut budget = self::rig(handler(Scenario {
        pods: large_pages,
        ..standard()
    }))?;
    budget.settings.max_bytes = Some(SMALL_PAGE);
    budget.settings.max_run_bytes = Some(SMALL_RUN);
    assert!(matches!(run(&budget).err().ok_or("ran")?, FetchError::RunTooLarge { .. }));
    let pod_lists = requests(&budget)?.iter().filter(|(_, target)| target.starts_with(PODS_PATH)).count();
    assert_eq!(pod_lists, THREE);
    Ok(())
}


#[test]
fn a_redirect_is_not_followed() -> TestResult {
    let elsewhere = start(handler(standard()))?;
    let target = format!("https://localhost:{}/api/v1/pods", elsewhere.port);
    let redirecting: Handler = Arc::new(move |seen: &Seen| {
        if seen.method == "POST" {
            review_answer(seen.body.contains("\"list\""))
        } else {
            Answer {
                status: STATUS_FOUND,
                location: Some(target.clone()),
                body: Vec::new(),
                declared: None,
            }
        }
    });
    let rig = rig(redirecting)?;
    assert!(matches!(run(&rig).err().ok_or("ran")?, FetchError::Status { status: STATUS_FOUND }));
    assert!(seen_of(&elsewhere)?.is_empty());
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing() -> TestResult {
    let rig = rig(handler(standard()))?;
    let mut session = open_session(&rig.settings)?;
    session.timeout = Duration::ZERO;
    assert!(matches!(
        get_reply(&mut session, PODS_PATH, &[], 1).err().ok_or("sent")?,
        FetchError::Deadline
    ));
    assert!(matches!(
        post_reply(&mut session, "/x", "{}", 1).err().ok_or("sent")?,
        FetchError::Deadline
    ));
    assert!(seen_of(&rig.stub)?.is_empty());
    Ok(())
}


#[test]
fn a_dead_port_an_unknown_ca_and_a_cut_body_are_refused() -> TestResult {
    let rig = rig(handler(standard()))?;
    let closed = TcpListener::bind("127.0.0.1:0")?;
    let mut refused = rig.settings.clone();
    refused.api_url = format!("https://localhost:{}", closed.local_addr()?.port());
    drop(closed);
    let mut dead = open_session(&refused)?;
    let error = get_reply(&mut dead, PODS_PATH, &[], 1).err().ok_or("connected")?;
    assert!(matches!(error, FetchError::Transport(_)));
    assert!(!chain(&error).contains(TOKEN));
    let other = self::rig(handler(standard()))?;
    let mut foreign = rig.settings.clone();
    foreign.ca_file = write_file(other.dir.path(), "other-ca.pem", &other.stub.ca_pem)?.into();
    let mut untrusted = open_session(&foreign)?;
    assert!(matches!(
        get_reply(&mut untrusted, PODS_PATH, &[], 1).err().ok_or("trusted")?,
        FetchError::Transport(_)
    ));
    let cut: Handler = Arc::new(|_| Answer {
        status: OK,
        location: None,
        body: b"{}".to_vec(),
        declared: Some(MEBIBYTE),
    });
    let truncated = self::rig(cut)?;
    let mut session = open_session(&truncated.settings)?;
    assert!(matches!(
        get_reply(&mut session, PODS_PATH, &[], u64::MAX / TWO_PAGES as u64).err().ok_or("read")?,
        FetchError::Body(_)
    ));
    Ok(())
}


#[test]
fn the_token_and_the_ca_are_read_through_checked_files() -> TestResult {
    let rig = rig(handler(standard()))?;
    let dir = rig.dir.path();
    let mut missing = rig.settings.clone();
    missing.token_file = dir.join("absent");
    assert!(matches!(open_session(&missing).err().ok_or("opened")?, FetchError::Token(_)));
    let mut empty = rig.settings.clone();
    empty.token_file = write_file(dir, "empty", "\n")?.into();
    assert!(matches!(open_session(&empty).err().ok_or("opened")?, FetchError::Token(_)));
    let mut spaced = rig.settings.clone();
    spaced.token_file = write_file(dir, "spaced", "two words")?.into();
    assert!(matches!(open_session(&spaced).err().ok_or("opened")?, FetchError::TokenEncoding));
    let mut directory = rig.settings.clone();
    directory.token_file = dir.into();
    assert!(matches!(open_session(&directory).err().ok_or("opened")?, FetchError::Token(_)));
    let mut no_ca = rig.settings.clone();
    no_ca.ca_file = dir.join("absent");
    assert!(matches!(open_session(&no_ca).err().ok_or("opened")?, FetchError::CaFile(_)));
    let mut bad_ca = rig.settings.clone();
    bad_ca.ca_file = write_file(dir, "bad-ca.pem", "not a certificate")?.into();
    assert!(matches!(open_session(&bad_ca).err().ok_or("opened")?, FetchError::CaInvalid(_)));
    assert!(matches!(new_agent(b"").err().ok_or("agent")?, FetchError::CaInvalid(_)));
    assert!(bearer_of(b"a\nb").is_err());
    assert_eq!(bearer_of(b"abc")?.as_str(), "Bearer abc");
    let mut invalid = rig.settings.clone();
    invalid.api_url = "http://localhost:1".to_owned();
    assert!(matches!(open_session(&invalid).err().ok_or("opened")?, FetchError::ApiUrl));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlinked_token_is_read_through_the_checked_handle() -> TestResult {
    let rig = rig(handler(standard()))?;
    let target = write_file(rig.dir.path(), "real-token", TOKEN)?;
    let link = rig.dir.path().join("link-token");
    std::os::unix::fs::symlink(&target, &link)?;
    let mut linked = rig.settings.clone();
    linked.token_file = link.clone();
    assert!(open_session(&linked).is_ok());
    let to_dir = rig.dir.path().join("link-dir");
    std::os::unix::fs::symlink(rig.dir.path(), &to_dir)?;
    linked.token_file = to_dir;
    assert!(matches!(open_session(&linked).err().ok_or("opened")?, FetchError::Token(_)));
    Ok(())
}


fn settings_error(change: fn(&mut FetchSettings)) -> Result<FetchError, Box<dyn Error>> {
    let rig = rig(handler(standard()))?;
    let mut settings = rig.settings.clone();
    change(&mut settings);
    validate_settings(&settings).err().ok_or_else(|| "accepted".into())
}


#[test]
fn settings_outside_their_ranges_are_refused() -> TestResult {
    let fields = [
        "timeout_ms",
        "timeout_ms",
        "max_bytes",
        "max_bytes",
        "max_run_bytes",
        "max_run_bytes",
        "max_pages",
        "max_pages",
        "max_total_items",
        "max_total_items",
        "page_size",
        "page_size",
    ];
    let changes: [fn(&mut FetchSettings); CASES] = [
        |settings| settings.timeout_ms = MIN_TIMEOUT_MS - 1,
        |settings| settings.timeout_ms = MAX_TIMEOUT_MS + 1,
        |settings| settings.max_bytes = Some(0),
        |settings| settings.max_bytes = Some(CEILING_PAGE_BYTES + 1),
        |settings| settings.max_run_bytes = Some(CEILING_RUN_BYTES + 1),
        |settings| settings.max_run_bytes = Some(0),
        |settings| settings.max_pages = Some(0),
        |settings| settings.max_pages = Some(CEILING_PAGES + 1),
        |settings| settings.max_total_items = Some(0),
        |settings| settings.max_total_items = Some(CEILING_TOTAL_ITEMS + 1),
        |settings| settings.page_size = Some(0),
        |settings| settings.page_size = Some(DEFAULT_MAX_ITEMS + 1),
    ];
    fields.iter().zip(changes).try_for_each(|(field, change)| -> TestResult {
        match settings_error(change)? {
            FetchError::Range { field: found, .. } => {
                assert_eq!(found, *field);
                Ok(())
            }
            other => Err(format!("unexpected {other}").into()),
        }
    })?;
    assert!(matches!(
        settings_error(|settings| settings.tenant = "-x".to_owned())?,
        FetchError::Scope(InventoryError::Tenant(_))
    ));
    assert!(matches!(
        settings_error(|settings| settings.cluster = String::new())?,
        FetchError::Scope(InventoryError::Cluster(_))
    ));
    assert_eq!(default_timeout_ms(), DEFAULT_TIMEOUT_MS);
    Ok(())
}


#[test]
fn an_http_url_or_a_path_or_userinfo_is_refused() -> TestResult {
    [
        "http://localhost:6443",
        "https://localhost:6443/api",
        "https://localhost:6443/",
        "https://u@localhost",
        "https://",
        "localhost:6443",
        "https://h?x=1",
        "https://a b",
        "https://h#f",
    ]
    .iter()
    .try_for_each(|url| -> TestResult {
        assert!(matches!(check_api_url(url), Err(FetchError::ApiUrl)), "{url}");
        Ok(())
    })?;
    let long = format!("https://{}", "a".repeat(MAX_URL_BYTES));
    assert!(matches!(check_api_url(&long), Err(FetchError::ApiUrl)));
    assert!(check_api_url("https://10.0.0.5:6443").is_ok());
    assert!(check_api_url("https://[::1]:6443").is_ok());
    Ok(())
}


#[test]
fn a_settings_file_is_strict_and_a_run_from_it_prints_the_inventory() -> TestResult {
    let rig = rig(handler(standard()))?;
    let dir = rig.dir.path();
    let text = format!(
        "api_url: {}\nca_file: {}\ntoken_file: {}\ntenant: acme\ncluster: prod-1\n",
        rig.settings.api_url,
        rig.settings.ca_file.display(),
        rig.settings.token_file.display()
    );
    let good = write_file(dir, "good.yaml", &text)?;
    assert_eq!(load_settings(good.as_ref())?.timeout_ms, DEFAULT_TIMEOUT_MS);
    let inventory = fetch_inventory(good.as_ref())?;
    assert_eq!(inventory_pods(&inventory).len(), THREE);
    let unknown = write_file(dir, "unknown.yaml", &format!("{text}extra: 1\n"))?;
    assert!(matches!(load_settings(unknown.as_ref()), Err(FetchError::Config(_))));
    let http = write_file(dir, "http.yaml", &text.replace("https://", "http://"))?;
    assert!(matches!(fetch_inventory(http.as_ref()), Err(FetchError::ApiUrl)));
    let pathy = write_file(dir, "path.yaml", &text.replace(" acme", " acme\napi_path: x"))?;
    assert!(matches!(load_settings(pathy.as_ref()), Err(FetchError::Config(_))));
    let in_url = write_file(
        dir,
        "url-path.yaml",
        &text.replacen("api_url: https://localhost", "api_url: https://localhost/v1#", 1),
    )?;
    assert!(matches!(load_settings(in_url.as_ref()), Err(FetchError::ApiUrl)));
    Ok(())
}


#[test]
fn the_token_never_appears_in_any_error_text() -> TestResult {
    let rig = rig(handler(standard()))?;
    let closed = TcpListener::bind("127.0.0.1:0")?;
    let mut dead = rig.settings.clone();
    dead.api_url = format!("https://localhost:{}", closed.local_addr()?.port());
    drop(closed);
    let mut session = open_session(&dead)?;
    let transport = get_reply(&mut session, PODS_PATH, &[("continue", TOKEN)], 1).err().ok_or("connected")?;
    let mut token_file = rig.settings.clone();
    token_file.token_file = rig.dir.path().join("absent-token");
    let real = vec![
        transport,
        open_session(&token_file).err().ok_or("opened")?,
        FetchError::TokenEncoding,
        FetchError::ApiUrl,
        FetchError::Deadline,
        FetchError::Status { status: STATUS_SERVER_ERROR },
        FetchError::TooLarge { max: 1 },
        FetchError::RunTooLarge { max: 1 },
        FetchError::ReviewMalformed {
            category: serde_json::error::Category::Data,
        },
        FetchError::WritableCredential {
            verb: "create",
            resource: "pods",
        },
        FetchError::MissingRead { resource: "pods" },
        FetchError::Range {
            field: "max_bytes",
            min: 1,
            max: TWO as u64,
        },
        FetchError::Parse(ParseError::Incomplete),
        FetchError::Body(std::io::Error::other("cut")),
    ];
    real.iter().for_each(|error| {
        let text = chain(error);
        assert!(!text.contains(TOKEN), "{text}");
        assert!(!format!("{error:?}").contains(&format!("Bearer {TOKEN}")));
    });
    let other = self::rig(handler(Scenario {
        allow: edit_role,
        ..standard()
    }))?;
    let refused = run(&other).err().ok_or("ran")?;
    assert!(!chain(&refused).contains(TOKEN));
    Ok(())
}


#[test]
fn a_bad_uid_page_still_yields_the_run_with_a_skip_count() -> TestResult {
    fn bad_pod_page(_seen: &Seen) -> Answer {
        let mut bad = pod("bad", "bad");
        set(&mut bad, "/metadata/uid", json!("NOT-A-UID")).map_or_else(
            |error| answer(STATUS_SERVER_ERROR, error.to_string()),
            |()| page("PodList", vec![bad, pod("ok", "ok")], ""),
        )
    }
    let rig = rig(handler(Scenario {
        pods: bad_pod_page,
        ..standard()
    }))?;
    let inventory = run(&rig)?;
    assert_eq!(inventory_pods(&inventory).len(), 1);
    assert_eq!(inventory_skipped_pods(&inventory).bad_field, 1);
    Ok(())
}


#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().map_err(|_| std::io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


#[test]
fn a_trace_subscriber_never_sees_the_token_through_ureq_or_this_crate() -> TestResult {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .try_init()
        .map_err(|error| error.to_string())?;
    let rig = rig(handler(standard()))?;
    write_file(rig.dir.path(), "token", TRACE_TOKEN)?;
    run(&rig)?;
    let broken = self::rig(handler(Scenario {
        pods: server_error,
        ..standard()
    }))?;
    write_file(broken.dir.path(), "token", TRACE_TOKEN)?;
    let yaml = format!(
        "api_url: {}\nca_file: {}\ntoken_file: {}\ntenant: acme\ncluster: prod-1\n",
        broken.settings.api_url,
        broken.settings.ca_file.display(),
        broken.settings.token_file.display()
    );
    let file = write_file(broken.dir.path(), "settings.yaml", &yaml)?;
    assert!(fetch_inventory(file.as_ref()).is_err());
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(logged.contains("k8s inventory fetch refused: the API answered status 500"), "{logged}");
    assert!(logged.contains("ureq"), "ureq logged nothing: the check proves nothing");
    assert!(!logged.contains(TRACE_TOKEN));
    assert!(!logged.contains("SECRET-SERVER-TEXT"));
    Ok(())
}


fn hostile_pages(seen: &Seen) -> Answer {
    padded_page(MEBIBYTE - PAD_SLACK, if seen.method.is_empty() { "" } else { "more" })
}


#[test]
fn memory_child_refuses_hostile_pages() -> TestResult {
    if std::env::var_os(CHILD_ENV).is_some() {
        let mut big = rig(handler(Scenario {
            pods: |_| padded_page(HOSTILE_BODY, ""),
            ..standard()
        }))?;
        big.settings.max_bytes = Some(MEBIBYTE as u64);
        assert!(matches!(run(&big).err().ok_or("ran")?, FetchError::TooLarge { .. }));
        let mut many = rig(handler(Scenario {
            pods: hostile_pages,
            ..standard()
        }))?;
        many.settings.max_bytes = Some(MEBIBYTE as u64);
        many.settings.max_run_bytes = Some(RUN_BYTES_HOSTILE);
        assert!(matches!(run(&many).err().ok_or("ran")?, FetchError::RunTooLarge { .. }));
    }
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_child_under_an_address_space_limit_refuses_hostile_pages() -> TestResult {
    let output = std::process::Command::new("prlimit")
        .arg(GIBIBYTE)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--exact", CHILD_TEST, "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"), "the child test did not run");
    Ok(())
}


#[test]
fn the_session_helpers_are_reachable_for_a_direct_check() -> TestResult {
    let rig = rig(handler(standard()))?;
    let mut session: Session = open_session(&rig.settings)?;
    check_read_only(&mut session)?;
    assert_eq!(settings_for(rig.dir.path(), &rig.stub)?.api_url, rig.settings.api_url);
    Ok(())
}
