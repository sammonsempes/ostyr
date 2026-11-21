use crate::support::scoped_logging;
use crate::types::TestResult;
use agent_channel::app::shared_log_audit;
use agent_linux::cursor::open_state_dir;
use agent_linux::error::{IsolationError, SourceError};
use agent_linux::isolation::{
    allowed_flows, apply, audit_entry, chain_text, check_listing, delete_arguments, error_rules, family_keyword, is_absent, isolate, list_arguments,
    output_rules, postrouting_rules, read_back, release, release_audited, render_ruleset, rule_exprs, rule_text, run_isolation, status,
    status_audited, write_ruleset, IsolationEnv, AUDIT_MISMATCH, CHAIN_PRIORITY, DNS_PORT, MAX_LISTING_ITEMS,
};
use agent_linux::model::{
    Endpoint, IsolationSettings, IsolationStatus, LinuxFile, Protocol, Rule, DEFAULT_NFT_PATH, MAX_DNS_RESOLVERS, MAX_ENDPOINTS,
};
use agent_linux::settings::{invalid_isolation_settings, validate_file};
use agent_linux::types::{NftFn, NftFuture};
use core_audit::error::AuditError;
use core_audit::log::open_file_log;
use core_config::load::load_file;
use core_config::types::SharedAuditFn;
use serde_json::{json, Value};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;


const V4: &str = include_str!("../fixtures/nft/v4.json");


const DUAL: &str = include_str!("../fixtures/nft/dual.json");


const NFT: &str = "/usr/sbin/nft";


const PLATFORM: &str = "192.168.102.196";


const PLATFORM_PORT: u16 = 8080;


const RELAY_PORT: u16 = 8443;


const HANDLE: u64 = 99;


const PAIR: usize = 2;


const ND_TYPE_COUNT: usize = 4;


const CHAIN_TEXT_LINES: usize = 4;


const ERROR_EXPRS: usize = 7;


const V4_INPUT_RULES: usize = 4;


const V4_OUTPUT_RULES: usize = 3;


const DESTINATION_EXPRS: usize = 3;


const FIRST_CHAIN_INDEX: usize = 2;


const FIRST_RULE_INDEX: usize = 6;


const ABSENT_TEXT: &str = "Error: No such file or directory";


const V4_TEXT: &str = r#"table inet ostyr_isolation
delete table inet ostyr_isolation
table inet ostyr_isolation {
    chain input {
        type filter hook input priority -150; policy drop;
        iifname "lo" accept
        icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
        icmp type destination-unreachable icmp code frag-needed ct state related ct protocol tcp ct original ip daddr 192.168.102.196 ct original proto-dst 8080 accept
        ip saddr 192.168.102.196 tcp sport 8080 ct state established,related accept
    }
    chain output {
        type filter hook output priority -150; policy drop;
        oifname "lo" accept
        icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
        ip daddr 192.168.102.196 tcp dport 8080 accept
    }
    chain forward {
        type filter hook forward priority -150; policy drop;
    }
    chain postrouting {
        type filter hook postrouting priority 150; policy drop;
        oifname "lo" accept
        icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
        ip daddr 192.168.102.196 tcp dport 8080 accept
    }
}
"#;


const DUAL_ERRORS: &str = r#"        icmp type destination-unreachable icmp code frag-needed ct state related ct protocol tcp ct original ip daddr 192.168.102.196 ct original proto-dst 8080 accept
        icmpv6 type packet-too-big ct state related ct protocol tcp ct original ip6 daddr fd00::2 ct original proto-dst 8443 accept
        icmp type destination-unreachable icmp code frag-needed ct state related ct protocol tcp ct original ip daddr 10.0.0.53 ct original proto-dst 53 accept
"#;


const DUAL_INPUT: &str = r#"        ip saddr 192.168.102.196 tcp sport 8080 ct state established,related accept
        ip6 saddr fd00::2 tcp sport 8443 ct state established,related accept
        ip saddr 10.0.0.53 udp sport 53 ct state established,related accept
        ip saddr 10.0.0.53 tcp sport 53 ct state established,related accept
"#;


const DUAL_OUTPUT: &str = r#"        ip daddr 192.168.102.196 tcp dport 8080 accept
        ip6 daddr fd00::2 tcp dport 8443 accept
        ip daddr 10.0.0.53 udp dport 53 accept
        ip daddr 10.0.0.53 tcp dport 53 accept
"#;


pub fn endpoint(address: &str, port: u16) -> Result<Endpoint, std::net::AddrParseError> {
    Ok(Endpoint {
        address: address.parse()?,
        port,
    })
}


pub fn v4_settings() -> Result<IsolationSettings, std::net::AddrParseError> {
    Ok(IsolationSettings {
        endpoints: vec![endpoint(PLATFORM, PLATFORM_PORT)?],
        dns: Vec::new(),
    })
}


pub fn dual_settings() -> Result<IsolationSettings, std::net::AddrParseError> {
    Ok(IsolationSettings {
        endpoints: vec![endpoint(PLATFORM, PLATFORM_PORT)?, endpoint("fd00::2", RELAY_PORT)?],
        dns: vec!["10.0.0.53".parse()?],
    })
}


pub fn exit(stderr: &str) -> IsolationError {
    IsolationError::Exit {
        code: Some(1),
        stderr: stderr.to_owned(),
    }
}


pub fn argument(arguments: &[String], index: usize) -> Result<String, IsolationError> {
    arguments.get(index).cloned().ok_or_else(|| exit("missing argument"))
}


pub fn rule_item(chain: &str) -> Value {
    json!({"rule": {"family": "inet", "table": "ostyr_isolation", "chain": chain, "handle": HANDLE, "expr": [{"accept": null}]}})
}


pub fn fake_nft(_program: PathBuf, arguments: Vec<String>) -> NftFuture {
    Box::pin(async move {
        match arguments.first().map(String::as_str) {
            Some("-j") => Ok(V4.to_owned()),
            Some("-f" | "delete") => Ok(String::new()),
            _ => Err(exit("unexpected arguments")),
        }
    })
}


pub fn fake_absent(_program: PathBuf, _arguments: Vec<String>) -> NftFuture {
    Box::pin(async move { Err(exit(ABSENT_TEXT)) })
}


pub fn fake_denied(_program: PathBuf, _arguments: Vec<String>) -> NftFuture {
    Box::pin(async move { Err(exit("Error: Operation not permitted")) })
}


pub fn fake_garbage(_program: PathBuf, _arguments: Vec<String>) -> NftFuture {
    Box::pin(async move { Ok("not json".to_owned()) })
}


pub fn fake_extra_rule(_program: PathBuf, arguments: Vec<String>) -> NftFuture {
    Box::pin(async move {
        match arguments.first().map(String::as_str) {
            Some("-j") => Ok(mutated(|items| {
                items.push(rule_item("output"));
            })?),
            _ => Ok(String::new()),
        }
    })
}


pub fn fake_file_content(_program: PathBuf, arguments: Vec<String>) -> NftFuture {
    Box::pin(async move {
        let path = argument(&arguments, 1)?;
        let content = fs::read_to_string(&path)?;
        Err(exit(&format!("{}|{path}|{content}", argument(&arguments, 0)?)))
    })
}


pub fn fake_file_ok(_program: PathBuf, arguments: Vec<String>) -> NftFuture {
    Box::pin(async move {
        let path = argument(&arguments, 1)?;
        Ok(fs::read_to_string(path)?)
    })
}


pub fn mutated(change: impl FnOnce(&mut Vec<Value>)) -> Result<String, serde_json::Error> {
    let mut listing: Value = serde_json::from_str(V4)?;
    if let Some(items) = listing.get_mut("nftables").and_then(Value::as_array_mut) {
        change(items);
    }
    Ok(listing.to_string())
}


fn set(items: &mut [Value], index: usize, path: &[&str], value: Value) {
    let target = path
        .iter()
        .fold(items.get_mut(index), |current, key| current.and_then(|node| node.get_mut(*key)));
    if let Some(slot) = target {
        *slot = value;
    }
}


fn audit_actions(path: &Path) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    fs::read_to_string(path)?
        .lines()
        .map(|line| -> Result<(String, String), Box<dyn std::error::Error>> {
            let record: Value = serde_json::from_str(line)?;
            let field = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_owned).ok_or("missing audit field");
            let action = field(record.get("action"))?;
            let result = field(record.get("parameters").and_then(|parameters| parameters.get("result")))?;
            Ok((action, result))
        })
        .collect()
}


#[test]
fn the_ipv4_ruleset_is_rendered_exactly() -> TestResult {
    assert_eq!(render_ruleset(&v4_settings()?)?, V4_TEXT);
    Ok(())
}


#[test]
fn ipv6_and_dns_endpoints_are_rendered_exactly() -> TestResult {
    let both = render_ruleset(&dual_settings()?)?;
    assert!(both.contains(&format!("{DUAL_OUTPUT}    }}\n    chain forward")));
    assert!(both.contains(&format!("{DUAL_OUTPUT}    }}\n}}\n")));
    assert!(both.contains(&format!("{DUAL_ERRORS}{DUAL_INPUT}")));
    let v6_only = IsolationSettings {
        endpoints: vec![endpoint("fd00::2", RELAY_PORT)?],
        dns: Vec::new(),
    };
    let text = render_ruleset(&v6_only)?;
    assert!(text.contains("        ip6 daddr fd00::2 tcp dport 8443 accept\n    }\n    chain forward"));
    assert!(
        text.contains("icmpv6 type packet-too-big ct state related ct protocol tcp ct original ip6 daddr fd00::2 ct original proto-dst 8443 accept")
    );
    assert!(!text.contains("udp"));
    let with_dns = IsolationSettings {
        dns: vec!["fd00::53".parse()?],
        ..v4_settings()?
    };
    assert!(render_ruleset(&with_dns)?.contains("ip6 daddr fd00::53 udp dport 53 accept\n        ip6 daddr fd00::53 tcp dport 53 accept\n"));
    Ok(())
}


#[test]
fn a_blanket_established_rule_in_the_listing_is_a_mismatch() -> TestResult {
    let expr = json!([{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": null}]);
    let blanket = json!({"rule": {"family": "inet", "table": "ostyr_isolation", "chain": "input", "handle": HANDLE, "expr": expr}});
    assert_mismatch(&mutated(|items| items.insert(FIRST_RULE_INDEX + 1, blanket))?, "rules")?;
    Ok(())
}


#[test]
fn established_is_accepted_only_for_the_listed_flows() -> TestResult {
    for settings in [v4_settings()?, dual_settings()?] {
        let text = render_ruleset(&settings)?;
        assert!(!text.contains("        ct state"), "{text}");
        let tracked = text.lines().filter(|line| line.contains("established")).count();
        assert_eq!(
            tracked,
            text.lines().filter(|line| line.contains(" saddr ") && line.contains(" sport ")).count()
        );
        assert!(text
            .lines()
            .filter(|line| line.contains("established"))
            .all(|line| line.contains(" sport ")));
    }
    let reply = Rule::Reply {
        address: PLATFORM.parse()?,
        protocol: Protocol::Tcp,
        port: PLATFORM_PORT,
    };
    assert_eq!(
        rule_text(&reply),
        "ip saddr 192.168.102.196 tcp sport 8080 ct state established,related accept"
    );
    Ok(())
}


#[test]
fn no_endpoint_means_no_ruleset() -> TestResult {
    assert!(matches!(render_ruleset(&IsolationSettings::default()), Err(IsolationError::NoEndpoints)));
    Ok(())
}


#[test]
fn rule_texts_and_helpers() -> TestResult {
    assert_eq!(rule_text(&Rule::Loopback("iifname")), "iifname \"lo\" accept");
    let address: IpAddr = "::1".parse()?;
    assert_eq!(family_keyword(&address), "ip6");
    assert_eq!(
        chain_text("input", CHAIN_PRIORITY, &[Rule::Loopback("iifname")]).lines().count(),
        CHAIN_TEXT_LINES
    );
    let exprs = rule_exprs(&Rule::Destination {
        address,
        protocol: Protocol::Udp,
        port: DNS_PORT,
    });
    assert_eq!(exprs.len(), DESTINATION_EXPRS);
    assert_eq!(list_arguments(), ["-j", "list", "table", "inet", "ostyr_isolation"]);
    assert_eq!(delete_arguments(), ["delete", "table", "inet", "ostyr_isolation"]);
    Ok(())
}


#[test]
fn the_listings_nft_printed_match_the_rendered_rules() -> TestResult {
    check_listing(V4, &v4_settings()?)?;
    check_listing(DUAL, &dual_settings()?)?;
    Ok(())
}


#[test]
fn settings_that_differ_from_the_table_are_a_mismatch() -> TestResult {
    assert!(matches!(check_listing(V4, &dual_settings()?), Err(IsolationError::Mismatch(reason)) if reason == "rules"));
    assert!(matches!(check_listing(DUAL, &v4_settings()?), Err(IsolationError::Mismatch(_))));
    Ok(())
}


fn assert_mismatch(text: &str, reason: &str) -> TestResult {
    let outcome = check_listing(text, &v4_settings()?);
    assert!(
        matches!(&outcome, Err(IsolationError::Mismatch(found)) if found.contains(reason)),
        "{outcome:?}"
    );
    Ok(())
}


#[test]
fn an_extra_missing_or_reordered_rule_is_a_mismatch() -> TestResult {
    assert_mismatch(&mutated(|items| items.push(rule_item("input")))?, "rules")?;
    assert_mismatch(
        &mutated(|items| {
            items.pop();
        })?,
        "rules",
    )?;
    assert_mismatch(&mutated(|items| items.swap(FIRST_RULE_INDEX, FIRST_RULE_INDEX + 1))?, "rules")?;
    assert_mismatch(&mutated(|items| items.push(rule_item("forward")))?, "rules")?;
    assert_mismatch(&mutated(|items| set(items, FIRST_RULE_INDEX, &["rule", "family"], json!("ip")))?, "rules")?;
    assert_mismatch(
        &mutated(|items| set(items, FIRST_RULE_INDEX, &["rule", "table"], json!("keepme")))?,
        "rules",
    )?;
    assert_mismatch(
        &mutated(|items| set(items, FIRST_RULE_INDEX, &["rule", "chain"], json!("output")))?,
        "rules",
    )?;
    let counter = json!([{"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]);
    assert_mismatch(&mutated(|items| set(items, FIRST_RULE_INDEX, &["rule", "expr"], counter))?, "rules")?;
    Ok(())
}


#[test]
fn a_chain_that_is_not_as_rendered_is_a_mismatch() -> TestResult {
    let changes: Vec<(&[&str], Value)> = vec![
        (&["chain", "policy"], json!("accept")),
        (&["chain", "prio"], json!(0)),
        (&["chain", "hook"], json!("forward")),
        (&["chain", "type"], json!("nat")),
        (&["chain", "family"], json!("ip")),
    ];
    for (path, value) in changes {
        let text = mutated(|items| set(items, FIRST_CHAIN_INDEX, path, value))?;
        assert_mismatch(&text, "chains")?;
    }
    assert_mismatch(
        &mutated(|items| set(items, FIRST_CHAIN_INDEX, &["chain", "table"], json!("other")))?,
        "chains",
    )?;
    assert_mismatch(
        &mutated(|items| set(items, FIRST_CHAIN_INDEX, &["chain", "name"], json!("forward")))?,
        "chains",
    )?;
    assert_mismatch(
        &mutated(|items| {
            items.remove(FIRST_CHAIN_INDEX + 1);
        })?,
        "chains",
    )?;
    let regular = json!({"chain": {"family": "inet", "table": "ostyr_isolation", "name": "extra", "handle": HANDLE}});
    assert_mismatch(&mutated(|items| items.push(regular))?, "chains")?;
    let without_type = mutated(|items| {
        if let Some(chain) = items
            .get_mut(FIRST_CHAIN_INDEX)
            .and_then(|item| item.get_mut("chain"))
            .and_then(Value::as_object_mut)
        {
            chain.remove("type");
        }
    })?;
    assert_mismatch(&without_type, "chains")?;
    Ok(())
}


#[test]
fn another_table_or_an_unknown_element_is_a_mismatch() -> TestResult {
    let second = json!({"table": {"family": "inet", "name": "other", "handle": HANDLE}});
    assert_mismatch(&mutated(|items| items.push(second))?, "table")?;
    assert_mismatch(&mutated(|items| set(items, 1, &["table", "name"], json!("keepme")))?, "table")?;
    assert_mismatch(&mutated(|items| set(items, 1, &["table", "family"], json!("ip")))?, "table")?;
    assert_mismatch(&mutated(|items| items.push(json!({"set": {"name": "s"}})))?, "unknown element")?;
    assert_mismatch(
        &mutated(|items| {
            items.remove(1);
        })?,
        "table",
    )?;
    Ok(())
}


#[test]
fn a_listing_over_the_item_cap_or_not_json_is_refused() -> TestResult {
    let many = mutated(|items| items.resize(MAX_LISTING_ITEMS + 1, json!({"metainfo": {}})))?;
    assert_mismatch(&many, "too many")?;
    assert!(matches!(check_listing("not json", &v4_settings()?), Err(IsolationError::Json(_))));
    assert!(matches!(check_listing("{\"other\":[]}", &v4_settings()?), Err(IsolationError::Json(_))));
    let broken = mutated(|items| items.push(json!({"chain": {}})))?;
    assert!(matches!(check_listing(&broken, &v4_settings()?), Err(IsolationError::Json(_))));
    Ok(())
}


#[tokio::test]
async fn apply_runs_nft_on_the_rendered_file_and_removes_it() -> TestResult {
    let dir = tempdir()?;
    let state = open_state_dir(&dir.path().join("cursor"))?;
    let outcome = apply(fake_file_content, Path::new(NFT), &state, V4_TEXT).await;
    let stderr = match outcome {
        Err(IsolationError::Exit { stderr, .. }) => Ok(stderr),
        other => Err(format!("the fake must report what it saw: {other:?}")),
    }?;
    let (flag, rest) = stderr.split_once('|').ok_or("no flag")?;
    let (path, content) = rest.split_once('|').ok_or("no path")?;
    assert_eq!(flag, "-f");
    assert!(path.starts_with("/proc/"), "{path}");
    assert_eq!(content, V4_TEXT);
    assert_eq!(fs::read_dir(dir.path())?.count(), 0);
    apply(fake_nft, Path::new(NFT), &state, V4_TEXT).await?;
    assert_eq!(fs::read_dir(dir.path())?.count(), 0);
    Ok(())
}


#[test]
fn the_ruleset_file_is_fresh_private_and_removed_on_drop() -> TestResult {
    let dir = tempdir()?;
    let state = open_state_dir(&dir.path().join("cursor"))?;
    let first = write_ruleset(&state, "a")?;
    let second = write_ruleset(&state, "b")?;
    assert_ne!(first.name, second.name);
    assert_eq!(fs::read_dir(dir.path())?.count(), PAIR);
    drop(first);
    drop(second);
    assert_eq!(fs::read_dir(dir.path())?.count(), 0);
    Ok(())
}


#[test]
fn a_state_directory_that_vanished_is_an_error_and_a_vanished_file_is_logged() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let sub = dir.path().join("state");
    fs::create_dir(&sub)?;
    let state = open_state_dir(&sub.join("cursor"))?;
    let file = write_ruleset(&state, "a")?;
    fs::remove_file(sub.join(&file.name))?;
    drop(file);
    fs::remove_dir(&sub)?;
    assert!(matches!(write_ruleset(&state, "a"), Err(IsolationError::Io(_))));
    Ok(())
}


#[tokio::test]
async fn a_failing_nft_leaves_a_typed_error_and_no_file() -> TestResult {
    let dir = tempdir()?;
    let state = open_state_dir(&dir.path().join("cursor"))?;
    let outcome = apply(fake_denied, Path::new(NFT), &state, V4_TEXT).await;
    assert!(matches!(outcome, Err(IsolationError::Exit { code: Some(1), .. })));
    assert_eq!(fs::read_dir(dir.path())?.count(), 0);
    Ok(())
}


#[tokio::test]
async fn read_back_and_status_report_the_table() -> TestResult {
    read_back(fake_nft, Path::new(NFT), &v4_settings()?).await?;
    assert_eq!(status(fake_nft, Path::new(NFT), &v4_settings()?).await?, IsolationStatus::Active);
    assert_eq!(status(fake_absent, Path::new(NFT), &v4_settings()?).await?, IsolationStatus::Absent);
    assert!(matches!(
        status(fake_denied, Path::new(NFT), &v4_settings()?).await,
        Err(IsolationError::Exit { .. })
    ));
    assert!(matches!(
        status(fake_extra_rule, Path::new(NFT), &v4_settings()?).await,
        Err(IsolationError::Mismatch(_))
    ));
    assert!(matches!(
        read_back(fake_garbage, Path::new(NFT), &v4_settings()?).await,
        Err(IsolationError::Json(_))
    ));
    assert!(is_absent(&exit(ABSENT_TEXT)));
    assert!(!is_absent(&exit("other")));
    assert!(!is_absent(&IsolationError::Timeout));
    Ok(())
}


#[tokio::test]
async fn release_says_whether_the_table_was_there() -> TestResult {
    assert_eq!(release(fake_nft, Path::new(NFT)).await?, IsolationStatus::Active);
    assert_eq!(release(fake_absent, Path::new(NFT)).await?, IsolationStatus::Absent);
    assert!(matches!(release(fake_denied, Path::new(NFT)).await, Err(IsolationError::Exit { .. })));
    Ok(())
}


struct Fixture {
    dir: tempfile::TempDir,
    state: agent_linux::model::StateDir,
    audit: Box<SharedAuditFn>,
}


fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let state = open_state_dir(&dir.path().join("cursor"))?;
    let log = Arc::new(open_file_log(&dir.path().join("audit"))?);
    let audit = shared_log_audit(&log);
    Ok(Fixture { dir, state, audit })
}


fn environment<'a>(fixture: &'a Fixture, run: NftFn) -> IsolationEnv<'a> {
    IsolationEnv {
        run,
        nft: Path::new(NFT),
        state: &fixture.state,
        tenant: "t1",
        audit: &*fixture.audit,
    }
}


#[tokio::test]
async fn isolate_release_and_a_mismatch_are_each_one_audit_record() -> TestResult {
    let fixture = fixture()?;
    isolate(&environment(&fixture, fake_nft), &v4_settings()?).await?;
    let mismatch = isolate(&environment(&fixture, fake_extra_rule), &v4_settings()?).await;
    assert!(matches!(mismatch, Err(IsolationError::Mismatch(_))));
    let failed = isolate(&environment(&fixture, fake_denied), &v4_settings()?).await;
    assert!(matches!(failed, Err(IsolationError::Exit { .. })));
    let empty = isolate(&environment(&fixture, fake_nft), &IsolationSettings::default()).await;
    assert!(matches!(empty, Err(IsolationError::NoEndpoints)));
    assert_eq!(release_audited(&environment(&fixture, fake_nft)).await?, IsolationStatus::Active);
    assert_eq!(release_audited(&environment(&fixture, fake_absent)).await?, IsolationStatus::Absent);
    assert_eq!(
        status_audited(&environment(&fixture, fake_nft), &v4_settings()?).await?,
        IsolationStatus::Active
    );
    assert_eq!(
        status_audited(&environment(&fixture, fake_absent), &v4_settings()?).await?,
        IsolationStatus::Absent
    );
    let drifted = status_audited(&environment(&fixture, fake_extra_rule), &v4_settings()?).await;
    assert!(matches!(drifted, Err(IsolationError::Mismatch(_))));
    let seen = audit_actions(&fixture.dir.path().join("audit"))?;
    let expected: Vec<(String, String)> = [
        ("isolation.isolate", "ok"),
        (AUDIT_MISMATCH, "mismatch"),
        ("isolation.isolate", "failed"),
        ("isolation.isolate", "failed"),
        ("isolation.release", "ok"),
        ("isolation.release", "absent"),
        (AUDIT_MISMATCH, "mismatch"),
    ]
    .map(|(action, result)| (action.to_owned(), result.to_owned()))
    .to_vec();
    assert_eq!(seen, expected);
    Ok(())
}


#[tokio::test]
async fn a_failing_audit_is_logged_and_never_undoes_the_isolation() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let state = open_state_dir(&dir.path().join("cursor"))?;
    let audit: Box<SharedAuditFn> = Box::new(|_| Err(AuditError::LogPoisoned));
    let env = IsolationEnv {
        run: fake_nft,
        nft: Path::new(NFT),
        state: &state,
        tenant: "t1",
        audit: &*audit,
    };
    isolate(&env, &v4_settings()?).await?;
    let entry = audit_entry("t1", "isolation.release", "failed");
    assert!(matches!(entry.outcome, core_audit::model::Outcome::Failure));
    Ok(())
}


const AGENT_YAML: &str = "server: \"192.0.2.1:7443\"\nserver_name: x\ncertificate: /c\nkey: /k\nplatform_ca: /p\ntenant: t1\nagent_id: a1\nkeys_file: /keys\nstate_file: /state\naudit_file: /agent-audit\nspool_file: /spool\nsequence_file: /seq\nexecuted_file: /exec\n";


fn write_files(dir: &Path, isolation: &str, extra: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fs::write(dir.join("agent.yaml"), AGENT_YAML)?;
    let path = dir.join("linux.yaml");
    fs::write(
        &path,
        format!(
            "agent_file: {0}/agent.yaml\nexport_path: {0}/export\ncursor_file: {0}/cursor\naudit_file: {0}/audit\n{extra}{isolation}",
            dir.display()
        ),
    )?;
    Ok(path)
}


const GOOD: &str = "isolation:\n  endpoints:\n    - address: 192.168.102.196\n      port: 8080\n";


#[tokio::test]
async fn the_example_actions_read_the_settings_and_report() -> TestResult {
    let dir = tempdir()?;
    let path = write_files(dir.path(), GOOD, "")?;
    assert_eq!(run_isolation(&path, "isolate", fake_nft).await?, "isolated");
    assert_eq!(run_isolation(&path, "status", fake_nft).await?, "status: Active");
    assert_eq!(run_isolation(&path, "release", fake_nft).await?, "released, table was Active");
    assert!(matches!(run_isolation(&path, "other", fake_nft).await, Err(IsolationError::Usage)));
    let seen = audit_actions(&dir.path().join("audit"))?;
    assert_eq!(seen.len(), PAIR);
    Ok(())
}


#[tokio::test]
async fn hostile_or_out_of_range_settings_are_refused_at_load() -> TestResult {
    let dir = tempdir()?;
    for address in ["1.2.3.4; flush ruleset", "{ 0.0.0.0/0 }", "1.2.3.0/24", "any"] {
        let hostile = format!("isolation:\n  endpoints:\n    - address: \"{address}\"\n      port: 8080\n");
        let path = write_files(dir.path(), &hostile, "")?;
        assert!(
            matches!(run_isolation(&path, "isolate", fake_nft).await, Err(IsolationError::Config(_))),
            "{address}"
        );
    }
    let port = write_files(
        dir.path(),
        "isolation:\n  endpoints:\n    - address: 1.2.3.4\n      port: \"80; drop\"\n",
        "",
    )?;
    assert!(matches!(run_isolation(&port, "isolate", fake_nft).await, Err(IsolationError::Config(_))));
    let relative = write_files(dir.path(), GOOD, "nft_path: nft\n")?;
    assert!(matches!(
        run_isolation(&relative, "isolate", fake_nft).await,
        Err(IsolationError::Settings(_))
    ));
    let none = write_files(dir.path(), "", "")?;
    assert!(matches!(
        run_isolation(&none, "isolate", fake_nft).await,
        Err(IsolationError::NoEndpoints)
    ));
    assert_eq!(
        fs::read_dir(dir.path())?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() == "audit")
            .count(),
        1
    );
    Ok(())
}


#[tokio::test]
async fn a_missing_agent_file_state_directory_or_audit_log_stops_the_command() -> TestResult {
    let dir = tempdir()?;
    let path = write_files(dir.path(), GOOD, "")?;
    fs::remove_file(dir.path().join("agent.yaml"))?;
    assert!(matches!(run_isolation(&path, "status", fake_nft).await, Err(IsolationError::App(_))));
    fs::write(dir.path().join("agent.yaml"), AGENT_YAML)?;
    fs::create_dir(dir.path().join("audit"))?;
    assert!(matches!(run_isolation(&path, "status", fake_nft).await, Err(IsolationError::Audit(_))));
    fs::remove_dir(dir.path().join("audit"))?;
    let moved = dir.path().join("moved.yaml");
    fs::write(
        &moved,
        fs::read_to_string(&path)?.replace("cursor_file: ", &format!("cursor_file: {}/gone/", dir.path().display())),
    )?;
    assert!(matches!(
        run_isolation(&moved, "status", fake_nft).await,
        Err(IsolationError::State(SourceError::StateDir(..)))
    ));
    Ok(())
}


#[tokio::test]
async fn the_ruleset_applied_is_the_one_written_even_when_a_name_is_swapped() -> TestResult {
    let dir = tempdir()?;
    let state = open_state_dir(&dir.path().join("cursor"))?;
    let evil = dir.path().join("evil.nft");
    fs::write(&evil, "add table inet evil\n")?;
    let file = write_ruleset(&state, V4_TEXT)?;
    fs::remove_file(dir.path().join(&file.name))?;
    std::os::unix::fs::symlink(&evil, dir.path().join(&file.name))?;
    let seen = fake_file_ok(PathBuf::from(NFT), vec!["-f".to_owned(), file.path.clone()]).await?;
    assert_eq!(seen, V4_TEXT);
    Ok(())
}


#[test]
fn isolation_settings_are_bounded_and_validated() -> TestResult {
    let dir = tempdir()?;
    let many: String = (1..=MAX_ENDPOINTS + 1)
        .map(|i| format!("    - address: 10.0.0.{i}\n      port: 80\n"))
        .collect();
    let dns: String = (1..=MAX_DNS_RESOLVERS + 1).map(|i| format!("    - 10.0.1.{i}\n")).collect();
    let path = write_files(dir.path(), &format!("isolation:\n  endpoints:\n{many}  dns:\n{dns}"), "nft_path: nft\n")?;
    let file = load_file::<LinuxFile>(&path)?;
    assert_eq!(invalid_isolation_settings(&file), ["isolation.endpoints", "isolation.dns", "nft_path"]);
    assert!(matches!(validate_file(&file), Err(SourceError::Settings(names)) if names.contains("isolation.dns")));
    let zero = write_files(dir.path(), "isolation:\n  endpoints:\n    - address: 10.0.0.1\n      port: 0\n", "")?;
    assert_eq!(invalid_isolation_settings(&load_file::<LinuxFile>(&zero)?), ["isolation.ports"]);
    for address in [
        "0.0.0.0",
        "::",
        "127.0.0.1",
        "::1",
        "224.0.0.1",
        "ff02::1",
        "255.255.255.255",
        "::ffff:127.0.0.1",
        "::ffff:0.0.0.0",
        "::ffff:224.0.0.1",
        "::ffff:255.255.255.255",
    ] {
        let text = format!("isolation:\n  endpoints:\n    - address: \"{address}\"\n      port: 80\n  dns:\n    - \"{address}\"\n");
        let hostile = load_file::<LinuxFile>(&write_files(dir.path(), &text, "")?)?;
        assert_eq!(
            invalid_isolation_settings(&hostile),
            ["isolation.endpoints.address", "isolation.dns.address"],
            "{address}"
        );
    }
    let good = write_files(dir.path(), GOOD, "")?;
    let valid = load_file::<LinuxFile>(&good)?;
    assert!(invalid_isolation_settings(&valid).is_empty());
    assert_eq!(valid.nft_path, Path::new(DEFAULT_NFT_PATH));
    validate_file(&valid)?;
    Ok(())
}


#[test]
fn the_forward_chain_has_no_accept_rule_and_neighbour_rules_need_hop_limit_255() -> TestResult {
    for settings in [v4_settings()?, dual_settings()?] {
        let text = render_ruleset(&settings)?;
        let forward = text.split("chain forward").nth(1).ok_or("no forward chain")?;
        assert!(forward.starts_with(" {\n        type filter hook forward priority -150; policy drop;\n    }\n    chain postrouting"));
        assert_eq!(text.matches("ip6 hoplimit 255 accept").count(), PAIR + 1);
        assert_eq!(text.matches("nd-").count(), (PAIR + 1) * ND_TYPE_COUNT);
    }
    assert_eq!(rule_exprs(&Rule::Neighbour).len(), DESTINATION_EXPRS);
    Ok(())
}


#[test]
fn an_icmp_error_is_accepted_only_for_a_listed_flow() -> TestResult {
    for settings in [v4_settings()?, dual_settings()?] {
        let text = render_ruleset(&settings)?;
        let flows = allowed_flows(&settings)
            .iter()
            .filter(|(_, protocol, _)| *protocol == Protocol::Tcp)
            .count();
        let errors: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("destination-unreachable") || line.contains("packet-too-big"))
            .collect();
        assert_eq!(errors.len(), flows);
        assert!(!text.contains(" saddr 192.168.102.196 ct state related"));
        assert!(text
            .split("chain output")
            .nth(1)
            .is_some_and(|rest| !rest.contains("packet-too-big") && !rest.contains("destination-unreachable")));
        assert!(errors
            .iter()
            .all(|line| line.contains("ct state related ct protocol") && line.contains("ct original proto-dst")));
        assert!(errors
            .iter()
            .all(|line| line.contains("ct original ip daddr") || line.contains("ct original ip6 daddr")));
        assert!(errors.iter().all(|line| !line.contains(" saddr ") && line.contains("ct protocol tcp")));
        assert!(!text.contains("ct protocol udp"));
        assert!(errors
            .iter()
            .all(|line| line.contains("icmp code frag-needed") || line.contains("icmpv6 type packet-too-big")));
        assert!(!text.contains("destination-unreachable ct state related accept"));
        assert!(!text.contains("packet-too-big ct state related accept"));
    }
    let v6: IpAddr = "fd00::2".parse()?;
    let tcp = Rule::PathError {
        address: v6,
        protocol: Protocol::Tcp,
        port: RELAY_PORT,
    };
    assert_eq!(
        rule_text(&tcp),
        "icmpv6 type packet-too-big ct state related ct protocol tcp ct original ip6 daddr fd00::2 ct original proto-dst 8443 accept"
    );
    let v4: IpAddr = PLATFORM.parse()?;
    let udp = Rule::PathError {
        address: v4,
        protocol: Protocol::Udp,
        port: DNS_PORT,
    };
    assert_eq!(rule_exprs(&udp).len(), ERROR_EXPRS);
    assert_eq!(rule_exprs(&tcp).len(), ERROR_EXPRS - 1);
    assert!(error_rules(&IsolationSettings {
        endpoints: Vec::new(),
        dns: Vec::new()
    })
    .is_empty());
    Ok(())
}


#[test]
fn an_icmp_error_rule_for_any_flow_in_the_listing_is_a_mismatch() -> TestResult {
    let any_flow = json!([
        {"match": {"op": "==", "left": {"payload": {"protocol": "icmp", "field": "type"}}, "right": "destination-unreachable"}},
        {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "related"}},
        {"accept": null}
    ]);
    let wide = mutated(|items| set(items, FIRST_RULE_INDEX + PAIR, &["rule", "expr"], any_flow.clone()))?;
    assert_mismatch(&wide, "rules")?;
    let other_port = mutated(|items| {
        if let Some(expr) = items
            .get_mut(FIRST_RULE_INDEX + PAIR)
            .and_then(|item| item.pointer_mut("/rule/expr/5/match/right"))
        {
            *expr = json!(1);
        }
    })?;
    assert_mismatch(&other_port, "rules")?;
    Ok(())
}


#[test]
fn the_postrouting_chain_judges_the_destination_after_nat() -> TestResult {
    for settings in [v4_settings()?, dual_settings()?] {
        assert_eq!(postrouting_rules(&settings), output_rules(&settings));
        let text = render_ruleset(&settings)?;
        let postrouting = text.split("chain postrouting").nth(1).ok_or("no postrouting chain")?;
        assert!(postrouting.starts_with(" {\n        type filter hook postrouting priority 150; policy drop;\n        oifname \"lo\" accept\n"));
        assert!(postrouting.contains("daddr"));
    }
    Ok(())
}


#[test]
fn a_listing_without_the_forward_chain_or_with_another_chain_wrong_is_a_mismatch() -> TestResult {
    assert_mismatch(
        &mutated(|items| {
            items.remove(FIRST_CHAIN_INDEX + PAIR);
        })?,
        "chains",
    )?;
    assert_mismatch(
        &mutated(|items| set(items, FIRST_CHAIN_INDEX + PAIR, &["chain", "policy"], json!("accept")))?,
        "chains",
    )?;
    assert_mismatch(
        &mutated(|items| set(items, FIRST_CHAIN_INDEX + 1, &["chain", "policy"], json!("accept")))?,
        "chains",
    )?;
    Ok(())
}


#[test]
fn a_listing_without_the_postrouting_chain_or_with_it_changed_is_a_mismatch() -> TestResult {
    let postrouting = FIRST_CHAIN_INDEX + PAIR + 1;
    assert_mismatch(
        &mutated(|items| {
            items.remove(postrouting);
        })?,
        "chains",
    )?;
    for (path, value) in [
        (&["chain", "prio"][..], json!(CHAIN_PRIORITY)),
        (&["chain", "policy"][..], json!("accept")),
        (&["chain", "hook"][..], json!("output")),
    ] {
        assert_mismatch(&mutated(|items| set(items, postrouting, path, value))?, "chains")?;
    }
    assert_mismatch(&mutated(|items| items.push(rule_item("postrouting")))?, "rules")?;
    let first_output = FIRST_RULE_INDEX + V4_INPUT_RULES;
    assert_mismatch(&mutated(|items| items.swap(first_output, first_output + 1))?, "rules")?;
    let first_postrouting = FIRST_RULE_INDEX + V4_INPUT_RULES + V4_OUTPUT_RULES;
    assert_mismatch(&mutated(|items| items.swap(first_postrouting, first_postrouting + 1))?, "rules")?;
    let last = mutated(|items| {
        items.pop();
    })?;
    assert_mismatch(&last, "rules")?;
    Ok(())
}


const OPEN_PARENT: u32 = 0o777;


#[tokio::test]
async fn a_group_writable_audit_parent_ends_the_command_before_any_record() -> TestResult {
    let dir = tempdir()?;
    let audit_dir = dir.path().join("auditdir");
    fs::create_dir(&audit_dir)?;
    fs::set_permissions(&audit_dir, fs::Permissions::from_mode(OPEN_PARENT))?;
    let path = write_files(dir.path(), GOOD, "")?;
    let text = fs::read_to_string(&path)?.replace(
        &format!("{}/audit\n", dir.path().display()),
        &format!("{}/auditdir/audit\n", dir.path().display()),
    );
    fs::write(&path, text)?;
    assert!(matches!(
        run_isolation(&path, "isolate", fake_nft).await,
        Err(IsolationError::App(agent_channel::error::AppError::SpoolDir { .. }))
    ));
    assert_eq!(fs::read_dir(&audit_dir)?.count(), 0);
    assert!(!dir.path().join("cursor").exists());
    Ok(())
}


#[tokio::test]
async fn a_group_writable_state_directory_ends_the_command_before_the_audit_file_exists() -> TestResult {
    let dir = tempdir()?;
    let state_dir = dir.path().join("state");
    fs::create_dir(&state_dir)?;
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(OPEN_PARENT))?;
    let path = write_files(dir.path(), GOOD, "")?;
    let text = fs::read_to_string(&path)?.replace(
        &format!("cursor_file: {}/cursor\n", dir.path().display()),
        &format!("cursor_file: {}/state/cursor\n", dir.path().display()),
    );
    fs::write(&path, text)?;
    assert!(matches!(
        run_isolation(&path, "isolate", fake_nft).await,
        Err(IsolationError::State(SourceError::StateDir(..)))
    ));
    assert!(!dir.path().join("audit").exists());
    Ok(())
}
