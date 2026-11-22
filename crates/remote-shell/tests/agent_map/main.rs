#[path = "../common/types.rs"]
mod common_types;
mod types;


use common_types::TestResult;
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::{NewEntry, Outcome};
use core_config::error::ConfigError;
use core_config::parse::MAX_FILE_BYTES;
use core_config::reload::{current_config, reload, ReloadContext, ReloadOutcome};
use core_config::types::SharedAuditFn;
use remote_shell::agent_map::{agent_state, open_agent_engine, parse_agent_map, resolve_agent, AgentMap, MAX_AGENT_ASSETS};
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use types::Recorded;


const TENANT: &str = "tenant-a";


const FILE: &str = "remote-shell-agents.yaml";


const STATE_SIZE: usize = 2;


const LONG_AGENT_ID: usize = 65;


fn parse(text: &str) -> Result<AgentMap, ConfigError> {
    parse_agent_map(&mut text.as_bytes(), FILE, TENANT)
}


fn refusal(text: &str) -> Result<String, io::Error> {
    parse(text)
        .err()
        .map(|error| error.to_string())
        .ok_or_else(|| io::Error::other("the file was accepted"))
}


fn file_text(entries: &[(&str, &str)]) -> String {
    let lines: String = entries
        .iter()
        .map(|(agent_id, asset)| format!("  - agent_id: {agent_id}\n    asset: {asset}\n"))
        .collect();
    format!("tenant: {TENANT}\nagents:\n{lines}")
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "remote-shell".to_owned(),
        tenant: TENANT.to_owned(),
        module: "remote-shell".to_owned(),
        target: FILE.to_owned(),
        request_id: "agent-map-reload".to_owned(),
    }
}


fn recording_audit() -> (Box<SharedAuditFn>, Recorded) {
    let recorded: Recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    let log = genesis_log(io::sink());
    let audit = move |entry: NewEntry| {
        sink.lock().map_err(|_| AuditError::LogPoisoned)?.push(entry.clone());
        append(&log, entry)
    };
    (Box::new(audit), recorded)
}


fn recorded_entries(recorded: &Recorded) -> Result<Vec<NewEntry>, io::Error> {
    recorded.lock().map(|guard| guard.clone()).map_err(|_| io::Error::other("poisoned"))
}


fn put_file(path: &Path, text: &str) -> io::Result<()> {
    fs::write(path, text)
}


#[test]
fn a_good_file_resolves_byte_exact_assets() -> TestResult {
    let map = parse(&file_text(&[("agent-1", "srv1"), ("agent-2", "db.main")]))?;
    let identity = resolve_agent(&map, TENANT, "srv1").ok_or("srv1 unresolved")?;
    assert_eq!(identity.agent_id, "agent-1");
    assert_eq!(identity.tenant, TENANT);
    assert!(resolve_agent(&map, TENANT, "SRV1").is_none());
    assert!(resolve_agent(&map, TENANT, "unknown").is_none());
    Ok(())
}


#[test]
fn another_tenant_never_resolves() -> TestResult {
    let map = parse(&file_text(&[("agent-1", "srv1")]))?;
    assert!(resolve_agent(&map, "tenant-b", "srv1").is_none());
    assert!(resolve_agent(&map, "TENANT-A", "srv1").is_none());
    Ok(())
}


#[test]
fn state_has_one_key_per_asset() -> TestResult {
    let map = parse(&file_text(&[("agent-1", "srv1"), ("agent-2", "srv2")]))?;
    let state = agent_state(&map);
    assert_eq!(state.len(), STATE_SIZE);
    assert_eq!(state.get("agents.srv1").map(String::as_str), Some("agent-1"));
    Ok(())
}


#[test]
fn a_duplicate_asset_is_refused_naming_both_indexes() -> TestResult {
    let text = refusal(&file_text(&[("agent-1", "srv1"), ("agent-2", "srv2"), ("agent-3", "srv1")]))?;
    assert!(text.contains("agents[2].asset repeats agents[0].asset"), "{text}");
    Ok(())
}


#[test]
fn a_case_only_duplicate_asset_is_refused() -> TestResult {
    let text = refusal(&file_text(&[("agent-1", "srv1"), ("agent-2", "SRV1")]))?;
    assert!(text.contains("agents[1].asset repeats agents[0].asset"), "{text}");
    Ok(())
}


#[test]
fn a_duplicate_agent_id_is_refused_also_by_case() -> TestResult {
    let same = refusal(&file_text(&[("agent-1", "srv1"), ("agent-1", "srv2")]))?;
    assert!(same.contains("agents[1].agent_id repeats agents[0].agent_id"), "{same}");
    let folded = refusal(&file_text(&[("Agent-1", "srv1"), ("agent-1", "srv2")]))?;
    assert!(folded.contains("agents[1].agent_id repeats agents[0].agent_id"), "{folded}");
    Ok(())
}


#[test]
fn another_tenant_in_the_file_is_refused() -> TestResult {
    let text = refusal("tenant: tenant-b\nagents: []\n")?;
    assert!(text.contains("`tenant` is not the tenant of this engine"), "{text}");
    Ok(())
}


#[test]
fn a_bad_tenant_grammar_is_refused() -> TestResult {
    let text = refusal("tenant: \"-x\"\nagents: []\n")?;
    assert!(text.contains("`tenant` is outside its grammar"), "{text}");
    Ok(())
}


#[test]
fn a_long_agent_id_is_refused_without_its_value() -> TestResult {
    let long = "a".repeat(LONG_AGENT_ID);
    let text = refusal(&file_text(&[("agent-0", "srv0"), (&long, "srv1")]))?;
    assert!(text.contains("agents[1].agent_id is outside its grammar"), "{text}");
    assert!(!text.contains(&long));
    Ok(())
}


#[test]
fn an_asset_with_escape_is_refused_without_the_escape() -> TestResult {
    let text = refusal("tenant: tenant-a\nagents:\n  - agent_id: agent-1\n    asset: \"srv\\e1\"\n")?;
    assert!(text.contains("agents[0].asset is outside its grammar"), "{text}");
    assert!(!text.contains('\u{1b}'));
    Ok(())
}


#[test]
fn unknown_fields_are_refused() -> TestResult {
    refusal("tenant: tenant-a\nagents: []\nextra: 1\n")?;
    refusal("tenant: tenant-a\nagents:\n  - agent_id: a\n    asset: b\n    more: c\n")?;
    Ok(())
}


fn many_entries(count: usize) -> String {
    let lines: String = (0..count).map(|i| format!("  - {{agent_id: a{i}, asset: s{i}}}\n")).collect();
    format!("tenant: {TENANT}\nagents:\n{lines}")
}


#[test]
fn the_entry_cap_is_exact() -> TestResult {
    let map = parse(&many_entries(MAX_AGENT_ASSETS))?;
    assert_eq!(map.agents.len(), MAX_AGENT_ASSETS);
    let text = refusal(&many_entries(MAX_AGENT_ASSETS + 1))?;
    assert!(text.contains("too many agent entries"), "{text}");
    Ok(())
}


#[test]
fn the_entry_after_the_cap_is_never_built() -> TestResult {
    let mut text = many_entries(MAX_AGENT_ASSETS);
    text.push_str("  - {agent_id: late, asset: late, surprise: 1}\n");
    let message = refusal(&text)?;
    assert!(message.contains("too many agent entries"), "{message}");
    Ok(())
}


#[test]
fn a_file_over_the_byte_cap_is_refused() -> TestResult {
    let mut text = file_text(&[("agent-1", "srv1")]);
    text.push_str(&"#".repeat(MAX_FILE_BYTES as usize));
    let message = refusal(&text)?;
    assert!(message.contains("larger than"), "{message}");
    Ok(())
}


#[test]
fn a_fifo_is_refused_without_hanging() -> TestResult {
    let dir = tempfile::tempdir()?;
    let fifo = dir.path().join(FILE);
    let status = Command::new("mkfifo").arg(&fifo).status()?;
    assert!(status.success());
    let (audit, _) = recording_audit();
    let error = open_agent_engine(fifo, audit, context()).err().ok_or("a FIFO was accepted")?;
    assert!(error.to_string().contains("not a regular file"), "{error}");
    Ok(())
}


#[test]
fn a_missing_first_file_fails_the_start() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (audit, _) = recording_audit();
    assert!(open_agent_engine(dir.path().join(FILE), audit, context()).is_err());
    Ok(())
}


#[test]
fn a_bad_first_file_fails_the_start() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    put_file(&path, &file_text(&[("a", "x"), ("b", "x")]))?;
    let (audit, _) = recording_audit();
    assert!(open_agent_engine(path, audit, context()).is_err());
    Ok(())
}


#[test]
fn a_bad_reload_keeps_the_old_mapping_and_is_audited() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    put_file(&path, &file_text(&[("agent-1", "srv1")]))?;
    let (audit, recorded) = recording_audit();
    let engine = open_agent_engine(path.clone(), audit, context())?;
    put_file(&path, &file_text(&[("agent-1", "srv1"), ("agent-2", "srv1")]))?;
    let outcome = reload(&engine);
    assert!(matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("agents[1].asset repeats agents[0].asset")));
    let snapshot = current_config(&engine);
    assert!(resolve_agent(&snapshot, TENANT, "srv1").is_some());
    let entries = recorded_entries(&recorded)?;
    assert_eq!(entries.len(), 1);
    assert!(entries.iter().all(|entry| entry.outcome == Outcome::Denied));
    Ok(())
}


#[test]
fn a_good_reload_swaps_and_removes_a_mapping() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    put_file(&path, &file_text(&[("agent-1", "srv1")]))?;
    let (audit, recorded) = recording_audit();
    let engine = open_agent_engine(path.clone(), audit, context())?;
    put_file(&path, &file_text(&[("agent-2", "srv2")]))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    let snapshot = current_config(&engine);
    assert!(resolve_agent(&snapshot, TENANT, "srv1").is_none());
    assert!(resolve_agent(&snapshot, TENANT, "srv2").is_some());
    assert_eq!(recorded_entries(&recorded)?.len(), 1);
    Ok(())
}
