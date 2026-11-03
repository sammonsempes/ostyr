#[path = "common/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::{NewEntry, Outcome};
use core_config::parse::parse_document;
use core_config::reload::{current_config, reload, ReloadOutcome};
use response_breakers::breakers::{open_breakers, BreakerSettings, Breakers};
use response_breakers::store::sync_path;
use response_playbooks::bundle::{
    bundle_state, find_playbook, open_playbooks, simulate_named, validate_bundle, Bundle, PlaybookSettings, CATALOGUE_DOCUMENT, MODULE,
};
use response_playbooks::cli::{execute, run_command, run_session, Session};
use response_playbooks::error::{CommandError, PlaybookError};
use response_playbooks::model::{Catalogue, Mode, Playbook, SimulationInput};
use response_playbooks::render::render_trace;
use response_playbooks::simulate::simulate;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use types::TestResult;


const CATALOGUE: &str = include_str!("../fixtures/catalogue.yaml");


const C2: &str = include_str!("../fixtures/c2.yaml");


const HOSTILE: &str = include_str!("../fixtures/alert_hostile.json");


const CRITICAL: &str = include_str!("../fixtures/alert_critical.json");


const BENIGN: &str = include_str!("../fixtures/alert_benign.json");


const START: i64 = 1_800_000_000;


const BIG_FLEET: u64 = 1_000_000;


const SIX: usize = 6;


const FOURTH: usize = 3;


const OVER_LIMIT: u64 = 25;


const INVALID_UTF8: u8 = 0xff;


const FIRST_ISOLATED: usize = 2;


const NO_ENTRY: usize = 0;


const SIM_CATALOGUE: &str = "
actions:
  - action: notify
    params:
      text: { type: string }
  - action: ban_ip
    destructive: true
    compensate: unban
    breaker: { kind: block_ip, target: ip, duration: ttl }
    params:
      ip: { type: string, optional: true }
      ttl: { type: string, optional: true }
  - action: unban
  - action: ban_ip_typed
    breaker: { kind: block_ip, target: ip, duration: ttl }
    params:
      ip: { type: ip }
      ttl: { type: duration, optional: true }
  - action: ban_domain
    breaker: { kind: block_domain, target: domain }
    params:
      domain: { type: domain }
  - action: ban_domain_timed
    breaker: { kind: block_domain, target: domain, duration: ttl }
    params:
      domain: { type: domain }
      ttl: { type: string }
  - action: disable
    breaker: { kind: disable_account, target: user }
    params:
      user: { type: string }
  - action: run
    breaker: { kind: rmm_script, target: host, machines: count }
    params:
      host: { type: string }
      count: { type: integer, optional: true }
  - action: run_blind
    breaker: { kind: rmm_script, target: host }
    params:
      host: { type: string }
  - action: isolate_number
    breaker: { kind: isolate_endpoint, target: host }
    params:
      host: { type: integer }
";


pub struct Harness {
    pub dir: TempDir,
    pub breakers: Breakers,
    pub entries: Arc<Mutex<Vec<NewEntry>>>,
}


fn recording_audit(entries: &Arc<Mutex<Vec<NewEntry>>>) -> impl Fn(NewEntry) -> Result<core_audit::model::Record, AuditError> + Send + Sync {
    let log = genesis_log(io::sink());
    let sink = Arc::clone(entries);
    move |entry: NewEntry| {
        sink.lock().map_err(|_| AuditError::LogPoisoned)?.push(entry.clone());
        append(&log, entry)
    }
}


fn harness() -> Result<Harness, Box<dyn Error>> {
    let dir = tempdir()?;
    fs::write(dir.path().join("limits.yaml"), "limits: {}\n")?;
    let entries = Arc::new(Mutex::new(Vec::new()));
    let breakers = open_breakers(BreakerSettings {
        config_path: dir.path().join("limits.yaml"),
        store_path: dir.path().join("counters.json"),
        sync: sync_path,
        audit: Arc::new(recording_audit(&entries)),
        clock: Box::new(|| OffsetDateTime::from_unix_timestamp(START).unwrap_or(OffsetDateTime::UNIX_EPOCH)),
    })?;
    Ok(Harness { dir, breakers, entries })
}


fn input(alert: &str, fail_action: Option<usize>) -> Result<SimulationInput, Box<dyn Error>> {
    Ok(SimulationInput {
        tenant: "acme".to_owned(),
        request_id: "test".to_owned(),
        alert: serde_json::from_str(alert)?,
        fleet_size: BIG_FLEET,
        isolated_now: 0,
        fail_action,
    })
}


fn snapshot(name: &str, text: &str) -> TestResult {
    let expected = fs::read_to_string(format!("{}/tests/snapshots/{name}.txt", env!("CARGO_MANIFEST_DIR")))?;
    assert_eq!(text, expected);
    Ok(())
}


fn fixtures() -> Result<(Catalogue, Playbook), Box<dyn Error>> {
    Ok((parse_document(CATALOGUE, "catalogue.yaml")?, parse_document(C2, "c2.yaml")?))
}


fn trace_of(harness: &Harness, alert: &str, fail_action: Option<usize>) -> Result<String, Box<dyn Error>> {
    let (catalogue, playbook) = fixtures()?;
    Ok(render_trace(&simulate(
        &playbook,
        &catalogue,
        &harness.breakers,
        &input(alert, fail_action)?,
    )))
}


fn custom_trace(steps: &str, alert: &Value, fail_action: Option<usize>) -> Result<String, Box<dyn Error>> {
    let text = format!(
        "name: custom\nversion: 1\nmode: simulate\nvariables: {{ channel: ops }}\nsteps:\n{steps}\non_error:\n  - action: notify\n    params: {{ text: \"failed {{{{ alert.name }}}}\" }}\n"
    );
    let playbook: Playbook = parse_document(&text, "custom.yaml")?;
    let catalogue: Catalogue = parse_document(SIM_CATALOGUE, "sim.yaml")?;
    let current = harness()?;
    let mut simulated = input("{}", fail_action)?;
    simulated.alert = alert.clone();
    Ok(render_trace(&simulate(&playbook, &catalogue, &current.breakers, &simulated)))
}


#[test]
fn the_spec_example_traces_are_snapshots() -> TestResult {
    snapshot("c2_hostile", &trace_of(&harness()?, HOSTILE, None)?)?;
    snapshot("c2_critical", &trace_of(&harness()?, CRITICAL, None)?)?;
    snapshot("c2_benign", &trace_of(&harness()?, BENIGN, None)?)?;
    snapshot("c2_failure", &trace_of(&harness()?, HOSTILE, Some(1))?)?;
    Ok(())
}


#[test]
fn the_sixth_isolation_needs_approval_and_is_audited() -> TestResult {
    let current = harness()?;
    let traces: Vec<String> = (0..SIX).map(|_| trace_of(&current, HOSTILE, None)).collect::<Result<_, _>>()?;
    snapshot("c2_sixth", traces.last().ok_or("no trace")?)?;
    assert!(traces.iter().take(SIX - 1).all(|trace| !trace.contains("halted")));
    let recorded = current.entries.lock().map_err(|_| "poisoned")?;
    let denied: Vec<&NewEntry> = recorded.iter().filter(|entry| entry.action == "breaker.needs_approval").collect();
    assert_eq!(denied.len(), 1);
    assert_eq!(denied.first().map(|entry| entry.outcome), Some(Outcome::Denied));
    Ok(())
}


#[test]
fn only_the_header_tells_enforce_from_simulate() -> TestResult {
    let (catalogue, playbook) = fixtures()?;
    let quiet = Playbook {
        mode: Mode::Simulate,
        ..playbook.clone()
    };
    let enforced = render_trace(&simulate(&playbook, &catalogue, &harness()?.breakers, &input(HOSTILE, None)?));
    let simulated = render_trace(&simulate(&quiet, &catalogue, &harness()?.breakers, &input(HOSTILE, None)?));
    assert_eq!(enforced.replace("mode=enforce", "mode=simulate"), simulated);
    Ok(())
}


#[test]
fn compensations_run_in_reverse_order_of_the_actions() -> TestResult {
    let (catalogue, _) = fixtures()?;
    let text = "name: c\nversion: 1\nmode: enforce\nsteps:\n  - connector: fortigate\n    action: block_ip\n    params: { ip: 198.51.100.7, duration: 1h }\n  - connector: entra_id\n    action: revoke_sessions\n    params: { user: bob }\n  - connector: dns\n    action: sinkhole\n    params: { domain: x.example, duration: 1h }\n  - action: isolate_endpoint\n    params: { host: h }\n  - connector: slack\n    action: notify\n    params: { channel: c, message: never }\non_error:\n  - connector: pagerduty\n    action: page\n    params: { severity: high, summary: failed }\n";
    let playbook: Playbook = parse_document(text, "c.yaml")?;
    let failed = render_trace(&simulate(&playbook, &catalogue, &harness()?.breakers, &input("{}", Some(FOURTH))?));
    let lines: Vec<&str> = failed.lines().collect();
    let position = |needle: &str| lines.iter().position(|line| line.contains(needle)).ok_or("missing line");
    assert!(position("compensation unsinkhole for sinkhole")? < position("compensation unblock_ip for block_ip")?);
    assert!(position("failure simulated steps.3 isolate_endpoint")? < position("compensation unsinkhole")?);
    assert!(position("compensation unblock_ip")? < position("on_error handler")?);
    assert!(!failed.contains("revoke_sessions for") && !failed.contains("isolate_endpoint for") && !failed.contains("never"));
    assert!(failed.contains("on_error.0 pagerduty/page"));
    let first = render_trace(&simulate(&playbook, &catalogue, &harness()?.breakers, &input("{}", Some(NO_ENTRY))?));
    assert!(!first.contains("compensation"));
    Ok(())
}


#[test]
fn guards_and_steps_that_cannot_run_are_traced() -> TestResult {
    let alert = json!({ "name": "n", "host": { "value": "h" } });
    let guarded = custom_trace(
        "  - if: \"{{ alert.x | nosuchfilter }}\"\n    then:\n      - action: notify\n        params: { text: no }\n    else:\n      - action: notify\n        params: { text: no }\n  - action: notify\n    params: { text: \"{{ playbook.variables.channel }} {{ alert.name }}\" }\n  - action: nothing\n  - connector: x\n    action: y\n  - {}\n  - action: notify\n    params: { text: \"{{ alert.missing }}\" }\n  - action: request_approval\n    params: { role: lead, timeout: 5m, action: ban }\n  - action: notify\n    params: { text: after }",
        &alert,
        None,
    )?;
    assert!(guarded.contains("condition steps.0 error"), "{guarded}");
    assert!(guarded.contains("nothing runs"));
    assert!(!guarded.contains("steps.0.then") && !guarded.contains("steps.0.else"));
    assert!(
        guarded.contains("action steps.1 notify text=\"ops n\" breakers=not applicable"),
        "{guarded}"
    );
    assert!(guarded.contains("rejected steps.2 nothing: no such action in the catalogue"));
    assert!(guarded.contains("rejected steps.3 y: no such action in the catalogue"));
    assert!(guarded.contains("rejected steps.4 : no such action in the catalogue"));
    assert!(guarded.contains("rejected steps.5 notify: parameter `text` is missing or empty"));
    assert!(guarded.contains("approval requested steps.6 action=\"ban\" role=\"lead\" timeout=\"5m\""));
    assert!(guarded.contains("action steps.7 notify text=\"after\""));
    Ok(())
}


#[test]
fn a_failing_action_in_a_branch_runs_the_error_handler_with_alert_data() -> TestResult {
    let alert = json!({ "name": "web-1" });
    let failed = custom_trace(
        "  - if: \"{{ alert.name }}\"\n    then:\n      - action: unban\n        compensate: unban\n      - action: notify\n        params: { text: ok }",
        &alert,
        Some(1),
    )?;
    assert!(failed.contains("failure simulated steps.0.then.1 notify"), "{failed}");
    assert!(failed.contains("compensation unban for unban"), "{failed}");
    assert!(failed.contains("on_error.0 notify text=\"failed web-1\""), "{failed}");
    Ok(())
}


#[test]
fn breaker_bindings_that_cannot_be_built_are_rejected() -> TestResult {
    let alert = json!({ "user": { "value": "adm", "tags": ["privileged"] }, "plain": { "value": "bob" }, "n": OVER_LIMIT });
    let rejected = custom_trace(
        "  - action: ban_ip\n  - action: ban_ip\n    params: { ip: notip }\n  - action: ban_ip\n    params: { ip: 198.51.100.1, ttl: xyz }\n  - action: ban_domain_timed\n    params: { domain: a.example, ttl: xyz }\n  - action: run\n    params: { host: h }\n  - action: run_blind\n    params: { host: h }",
        &alert,
        None,
    )?;
    assert!(
        rejected.contains("rejected steps.0 ban_ip: the breaker target `ip` is missing"),
        "{rejected}"
    );
    assert!(
        rejected.contains("rejected steps.1 ban_ip: `\"notip\"` is not an IP address"),
        "{rejected}"
    );
    assert!(rejected.contains("rejected steps.2 ban_ip: `\"xyz\"` is not a duration"), "{rejected}");
    assert!(
        rejected.contains("rejected steps.3 ban_domain_timed: `\"xyz\"` is not a duration"),
        "{rejected}"
    );
    assert!(rejected.contains("rejected steps.4 run: the number of machines is missing"), "{rejected}");
    assert!(
        rejected.contains("rejected steps.5 run_blind: the number of machines is missing"),
        "{rejected}"
    );
    assert!(!rejected.contains("halted"));
    Ok(())
}


#[test]
fn the_breakers_decide_every_kind_of_action() -> TestResult {
    let alert = json!({ "user": { "value": "adm", "tags": ["privileged"] }, "plain": { "value": "bob" }, "n": OVER_LIMIT });
    let decided = custom_trace(
        "  - action: ban_ip_typed\n    params: { ip: 198.51.100.1, ttl: 1h }\n  - action: ban_domain_timed\n    params: { domain: a.example, ttl: 1h }\n  - action: disable\n    params: { user: \"{{ alert.plain }}\" }\n  - action: run\n    params: { host: h, count: 3 }\n  - action: isolate_number\n    params: { host: 7 }\n  - action: ban_ip\n    params: { ip: 198.51.100.1 }",
        &alert,
        None,
    )?;
    assert!(
        decided.contains("ban_ip_typed ip=\"198.51.100.1\" ttl=\"1h\" breakers=allowed"),
        "{decided}"
    );
    assert!(
        decided.contains("ban_domain_timed domain=\"a.example\" ttl=\"1h\" breakers=allowed"),
        "{decided}"
    );
    assert!(decided.contains("disable user=\"bob\" breakers=allowed"), "{decided}");
    assert!(decided.contains("run count=3 host=\"h\" breakers=allowed"), "{decided}");
    assert!(decided.contains("isolate_number host=7 breakers=allowed"), "{decided}");
    assert!(
        decided.contains("ban_ip ip=\"198.51.100.1\" breakers=needs-approval alert=true reason=limit block_duration reached"),
        "{decided}"
    );
    assert!(
        decided.ends_with("halted steps.5: waiting for approval, on-call alert raised\n"),
        "{decided}"
    );
    for (steps, reason) in [
        (
            "  - action: disable\n    params: { user: \"{{ alert.user }}\" }",
            "protected target tagged `privileged`",
        ),
        (
            "  - action: run\n    params: { host: h, count: \"{{ alert.n }}\" }",
            "limit rmm_machines reached: 25 of 20",
        ),
        (
            "  - action: ban_ip_typed\n    params: { ip: 10.0.0.5, ttl: 1h }",
            "inside the reserved range 10.0.0.0/8",
        ),
        (
            "  - action: ban_domain\n    params: { domain: a.example }",
            "limit block_duration reached",
        ),
        (
            "  - action: ban_domain\n    params: { domain: a.example }\n  - action: notify\n    params: { text: unreachable }",
            "limit block_duration reached",
        ),
    ] {
        let stopped = custom_trace(steps, &alert, None)?;
        assert!(
            stopped.contains(reason) && stopped.contains("halted steps.0") && !stopped.contains("unreachable"),
            "{reason}: {stopped}"
        );
    }
    Ok(())
}


#[test]
fn the_current_bundle_is_found_by_name_or_file_stem() -> TestResult {
    let rig = rig()?;
    let bundle = current_config(&rig.session.engine);
    assert!(find_playbook(&bundle, "Block confirmed C2").is_some());
    assert!(find_playbook(&bundle, "c2").is_some());
    assert!(find_playbook(&bundle, "other").is_none());
    assert!(simulate_named(&bundle, &rig.session.breakers, "c2", &input(HOSTILE, None)?).is_some());
    assert!(simulate_named(&bundle, &rig.session.breakers, "other", &input(HOSTILE, None)?).is_none());
    let state = bundle_state(&bundle);
    assert!(state.contains_key(CATALOGUE_DOCUMENT));
    assert_eq!(state.len(), FIRST_ISOLATED);
    assert!(validate_bundle(&bundle).is_ok());
    Ok(())
}


pub struct Rig {
    pub dir: TempDir,
    pub session: Session,
    pub entries: Arc<Mutex<Vec<NewEntry>>>,
    pub breaker_dir: TempDir,
}


fn path_in(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}


fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


fn settings_in(dir: &Path, entries: &Arc<Mutex<Vec<NewEntry>>>) -> PlaybookSettings {
    PlaybookSettings {
        catalogue_path: path_in(dir, "catalogue.yaml"),
        playbook_paths: vec![path_in(dir, "c2.yaml")],
        audit: Arc::new(recording_audit(entries)),
    }
}


fn rig() -> Result<Rig, Box<dyn Error>> {
    let dir = tempdir()?;
    replace_file(&path_in(dir.path(), "catalogue.yaml"), CATALOGUE)?;
    replace_file(&path_in(dir.path(), "c2.yaml"), C2)?;
    let entries = Arc::new(Mutex::new(Vec::new()));
    let engine = Arc::new(open_playbooks(settings_in(dir.path(), &entries))?);
    let current = harness()?;
    Ok(Rig {
        dir,
        session: Session {
            engine,
            breakers: current.breakers,
        },
        entries,
        breaker_dir: current.dir,
    })
}


fn recorded_for(rig: &Rig, outcome: Outcome) -> Result<Vec<NewEntry>, Box<dyn Error>> {
    let all = rig.entries.lock().map_err(|_| "poisoned")?;
    Ok(all
        .iter()
        .filter(|entry| entry.outcome == outcome && entry.module == MODULE)
        .cloned()
        .collect())
}


fn alert_file(rig: &Rig, name: &str, text: &str) -> Result<String, Box<dyn Error>> {
    let path = path_in(rig.breaker_dir.path(), name);
    fs::write(&path, text)?;
    Ok(path.display().to_string())
}


#[test]
fn a_changed_playbook_is_applied_without_restart_and_audited() -> TestResult {
    let rig = rig()?;
    let before = execute(&rig.session, &["simulate", "c2", &alert_file(&rig, "hostile.json", HOSTILE)?])?;
    assert!(!before.contains("#extra"));
    assert_eq!(reload(&rig.session.engine), ReloadOutcome::Unchanged);
    let extended = C2.replace(
        "on_error:",
        "  - connector: slack\n    action: notify\n    params: { channel: \"#extra\", message: added }\non_error:",
    );
    replace_file(&path_in(rig.dir.path(), "c2.yaml"), &extended)?;
    assert!(matches!(reload(&rig.session.engine), ReloadOutcome::Applied { keys } if keys.iter().any(|key| key.contains("c2.yaml"))));
    let after = execute(&rig.session, &["simulate", "c2", &alert_file(&rig, "hostile.json", HOSTILE)?])?;
    assert!(after.contains("#extra"), "{after}");
    assert_eq!(recorded_for(&rig, Outcome::Success)?.len(), 1);
    Ok(())
}


#[test]
fn an_invalid_playbook_is_refused_audited_and_the_old_one_stays() -> TestResult {
    let rig = rig()?;
    let session = &rig.session;
    let alert = alert_file(&rig, "hostile.json", HOSTILE)?;
    let before = execute(session, &["simulate", "c2", &alert])?;
    replace_file(&path_in(rig.dir.path(), "c2.yaml"), &C2.replace("version: 3", "version: 3\nbogus: 1"))?;
    let refused = reload(&rig.session.engine);
    assert!(
        matches!(&refused, ReloadOutcome::Refused { reason } if reason.contains("c2.yaml:") && reason.contains("bogus")),
        "{refused:?}"
    );
    replace_file(&path_in(rig.dir.path(), "c2.yaml"), &C2.replace("action: sinkhole", "action: vanish"))?;
    let semantic = reload(&rig.session.engine);
    assert!(
        matches!(&semantic, ReloadOutcome::Refused { reason } if reason.contains("section `validation`") && reason.contains("unknown action `vanish`")),
        "{semantic:?}"
    );
    assert_eq!(execute(&rig.session, &["simulate", "c2", &alert])?, before);
    let denied = recorded_for(&rig, Outcome::Denied)?;
    assert_eq!(denied.len(), FIRST_ISOLATED);
    assert!(denied
        .iter()
        .all(|entry| entry.parameters.get("result").map(String::as_str) == Some("refused")));
    assert_eq!(
        execute(session, &["reload"])?,
        format!(
            "refused {}",
            match semantic {
                ReloadOutcome::Refused { reason } => reason,
                other => format!("{other:?}"),
            }
        )
    );
    Ok(())
}


#[test]
fn a_bundle_that_does_not_load_or_validate_does_not_open() -> TestResult {
    let dir = tempdir()?;
    let entries = Arc::new(Mutex::new(Vec::new()));
    replace_file(&path_in(dir.path(), "c2.yaml"), C2)?;
    let missing = open_playbooks(settings_in(dir.path(), &entries)).err().ok_or("expected a failure")?;
    assert!(matches!(missing, PlaybookError::Config(_)));
    replace_file(&path_in(dir.path(), "catalogue.yaml"), "actions: 3\n")?;
    let broken = open_playbooks(settings_in(dir.path(), &entries)).err().ok_or("expected a failure")?;
    assert!(broken.to_string().contains("catalogue.yaml:1:"), "{broken}");
    replace_file(&path_in(dir.path(), "catalogue.yaml"), CATALOGUE)?;
    replace_file(
        &path_in(dir.path(), "c2.yaml"),
        "name: x\nversion: 1\nmode: simulate\nsteps: [ { bogus: 1 } ]\n",
    )?;
    let unreadable = open_playbooks(settings_in(dir.path(), &entries)).err().ok_or("expected a failure")?;
    assert!(unreadable.to_string().contains("c2.yaml:"), "{unreadable}");
    replace_file(&path_in(dir.path(), "c2.yaml"), "name: \"\"\nversion: 1\nmode: simulate\nsteps: []\n")?;
    let invalid = open_playbooks(settings_in(dir.path(), &entries)).err().ok_or("expected a failure")?;
    assert!(matches!(invalid, PlaybookError::Invalid(_)));
    let message = invalid.to_string();
    assert!(
        message.contains("the name is empty") && message.contains("steps is empty") && message.contains("on_error is missing"),
        "{message}"
    );
    Ok(())
}


#[test]
fn the_command_line_reports_and_never_stops_on_an_error() -> TestResult {
    let rig = rig()?;
    let session = &rig.session;
    let hostile = alert_file(&rig, "hostile.json", HOSTILE)?;
    let broken = alert_file(&rig, "broken.json", "{")?;
    let script = format!(
        "list\nvalidate\nreload\nsimulate c2 {hostile}\nsimulate nothing {hostile}\nsimulate c2 /nonexistent\nsimulate c2 {broken}\nsimulate c2 {hostile} x\nsimulate c2 {hostile} 0\nbogus\n\nquit\nlist\n"
    );
    let mut out = Vec::new();
    run_session(session, script.as_bytes(), &mut out)?;
    let text = String::from_utf8(out)?;
    assert!(
        text.starts_with("Block confirmed C2 v3 mode=enforce\nvalid: 1 playbook(s)\nunchanged\nplaybook Block confirmed C2 v3"),
        "{text}"
    );
    assert!(text.contains("error: unknown playbook `nothing`"));
    assert!(text.contains("error: cannot read the alert:"));
    assert!(text.contains("error: the alert is not valid JSON:"));
    assert!(text.contains("error: not a number:"));
    assert!(text.contains("failure simulated steps.0.then.0 block_ip"));
    assert!(text.matches("error: usage: list | validate").count() == FIRST_ISOLATED);
    let invalid = Bundle {
        playbooks: Vec::new(),
        catalogue: parse_document("actions:\n  - action: a\n  - action: a\n", "dup.yaml")?,
    };
    rig.session.engine.current.store(Arc::new(invalid));
    assert!(matches!(execute(session, &["validate"]), Err(CommandError::Invalid(_))));
    Ok(())
}


#[test]
fn input_that_cannot_be_read_ends_the_session_with_an_error() -> TestResult {
    let rig = rig()?;
    let session = &rig.session;
    let mut out = Vec::new();
    let failure = run_session(session, &[INVALID_UTF8, b'\n'][..], &mut out)
        .err()
        .ok_or("expected a read failure")?;
    assert_eq!(failure.kind(), io::ErrorKind::InvalidData);
    let mut sink = FailingWriter;
    assert!(run_command(session, "list", &mut sink).is_err());
    assert!(run_command(session, "bogus", &mut sink).is_err());
    Ok(())
}


pub struct FailingWriter;


impl io::Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("closed"))
    }
}
