#[path = "common/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::{NewEntry, Outcome};
use core_config::parse::parse_document;
use core_config::plan::{change_of, Change, ChangeKind};
use core_config::reload::{bounded_parameter, changed_files_text, changed_settings_text, current_config, diff_text, reload, ReloadOutcome};
use core_config::watch::watch_files;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use response_breakers::breakers::{open_breakers, BreakerSettings, Breakers};
use response_breakers::store::sync_path;
use response_playbooks::bundle::{
    bundle_state, document_value, find_playbook, leaves, open_playbooks, retarget, simulate_named, validate_bundle, Bundle, PlaybookSettings,
    MAX_STATE_DEPTH, MODULE,
};
use response_playbooks::cli::{execute, run_command, run_session, Session};
use response_playbooks::error::{CommandError, PlaybookError};
use response_playbooks::model::{Catalogue, Inventory, Mode, Playbook, SimulationInput};
use response_playbooks::render::render_trace;
use response_playbooks::simulate::{simulate, MAX_WORK};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use types::TestResult;


const CHANGED_KEYS: usize = 300;


const CATALOGUE: &str = include_str!("../fixtures/catalogue.yaml");


const INVENTORY: &str = "
hosts:
  dc-01: { tags: [critical, domain-controller] }
  ws-0042: { tags: [workstation] }
  h: {}
  '7': {}
accounts:
  admin-ops: { tags: [privileged] }
  jdoe: {}
  bob: {}
  adm: {}
";


const FIXTURE_INVENTORY: &str = include_str!("../fixtures/inventory.yaml");


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
        approvals: Vec::new(),
    })
}


fn inventory() -> Result<Inventory, Box<dyn Error>> {
    Ok(parse_document(INVENTORY, "inventory.yaml")?)
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
        &inventory()?,
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
    simulated.approvals = vec!["granted".to_owned()];
    Ok(render_trace(&simulate(
        &playbook,
        &catalogue,
        &inventory()?,
        &current.breakers,
        &simulated,
    )))
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
    let enforced = render_trace(&simulate(
        &playbook,
        &catalogue,
        &inventory()?,
        &harness()?.breakers,
        &input(HOSTILE, None)?,
    ));
    let simulated = render_trace(&simulate(&quiet, &catalogue, &inventory()?, &harness()?.breakers, &input(HOSTILE, None)?));
    assert_eq!(enforced.replace("mode=enforce", "mode=simulate"), simulated);
    Ok(())
}


#[test]
fn compensations_run_in_reverse_order_of_the_actions() -> TestResult {
    let (catalogue, _) = fixtures()?;
    let text = "name: c\nversion: 1\nmode: enforce\nsteps:\n  - connector: fortigate\n    action: block_ip\n    params: { ip: 198.51.100.7, duration: 1h }\n  - connector: entra_id\n    action: revoke_sessions\n    params: { user: bob }\n  - connector: dns\n    action: sinkhole\n    params: { domain: x.example, duration: 1h }\n  - action: isolate_endpoint\n    params: { host: h }\n  - connector: slack\n    action: notify\n    params: { channel: c, message: never }\non_error:\n  - connector: pagerduty\n    action: page\n    params: { severity: high, summary: failed }\n";
    let playbook: Playbook = parse_document(text, "c.yaml")?;
    let failed = render_trace(&simulate(
        &playbook,
        &catalogue,
        &inventory()?,
        &harness()?.breakers,
        &input("{}", Some(FOURTH))?,
    ));
    let lines: Vec<&str> = failed.lines().collect();
    let position = |needle: &str| lines.iter().position(|line| line.contains(needle)).ok_or("missing line");
    assert!(position("compensation unsinkhole for sinkhole")? < position("compensation unblock_ip for block_ip")?);
    assert!(position("failure simulated steps.3 isolate_endpoint")? < position("compensation unsinkhole")?);
    assert!(position("compensation unblock_ip")? < position("on_error handler")?);
    assert!(!failed.contains("revoke_sessions for") && !failed.contains("isolate_endpoint for") && !failed.contains("never"));
    assert!(failed.contains("on_error.0 pagerduty/page"));
    let first = render_trace(&simulate(
        &playbook,
        &catalogue,
        &inventory()?,
        &harness()?.breakers,
        &input("{}", Some(NO_ENTRY))?,
    ));
    assert!(!first.contains("compensation"));
    Ok(())
}


#[test]
fn an_unresolvable_approval_stops_the_run() -> TestResult {
    let alert = json!({ "name": "n", "host": { "value": "h" } });
    let halted = custom_trace(
        "  - action: request_approval\n    params: { role: lead, timeout: 5m, action: \"{{ alert.missing }}\" }\n  - action: notify\n    params: { text: after }\n  - action: nothing",
        &alert,
        None,
    )?;
    assert!(halted.contains("rejected steps.0 request_approval"), "{halted}");
    assert!(halted.contains("halted steps.1 notify"), "{halted}");
    assert!(halted.contains("halted steps.2"), "{halted}");
    assert!(!halted.contains("action steps.1"), "{halted}");
    let after_approval = custom_trace(
        "  - action: request_approval\n    params: { role: lead, timeout: 5m, action: ban }\n  - action: nothing\n  - action: notify\n    params: { text: after }",
        &alert,
        None,
    )?;
    assert!(after_approval.contains("halted steps.1"), "{after_approval}");
    assert!(!after_approval.contains("action steps.2"), "{after_approval}");
    let granted = custom_trace(
        "  - action: request_approval\n    params: { role: lead, timeout: 5m, action: granted }\n  - action: nothing\n  - action: notify\n    params: { text: after }",
        &alert,
        None,
    )?;
    assert!(granted.contains("rejected steps.1 nothing"), "{granted}");
    assert!(granted.contains("halted steps.2 notify"), "{granted}");
    assert!(!granted.contains("action steps.2"), "{granted}");
    Ok(())
}


#[test]
fn guards_and_steps_that_cannot_run_halt_the_run() -> TestResult {
    let alert = json!({ "name": "n", "host": { "value": "h" } });
    let guarded = custom_trace(
        "  - if: \"{{ alert.x | nosuchfilter }}\"\n    then:\n      - action: notify\n        params: { text: no }\n    else:\n      - action: notify\n        params: { text: no }\n  - action: notify\n    params: { text: after }",
        &alert,
        None,
    )?;
    assert!(guarded.contains("condition steps.0 error"), "{guarded}");
    assert!(guarded.contains("run halted"));
    assert!(!guarded.contains("steps.0.then") && !guarded.contains("steps.0.else"));
    assert!(guarded.contains("halted steps.1 notify: not run"), "{guarded}");
    assert!(!guarded.contains("action steps.1"), "{guarded}");
    let ran = custom_trace(
        "  - action: notify\n    params: { text: \"{{ playbook.variables.channel }} {{ alert.name }}\" }",
        &alert,
        None,
    )?;
    assert!(ran.contains("action steps.0 notify text=\"ops n\" breakers=not applicable"), "{ran}");
    let failing = [
        ("  - action: nothing\n", "rejected steps.0 nothing: no such action in the catalogue"),
        ("  - connector: x\n    action: y\n", "rejected steps.0 y: no such action in the catalogue"),
        ("  - {}\n", "rejected steps.0 : no such action in the catalogue"),
        (
            "  - action: notify\n    params: { text: \"{{ alert.missing }}\" }\n",
            "rejected steps.0 notify: parameter `text` is missing or empty",
        ),
    ];
    failing.iter().try_for_each(|(step, expected)| -> TestResult {
        let trace = custom_trace(&format!("{step}  - action: notify\n    params: {{ text: after }}"), &alert, None)?;
        assert!(trace.contains(expected), "{trace}");
        assert!(trace.contains("halted steps.1 notify: not run"), "{trace}");
        Ok(())
    })
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
    let cases = [
        ("  - action: ban_ip\n", "rejected steps.0 ban_ip: the breaker target `ip` is missing"),
        (
            "  - action: ban_ip\n    params: { ip: notip }\n",
            "rejected steps.0 ban_ip: `\"notip\"` is not an IP address",
        ),
        (
            "  - action: ban_ip\n    params: { ip: 198.51.100.1, ttl: xyz }\n",
            "rejected steps.0 ban_ip: `\"xyz\"` is not a duration",
        ),
        (
            "  - action: ban_domain_timed\n    params: { domain: a.example, ttl: xyz }\n",
            "rejected steps.0 ban_domain_timed: `\"xyz\"` is not a duration",
        ),
        (
            "  - action: run\n    params: { host: h }\n",
            "rejected steps.0 run: the number of machines is missing",
        ),
        (
            "  - action: run_blind\n    params: { host: h }\n",
            "rejected steps.0 run_blind: the number of machines is missing",
        ),
    ];
    cases.iter().try_for_each(|(step, expected)| -> TestResult {
        let rejected = custom_trace(&format!("{step}  - action: notify\n    params: {{ text: after }}"), &alert, None)?;
        assert!(rejected.contains(expected), "{rejected}");
        assert!(rejected.contains("halted steps.1 notify: not run"), "{rejected}");
        assert!(!rejected.contains("action steps.1"), "{rejected}");
        Ok(())
    })
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
    assert!(state.keys().any(|key| key.ends_with("catalogue.yaml::actions.0.action")));
    assert!(state.keys().any(|key| key.ends_with("inventory.yaml::hosts.dc-01.tags.0")));
    assert!(state.keys().any(|key| key.ends_with("c2.yaml::steps.2.else.0.params.role")));
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
        inventory_path: path_in(dir, "inventory.yaml"),
        playbook_paths: vec![path_in(dir, "c2.yaml")],
        audit: Arc::new(recording_audit(entries)),
    }
}


fn rig() -> Result<Rig, Box<dyn Error>> {
    let dir = tempdir()?;
    replace_file(&path_in(dir.path(), "catalogue.yaml"), CATALOGUE)?;
    replace_file(&path_in(dir.path(), "inventory.yaml"), FIXTURE_INVENTORY)?;
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
        matches!(&refused, ReloadOutcome::Refused { reason } if reason.contains("c2.yaml:") && reason.contains("unknown field")),
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
    let no_inventory = open_playbooks(settings_in(dir.path(), &entries)).err().ok_or("expected a failure")?;
    assert!(no_inventory.to_string().contains("inventory.yaml"), "{no_inventory}");
    replace_file(&path_in(dir.path(), "inventory.yaml"), "hosts:\n  h:\n    tag: [x]\n")?;
    let strict = open_playbooks(settings_in(dir.path(), &entries)).err().ok_or("expected a failure")?;
    assert!(
        strict.to_string().contains("inventory.yaml:3:") && strict.to_string().contains("tag"),
        "{strict}"
    );
    replace_file(&path_in(dir.path(), "inventory.yaml"), FIXTURE_INVENTORY)?;
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
        catalogue_file: "dup.yaml".to_owned(),
        inventory: Inventory::default(),
        inventory_file: "inventory.yaml".to_owned(),
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


fn probe_trace(steps: &str, alert: &str, approvals: &[&str]) -> Result<String, Box<dyn Error>> {
    let text = format!(
        "name: probe\nversion: 1\nmode: enforce\nsteps:\n{steps}\non_error:\n  - connector: pagerduty\n    action: page\n    params: {{ severity: high, summary: failed }}\n"
    );
    let playbook: Playbook = parse_document(&text, "probe.yaml")?;
    let catalogue: Catalogue = parse_document(CATALOGUE, "catalogue.yaml")?;
    let mut simulated = input(alert, None)?;
    simulated.approvals = approvals.iter().map(|approved| (*approved).to_owned()).collect();
    Ok(render_trace(&simulate(
        &playbook,
        &catalogue,
        &inventory()?,
        &harness()?.breakers,
        &simulated,
    )))
}


const APPROVE_ISOLATION: &str = "  - action: request_approval\n    params: { role: soc_lead, timeout: 15m, action: isolate_endpoint }\n";


const ISOLATE_HOST: &str = "  - action: isolate_endpoint\n    params: { host: \"{{ alert.host }}\" }\n";


const NESTED_APPROVAL: &str =
    "  - if: \"{{ true }}\"\n    then:\n      - action: request_approval\n        params: { role: r, timeout: 5m, action: isolate_endpoint }\n";


const OPPOSITE_BRANCH: &str = "  - if: \"{{ true }}\"\n    then:\n      - action: isolate_endpoint\n        params: { host: \"{{ alert.host }}\" }\n    else:\n      - action: request_approval\n        params: { role: r, timeout: 5m, action: isolate_endpoint }\n";


#[test]
fn probe_one_an_approval_that_nobody_gave_halts_the_sequence() -> TestResult {
    let waiting = probe_trace(&format!("{APPROVE_ISOLATION}{ISOLATE_HOST}"), CRITICAL, &[])?;
    assert!(waiting.contains("approval requested steps.0"), "{waiting}");
    assert!(waiting.contains("halted steps.1 isolate_endpoint"), "{waiting}");
    assert!(!waiting.contains("action steps.1") && !waiting.contains("breakers=allowed"), "{waiting}");
    let blank = probe_trace(&format!("{APPROVE_ISOLATION}  - {{}}\n"), CRITICAL, &[])?;
    assert!(blank.contains("halted steps.1 (empty step)"), "{blank}");
    let nested = probe_trace(&format!("{NESTED_APPROVAL}{ISOLATE_HOST}"), CRITICAL, &[])?;
    assert!(
        nested.contains("halted steps.1 isolate_endpoint") && !nested.contains("action steps.1"),
        "{nested}"
    );
    let granted = probe_trace(&format!("{APPROVE_ISOLATION}{ISOLATE_HOST}"), CRITICAL, &["isolate_endpoint"])?;
    assert!(granted.contains("approval granted steps.0"), "{granted}");
    assert!(
        granted.contains("action steps.1 isolate_endpoint host=\"dc-01\" breakers=needs-approval") && granted.contains("halted steps.1"),
        "{granted}"
    );
    let other = probe_trace(&format!("{APPROVE_ISOLATION}{ISOLATE_HOST}"), CRITICAL, &["disable_account"])?;
    assert!(
        other.contains("approval requested steps.0") && other.contains("halted steps.1"),
        "{other}"
    );
    Ok(())
}


#[test]
fn probe_two_an_approval_in_the_opposite_branch_is_no_gate() -> TestResult {
    let trace = probe_trace(OPPOSITE_BRANCH, CRITICAL, &[])?;
    assert!(!trace.contains("breakers=allowed"), "{trace}");
    assert!(
        trace.contains("breakers=needs-approval alert=true reason=protected target tagged `critical`"),
        "{trace}"
    );
    assert!(trace.contains("halted steps.0.then.0"), "{trace}");
    Ok(())
}


#[test]
fn probe_three_protection_comes_from_the_inventory_not_from_the_alert() -> TestResult {
    let stripped = r#"{ "host": { "value": "dc-01", "criticality": "normal", "tags": [] } }"#;
    for host in ["{{ alert.host }}", "{{ alert.host.value }}", "h-{{ alert.host }}", "dc-01"] {
        let trace = probe_trace(
            &format!("  - action: isolate_endpoint\n    params: {{ host: \"{host}\" }}\n"),
            stripped,
            &[],
        )?;
        assert!(!trace.contains("breakers=allowed"), "{host}: {trace}");
    }
    let known = probe_trace(ISOLATE_HOST, stripped, &[])?;
    assert!(known.contains("reason=protected target tagged `critical`"), "{known}");
    assert!(!known.contains("unknown asset"), "{known}");
    let ghost = probe_trace(ISOLATE_HOST, r#"{ "host": { "value": "ghost" } }"#, &[])?;
    assert!(
        ghost.contains("unknown asset steps.0 ghost: not in the inventory, treated as protected"),
        "{ghost}"
    );
    assert!(ghost.contains("breakers=needs-approval") && ghost.contains("halted steps.0"), "{ghost}");
    let plain = probe_trace(ISOLATE_HOST, r#"{ "host": { "value": "ws-0042" } }"#, &[])?;
    assert!(plain.contains("breakers=allowed"), "{plain}");
    let added = probe_trace(ISOLATE_HOST, r#"{ "host": { "value": "ws-0042", "tags": ["hypervisor"] } }"#, &[])?;
    assert!(added.contains("protected target tagged `hypervisor`"), "{added}");
    Ok(())
}


#[test]
fn accounts_are_looked_up_in_the_inventory_too() -> TestResult {
    let disable = |alert: &str| -> Result<String, Box<dyn Error>> {
        custom_trace(
            "  - action: disable\n    params: { user: \"{{ alert.user }}\" }",
            &serde_json::from_str(alert)?,
            None,
        )
    };
    assert!(disable(r#"{ "user": { "value": "admin-ops" } }"#)?.contains("protected target tagged `privileged`"));
    assert!(disable(r#"{ "user": { "value": "bob" } }"#)?.contains("breakers=allowed"));
    let ghost = disable(r#"{ "user": { "value": "ghost" } }"#)?;
    assert!(
        ghost.contains("unknown asset steps.0 ghost") && ghost.contains("protected target tagged `privileged`"),
        "{ghost}"
    );
    Ok(())
}


#[test]
fn probe_four_a_destructive_action_without_a_breaker_binding_does_not_open() -> TestResult {
    let dir = tempdir()?;
    let entries = Arc::new(Mutex::new(Vec::new()));
    let unbound = CATALOGUE.replace("    breaker: { kind: isolate_endpoint, target: host }\n", "");
    replace_file(&path_in(dir.path(), "catalogue.yaml"), &unbound)?;
    replace_file(&path_in(dir.path(), "inventory.yaml"), FIXTURE_INVENTORY)?;
    replace_file(&path_in(dir.path(), "c2.yaml"), C2)?;
    let refused = open_playbooks(settings_in(dir.path(), &entries)).err().ok_or("expected a failure")?;
    assert!(
        refused
            .to_string()
            .contains("`isolate_endpoint`: a destructive action needs a `breaker` binding"),
        "{refused}"
    );
    Ok(())
}


#[test]
fn the_simulation_input_can_grant_approvals_from_the_command_line() -> TestResult {
    let rig = rig()?;
    let critical = alert_file(&rig, "critical.json", CRITICAL)?;
    let waiting = execute(&rig.session, &["simulate", "c2", &critical])?;
    assert!(waiting.contains("halted steps.4 slack/notify"), "{waiting}");
    let granted = execute(&rig.session, &["simulate", "c2", &critical, "approve=isolate_endpoint"])?;
    assert!(
        granted.contains("approval granted steps.2.else.0") && granted.contains("action steps.4 slack/notify"),
        "{granted}"
    );
    let both = execute(&rig.session, &["simulate", "c2", &critical, "1", "approve=isolate_endpoint", "approve=x"])?;
    assert!(both.contains("approval granted"), "{both}");
    assert!(matches!(
        execute(&rig.session, &["simulate", "c2", &critical, "1", "2"]),
        Err(CommandError::Usage(_))
    ));
    Ok(())
}


#[test]
fn a_reload_is_audited_with_the_changed_file_and_the_changed_settings() -> TestResult {
    let rig = rig()?;
    let changed = FIXTURE_INVENTORY.replace("tags: [workstation]", "tags: [workstation, lab]");
    replace_file(&path_in(rig.dir.path(), "inventory.yaml"), &changed)?;
    let outcome = reload(&rig.session.engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Applied { keys } if keys.len() == 1 && keys.iter().all(|key| key.ends_with("inventory.yaml::hosts.ws-0042.tags.1"))),
        "{outcome:?}"
    );
    replace_file(&path_in(rig.dir.path(), "c2.yaml"), &C2.replace("version: 3", "version: 4"))?;
    replace_file(&path_in(rig.dir.path(), "catalogue.yaml"), &format!("{CATALOGUE}  - action: extra\n"))?;
    assert!(matches!(reload(&rig.session.engine), ReloadOutcome::Applied { .. }));
    let applied = recorded_for(&rig, Outcome::Success)?;
    assert_eq!(applied.len(), FIRST_ISOLATED);
    let first = applied.first().ok_or("no entry")?;
    assert!(
        first.target.ends_with("inventory.yaml") && !first.target.contains(','),
        "{}",
        first.target
    );
    let diff = first.parameters.get("diff").ok_or("no diff")?;
    assert!(
        diff.contains("--- a/") && diff.contains("hosts.ws-0042.tags.1") && !diff.contains("Inventory {"),
        "{diff}"
    );
    let second = applied.get(1).ok_or("no entry")?;
    assert!(
        second.target.contains("c2.yaml") && second.target.contains("catalogue.yaml") && second.target.contains(','),
        "{}",
        second.target
    );
    replace_file(&path_in(rig.dir.path(), "inventory.yaml"), "hosts: 3\n")?;
    assert!(matches!(reload(&rig.session.engine), ReloadOutcome::Refused { .. }));
    let denied = recorded_for(&rig, Outcome::Denied)?;
    assert!(denied.first().is_some_and(|entry| entry.target.ends_with("catalogue.yaml")));
    Ok(())
}


#[test]
fn a_document_that_cannot_be_serialised_is_kept_as_an_error_text() -> TestResult {
    let unkeyed: BTreeMap<(u8, u8), u8> = BTreeMap::from([((1, 1), 1)]);
    let value = document_value(&unkeyed);
    assert!(value.as_str().is_some_and(|text| text.contains("key must be a string")), "{value}");
    Ok(())
}


#[test]
fn a_document_deeper_than_the_state_limit_keeps_its_tail_as_text() -> TestResult {
    let deep = (0..=MAX_STATE_DEPTH).fold(json!("end"), |inner, _| json!({ "k": inner }));
    let found = leaves("f", &deep);
    assert_eq!(found.len(), 1);
    let (key, text) = found.first().ok_or("no leaf")?;
    assert!(key.starts_with("f::k.k") && text.contains("end"), "{key} {text}");
    assert_eq!(
        leaves("f", &json!({ "a": [], "b": { "c": 1 } })),
        vec![("f::a".to_owned(), "[]".to_owned()), ("f::b.c".to_owned(), "1".to_owned())]
    );
    Ok(())
}


#[test]
fn a_serialisation_failure_becomes_text() -> TestResult {
    let unserialisable: BTreeMap<(u8, u8), u8> = BTreeMap::from([((0, 1), 1)]);
    let value = response_playbooks::bundle::document_value(&unserialisable);
    assert!(value.as_str().is_some_and(|text| text.contains("key must be a string")), "{value}");
    Ok(())
}


const UNPROTECTED: &str = r#"{ "name": "n", "host": { "value": "ws-0042" } }"#;


const ERROR_PAGE: &str = "  - connector: pagerduty\n    action: page\n    params: { severity: high, summary: failed }\n";


fn halting_trace(steps: &str, on_error: &str, fail_action: Option<usize>, approvals: &[&str]) -> Result<String, Box<dyn Error>> {
    let text = format!("name: probe\nversion: 1\nmode: enforce\nsteps:\n{steps}\non_error:\n{on_error}");
    let playbook: Playbook = parse_document(&text, "probe.yaml")?;
    let catalogue: Catalogue = parse_document(CATALOGUE, "catalogue.yaml")?;
    let mut simulated = input(UNPROTECTED, fail_action)?;
    simulated.approvals = approvals.iter().map(|approved| (*approved).to_owned()).collect();
    Ok(render_trace(&simulate(
        &playbook,
        &catalogue,
        &inventory()?,
        &harness()?.breakers,
        &simulated,
    )))
}


fn isolated(trace: &str) -> bool {
    trace.lines().any(|line| line.starts_with("action ") && line.contains("isolate_endpoint"))
}


const UNRESOLVED_APPROVAL: &str = "  - action: request_approval\n    params: { role: lead, timeout: 5m, action: \"{{ alert.missing }}\" }\n";


const BROKEN_CONDITION: &str = "  - if: \"{{ alert.host.value / 2 > 1 }}\"\n    then:\n      - action: request_approval\n        params: { role: r, timeout: 5m, action: isolate_endpoint }\n";


const REJECTED_STEP: &str = "  - action: nothing\n";


#[test]
fn probe_five_an_unresolvable_approval_halts_before_a_destructive_action() -> TestResult {
    let trace = halting_trace(&format!("{UNRESOLVED_APPROVAL}{ISOLATE_HOST}"), ERROR_PAGE, None, &[])?;
    assert!(trace.contains("rejected steps.0 request_approval"), "{trace}");
    assert!(trace.contains("halted steps.1 isolate_endpoint: not run"), "{trace}");
    assert!(!isolated(&trace), "{trace}");
    Ok(())
}


#[test]
fn probe_six_a_condition_that_fails_to_evaluate_halts_the_run() -> TestResult {
    let trace = halting_trace(&format!("{BROKEN_CONDITION}{ISOLATE_HOST}"), ERROR_PAGE, None, &[])?;
    assert!(trace.contains("condition steps.0 error"), "{trace}");
    assert!(trace.contains("halted steps.1 isolate_endpoint: not run"), "{trace}");
    assert!(!isolated(&trace), "{trace}");
    let granted = halting_trace(&format!("{BROKEN_CONDITION}{ISOLATE_HOST}"), ERROR_PAGE, None, &["isolate_endpoint"])?;
    assert!(!isolated(&granted), "{granted}");
    Ok(())
}


#[test]
fn probe_seven_a_rejected_step_in_on_error_halts_the_handler() -> TestResult {
    let handler = format!("{REJECTED_STEP}{ISOLATE_HOST}");
    let trace = halting_trace(&format!("{APPROVE_ISOLATION}{ISOLATE_HOST}"), &handler, Some(0), &["isolate_endpoint"])?;
    assert!(trace.contains("approval granted steps.0"), "{trace}");
    assert!(trace.contains("on_error handler"), "{trace}");
    assert!(trace.contains("rejected on_error.0 nothing"), "{trace}");
    assert!(trace.contains("halted on_error.1 isolate_endpoint: not run"), "{trace}");
    let plain = halting_trace(&format!("{ISOLATE_HOST}{ISOLATE_HOST}"), &handler, Some(0), &[])?;
    assert!(plain.contains("halted on_error.1 isolate_endpoint: not run"), "{plain}");
    Ok(())
}


#[test]
fn probe_eight_a_destructive_step_in_on_error_goes_through_the_breakers() -> TestResult {
    let critical = r#"{ "host": { "value": "dc-01" } }"#;
    let text =
        format!("name: probe\nversion: 1\nmode: enforce\nsteps:\n  - action: release_endpoint\n    params: {{ host: h }}\non_error:\n{ISOLATE_HOST}");
    let playbook: Playbook = parse_document(&text, "probe.yaml")?;
    let catalogue: Catalogue = parse_document(CATALOGUE, "catalogue.yaml")?;
    let simulated = input(critical, Some(0))?;
    let trace = render_trace(&simulate(&playbook, &catalogue, &inventory()?, &harness()?.breakers, &simulated));
    assert!(
        trace.contains("action on_error.0 isolate_endpoint host=\"dc-01\" breakers=needs-approval"),
        "{trace}"
    );
    assert!(trace.contains("halted on_error.0:"), "{trace}");
    Ok(())
}


const STEP_KINDS: usize = 9;


const MAX_STEPS: usize = 6;


const PROPTEST_CASES: u32 = 64;


const STEP_TEXTS: [&str; STEP_KINDS] = [
    "  - connector: slack\n    action: notify\n    params: { channel: c, message: m }\n",
    ISOLATE_HOST,
    "  - action: isolate_endpoint\n    params: { host: \"{{ alert.missing }}\" }\n",
    "  - if: \"{{ alert.host.value / 2 > 1 }}\"\n    then:\n      - action: isolate_endpoint\n        params: { host: \"{{ alert.host }}\" }\n    else:\n      - action: isolate_endpoint\n        params: { host: \"{{ alert.host }}\" }\n",
    "  - action: request_approval\n    params: { role: r, timeout: 5m, action: other }\n",
    APPROVE_ISOLATION,
    REJECTED_STEP,
    "  - connector: fortigate\n    action: block_ip\n    params: { ip: notip, duration: 1h }\n",
    "  - if: \"{{ true }}\"\n    then:\n      - action: isolate_endpoint\n        params: { host: \"{{ alert.host }}\" }\n",
];


fn sequence_text(kinds: &[usize]) -> String {
    kinds.iter().map(|kind| STEP_TEXTS.get(*kind).copied().unwrap_or(REJECTED_STEP)).collect()
}


fn poisoned(line: &str) -> bool {
    line.starts_with("rejected ") || line.starts_with("approval requested ") || line.starts_with("halted ") || line.contains("run halted")
}


fn ran_after_poison(trace: &str) -> bool {
    trace.lines().skip_while(|line| !poisoned(line)).any(|line| line.starts_with("action "))
}


fn generated_trace(steps: &[usize], on_error: &[usize], fail_action: Option<usize>, granted: bool) -> Result<String, TestCaseError> {
    let approvals: &[&str] = if granted { &["isolate_endpoint"] } else { &[] };
    halting_trace(&sequence_text(steps), &sequence_text(on_error), fail_action, approvals).map_err(|failure| TestCaseError::fail(failure.to_string()))
}


proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    #[test]
    fn no_action_is_traced_after_the_first_failure_or_ungranted_approval(
        steps in proptest::collection::vec(0..STEP_KINDS, 1..MAX_STEPS),
        on_error in proptest::collection::vec(0..STEP_KINDS, 1..MAX_STEPS),
        fail_action in proptest::option::of(0..MAX_STEPS),
        granted in any::<bool>(),
    ) {
        let trace = generated_trace(&steps, &on_error, fail_action, granted)?;
        prop_assert!(!ran_after_poison(&trace), "{}", trace);
    }
}


const PROBE_TERMS: usize = 12_000;


const NESTING_PROBE: usize = 500;


const FUEL_TERMS: usize = 60;


const C2_MESSAGE: &str = "\"C2 confirmed on {{ alert.host }}: actions {{ playbook.actions_done }}\"";


fn oversized_reload(replacement: &str) -> TestResult {
    let rig = rig()?;
    let alert = alert_file(&rig, "hostile.json", HOSTILE)?;
    let before = execute(&rig.session, &["simulate", "c2", &alert])?;
    replace_file(&path_in(rig.dir.path(), "c2.yaml"), &C2.replace(C2_MESSAGE, replacement))?;
    let refused = reload(&rig.session.engine);
    assert!(
        matches!(&refused, ReloadOutcome::Refused { reason } if reason.contains("c2.yaml") && reason.contains("limit is")),
        "{refused:?}"
    );
    assert_eq!(execute(&rig.session, &["simulate", "c2", &alert])?, before);
    assert_eq!(recorded_for(&rig, Outcome::Denied)?.len(), 1);
    Ok(())
}


#[test]
fn a_twelve_thousand_term_expression_is_refused_on_reload_and_the_old_bundle_stays() -> TestResult {
    oversized_reload(&format!("\"{{{{ {}1 }}}}\"", "1 + ".repeat(PROBE_TERMS)))
}


#[test]
fn a_deeply_nested_expression_is_refused_on_reload_and_the_old_bundle_stays() -> TestResult {
    oversized_reload(&format!("\"{{{{ {}1{} }}}}\"", "(".repeat(NESTING_PROBE), ")".repeat(NESTING_PROBE)))
}


#[test]
fn a_twelve_thousand_term_expression_does_not_validate() -> TestResult {
    let text = format!(
        "name: probe\nversion: 1\nmode: enforce\nsteps:\n  - connector: slack\n    action: notify\n    params: {{ channel: c, message: \"{{{{ {}1 }}}}\" }}\non_error:\n{ERROR_PAGE}",
        "1 + ".repeat(PROBE_TERMS)
    );
    let playbook: Playbook = parse_document(&text, "probe.yaml")?;
    let catalogue: Catalogue = parse_document(CATALOGUE, "catalogue.yaml")?;
    let found = response_playbooks::validate::playbook_problems(&playbook, &catalogue);
    assert!(found.iter().any(|problem| problem.to_string().contains("limit is")), "{found:?}");
    Ok(())
}


#[test]
fn an_expression_that_runs_out_of_fuel_halts_the_run() -> TestResult {
    let condition = format!(
        "  - if: \"{{{{ {}a.b }}}}\"\n    then:\n      - action: isolate_endpoint\n        params: {{ host: \"{{{{ alert.host }}}}\" }}\n",
        "a.b ~ ".repeat(FUEL_TERMS)
    );
    let trace = halting_trace(&format!("{condition}{ISOLATE_HOST}"), ERROR_PAGE, None, &[])?;
    assert!(trace.contains("condition steps.0 error"), "{trace}");
    assert!(trace.to_lowercase().contains("fuel"), "{trace}");
    assert!(trace.contains("halted steps.1 isolate_endpoint: not run"), "{trace}");
    assert!(!isolated(&trace), "{trace}");
    Ok(())
}


#[test]
fn an_optional_parameter_that_resolves_empty_halts_the_run() -> TestResult {
    let step = "  - action: ban_ip\n    params: { ip: \"{{ alert.missing }}\" }\n";
    let trace = custom_trace(&format!("{step}{NOTIFY_STEP_SIM}"), &json!({}), None)?;
    assert!(trace.contains("rejected steps.0 ban_ip"), "{trace}");
    assert!(trace.contains("halted steps.1 notify: not run"), "{trace}");
    Ok(())
}


const NOTIFY_STEP_SIM: &str = "  - action: notify\n    params: { text: hi }\n";


#[test]
fn work_beyond_the_cap_halts_the_run_and_traces_what_is_left() -> TestResult {
    let skipped = "  - if: \"{{ false }}\"\n    then:\n      - action: isolate_endpoint\n        params: { host: h }\n";
    let text = format!("name: probe\nversion: 1\nmode: enforce\nsteps:\n{skipped}on_error:\n{ERROR_PAGE}");
    let mut playbook: Playbook = parse_document(&text, "probe.yaml")?;
    let step = playbook.steps.first().cloned().ok_or("no step")?;
    playbook.steps = vec![step; MAX_WORK + 1];
    let catalogue: Catalogue = parse_document(CATALOGUE, "catalogue.yaml")?;
    let trace = render_trace(&simulate(
        &playbook,
        &catalogue,
        &inventory()?,
        &harness()?.breakers,
        &input(UNPROTECTED, None)?,
    ));
    assert!(trace.contains(&format!("halted steps.{MAX_WORK} {{{{ false }}}}: not run")), "{trace}");
    playbook.steps.truncate(MAX_WORK);
    let exact = render_trace(&simulate(
        &playbook,
        &catalogue,
        &inventory()?,
        &harness()?.breakers,
        &input(UNPROTECTED, None)?,
    ));
    assert!(!exact.contains("halted"), "exact fit must not halt");
    let rejecting: Playbook = parse_document(&text.replace(skipped, REJECTED_STEP), "probe.yaml")?;
    let last = rejecting.steps.first().cloned().ok_or("no step")?;
    playbook.steps.truncate(MAX_WORK - 1);
    playbook.steps.push(last);
    let rejected = render_trace(&simulate(
        &playbook,
        &catalogue,
        &inventory()?,
        &harness()?.breakers,
        &input(UNPROTECTED, None)?,
    ));
    assert!(rejected.contains("rejected steps.99999 nothing"), "last iteration rejection");
    Ok(())
}


const REVIEWER_PROBE: usize = 1985;


const WATCH_DEBOUNCE: Duration = Duration::from_millis(100);


const WATCH_POLL: Duration = Duration::from_millis(100);


const WATCH_ATTEMPTS: usize = 100;


#[test]
fn the_unary_minus_probe_is_refused_on_reload_and_the_old_bundle_stays() -> TestResult {
    oversized_reload(&format!("\"{{{{ {}1 }}}}\"", "-".repeat(REVIEWER_PROBE)))
}


#[test]
fn the_unary_minus_probe_is_refused_by_the_file_watcher_and_the_old_bundle_stays() -> TestResult {
    let rig = rig()?;
    let alert = alert_file(&rig, "hostile.json", HOSTILE)?;
    let before = execute(&rig.session, &["simulate", "c2", &alert])?;
    let watched = [path_in(rig.dir.path(), "c2.yaml")];
    let watcher = watch_files(Arc::clone(&rig.session.engine), &watched, WATCH_DEBOUNCE)?;
    replace_file(
        &path_in(rig.dir.path(), "c2.yaml"),
        &C2.replace(C2_MESSAGE, &format!("\"{{{{ {}1 }}}}\"", "-".repeat(REVIEWER_PROBE))),
    )?;
    let refused = (0..WATCH_ATTEMPTS).find_map(|_| {
        std::thread::sleep(WATCH_POLL);
        recorded_for(&rig, Outcome::Denied).ok().filter(|entries| !entries.is_empty())
    });
    drop(watcher);
    let entries = refused.ok_or("the watcher never refused the reload")?;
    assert!(entries.iter().any(|entry| format!("{entry:?}").contains("limit is")), "{entries:?}");
    assert_eq!(execute(&rig.session, &["simulate", "c2", &alert])?, before);
    Ok(())
}


#[test]
fn a_constant_of_the_wrong_type_is_refused_on_reload_and_by_the_file_watcher() -> TestResult {
    let rig = rig()?;
    let alert = alert_file(&rig, "hostile.json", HOSTILE)?;
    let before = execute(&rig.session, &["simulate", "c2", &alert])?;
    let percent = format!("\"{{{{ 1{} }}}}\"", "%1".repeat(PERCENT_TERMS));
    replace_file(&path_in(rig.dir.path(), "c2.yaml"), &C2.replace(C2_MESSAGE, &percent))?;
    assert!(matches!(reload(&rig.session.engine), ReloadOutcome::Refused { .. }));
    replace_file(&path_in(rig.dir.path(), "c2.yaml"), &C2.replace(C2_MESSAGE, "\"{{ ---1 }}\""))?;
    let refused = reload(&rig.session.engine);
    assert!(
        matches!(&refused, ReloadOutcome::Refused { reason } if reason.contains("steps.")),
        "{refused:?}"
    );
    replace_file(&path_in(rig.dir.path(), "c2.yaml"), C2)?;
    let watched = [path_in(rig.dir.path(), "c2.yaml")];
    let watcher = watch_files(Arc::clone(&rig.session.engine), &watched, WATCH_DEBOUNCE)?;
    let denied_before = recorded_for(&rig, Outcome::Denied)?.len();
    replace_file(&path_in(rig.dir.path(), "c2.yaml"), &C2.replace(C2_MESSAGE, "\"{{ ---1 }}\""))?;
    let seen = (0..WATCH_ATTEMPTS).find_map(|_| {
        std::thread::sleep(WATCH_POLL);
        recorded_for(&rig, Outcome::Denied).ok().filter(|entries| entries.len() > denied_before)
    });
    drop(watcher);
    seen.ok_or("the watcher never refused the reload")?;
    assert_eq!(execute(&rig.session, &["simulate", "c2", &alert])?, before);
    Ok(())
}


const PERCENT_TERMS: usize = 250;


const MEMORY_LIMIT_ENV: &str = "PLAYBOOKS_ENGINE_MEMORY_CHILD";


const MEMORY_LIMIT_BYTES: &str = "--as=4000000000";


const JOIN_PROBE: &str = "(['x' * 1000000] * 100000) | join";


const HOSTILE_MESSAGES: [&str; 5] = [
    JOIN_PROBE,
    "'x' * 100000000",
    "('x' * 1000) ~ 'y'",
    "'a' | replace('a', 'bbbbbbbbbb') | replace('b', 'cccccccccc')",
    "'x' | center(1000000000)",
];


fn every_hostile_reload_is_refused() -> TestResult {
    let rig = rig()?;
    let alert = alert_file(&rig, "hostile.json", HOSTILE)?;
    let before = execute(&rig.session, &["simulate", "c2", &alert])?;
    HOSTILE_MESSAGES.iter().try_for_each(|message| {
        replace_file(
            &path_in(rig.dir.path(), "c2.yaml"),
            &C2.replace(C2_MESSAGE, &format!("\"{{{{ {message} }}}}\"")),
        )?;
        let refused = reload(&rig.session.engine);
        assert!(
            matches!(&refused, ReloadOutcome::Refused { reason } if reason.contains("c2.yaml")),
            "{message}: {refused:?}"
        );
        Ok::<(), Box<dyn Error>>(())
    })?;
    assert_eq!(execute(&rig.session, &["simulate", "c2", &alert])?, before);
    assert_eq!(recorded_for(&rig, Outcome::Denied)?.len(), HOSTILE_MESSAGES.len());
    Ok(())
}


#[test]
fn hostile_expressions_are_refused_on_reload_and_the_old_bundle_stays() -> TestResult {
    every_hostile_reload_is_refused()
}


#[test]
fn memory_limited_child_refuses_every_hostile_reload() -> TestResult {
    std::env::var(MEMORY_LIMIT_ENV).map_or(Ok(()), |_marker| every_hostile_reload_is_refused())
}


#[test]
fn hostile_reloads_do_not_allocate_under_a_memory_limit() -> TestResult {
    let output = std::process::Command::new("prlimit")
        .arg(MEMORY_LIMIT_BYTES)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--exact", "memory_limited_child_refuses_every_hostile_reload", "--test-threads=1"])
        .env(MEMORY_LIMIT_ENV, "1")
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"), "the child test did not run");
    Ok(())
}


#[test]
fn the_join_probe_is_refused_by_the_file_watcher_and_the_old_bundle_stays() -> TestResult {
    let rig = rig()?;
    let alert = alert_file(&rig, "hostile.json", HOSTILE)?;
    let before = execute(&rig.session, &["simulate", "c2", &alert])?;
    let watched = [path_in(rig.dir.path(), "c2.yaml")];
    let watcher = watch_files(Arc::clone(&rig.session.engine), &watched, WATCH_DEBOUNCE)?;
    replace_file(
        &path_in(rig.dir.path(), "c2.yaml"),
        &C2.replace(C2_MESSAGE, &format!("\"{{{{ {JOIN_PROBE} }}}}\"")),
    )?;
    let refused = (0..WATCH_ATTEMPTS).find_map(|_| {
        std::thread::sleep(WATCH_POLL);
        recorded_for(&rig, Outcome::Denied).ok().filter(|entries| !entries.is_empty())
    });
    drop(watcher);
    refused.ok_or("the watcher never refused the reload")?;
    assert_eq!(execute(&rig.session, &["simulate", "c2", &alert])?, before);
    Ok(())
}


#[test]
fn a_hostile_expression_that_reaches_run_time_halts_the_run() -> TestResult {
    let step = "  - action: notify\n    params: { text: \"{{ alert.name ~ ('x' * 100000000) }}\" }\n";
    let trace = custom_trace(&format!("{step}{NOTIFY_STEP_SIM}"), &json!({ "name": "n" }), None)?;
    assert!(trace.contains("rejected steps.0 notify"), "{trace}");
    assert!(trace.contains("halted steps.1 notify: not run"), "{trace}");
    Ok(())
}


fn reload_entry(changes: &[Change]) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::UNIX_EPOCH,
        actor: core_audit::model::Actor {
            kind: core_audit::model::ActorKind::System,
            id: "system".to_owned(),
        },
        tenant: "t".to_owned(),
        module: "m".to_owned(),
        action: "config.reload".to_owned(),
        target: "catalogue".to_owned(),
        outcome: Outcome::Success,
        request_id: "r".to_owned(),
        justification: None,
        parameters: [
            ("diff".to_owned(), bounded_parameter("diff", &diff_text(changes))),
            (
                "changed_settings".to_owned(),
                bounded_parameter("changed_settings", &changed_settings_text(changes)),
            ),
            (
                "changed_files".to_owned(),
                bounded_parameter("changed_files", &changed_files_text(changes)),
            ),
        ]
        .into(),
    }
}


fn two_files() -> Vec<String> {
    vec!["a.yaml".to_owned(), "other.yaml".to_owned()]
}


#[test]
fn retarget_reads_only_the_changed_settings() -> Result<(), Box<dyn Error>> {
    let files = vec!["a.yaml".to_owned(), "b.yaml".to_owned(), "c.yaml".to_owned()];
    let entry = reload_entry(&[
        change_of(ChangeKind::Update, "a.yaml::steps.0", "1", "2"),
        change_of(ChangeKind::Update, "c.yaml::x", "1", "2"),
        change_of(ChangeKind::Update, "other::y", "1", "2"),
    ]);
    assert_eq!(retarget(entry.clone(), &files).target, "a.yaml,c.yaml");
    let bare = NewEntry {
        parameters: BTreeMap::new(),
        ..entry
    };
    assert_eq!(retarget(bare, &files).target, "catalogue");
    Ok(())
}


#[test]
fn a_key_holding_a_comma_and_another_file_prefix_retargets_only_the_changed_file() -> Result<(), Box<dyn Error>> {
    let key = change_of(ChangeKind::Update, "a.yaml::x,other.yaml::y", "1", "2");
    assert_eq!(retarget(reload_entry(&[key]), &two_files()).target, "a.yaml");
    let raw = NewEntry {
        parameters: [("changed_files".to_owned(), "a.yaml::x,other.yaml::y".to_owned())].into(),
        ..reload_entry(&[])
    };
    assert_eq!(retarget(raw, &two_files()).target, "catalogue");
    Ok(())
}


#[test]
fn a_cut_changed_settings_still_names_every_changed_file() -> Result<(), Box<dyn Error>> {
    let mut changes: Vec<Change> = (0..CHANGED_KEYS)
        .map(|index| change_of(ChangeKind::Update, &format!("a.yaml::k{index:04}"), "1", "2"))
        .collect();
    changes.push(change_of(ChangeKind::Update, "b.yaml::z", "1", "2"));
    let entry = reload_entry(&changes);
    let settings = entry.parameters.get("changed_settings").ok_or("no changed_settings")?;
    assert!(settings.contains("more keys omitted"), "{settings}");
    let files = vec!["a.yaml".to_owned(), "b.yaml".to_owned(), "c.yaml".to_owned()];
    assert_eq!(retarget(entry, &files).target, "a.yaml,b.yaml");
    Ok(())
}


#[test]
fn a_key_or_value_imitating_a_diff_header_does_not_retarget_another_file() -> Result<(), Box<dyn Error>> {
    let key = change_of(ChangeKind::Update, "a.yaml::hosts.x,--- a/other.yaml::y", "1", "2");
    assert_eq!(retarget(reload_entry(&[key]), &two_files()).target, "a.yaml");
    let value = change_of(ChangeKind::Update, "a.yaml::note", "old", "see --- a/other.yaml::z");
    assert_eq!(retarget(reload_entry(&[value]), &two_files()).target, "a.yaml");
    Ok(())
}


#[test]
fn a_watched_path_with_the_key_separator_or_too_long_does_not_open() -> TestResult {
    let dir = tempdir()?;
    let entries = Arc::new(Mutex::new(Vec::new()));
    let mut ambiguous = settings_in(dir.path(), &entries);
    ambiguous.playbook_paths = vec![path_in(dir.path(), "x::y.yaml")];
    let refused = open_playbooks(ambiguous).err().ok_or("expected a failure")?;
    assert!(refused.to_string().contains("x::y.yaml"), "{refused}");
    let mut long = settings_in(dir.path(), &entries);
    long.playbook_paths = vec![path_in(dir.path(), &"a".repeat(core_config::reload::MAX_DIFF_CHARS))];
    let too_long = open_playbooks(long).err().ok_or("expected a failure")?;
    assert!(too_long.to_string().contains("exceed"), "{too_long}");
    Ok(())
}
