#[path = "common/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::{NewEntry, Outcome};
use core_config::parse::parse_document;
use response_breakers::breakers::{open_breakers, BreakerSettings, Breakers};
use response_breakers::store::sync_path;
use response_playbooks::error::ConnectorError;
use response_playbooks::model::{Catalogue, ConnectorCall, ConnectorResult, Executor, Inventory, Mode, Playbook, SimulationInput, Trace};
use response_playbooks::render::render_trace;
use response_playbooks::run::{bounded, permitted_compensation, run, MAX_DETAIL_CHARS};
use response_playbooks::simulate::{simulate, Context, Done};
use response_playbooks::types::{ConnectorFn, MonotonicFn};
use std::error::Error;
use std::fs;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use types::TestResult;


const CATALOGUE: &str = include_str!("../fixtures/catalogue.yaml");


const INVENTORY: &str = include_str!("../fixtures/inventory.yaml");


const C2: &str = include_str!("../fixtures/c2.yaml");


const HOSTILE: &str = include_str!("../fixtures/alert_hostile.json");


const CRITICAL: &str = include_str!("../fixtures/alert_critical.json");


const START: i64 = 1_800_000_000;


const BIG_FLEET: u64 = 1_000_000;


const DEADLINE: Duration = Duration::from_secs(5);


const SLOW_STEP: u64 = 10;


const FOURTH: usize = 3;


const FIVE: usize = 5;


const THREE: usize = 3;


const LONG_TEXT: usize = 1000;


const ALL_FIVE: [&str; 5] = ["block_ip", "sinkhole", "isolate_endpoint", "revoke_sessions", "notify"];


const GHOST_CATALOGUE: &str = "
actions:
  - action: ban
    destructive: true
    compensate: ghost
    breaker: { kind: block_domain, target: domain, duration: ttl }
    params:
      domain: { type: domain }
      ttl: { type: duration }
  - action: boom
";


const GHOST_PLAYBOOK: &str = "
name: ghost
version: 1
mode: enforce
steps:
  - action: ban
    params: { domain: example.org, ttl: 1h }
  - action: boom
on_error: []
";


pub struct Rig {
    pub dir: TempDir,
    pub breakers: Breakers,
    pub entries: Arc<Mutex<Vec<NewEntry>>>,
}


fn rig_with(failing_audit: bool, limits: &str) -> Result<Rig, Box<dyn Error>> {
    let dir = tempdir()?;
    fs::write(dir.path().join("limits.yaml"), limits)?;
    let entries: Arc<Mutex<Vec<NewEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&entries);
    let log = genesis_log(io::sink());
    let audit = move |entry: NewEntry| {
        sink.lock().map_err(|_| AuditError::LogPoisoned)?.push(entry.clone());
        if failing_audit {
            Err(AuditError::LogPoisoned)
        } else {
            append(&log, entry)
        }
    };
    let breakers = open_breakers(BreakerSettings {
        config_path: dir.path().join("limits.yaml"),
        store_path: dir.path().join("counters.json"),
        sync: sync_path,
        audit: Arc::new(audit),
        clock: Box::new(|| OffsetDateTime::from_unix_timestamp(START).unwrap_or(OffsetDateTime::UNIX_EPOCH)),
    })?;
    Ok(Rig { dir, breakers, entries })
}


fn rig() -> Result<Rig, Box<dyn Error>> {
    rig_with(false, "limits: {}\n")
}


fn input(alert: &str, approvals: &[&str]) -> Result<SimulationInput, Box<dyn Error>> {
    Ok(SimulationInput {
        tenant: "acme".to_owned(),
        request_id: "test".to_owned(),
        alert: serde_json::from_str(alert)?,
        fleet_size: BIG_FLEET,
        isolated_now: 0,
        fail_action: None,
        approvals: approvals.iter().map(|name| (*name).to_owned()).collect(),
    })
}


fn playbook(mode: Mode) -> Result<Playbook, Box<dyn Error>> {
    let mut parsed: Playbook = parse_document(C2, "c2.yaml")?;
    parsed.mode = mode;
    Ok(parsed)
}


fn recorder(calls: &Arc<Mutex<Vec<ConnectorCall>>>, failing: &[&str]) -> Box<ConnectorFn> {
    let sink = Arc::clone(calls);
    let failing_names: Vec<String> = failing.iter().map(|name| (*name).to_owned()).collect();
    Box::new(move |call: &ConnectorCall| {
        sink.lock().map_err(|_| ConnectorError::Failed("poisoned".to_owned()))?.push(call.clone());
        if failing_names.contains(&call.action) {
            Err(ConnectorError::Failed("x".repeat(LONG_TEXT)))
        } else {
            Ok(ConnectorResult { summary: "done".to_owned() })
        }
    })
}


fn clock_of(step: u64) -> Box<MonotonicFn> {
    let ticks = AtomicU64::new(0);
    Box::new(move || Duration::from_secs(ticks.fetch_add(step, Ordering::SeqCst)))
}


fn go(
    rig: &Rig,
    book: &Playbook,
    catalogue: &Catalogue,
    alert: &SimulationInput,
    connector: &ConnectorFn,
    step: u64,
) -> Result<Trace, Box<dyn Error>> {
    let inventory: Inventory = parse_document(INVENTORY, "inventory.yaml")?;
    let clock = clock_of(step);
    let exec = Executor {
        connector,
        clock: &*clock,
        deadline: DEADLINE,
    };
    Ok(run(book, catalogue, &inventory, &rig.breakers, alert, &exec))
}


fn fixture_catalogue() -> Result<Catalogue, Box<dyn Error>> {
    Ok(parse_document(CATALOGUE, "catalogue.yaml")?)
}


fn names(calls: &Arc<Mutex<Vec<ConnectorCall>>>) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(calls.lock().map_err(|_| "poisoned")?.iter().map(|call| call.action.clone()).collect())
}


fn call_named(calls: &Arc<Mutex<Vec<ConnectorCall>>>, action: &str) -> Result<ConnectorCall, Box<dyn Error>> {
    calls
        .lock()
        .map_err(|_| "poisoned")?
        .iter()
        .find(|call| call.action == action)
        .cloned()
        .ok_or_else(|| "no such call".into())
}


fn audited(rig: &Rig, action: &str) -> Result<Vec<NewEntry>, Box<dyn Error>> {
    Ok(rig
        .entries
        .lock()
        .map_err(|_| "poisoned")?
        .iter()
        .filter(|entry| entry.action == action)
        .cloned()
        .collect())
}


#[test]
fn a_real_run_traces_like_the_simulation_and_calls_in_order() -> TestResult {
    let calls = Arc::default();
    let real = go(
        &rig()?,
        &playbook(Mode::Enforce)?,
        &fixture_catalogue()?,
        &input(HOSTILE, &[])?,
        &*recorder(&calls, &[]),
        1,
    )?;
    let inventory: Inventory = parse_document(INVENTORY, "inventory.yaml")?;
    let simulated = simulate(
        &playbook(Mode::Enforce)?,
        &fixture_catalogue()?,
        &inventory,
        &rig()?.breakers,
        &input(HOSTILE, &[])?,
    );
    assert_eq!(render_trace(&real), render_trace(&simulated));
    assert_eq!(names(&calls)?, ALL_FIVE);
    let first = call_named(&calls, "block_ip")?;
    assert_eq!(first.deadline, DEADLINE);
    assert_eq!(first.tenant, "acme");
    Ok(())
}


#[test]
fn every_action_is_audited() -> TestResult {
    let current = rig()?;
    let calls = Arc::default();
    go(
        &current,
        &playbook(Mode::Enforce)?,
        &fixture_catalogue()?,
        &input(HOSTILE, &[])?,
        &*recorder(&calls, &[]),
        1,
    )?;
    let done = audited(&current, "playbook.action")?;
    assert_eq!(done.len(), FIVE);
    assert!(done.iter().all(|entry| entry.outcome == Outcome::Success));
    Ok(())
}


#[test]
fn a_protected_asset_is_never_acted_on_and_the_stop_is_audited() -> TestResult {
    let current = rig()?;
    let calls = Arc::default();
    let trace = go(
        &current,
        &playbook(Mode::Enforce)?,
        &fixture_catalogue()?,
        &input(CRITICAL, &[])?,
        &*recorder(&calls, &[]),
        1,
    )?;
    assert!(!names(&calls)?.contains(&"isolate_endpoint".to_owned()));
    assert!(render_trace(&trace).contains("requested"));
    let protected: Playbook = parse_document(
        "name: p\nversion: 1\nmode: enforce\nsteps:\n  - action: isolate_endpoint\n    params: { host: \"{{ alert.host }}\" }\non_error: []\n",
        "p.yaml",
    )?;
    let stopped = go(
        &current,
        &protected,
        &fixture_catalogue()?,
        &input(CRITICAL, &[])?,
        &*recorder(&calls, &[]),
        1,
    )?;
    assert!(render_trace(&stopped).contains("waiting for approval"));
    assert!(!names(&calls)?.contains(&"isolate_endpoint".to_owned()));
    assert_eq!(audited(&current, "playbook.denied")?.len(), 1);
    Ok(())
}


#[test]
fn a_tripped_breaker_stops_the_run_before_the_connector() -> TestResult {
    let current = rig_with(false, "limits: { blocks_per_hour: 0 }\n")?;
    let calls = Arc::default();
    let trace = go(
        &current,
        &playbook(Mode::Enforce)?,
        &fixture_catalogue()?,
        &input(HOSTILE, &[])?,
        &*recorder(&calls, &[]),
        1,
    )?;
    let text = render_trace(&trace);
    assert!(text.contains("waiting for approval"), "{text}");
    assert!(names(&calls)?.is_empty());
    assert_eq!(audited(&current, "playbook.denied")?.len(), 1);
    assert!(audited(&current, "playbook.action")?.is_empty());
    Ok(())
}


#[test]
fn a_failure_compensates_in_reverse_order_and_survives_a_failed_undo() -> TestResult {
    let calls = Arc::default();
    let current = rig()?;
    let trace = go(
        &current,
        &playbook(Mode::Enforce)?,
        &fixture_catalogue()?,
        &input(HOSTILE, &[])?,
        &*recorder(&calls, &["revoke_sessions", "unsinkhole"]),
        1,
    )?;
    let order = names(&calls)?;
    assert_eq!(
        order.get(FOURTH..).ok_or("short")?,
        ["revoke_sessions", "release_endpoint", "unsinkhole", "unblock_ip", "page"]
    );
    let text = render_trace(&trace);
    assert!(text.contains("failure steps.3.then.0 revoke_sessions: connector failed"), "{text}");
    assert!(text.contains("failure compensation unsinkhole: connector failed"), "{text}");
    assert!(text.contains("on_error handler"));
    let undone = audited(&current, "playbook.compensation")?;
    assert_eq!(undone.len(), THREE);
    assert!(undone.iter().any(|entry| entry.outcome == Outcome::Failure));
    let detail_ok = audited(&current, "playbook.action")?.iter().all(|entry| {
        entry
            .parameters
            .get("detail")
            .is_none_or(|detail| detail.chars().count() <= MAX_DETAIL_CHARS)
    });
    assert!(detail_ok);
    let undo = call_named(&calls, "unblock_ip")?;
    assert_eq!(undo.params.len(), 1);
    assert_eq!(undo.connector.as_deref(), Some("fortigate"));
    Ok(())
}


#[test]
fn a_call_past_its_deadline_is_a_failure() -> TestResult {
    let calls = Arc::default();
    let trace = go(
        &rig()?,
        &playbook(Mode::Enforce)?,
        &fixture_catalogue()?,
        &input(HOSTILE, &[])?,
        &*recorder(&calls, &[]),
        SLOW_STEP,
    )?;
    let text = render_trace(&trace);
    assert!(text.contains("failure steps.0.then.0 block_ip: connector took"), "{text}");
    assert_eq!(names(&calls)?, ["block_ip", "unblock_ip", "page"]);
    assert!(text.contains("failure compensation unblock_ip: connector took"), "{text}");
    Ok(())
}


#[test]
fn dry_run_and_simulate_modes_never_call_a_connector() -> TestResult {
    let calls = Arc::default();
    let current = rig()?;
    let traces = [Mode::DryRun, Mode::Simulate]
        .into_iter()
        .map(|mode| {
            go(
                &current,
                &playbook(mode)?,
                &fixture_catalogue()?,
                &input(HOSTILE, &[])?,
                &*recorder(&calls, &[]),
                1,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(names(&calls)?.is_empty());
    assert!(traces
        .iter()
        .all(|trace| render_trace(trace).contains("action steps.2.then.0 isolate_endpoint")));
    assert!(render_trace(traces.first().ok_or("none")?).starts_with("playbook Block confirmed C2 v3 mode=dry-run"));
    let flags = audited(&current, "playbook.action")?;
    assert!(flags
        .iter()
        .all(|entry| entry.parameters.get("executed").is_some_and(|flag| flag == "false")));
    Ok(())
}


#[test]
fn approval_required_runs_only_what_has_an_approval_record() -> TestResult {
    let calls = Arc::default();
    let current = rig()?;
    let refused = go(
        &current,
        &playbook(Mode::ApprovalRequired)?,
        &fixture_catalogue()?,
        &input(HOSTILE, &[])?,
        &*recorder(&calls, &[]),
        1,
    )?;
    assert!(names(&calls)?.is_empty());
    assert!(render_trace(&refused).contains("rejected steps.0.then.0 block_ip: no approval record for `block_ip`"));
    assert_eq!(audited(&current, "playbook.denied")?.len(), 1);
    let granted = go(
        &rig()?,
        &playbook(Mode::ApprovalRequired)?,
        &fixture_catalogue()?,
        &input(HOSTILE, &ALL_FIVE)?,
        &*recorder(&calls, &[]),
        1,
    )?;
    assert_eq!(names(&calls)?.len(), FIVE);
    assert!(!render_trace(&granted).contains("rejected"));
    Ok(())
}


#[test]
fn a_compensation_missing_from_the_catalogue_is_refused_and_never_called() -> TestResult {
    let calls = Arc::default();
    let current = rig()?;
    let catalogue: Catalogue = parse_document(GHOST_CATALOGUE, "ghost.yaml")?;
    let book: Playbook = parse_document(GHOST_PLAYBOOK, "ghost.yaml")?;
    let trace = go(&current, &book, &catalogue, &input("{}", &[])?, &*recorder(&calls, &["boom"]), 1)?;
    let text = render_trace(&trace);
    assert!(text.contains("compensation ghost for ban"));
    assert!(
        text.contains("failure compensation ghost: no such compensation in the catalogue"),
        "{text}"
    );
    assert!(!names(&calls)?.contains(&"ghost".to_owned()));
    assert_eq!(audited(&current, "playbook.denied")?.len(), 1);
    Ok(())
}


const UNDO_PLAYBOOK: &str = "
name: undo
version: 1
mode: enforce
steps:
  - action: release_endpoint
    compensate: isolate_endpoint
    params: { host: \"{{ alert.host }}\" }
  - connector: slack
    action: notify
    params: { channel: ops, message: hi }
on_error: []
";


#[test]
fn a_destructive_compensation_is_never_called_in_any_mode() -> TestResult {
    let book: Playbook = parse_document(UNDO_PLAYBOOK, "undo.yaml")?;
    let static_problems = response_playbooks::validate::playbook_problems(&book, &fixture_catalogue()?);
    assert!(static_problems
        .iter()
        .any(|problem| matches!(problem, response_playbooks::error::Problem::UnsafeCompensation { .. })));
    [Mode::Enforce, Mode::ApprovalRequired].into_iter().try_for_each(|mode| -> TestResult {
        let calls = Arc::default();
        let current = rig()?;
        let moded = Playbook { mode, ..book.clone() };
        let trace = go(
            &current,
            &moded,
            &fixture_catalogue()?,
            &input(CRITICAL, &["release_endpoint", "notify"])?,
            &*recorder(&calls, &["notify"]),
            1,
        )?;
        assert!(!names(&calls)?.contains(&"isolate_endpoint".to_owned()));
        let text = render_trace(&trace);
        assert!(
            text.contains("failure compensation isolate_endpoint: the compensation is destructive"),
            "{text}"
        );
        assert_eq!(audited(&current, "playbook.denied")?.len(), 1);
        Ok(())
    })
}


#[test]
fn approval_required_does_not_compensate_without_the_approval_of_the_action() -> TestResult {
    let calls = Arc::default();
    let current = rig()?;
    let mut book = playbook(Mode::ApprovalRequired)?;
    book.on_error = Vec::new();
    let trace = go(
        &current,
        &book,
        &fixture_catalogue()?,
        &input(HOSTILE, &ALL_FIVE)?,
        &*recorder(&calls, &["revoke_sessions"]),
        1,
    )?;
    assert!(render_trace(&trace).contains("compensation"));
    let unapproved_input = input(HOSTILE, &["block_ip", "sinkhole", "isolate_endpoint", "revoke_sessions"])?;
    let done = Done {
        action: "ghost_action".to_owned(),
        compensate: Some("unblock_ip".to_owned()),
        connector: Some("fortigate".to_owned()),
        compensation_params: Default::default(),
    };
    let inventory: Inventory = parse_document(INVENTORY, "inventory.yaml")?;
    let catalogue = fixture_catalogue()?;
    let context = Context {
        playbook: &book,
        catalogue: &catalogue,
        inventory: &inventory,
        breakers: &current.breakers,
        input: &unapproved_input,
        exec: None,
    };
    let refused = permitted_compensation(&context, &done, "unblock_ip");
    assert_eq!(refused.err(), Some(ConnectorError::UnapprovedCompensation));
    Ok(())
}


#[test]
fn a_failing_audit_never_stops_or_widens_a_run() -> TestResult {
    let calls = Arc::default();
    let trace = go(
        &rig_with(true, "limits: {}\n")?,
        &playbook(Mode::Enforce)?,
        &fixture_catalogue()?,
        &input(HOSTILE, &[])?,
        &*recorder(&calls, &[]),
        1,
    )?;
    assert!(render_trace(&trace).contains("action steps.4 slack/notify"));
    assert_eq!(names(&calls)?.len(), FIVE);
    Ok(())
}


#[test]
fn text_is_cut_to_the_bound() -> TestResult {
    assert_eq!(bounded(&"é".repeat(LONG_TEXT)).chars().count(), MAX_DETAIL_CHARS);
    assert_eq!(bounded("short"), "short");
    Ok(())
}
