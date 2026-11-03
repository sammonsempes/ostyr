mod common;


use common::types::TestResult;
use common::{advance, harness, harness_with, limits_path, recorded, reopen, replace_file, store_path, verdict_for, Harness};
use common::{BIG_FLEET, DAY, DEFAULT_LIMITS, HOUR, START, TENANT};
use core_audit::model::{ActorKind, Outcome};
use core_config::reload::{reload, ReloadOutcome};
use response_breakers::check::needs_approval;
use response_breakers::cli::run_session;
use response_breakers::config::config_state;
use response_breakers::error::BreakerError;
use response_breakers::grant::{grant_override, OverrideGrant};
use response_breakers::model::{ActionKind, LimitName, Reason, Verdict};
use response_breakers::store::{open_store, sync_path};
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use time::OffsetDateTime;


const HOURLY_ISOLATIONS: usize = 5;


const DAILY_ISOLATIONS: usize = 20;


const HOURLY_DISABLINGS: usize = 3;


const HOURLY_BLOCKS: usize = 50;


const RMM_LIMIT: u64 = 20;


const SEVEN_DAYS: u64 = 604_800;


const SMALL_FLEET: u64 = 50;


const LARGE_FLEET: u64 = 10_000;


const LARGE_FLEET_ALLOWED: u64 = 200;


const THREADS: usize = 20;


const TWO_RECORDED: usize = 2;


const TWO_NUMBER_ERRORS: usize = 2;


const INVALID_UTF8: u8 = 0xff;


const OVERRIDE_SECONDS: i64 = 1000;


const RAISED_LIMIT: usize = 10;


fn isolate(isolated_now: u64) -> ActionKind {
    ActionKind::IsolateEndpoint {
        fleet_size: BIG_FLEET,
        isolated_now,
    }
}


fn block_domain(seconds: u64) -> ActionKind {
    ActionKind::BlockDomain {
        duration: Duration::from_secs(seconds),
    }
}


fn block_ip(text: &str) -> Result<ActionKind, std::net::AddrParseError> {
    Ok(ActionKind::BlockIp {
        address: text.parse::<IpAddr>()?,
        duration: Duration::from_secs(1),
    })
}


fn allowed() -> Verdict {
    Verdict::Allowed { overridden: Vec::new() }
}


fn limit_reached(limit: LimitName, current: u64, max: u64) -> Verdict {
    needs_approval(Reason::LimitReached { limit, current, max })
}


fn run_n(harness: &Harness, count: usize, kind: &dyn Fn() -> ActionKind) -> Vec<Verdict> {
    (0..count).map(|_| verdict_for(&harness.breakers, TENANT, kind(), &[])).collect()
}


fn grant(harness: &Harness, limit: LimitName, seconds: i64) -> OverrideGrant {
    OverrideGrant {
        admin: "alice".to_owned(),
        tenant: TENANT.to_owned(),
        limit,
        until: OffsetDateTime::from_unix_timestamp(START + seconds).unwrap_or(OffsetDateTime::UNIX_EPOCH),
        justification: "incident 42".to_owned(),
        request_id: format!("request-{}", harness.dir.path().display()),
    }
}


fn events_in_memory(harness: &Harness) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(harness.breakers.store.state.lock().map_err(|_| "poisoned")?.events.len())
}


fn sync_fails_on_file(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        Ok(())
    } else {
        Err(io::Error::other("disk"))
    }
}


fn sync_fails_on_directory(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        Err(io::Error::other("disk"))
    } else {
        Ok(())
    }
}


#[test]
fn isolations_per_hour_boundary() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let verdicts = run_n(&fixture, HOURLY_ISOLATIONS + 1, &|| isolate(0));
    assert!(verdicts.iter().take(HOURLY_ISOLATIONS).all(|verdict| *verdict == allowed()));
    assert_eq!(
        verdicts.last(),
        Some(&limit_reached(
            LimitName::IsolationsPerHour,
            HOURLY_ISOLATIONS as u64,
            HOURLY_ISOLATIONS as u64
        ))
    );
    Ok(())
}


#[test]
fn window_expires_with_the_injected_clock() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    run_n(&fixture, HOURLY_ISOLATIONS, &|| isolate(0));
    advance(&fixture, HOUR - 1);
    assert!(matches!(
        verdict_for(&fixture.breakers, TENANT, isolate(0), &[]),
        Verdict::NeedsApproval { .. }
    ));
    advance(&fixture, 1);
    assert_eq!(verdict_for(&fixture.breakers, TENANT, isolate(0), &[]), allowed());
    Ok(())
}


#[test]
fn isolations_per_day_boundary_and_expiry() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let hours = DAILY_ISOLATIONS / HOURLY_ISOLATIONS;
    (0..hours).for_each(|_| {
        run_n(&fixture, HOURLY_ISOLATIONS, &|| isolate(0));
        advance(&fixture, HOUR);
    });
    assert_eq!(
        verdict_for(&fixture.breakers, TENANT, isolate(0), &[]),
        limit_reached(LimitName::IsolationsPerDay, DAILY_ISOLATIONS as u64, DAILY_ISOLATIONS as u64)
    );
    advance(&fixture, DAY - HOUR * hours as i64);
    assert_eq!(verdict_for(&fixture.breakers, TENANT, isolate(0), &[]), allowed());
    Ok(())
}


#[test]
fn disablings_per_hour_boundary() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let verdicts = run_n(&fixture, HOURLY_DISABLINGS + 1, &|| ActionKind::DisableAccount);
    assert!(verdicts.iter().take(HOURLY_DISABLINGS).all(|verdict| *verdict == allowed()));
    assert_eq!(
        verdicts.last(),
        Some(&limit_reached(
            LimitName::DisablingsPerHour,
            HOURLY_DISABLINGS as u64,
            HOURLY_DISABLINGS as u64
        ))
    );
    Ok(())
}


#[test]
fn blocks_per_hour_boundary_and_tenants_are_separate() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let verdicts = run_n(&fixture, HOURLY_BLOCKS + 1, &|| block_domain(1));
    assert!(verdicts.iter().take(HOURLY_BLOCKS).all(|verdict| *verdict == allowed()));
    assert_eq!(
        verdicts.last(),
        Some(&limit_reached(LimitName::BlocksPerHour, HOURLY_BLOCKS as u64, HOURLY_BLOCKS as u64))
    );
    assert_eq!(verdict_for(&fixture.breakers, "other", block_domain(1), &[]), allowed());
    Ok(())
}


#[test]
fn block_duration_over_seven_days_needs_approval() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    assert_eq!(verdict_for(&fixture.breakers, TENANT, block_domain(SEVEN_DAYS), &[]), allowed());
    assert_eq!(
        verdict_for(&fixture.breakers, TENANT, block_domain(SEVEN_DAYS + 1), &[]),
        limit_reached(LimitName::BlockDuration, SEVEN_DAYS + 1, SEVEN_DAYS)
    );
    Ok(())
}


#[test]
fn rmm_machine_count_boundary_is_not_recorded() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let machines = |count| ActionKind::RmmScript { machines: count };
    assert_eq!(verdict_for(&fixture.breakers, TENANT, machines(RMM_LIMIT), &[]), allowed());
    assert_eq!(
        verdict_for(&fixture.breakers, TENANT, machines(RMM_LIMIT + 1), &[]),
        limit_reached(LimitName::RmmMachines, RMM_LIMIT + 1, RMM_LIMIT)
    );
    assert_eq!(events_in_memory(&fixture)?, 0);
    Ok(())
}


#[test]
fn fleet_percentage_rule_with_two_fleet_sizes() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let at = |fleet_size, isolated_now| ActionKind::IsolateEndpoint { fleet_size, isolated_now };
    assert_eq!(verdict_for(&fixture.breakers, "small-a", at(SMALL_FLEET, 0), &[]), allowed());
    assert_eq!(
        verdict_for(&fixture.breakers, "small-b", at(SMALL_FLEET, 1), &[]),
        limit_reached(LimitName::FleetIsolatedPercent, 1, 1)
    );
    assert_eq!(
        verdict_for(&fixture.breakers, "large-a", at(LARGE_FLEET, LARGE_FLEET_ALLOWED - 1), &[]),
        allowed()
    );
    assert_eq!(
        verdict_for(&fixture.breakers, "large-b", at(LARGE_FLEET, LARGE_FLEET_ALLOWED), &[]),
        limit_reached(LimitName::FleetIsolatedPercent, LARGE_FLEET_ALLOWED, LARGE_FLEET_ALLOWED)
    );
    Ok(())
}


#[test]
fn protected_tags_are_never_allowed() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let protected = |tag: &str| needs_approval(Reason::ProtectedTag { tag: tag.to_owned() });
    ["domain-controller", "hypervisor", "critical"].iter().for_each(|tag| {
        assert_eq!(verdict_for(&fixture.breakers, TENANT, isolate(0), &[tag]), protected(tag));
    });
    ["privileged", "break-glass", "service"].iter().for_each(|tag| {
        assert_eq!(verdict_for(&fixture.breakers, TENANT, ActionKind::DisableAccount, &[tag]), protected(tag));
    });
    assert_eq!(
        verdict_for(&fixture.breakers, TENANT, ActionKind::RmmScript { machines: 1 }, &["plain", "hypervisor"]),
        protected("hypervisor")
    );
    assert_eq!(verdict_for(&fixture.breakers, TENANT, isolate(0), &["privileged"]), allowed());
    assert_eq!(verdict_for(&fixture.breakers, TENANT, block_domain(1), &["critical"]), allowed());
    assert_eq!(events_in_memory(&fixture)?, TWO_RECORDED);
    Ok(())
}


#[test]
fn reserved_ranges_are_never_blocked() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let reserved = |range: &str| needs_approval(Reason::ReservedRange { range: range.to_owned() });
    assert_eq!(verdict_for(&fixture.breakers, TENANT, block_ip("10.1.2.3")?, &[]), reserved("10.0.0.0/8"));
    assert_eq!(verdict_for(&fixture.breakers, TENANT, block_ip("fd00::1")?, &[]), reserved("fc00::/7"));
    assert_eq!(
        verdict_for(&fixture.breakers, TENANT, block_ip("::ffff:10.0.0.1")?, &[]),
        reserved("10.0.0.0/8")
    );
    assert_eq!(verdict_for(&fixture.breakers, TENANT, block_ip("8.8.8.8")?, &[]), allowed());
    assert_eq!(verdict_for(&fixture.breakers, TENANT, block_ip("2001:db8::1")?, &[]), allowed());
    Ok(())
}


#[test]
fn tenant_override_and_reserved_range_come_from_the_file() -> TestResult {
    let text =
        "limits:\n  reserved_ranges: [\"203.0.113.0/24\"]\ntenants:\n  strict:\n    isolations_per_hour: 1\n    protected_host_tags: [\"lab\"]\n";
    let fixture = harness(text)?;
    assert_eq!(verdict_for(&fixture.breakers, TENANT, block_ip("10.1.2.3")?, &[]), allowed());
    assert_eq!(
        verdict_for(&fixture.breakers, TENANT, block_ip("203.0.113.9")?, &[]),
        needs_approval(Reason::ReservedRange {
            range: "203.0.113.0/24".to_owned()
        })
    );
    assert_eq!(verdict_for(&fixture.breakers, "strict", isolate(0), &[]), allowed());
    assert_eq!(
        verdict_for(&fixture.breakers, "strict", isolate(0), &[]),
        limit_reached(LimitName::IsolationsPerHour, 1, 1)
    );
    assert_eq!(
        verdict_for(&fixture.breakers, "strict", ActionKind::RmmScript { machines: 1 }, &["lab"]),
        needs_approval(Reason::ProtectedTag { tag: "lab".to_owned() })
    );
    assert_eq!(run_n(&fixture, HOURLY_ISOLATIONS, &|| isolate(0)).last(), Some(&allowed()));
    Ok(())
}


#[test]
fn live_reload_is_applied_and_an_invalid_file_is_refused() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let file = limits_path(fixture.dir.path());
    replace_file(&file, "limits:\n  isolations_per_hour: 10\n")?;
    assert!(matches!(reload(&fixture.breakers.engine), ReloadOutcome::Applied { .. }));
    assert!(run_n(&fixture, RAISED_LIMIT, &|| isolate(0)).iter().all(|verdict| *verdict == allowed()));
    assert!(matches!(
        verdict_for(&fixture.breakers, TENANT, isolate(0), &[]),
        Verdict::NeedsApproval { .. }
    ));
    replace_file(&file, "limits:\n  isolations_per_hour: 99\n  surprise: 1\n")?;
    assert!(matches!(reload(&fixture.breakers.engine), ReloadOutcome::Refused { .. }));
    advance(&fixture, HOUR);
    assert_eq!(
        run_n(&fixture, RAISED_LIMIT + 1, &|| isolate(0)).last(),
        Some(&limit_reached(LimitName::IsolationsPerHour, RAISED_LIMIT as u64, RAISED_LIMIT as u64))
    );
    assert!(matches!(reload(&fixture.breakers.engine), ReloadOutcome::Refused { .. }));
    let refused = recorded(&fixture)?
        .iter()
        .filter(|entry| entry.outcome == Outcome::Denied && entry.action == "config.reload")
        .count();
    assert!(refused >= 1);
    Ok(())
}


#[test]
fn counters_survive_a_restart() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    run_n(&fixture, HOURLY_ISOLATIONS, &|| isolate(0));
    let reopened = reopen(&fixture)?;
    assert_eq!(
        verdict_for(&reopened, TENANT, isolate(0), &[]),
        limit_reached(LimitName::IsolationsPerHour, HOURLY_ISOLATIONS as u64, HOURLY_ISOLATIONS as u64)
    );
    Ok(())
}


#[test]
fn old_events_are_pruned_when_the_file_is_rewritten() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    run_n(&fixture, 1, &|| isolate(0));
    advance(&fixture, DAY);
    run_n(&fixture, 1, &|| isolate(0));
    let on_disk = open_store(&store_path(fixture.dir.path()), sync_path)?;
    assert_eq!(on_disk.state.lock().map_err(|_| "poisoned")?.events.len(), 1);
    Ok(())
}


#[test]
fn a_failing_store_fails_closed() -> TestResult {
    let on_file = harness_with(DEFAULT_LIMITS, sync_fails_on_file)?;
    let verdict = verdict_for(&on_file.breakers, TENANT, isolate(0), &[]);
    assert!(matches!(
        verdict,
        Verdict::NeedsApproval {
            reason: Reason::RecordFailed { .. },
            alert_on_call: true
        }
    ));
    assert_eq!(events_in_memory(&on_file)?, 0);
    let on_directory = harness_with(DEFAULT_LIMITS, sync_fails_on_directory)?;
    assert!(matches!(
        verdict_for(&on_directory.breakers, TENANT, isolate(0), &[]),
        Verdict::NeedsApproval {
            reason: Reason::RecordFailed { .. },
            ..
        }
    ));
    let unwritable = harness(DEFAULT_LIMITS)?;
    fs::create_dir(store_path(unwritable.dir.path()))?;
    assert!(matches!(
        verdict_for(&unwritable.breakers, TENANT, isolate(0), &[]),
        Verdict::NeedsApproval {
            reason: Reason::RecordFailed { .. },
            ..
        }
    ));
    let entries = recorded(&on_file)?;
    assert!(entries
        .iter()
        .any(|entry| entry.parameters.get("reason").is_some_and(|text| text.contains("cannot record"))));
    Ok(())
}


#[test]
fn a_failing_audit_never_allows() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    fixture.fail_audit.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        verdict_for(&fixture.breakers, TENANT, ActionKind::RmmScript { machines: RMM_LIMIT + 1 }, &[]),
        Verdict::NeedsApproval { .. }
    ));
    assert_eq!(verdict_for(&fixture.breakers, TENANT, isolate(0), &[]), allowed());
    let result = grant_override(&fixture.breakers, &grant(&fixture, LimitName::RmmMachines, OVERRIDE_SECONDS));
    assert!(matches!(result, Err(BreakerError::Audit(_))));
    fixture.fail_audit.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        verdict_for(&fixture.breakers, TENANT, ActionKind::RmmScript { machines: RMM_LIMIT + 1 }, &[]),
        Verdict::NeedsApproval { .. }
    ));
    Ok(())
}


#[test]
fn needs_approval_is_audited_with_the_alert_flag() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let verdict = verdict_for(&fixture.breakers, TENANT, ActionKind::RmmScript { machines: RMM_LIMIT + 1 }, &[]);
    assert!(matches!(verdict, Verdict::NeedsApproval { alert_on_call: true, .. }));
    let entries = recorded(&fixture)?;
    let entry = entries.last().ok_or("no audit entry")?;
    assert_eq!(entry.action, "breaker.needs_approval");
    assert_eq!(entry.outcome, Outcome::Denied);
    assert_eq!(entry.tenant, TENANT);
    assert_eq!(entry.target, "target-1");
    assert_eq!(entry.parameters.get("alert_on_call").map(String::as_str), Some("true"));
    assert_eq!(entry.parameters.get("proposed").map(String::as_str), Some("rmm_script"));
    assert!(entry.parameters.get("reason").is_some_and(|text| text.contains("rmm_machines")));
    Ok(())
}


#[test]
fn an_override_lifts_a_limit_until_it_expires_and_is_audited() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    run_n(&fixture, HOURLY_ISOLATIONS, &|| isolate(0));
    assert!(matches!(
        verdict_for(&fixture.breakers, TENANT, isolate(0), &[]),
        Verdict::NeedsApproval { .. }
    ));
    grant_override(&fixture.breakers, &grant(&fixture, LimitName::IsolationsPerHour, OVERRIDE_SECONDS))?;
    let lifted = verdict_for(&fixture.breakers, TENANT, isolate(0), &[]);
    assert_eq!(
        lifted,
        Verdict::Allowed {
            overridden: vec![LimitName::IsolationsPerHour]
        }
    );
    assert!(lifted.to_string().contains("override of isolations_per_hour"));
    let entries = recorded(&fixture)?;
    let entry = entries
        .iter()
        .find(|entry| entry.action == "breaker.override")
        .ok_or("no override entry")?;
    assert_eq!(entry.actor.kind, ActorKind::User);
    assert_eq!(entry.actor.id, "alice");
    assert_eq!(entry.target, "isolations_per_hour");
    assert_eq!(entry.justification.as_deref(), Some("incident 42"));
    assert!(entry.parameters.contains_key("until"));
    let reopened = reopen(&fixture)?;
    assert!(matches!(verdict_for(&reopened, TENANT, isolate(0), &[]), Verdict::Allowed { .. }));
    advance(&fixture, OVERRIDE_SECONDS);
    assert!(matches!(
        verdict_for(&fixture.breakers, TENANT, isolate(0), &[]),
        Verdict::NeedsApproval { .. }
    ));
    Ok(())
}


#[test]
fn an_override_does_not_lift_protection_and_must_be_in_the_future() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    grant_override(&fixture.breakers, &grant(&fixture, LimitName::IsolationsPerHour, OVERRIDE_SECONDS))?;
    assert!(matches!(
        verdict_for(&fixture.breakers, TENANT, isolate(0), &["critical"]),
        Verdict::NeedsApproval {
            reason: Reason::ProtectedTag { .. },
            ..
        }
    ));
    assert!(matches!(
        grant_override(&fixture.breakers, &grant(&fixture, LimitName::RmmMachines, 0)),
        Err(BreakerError::AlreadyExpired)
    ));
    Ok(())
}


#[test]
fn an_override_on_another_limit_or_tenant_does_not_apply() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    run_n(&fixture, HOURLY_ISOLATIONS, &|| isolate(0));
    grant_override(&fixture.breakers, &grant(&fixture, LimitName::IsolationsPerDay, OVERRIDE_SECONDS))?;
    assert!(matches!(
        verdict_for(&fixture.breakers, TENANT, isolate(0), &[]),
        Verdict::NeedsApproval { .. }
    ));
    grant_override(&fixture.breakers, &grant(&fixture, LimitName::IsolationsPerHour, OVERRIDE_SECONDS))?;
    assert!(matches!(
        verdict_for(&fixture.breakers, "other", isolate(0), &[]),
        Verdict::Allowed { .. }
    ));
    grant_override(&fixture.breakers, &grant(&fixture, LimitName::RmmMachines, OVERRIDE_SECONDS))?;
    let machines = ActionKind::RmmScript { machines: RMM_LIMIT + 1 };
    assert!(matches!(
        verdict_for(&fixture.breakers, "other", machines, &[]),
        Verdict::NeedsApproval { .. }
    ));
    Ok(())
}


#[test]
fn concurrent_checks_cannot_take_the_same_slot() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let breakers = Arc::new(fixture.breakers);
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let shared = Arc::clone(&breakers);
            thread::spawn(move || verdict_for(&shared, TENANT, isolate(0), &[]))
        })
        .collect();
    let verdicts: Vec<Verdict> = handles.into_iter().filter_map(|handle| handle.join().ok()).collect();
    assert_eq!(verdicts.len(), THREADS);
    assert_eq!(verdicts.iter().filter(|verdict| **verdict == allowed()).count(), HOURLY_ISOLATIONS);
    Ok(())
}


#[test]
fn opening_refuses_unreadable_state() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    fs::remove_file(limits_path(fixture.dir.path()))?;
    assert!(matches!(reopen(&fixture), Err(BreakerError::Config(_))));
    replace_file(&limits_path(fixture.dir.path()), DEFAULT_LIMITS)?;
    fs::write(store_path(fixture.dir.path()), "not json")?;
    assert!(matches!(reopen(&fixture), Err(BreakerError::Store(_))));
    fs::remove_file(store_path(fixture.dir.path()))?;
    fs::create_dir(store_path(fixture.dir.path()))?;
    assert!(matches!(reopen(&fixture), Err(BreakerError::Store(_))));
    Ok(())
}


#[test]
fn the_state_of_the_config_names_each_section() -> TestResult {
    let fixture = harness("tenants:\n  acme:\n    blocks_per_hour: 1\n")?;
    let config = core_config::reload::current_config(&fixture.breakers.engine);
    let keys: Vec<String> = config_state(&config).into_keys().collect();
    assert_eq!(keys, vec!["limits".to_owned(), "tenants.acme".to_owned()]);
    Ok(())
}


#[test]
fn the_command_line_session_drives_checks_overrides_and_reloads() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let script = "isolate acme host-1 1000000 0\n\
                  isolate acme host-1 1000000 0 critical\n\
                  disable acme bob privileged\n\
                  block-ip acme 10.0.0.1 5\n\
                  block-ip acme 8.8.8.8 5\n\
                  block-domain acme example.org 5\n\
                  rmm acme host-1 21\n\
                  limits acme\n\
                  reload\n\
                  override acme rmm_machines 100 alice\n\
                  rmm acme host-1 21\n\
                  override acme nothing 100 alice\n\
                  override acme rmm_machines soon alice\n\
                  isolate acme host-1 many 0\n\
                  block-ip acme not-an-ip 5\n\
                  nonsense\n\
                  quit\n\
                  limits acme\n";
    let mut out = Vec::new();
    run_session(&fixture.breakers, script.as_bytes(), &mut out)?;
    let text = String::from_utf8(out)?;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.first(), Some(&"allowed"));
    assert!(lines.iter().any(|line| line.contains("protected target tagged `critical`")));
    assert!(lines.iter().any(|line| line.contains("reserved range 10.0.0.0/8")));
    assert!(lines.iter().any(|line| line.starts_with("isolations_per_hour=5 isolations_per_day=20")));
    assert!(lines.contains(&"unchanged"));
    assert!(lines.iter().any(|line| line.starts_with("override of rmm_machines until")));
    assert!(lines.iter().any(|line| line.starts_with("allowed only by override of rmm_machines")));
    assert!(lines.iter().any(|line| line.contains("unknown limit `nothing`")));
    assert_eq!(
        lines.iter().filter(|line| line.starts_with("error: not a number")).count(),
        TWO_NUMBER_ERRORS
    );
    assert!(lines.iter().any(|line| line.starts_with("error: not an address")));
    assert!(lines.iter().any(|line| line.starts_with("error: usage:")));
    assert_eq!(lines.iter().filter(|line| line.starts_with("isolations_per_hour")).count(), 1);
    replace_file(&limits_path(fixture.dir.path()), "limits:\n  isolations_per_hour: 7\n")?;
    let mut again = Vec::new();
    run_session(&fixture.breakers, "reload\nlimits acme\n".as_bytes(), &mut again)?;
    let reloaded = String::from_utf8(again)?;
    assert!(reloaded.contains("applied limits"));
    assert!(reloaded.contains("isolations_per_hour=7"));
    replace_file(&limits_path(fixture.dir.path()), "limits: nonsense\n")?;
    let mut refused = Vec::new();
    run_session(&fixture.breakers, "reload\n".as_bytes(), &mut refused)?;
    assert!(String::from_utf8(refused)?.starts_with("refused "));
    Ok(())
}


#[test]
fn a_failing_input_ends_the_session_with_the_error() -> TestResult {
    let fixture = harness(DEFAULT_LIMITS)?;
    let mut out = Vec::new();
    let result = run_session(&fixture.breakers, &[INVALID_UTF8, b'\n'][..], &mut out);
    assert!(result.is_err());
    Ok(())
}
