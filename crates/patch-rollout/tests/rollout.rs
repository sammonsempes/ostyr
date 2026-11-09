#[path = "common/types.rs"]
mod types;


use patch_rollout::decide::{next_actions, ring_status};
use patch_rollout::error::{PolicyError, RolloutError, ValidationError};
use patch_rollout::limits::RolloutLimits;
use patch_rollout::model::{
    Action, Decision, DeferReason, Deferred, DevicePhase, DeviceState, Issue, Outcome, RingState, RingStatus, RolloutPolicy, StepKind, Stop,
    StopReason,
};
use patch_rollout::policy::{load_policy, parse_policy};
use response_breakers::model::{ActionKind, ProposedAction, Target};
use std::fs;
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;


const NOW: i64 = 1_800_000_000;


const SOAK: i64 = 3600;


const AGES_AGO: i64 = 1_000_000;


const PILOT_SIZE: usize = 2;


const PROD_SIZE: usize = 4;


const SMALL_CAP: usize = 1;


const RING_COUNT: usize = 3;


const PROD_PERCENT: usize = 25;


const OVER_PERCENT: usize = 101;


fn policy_text(reboot_outside_window: bool) -> String {
    format!(
        "tenant: acme
reboot_outside_window: {reboot_outside_window}
groups:
  pilot-ws: {{window: weekend, devices: [p1, p2], workstation: true}}
  prod-srv: {{window: night, devices: [s1, s2, s3, s4]}}
  db-srv: {{window: night, devices: [d1], prompt_before_reboot: true}}
rings:
  - {{name: pilot, groups: [pilot-ws], soak_seconds: 3600, max_failures: 1, max_failure_percent: 50}}
  - {{name: prod, groups: [prod-srv], soak_seconds: 3600, max_failures: 5, max_failure_percent: 25}}
  - {{name: late, groups: [db-srv], soak_seconds: 0, max_failures: 0, max_failure_percent: 0}}
"
    )
}


fn policy(reboot_outside_window: bool) -> Result<RolloutPolicy, PolicyError> {
    parse_policy(&policy_text(reboot_outside_window), "policy.yaml", &RolloutLimits::default())
}


fn at(offset: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(NOW + offset)
}


fn device(id: &str, phase: DevicePhase, in_window: bool) -> DeviceState {
    DeviceState {
        tenant: "acme".to_owned(),
        device: id.to_owned(),
        phase,
        in_window,
    }
}


fn ring(name: &str, status: RingStatus) -> RingState {
    RingState {
        tenant: "acme".to_owned(),
        ring: name.to_owned(),
        status,
    }
}


fn finished(name: &str, offset: i64) -> Result<RingState, time::error::ComponentRange> {
    Ok(ring(name, RingStatus::Finished { at: at(offset)? }))
}


fn action(id: &str, kind: StepKind) -> Action {
    Action { device: id.to_owned(), kind }
}


fn run(reboot_outside_window: bool, rings: &[RingState], devices: &[DeviceState], now: i64) -> Result<Decision, Box<dyn std::error::Error>> {
    Ok(next_actions(
        &policy(reboot_outside_window)?,
        rings,
        devices,
        at(now)?,
        &RolloutLimits::default(),
    )?)
}


fn proceed(ring: &str, actions: Vec<Action>) -> Outcome {
    Outcome::Proceed {
        ring: ring.to_owned(),
        actions,
    }
}


fn stop_of(ring: &str, reason: StopReason, machines: u64) -> Outcome {
    Outcome::Stop(Stop {
        ring: ring.to_owned(),
        reason,
        breaker_input: ProposedAction {
            tenant: "acme".to_owned(),
            request_id: format!("patch-rollout-stop-{ring}"),
            kind: ActionKind::RmmScript { machines },
            target: Target {
                id: ring.to_owned(),
                tags: Vec::new(),
            },
        },
    })
}


#[test]
fn policy_defaults_are_conservative() -> TestResult {
    let parsed = policy(false)?;
    assert!(!parsed.reboot_outside_window);
    assert!(parsed
        .groups
        .get("prod-srv")
        .is_some_and(|group| !group.workstation && !group.prompt_before_reboot));
    assert!(parsed.groups.get("db-srv").is_some_and(|group| group.prompt_before_reboot));
    assert_eq!(parsed.rings.len(), RING_COUNT);
    assert!(RolloutLimits::default().max_rings > 0);
    Ok(())
}


#[test]
fn policy_unknown_field_is_refused() -> TestResult {
    let result = parse_policy("tenant: acme\nsurprise: 1\ngroups: {}\nrings: []\n", "p.yaml", &RolloutLimits::default());
    assert!(matches!(result, Err(PolicyError::Config(_))));
    Ok(())
}


#[test]
fn policy_unknown_group_is_refused() -> TestResult {
    let text = policy_text(false).replace("groups: [db-srv]", "groups: [nowhere]");
    let result = parse_policy(&text, "p.yaml", &RolloutLimits::default());
    assert!(matches!(
        result,
        Err(PolicyError::Invalid(ValidationError::UnknownGroup { ref ring, ref group })) if ring == "late" && group == "nowhere"
    ));
    Ok(())
}


#[test]
fn policy_ring_without_device_is_refused() -> TestResult {
    let no_groups = policy_text(false).replace("groups: [db-srv]", "groups: []");
    let no_devices = policy_text(false).replace("devices: [d1]", "devices: []");
    for text in [no_groups, no_devices] {
        let result = parse_policy(&text, "p.yaml", &RolloutLimits::default());
        assert!(matches!(result, Err(PolicyError::Invalid(ValidationError::EmptyRing { ref ring })) if ring == "late"));
    }
    Ok(())
}


#[test]
fn policy_device_in_two_rings_is_refused() -> TestResult {
    let text = policy_text(false).replace("groups: [db-srv]", "groups: [db-srv, prod-srv]");
    let result = parse_policy(&text, "p.yaml", &RolloutLimits::default());
    assert!(matches!(
        result,
        Err(PolicyError::Invalid(ValidationError::DeviceInTwoRings { ref device, ref first, ref second }))
            if device == "s1" && first == "prod" && second == "late"
    ));
    Ok(())
}


#[test]
fn policy_device_in_two_groups_is_refused() -> TestResult {
    let text = policy_text(false).replace("devices: [d1]", "devices: [d1, s2]");
    let result = parse_policy(&text, "p.yaml", &RolloutLimits::default());
    assert!(matches!(
        result,
        Err(PolicyError::Invalid(ValidationError::DeviceInTwoGroups { ref device, ref first, ref second }))
            if device == "s2" && first == "db-srv" && second == "prod-srv"
    ));
    let same_ring = policy_text(false)
        .replace("devices: [s1, s2, s3, s4]", "devices: [s1, s2, s3, p1]")
        .replace("groups: [pilot-ws]", "groups: [pilot-ws, prod-srv]");
    let by_same_ring = parse_policy(&same_ring, "p.yaml", &RolloutLimits::default());
    assert!(matches!(
        by_same_ring,
        Err(PolicyError::Invalid(ValidationError::DeviceInTwoGroups { .. }))
    ));
    Ok(())
}


#[test]
fn policy_duplicate_ring_name_is_refused() -> TestResult {
    let text = policy_text(false).replace("name: late", "name: pilot");
    let result = parse_policy(&text, "p.yaml", &RolloutLimits::default());
    assert!(matches!(result, Err(PolicyError::Invalid(ValidationError::DuplicateRing { ref ring })) if ring == "pilot"));
    Ok(())
}


#[test]
fn policy_percent_over_100_is_refused() -> TestResult {
    let text = policy_text(false).replace("max_failure_percent: 0", "max_failure_percent: 101");
    let result = parse_policy(&text, "p.yaml", &RolloutLimits::default());
    assert!(matches!(
        result,
        Err(PolicyError::Invalid(ValidationError::PercentOver { ref ring, percent })) if ring == "late" && percent == OVER_PERCENT
    ));
    let at_limit = policy_text(false).replace("max_failure_percent: 0", "max_failure_percent: 100");
    parse_policy(&at_limit, "p.yaml", &RolloutLimits::default())?;
    Ok(())
}


#[test]
fn duplicate_or_unknown_states_are_refused() -> TestResult {
    let twice = run(
        false,
        &[ring("pilot", RingStatus::Running), ring("pilot", RingStatus::NotStarted)],
        &[],
        0,
    );
    assert_eq!(
        twice.err().map(|error| error.to_string()),
        Some(RolloutError::DuplicateRingState { ring: "pilot".to_owned() }.to_string())
    );
    let unknown = run(false, &[ring("ghost", RingStatus::Running)], &[], 0);
    assert_eq!(
        unknown.err().map(|error| error.to_string()),
        Some(RolloutError::UnknownRingState { ring: "ghost".to_owned() }.to_string())
    );
    let devices = [device("p1", DevicePhase::Failed, true), device("p1", DevicePhase::Pending, true)];
    let repeated = run(false, &[], &devices, 0);
    assert_eq!(
        repeated.err().map(|error| error.to_string()),
        Some(RolloutError::DuplicateDeviceState { device: "p1".to_owned() }.to_string())
    );
    Ok(())
}


#[test]
fn failed_device_gets_no_install() -> TestResult {
    let decision = run(
        false,
        &[],
        &[device("p1", DevicePhase::Failed, true), device("p2", DevicePhase::Pending, true)],
        0,
    )?;
    assert_eq!(decision.outcome, proceed("pilot", vec![action("p2", StepKind::Install)]));
    Ok(())
}


#[test]
fn policy_device_twice_in_one_ring_is_accepted() -> TestResult {
    let repeated = policy_text(false).replace("devices: [s1, s2, s3, s4]", "devices: [s1, s1, s2, s3, s4]");
    parse_policy(&repeated, "p.yaml", &RolloutLimits::default())?;
    let text = policy_text(false).replace("groups: [prod-srv]", "groups: [prod-srv, prod-srv]");
    parse_policy(&text, "p.yaml", &RolloutLimits::default())?;
    Ok(())
}


#[test]
fn policy_caps_are_enforced_at_load() -> TestResult {
    let base = RolloutLimits::default();
    let cases = [
        (
            RolloutLimits {
                max_rings: SMALL_CAP,
                ..base
            },
            "rings",
        ),
        (
            RolloutLimits {
                max_groups: SMALL_CAP,
                ..base
            },
            "groups",
        ),
        (
            RolloutLimits {
                max_devices: SMALL_CAP,
                ..base
            },
            "devices",
        ),
    ];
    for (limits, what) in cases {
        let result = parse_policy(&policy_text(false), "p.yaml", &limits);
        assert!(matches!(result, Err(PolicyError::Invalid(ValidationError::TooMany { what: found, max })) if found == what && max == SMALL_CAP));
    }
    Ok(())
}


#[test]
fn policy_loads_from_a_file_and_reports_a_missing_one() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("rollout.yaml");
    fs::write(&path, policy_text(true))?;
    assert!(load_policy(&path, &RolloutLimits::default())?.reboot_outside_window);
    let missing = load_policy(&directory.path().join("absent.yaml"), &RolloutLimits::default());
    assert!(matches!(missing, Err(PolicyError::Config(_))));
    Ok(())
}


#[test]
fn error_messages_name_the_cause() -> TestResult {
    let error = RolloutError::TenantMismatch {
        expected: "acme".to_owned(),
        found: "other".to_owned(),
    };
    assert!(error.to_string().contains("other"));
    assert!(ValidationError::EmptyRing { ring: "r".to_owned() }.to_string().contains("no device"));
    assert!(ValidationError::DuplicateRing { ring: "r".to_owned() }.to_string().contains("twice"));
    Ok(())
}


#[test]
fn first_ring_starts_with_installs_inside_the_window() -> TestResult {
    let devices = [device("p1", DevicePhase::Pending, true), device("p2", DevicePhase::Pending, false)];
    let decision = run(false, &[], &devices, 0)?;
    assert_eq!(decision.outcome, proceed("pilot", vec![action("p1", StepKind::Install)]));
    assert_eq!(
        decision.deferred,
        vec![Deferred {
            subject: "p2".to_owned(),
            reason: DeferReason::OutsideWindow
        }]
    );
    assert!(decision.issues.is_empty());
    Ok(())
}


#[test]
fn running_ring_keeps_later_rings_waiting() -> TestResult {
    let devices = [device("p1", DevicePhase::Done, true), device("s1", DevicePhase::Pending, true)];
    let decision = run(false, &[ring("pilot", RingStatus::Running)], &devices, 0)?;
    assert_eq!(decision.outcome, proceed("pilot", Vec::new()));
    assert!(decision.issues.is_empty());
    assert!(decision.deferred.is_empty());
    Ok(())
}


#[test]
fn soak_not_elapsed_one_tick_before_the_boundary() -> TestResult {
    let decision = run(false, &[finished("pilot", 0)?], &[], SOAK - 1)?;
    assert_eq!(
        decision.outcome,
        Outcome::Waiting {
            ring: "pilot".to_owned(),
            until: at(SOAK)?
        }
    );
    Ok(())
}


#[test]
fn soak_elapsed_exactly_at_the_boundary_starts_the_next_ring() -> TestResult {
    let devices = [device("s1", DevicePhase::Pending, true)];
    let decision = run(false, &[finished("pilot", 0)?], &devices, SOAK)?;
    assert_eq!(decision.outcome, proceed("prod", vec![action("s1", StepKind::Install)]));
    Ok(())
}


#[test]
fn unknown_status_of_another_ring_is_ignored() -> TestResult {
    let states = [ring("elsewhere", RingStatus::Running)];
    assert_eq!(ring_status(&states, "pilot"), RingStatus::NotStarted);
    assert_eq!(ring_status(&states, "elsewhere"), RingStatus::Running);
    Ok(())
}


#[test]
fn threshold_by_count_stops_the_rollout() -> TestResult {
    let devices = [device("p1", DevicePhase::Failed, true), device("p2", DevicePhase::Failed, true)];
    let decision = run(false, &[ring("pilot", RingStatus::Running)], &devices, 0)?;
    assert_eq!(
        decision.outcome,
        stop_of("pilot", StopReason::FailureCount { failed: PILOT_SIZE, max: 1 }, PILOT_SIZE as u64)
    );
    Ok(())
}


#[test]
fn failures_at_the_threshold_do_not_stop() -> TestResult {
    let devices = [device("p1", DevicePhase::Failed, true), device("p2", DevicePhase::Pending, true)];
    let decision = run(false, &[ring("pilot", RingStatus::Running)], &devices, 0)?;
    assert_eq!(decision.outcome, proceed("pilot", vec![action("p2", StepKind::Install)]));
    Ok(())
}


#[test]
fn threshold_by_percentage_stops_the_rollout() -> TestResult {
    let devices = [device("s1", DevicePhase::Failed, true), device("s2", DevicePhase::Failed, true)];
    let rings = [finished("pilot", -AGES_AGO)?, ring("prod", RingStatus::Running)];
    let decision = run(false, &rings, &devices, 0)?;
    assert_eq!(
        decision.outcome,
        stop_of(
            "prod",
            StopReason::FailurePercent {
                failed: PILOT_SIZE,
                total: PROD_SIZE,
                max_percent: PROD_PERCENT
            },
            PROD_SIZE as u64
        )
    );
    Ok(())
}


#[test]
fn one_failure_at_the_percentage_does_not_stop() -> TestResult {
    let devices = [device("s1", DevicePhase::Failed, true), device("s2", DevicePhase::Pending, true)];
    let rings = [finished("pilot", -AGES_AGO)?, ring("prod", RingStatus::Running)];
    let decision = run(false, &rings, &devices, 0)?;
    assert_eq!(decision.outcome, proceed("prod", vec![action("s2", StepKind::Install)]));
    Ok(())
}


#[test]
fn stop_in_an_earlier_ring_blocks_every_later_ring() -> TestResult {
    let devices = [
        device("p1", DevicePhase::Failed, true),
        device("p2", DevicePhase::Failed, true),
        device("s1", DevicePhase::Pending, true),
    ];
    let rings = [finished("pilot", -AGES_AGO)?, ring("prod", RingStatus::Running)];
    let decision = run(false, &rings, &devices, 0)?;
    assert_eq!(
        decision.outcome,
        stop_of("pilot", StopReason::FailureCount { failed: PILOT_SIZE, max: 1 }, PILOT_SIZE as u64)
    );
    assert!(decision.deferred.is_empty());
    Ok(())
}


#[test]
fn all_rings_finished_and_soaked_is_complete() -> TestResult {
    let rings = [finished("pilot", -AGES_AGO)?, finished("prod", -AGES_AGO)?, finished("late", -AGES_AGO)?];
    let decision = run(false, &rings, &[], 0)?;
    assert_eq!(decision.outcome, Outcome::Complete);
    Ok(())
}


#[test]
fn reboot_is_refused_outside_the_window() -> TestResult {
    let devices = [device("s1", DevicePhase::NeedsReboot, false)];
    let rings = [finished("pilot", -AGES_AGO)?, ring("prod", RingStatus::Running)];
    let decision = run(false, &rings, &devices, 0)?;
    assert_eq!(decision.outcome, proceed("prod", Vec::new()));
    assert_eq!(
        decision.deferred,
        vec![Deferred {
            subject: "s1".to_owned(),
            reason: DeferReason::OutsideWindow
        }]
    );
    Ok(())
}


#[test]
fn reboot_outside_the_window_needs_the_policy_flag() -> TestResult {
    let devices = [device("s1", DevicePhase::NeedsReboot, false)];
    let rings = [finished("pilot", -AGES_AGO)?, ring("prod", RingStatus::Running)];
    let decision = run(true, &rings, &devices, 0)?;
    assert_eq!(decision.outcome, proceed("prod", vec![action("s1", StepKind::Reboot)]));
    assert!(decision.deferred.is_empty());
    Ok(())
}


#[test]
fn reboot_inside_the_window_is_proposed() -> TestResult {
    let devices = [device("s1", DevicePhase::NeedsReboot, true)];
    let rings = [finished("pilot", -AGES_AGO)?, ring("prod", RingStatus::Running)];
    let decision = run(false, &rings, &devices, 0)?;
    assert_eq!(decision.outcome, proceed("prod", vec![action("s1", StepKind::Reboot)]));
    Ok(())
}


#[test]
fn workstation_reboot_is_preceded_by_a_prompt() -> TestResult {
    let first = run(false, &[], &[device("p1", DevicePhase::NeedsReboot, true)], 0)?;
    assert_eq!(first.outcome, proceed("pilot", vec![action("p1", StepKind::PromptReboot)]));
    let second = run(false, &[], &[device("p1", DevicePhase::RebootPrompted, true)], 0)?;
    assert_eq!(second.outcome, proceed("pilot", vec![action("p1", StepKind::Reboot)]));
    let outside = run(false, &[], &[device("p1", DevicePhase::RebootPrompted, false)], 0)?;
    assert_eq!(outside.outcome, proceed("pilot", Vec::new()));
    assert_eq!(outside.deferred.len(), 1);
    Ok(())
}


#[test]
fn server_group_can_ask_for_a_prompt() -> TestResult {
    let rings = [finished("pilot", -AGES_AGO)?, finished("prod", -AGES_AGO)?];
    let decision = run(false, &rings, &[device("d1", DevicePhase::NeedsReboot, true)], 0)?;
    assert_eq!(decision.outcome, proceed("late", vec![action("d1", StepKind::PromptReboot)]));
    Ok(())
}


#[test]
fn failed_and_done_devices_get_nothing() -> TestResult {
    let devices = [device("p1", DevicePhase::Failed, true), device("p2", DevicePhase::Done, true)];
    let decision = run(false, &[], &devices, 0)?;
    assert_eq!(decision.outcome, proceed("pilot", Vec::new()));
    assert!(decision.deferred.is_empty());
    Ok(())
}


#[test]
fn unknown_device_is_reported_and_other_ring_devices_are_left_alone() -> TestResult {
    let devices = [device("ghost", DevicePhase::Pending, true), device("s1", DevicePhase::Pending, true)];
    let decision = run(false, &[], &devices, 0)?;
    assert_eq!(decision.outcome, proceed("pilot", Vec::new()));
    assert_eq!(decision.issues, vec![Issue::UnknownDevice("ghost".to_owned())]);
    Ok(())
}


#[test]
fn device_cap_defers_the_rest_with_a_reason_and_still_counts_failures() -> TestResult {
    let limits = RolloutLimits {
        max_devices: SMALL_CAP,
        ..RolloutLimits::default()
    };
    let devices = [
        device("p1", DevicePhase::Pending, true),
        device("p2", DevicePhase::Pending, true),
        device("ghost", DevicePhase::Pending, true),
    ];
    let decision = next_actions(&policy(false)?, &[], &devices, at(0)?, &limits)?;
    assert_eq!(decision.outcome, proceed("pilot", vec![action("p1", StepKind::Install)]));
    assert_eq!(
        decision.deferred,
        ["p2", "ghost"]
            .map(|subject| Deferred {
                subject: subject.to_owned(),
                reason: DeferReason::DeviceCap
            })
            .to_vec()
    );
    assert!(decision.issues.is_empty());
    let hidden_failures = [
        device("s1", DevicePhase::Pending, true),
        device("p1", DevicePhase::Failed, true),
        device("p2", DevicePhase::Failed, true),
    ];
    let stopped = next_actions(&policy(false)?, &[], &hidden_failures, at(0)?, &limits)?;
    assert_eq!(
        stopped.outcome,
        stop_of("pilot", StopReason::FailureCount { failed: PILOT_SIZE, max: 1 }, PILOT_SIZE as u64)
    );
    Ok(())
}


#[test]
fn ring_cap_defers_later_rings_with_a_reason() -> TestResult {
    let limits = RolloutLimits {
        max_rings: SMALL_CAP,
        ..RolloutLimits::default()
    };
    let rings = [finished("pilot", -AGES_AGO)?];
    let decision = next_actions(&policy(false)?, &rings, &[], at(0)?, &limits)?;
    assert_eq!(decision.outcome, Outcome::Capped);
    assert_eq!(
        decision.deferred,
        ["prod", "late"]
            .map(|subject| Deferred {
                subject: subject.to_owned(),
                reason: DeferReason::RingCap
            })
            .to_vec()
    );
    Ok(())
}


#[test]
fn mixed_tenants_are_refused() -> TestResult {
    let foreign_device = DeviceState {
        tenant: "other".to_owned(),
        ..device("p1", DevicePhase::Pending, true)
    };
    let foreign_ring = RingState {
        tenant: "other".to_owned(),
        ..ring("pilot", RingStatus::Running)
    };
    let expected = RolloutError::TenantMismatch {
        expected: "acme".to_owned(),
        found: "other".to_owned(),
    };
    let by_device = run(false, &[], &[foreign_device], 0);
    assert_eq!(by_device.err().map(|error| error.to_string()), Some(expected.to_string()));
    let by_ring = run(false, &[foreign_ring], &[], 0);
    assert_eq!(by_ring.err().map(|error| error.to_string()), Some(expected.to_string()));
    Ok(())
}
