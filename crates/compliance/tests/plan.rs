#[path = "common/types.rs"]
mod types;


use compliance::error::ComplianceError;
use compliance::load::{load_policy, parse_baseline, parse_policy, MAX_ACTIONS, MAX_CAP, MAX_ID_LEN};
use compliance::model::{Baseline, DeferReason, DeviceVerdicts, Exception, Plan, Policy, Scope, Target, Verdict};
use compliance::plan::plan_corrections;
use time::OffsetDateTime;
use types::TestResult;


const NOW: i64 = 1_800_000_000;


const ROOMY: usize = 5;


const TWO: usize = 2;


const THREE: usize = 3;


const BASELINE: &str = "version: 1
tenant: acme
name: base
actions: [lock, fix]
controls:
  - id: on
    query: q
    severity: low
    expect: {row_count: 0}
    correction: {action: lock, enabled: true}
  - id: on2
    query: q
    severity: low
    expect: {row_count: 0}
    correction: {action: fix, enabled: true}
  - id: off
    query: q
    severity: low
    expect: {row_count: 0}
    correction: {action: lock}
  - id: none
    query: q
    severity: low
    expect: {row_count: 0}
";


fn baseline() -> Result<Baseline, Box<dyn std::error::Error>> {
    Ok(parse_baseline(&mut BASELINE.as_bytes(), "base.yaml")?)
}


fn policy(dry_run: bool, max_devices: usize, max_corrections_per_device: usize) -> Policy {
    Policy {
        version: 1,
        tenant: "acme".to_string(),
        dry_run,
        max_devices,
        max_corrections_per_device,
    }
}


fn fail() -> Verdict {
    Verdict::Fail {
        offending: Vec::new(),
        total: 0,
    }
}


fn device(name: &str, controls: &[(&str, Verdict)]) -> DeviceVerdicts {
    DeviceVerdicts {
        tenant: "acme".to_string(),
        target: Target {
            device: name.to_string(),
            tags: vec!["lab".to_string()],
        },
        verdicts: controls.iter().map(|(id, verdict)| ((*id).to_string(), verdict.clone())).collect(),
    }
}


fn exception(expires: i64) -> Result<Exception, Box<dyn std::error::Error>> {
    Ok(Exception {
        control: "on".to_string(),
        scope: Scope::Device("d1".to_string()),
        owner: "o".to_string(),
        reason: "r".to_string(),
        expires: OffsetDateTime::from_unix_timestamp(expires)?,
    })
}


fn run(verdicts: &[DeviceVerdicts], exceptions: &[Exception], policy: &Policy) -> Result<Plan, Box<dyn std::error::Error>> {
    Ok(plan_corrections(
        verdicts,
        &baseline()?,
        exceptions,
        policy,
        OffsetDateTime::from_unix_timestamp(NOW)?,
    )?)
}


#[test]
fn only_fail_of_enabled_controls_is_requested() -> TestResult {
    let error = Verdict::Error { reason: "x".to_string() };
    let verdicts = [device(
        "d1",
        &[("on", error), ("off", fail()), ("none", fail()), ("on2", fail()), ("on", Verdict::Pass)],
    )];
    let plan = run(&verdicts, &[], &policy(false, ROOMY, ROOMY))?;
    assert_eq!(plan.requests.len(), 1);
    let request = plan.requests.first().ok_or("missing")?;
    assert_eq!(
        (request.control.as_str(), request.device.as_str(), request.action.as_str()),
        ("on2", "d1", "fix")
    );
    assert!(plan.would_run.is_empty() && plan.deferred.is_empty() && !plan.dry_run);
    assert_eq!(plan.tenant, "acme");
    Ok(())
}


#[test]
fn exception_is_active_until_expiry_exclusive() -> TestResult {
    let verdicts = [device("d1", &[("on", fail())])];
    let open = policy(false, ROOMY, ROOMY);
    assert!(run(&verdicts, &[exception(NOW + 1)?], &open)?.requests.is_empty());
    assert_eq!(run(&verdicts, &[exception(NOW)?], &open)?.requests.len(), 1);
    assert_eq!(run(&verdicts, &[exception(NOW - 1)?], &open)?.requests.len(), 1);
    Ok(())
}


#[test]
fn dry_run_lists_without_requesting() -> TestResult {
    let verdicts = [device("d1", &[("on", fail())])];
    let plan = run(&verdicts, &[], &policy(true, ROOMY, ROOMY))?;
    assert!(plan.requests.is_empty() && plan.dry_run);
    assert_eq!(plan.would_run.len(), 1);
    Ok(())
}


#[test]
fn correction_cap_defers_with_reason() -> TestResult {
    let verdicts = [device("d1", &[("on", fail()), ("on2", fail())])];
    let plan = run(&verdicts, &[], &policy(false, ROOMY, 1))?;
    assert_eq!(plan.requests.len(), 1);
    let deferred = plan.deferred.first().ok_or("missing")?;
    assert_eq!(deferred.reason, DeferReason::DeviceCorrectionCapReached);
    assert_eq!(deferred.request.control, "on2");
    Ok(())
}


#[test]
fn device_cap_defers_with_reason_and_skips_clean_devices() -> TestResult {
    let verdicts = [
        device("d0", &[("on", Verdict::Pass)]),
        device("d1", &[("on", fail())]),
        device("d2", &[("on", fail())]),
    ];
    let plan = run(&verdicts, &[], &policy(false, 1, ROOMY))?;
    assert_eq!(plan.requests.len(), 1);
    let deferred = plan.deferred.first().ok_or("missing")?;
    assert_eq!((deferred.reason, deferred.request.device.as_str()), (DeferReason::DeviceCapReached, "d2"));
    Ok(())
}


#[test]
fn mixed_tenants_are_refused() -> TestResult {
    let mut foreign = device("d1", &[("on", fail())]);
    foreign.tenant = "other".to_string();
    let result = plan_corrections(
        &[foreign],
        &baseline()?,
        &[],
        &policy(false, ROOMY, ROOMY),
        OffsetDateTime::from_unix_timestamp(NOW)?,
    );
    assert!(matches!(result, Err(ComplianceError::TenantMismatch { .. })));
    let mut other_policy = policy(false, ROOMY, ROOMY);
    other_policy.tenant = "other".to_string();
    let message = run(&[], &[], &other_policy).err().ok_or("expected refusal")?.to_string();
    assert!(message.contains("other") && message.contains("acme"));
    Ok(())
}


#[test]
fn unknown_control_is_refused() -> TestResult {
    let message = run(&[device("d1", &[("ghost", fail())])], &[], &policy(false, ROOMY, ROOMY))
        .err()
        .ok_or("expected refusal")?
        .to_string();
    assert!(message.contains("ghost"));
    Ok(())
}


#[test]
fn unknown_action_is_refused_at_load() -> TestResult {
    let text = BASELINE.replace("actions: [lock, fix]", "actions: [lock]");
    let message = parse_baseline(&mut text.as_bytes(), "b.yaml")
        .err()
        .ok_or("expected refusal")?
        .to_string();
    assert!(message.contains("`fix`") && message.contains("not declared"));
    Ok(())
}


#[test]
fn baseline_actions_and_tenant_are_bounded() -> TestResult {
    let long = "a".repeat(MAX_ID_LEN + 1);
    let many = (0..=MAX_ACTIONS).map(|index| format!("a{index}")).collect::<Vec<_>>().join(", ");
    for text in [
        BASELINE.replace("tenant: acme", "tenant: ''"),
        BASELINE.replace("[lock, fix]", &format!("[{long}]")),
        BASELINE.replace("[lock, fix]", &format!("[{many}]")),
    ] {
        assert!(parse_baseline(&mut text.as_bytes(), "b.yaml").is_err());
    }
    Ok(())
}


#[test]
fn policy_defaults_to_dry_run_and_validates() -> TestResult {
    let parsed = parse_policy(
        &mut "version: 1\ntenant: acme\nmax_devices: 2\nmax_corrections_per_device: 3\n".as_bytes(),
        "p.yaml",
    )?;
    assert!(parsed.dry_run);
    assert_eq!((parsed.max_devices, parsed.max_corrections_per_device), (TWO, THREE));
    let over = MAX_CAP + 1;
    for text in [
        "version: 2\ntenant: a\nmax_devices: 1\nmax_corrections_per_device: 1\n".to_string(),
        "version: 1\ntenant: a\nmax_devices: 0\nmax_corrections_per_device: 1\n".to_string(),
        format!("version: 1\ntenant: a\nmax_devices: {over}\nmax_corrections_per_device: 1\n"),
        "version: 1\ntenant: a\nmax_devices: 1\nmax_corrections_per_device: 0\n".to_string(),
        format!("version: 1\ntenant: a\nmax_devices: 1\nmax_corrections_per_device: {over}\n"),
        "version: 1\ntenant: ''\nmax_devices: 1\nmax_corrections_per_device: 1\n".to_string(),
    ] {
        assert!(parse_policy(&mut text.as_bytes(), "p.yaml").is_err());
    }
    Ok(())
}


#[test]
fn policy_loads_from_a_path() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("p.yaml");
    std::fs::write(
        &path,
        "version: 1\ntenant: acme\ndry_run: false\nmax_devices: 1\nmax_corrections_per_device: 1\n",
    )?;
    assert!(!load_policy(&path)?.dry_run);
    assert!(load_policy(&directory.path().join("missing.yaml")).is_err());
    Ok(())
}
