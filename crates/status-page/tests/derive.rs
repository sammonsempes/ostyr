#[path = "common/types.rs"]
mod types;


use status_page::config::validate_config;
use status_page::derive::{derive_states, MAX_CHECK_RESULTS};
use status_page::error::StatusPageError;
use status_page::model::{
    CheckResult, ComponentConfig, ComponentState, Limits, ManualOverride, PageConfig, RuleConfig, ServiceState, DEFAULT_LIMITS,
};
use status_page::render::render;
use types::TestResult;


const TENANT: &str = "acme";


const NOW: i64 = 10_000;


const WINDOW: u32 = 300;


const DEGRADED: u32 = 2;


const DOWN: u32 = 3;


const RECOVER: u32 = 3;


const SECRET_CHECK: &str = "check-internal-9z";


const SECRET_TARGET: &str = "10.9.8.7";


const SERVICE: &str = "svc-web";


const FAR: i64 = 50;


const PAIR_I64: i64 = 2;


const PAIR: usize = 2;


const SHORT: usize = 4;


fn rule(checks: &[&str]) -> RuleConfig {
    RuleConfig {
        checks: checks.iter().map(|check| (*check).to_string()).collect(),
        degraded_after: DEGRADED,
        down_after: DOWN,
        recover_after: RECOVER,
        window_seconds: WINDOW,
        unknown_state: None,
    }
}


fn config_with(rule: Option<RuleConfig>) -> PageConfig {
    PageConfig {
        id: "main".to_string(),
        tenant: TENANT.to_string(),
        title: "Acme status".to_string(),
        checks: vec![SECRET_CHECK.to_string(), "other".to_string()],
        components: vec![
            ComponentConfig {
                name: "Website".to_string(),
                service: SERVICE.to_string(),
                objective_ppm: None,
                rule,
            },
            ComponentConfig {
                name: "Static".to_string(),
                service: "svc-static".to_string(),
                objective_ppm: None,
                rule: None,
            },
        ],
    }
}


fn config() -> PageConfig {
    config_with(Some(rule(&[SECRET_CHECK])))
}


fn result(check: &str, location: &str, at: i64, passed: bool) -> CheckResult {
    CheckResult {
        tenant: TENANT.to_string(),
        check: check.to_string(),
        location: location.to_string(),
        at,
        passed,
    }
}


fn failing(locations: u32) -> Vec<CheckResult> {
    (0..locations)
        .map(|location| result(SECRET_CHECK, &format!("{SECRET_TARGET}-{location}"), NOW - 1, false))
        .collect()
}


fn manual(state: ComponentState, expires_at: i64) -> ManualOverride {
    ManualOverride {
        tenant: TENANT.to_string(),
        service: SERVICE.to_string(),
        state,
        author: "alice".to_string(),
        expires_at,
    }
}


fn derived(results: &[CheckResult], overrides: &[ManualOverride]) -> Result<Vec<ServiceState>, StatusPageError> {
    derive_states(&config(), results, overrides, NOW, &DEFAULT_LIMITS)
}


fn web_state(states: &[ServiceState]) -> Result<ComponentState, &'static str> {
    states
        .iter()
        .find(|state| state.service == SERVICE)
        .map(|state| state.state)
        .ok_or("no state")
}


#[test]
fn thresholds_at_equality_and_one_over() -> TestResult {
    let expected = [
        (0, ComponentState::Operational),
        (DEGRADED - 1, ComponentState::Operational),
        (DEGRADED, ComponentState::Degraded),
        (DOWN - 1, ComponentState::Degraded),
        (DOWN, ComponentState::MajorOutage),
        (DOWN + 1, ComponentState::MajorOutage),
    ];
    expected.iter().try_for_each(|(count, state)| -> TestResult {
        let mut results = failing(*count);
        results.push(result(SECRET_CHECK, "healthy", NOW - 1, true));
        assert_eq!(web_state(&derived(&results, &[])?)?, *state, "{count} failing");
        Ok(())
    })
}


#[test]
fn equal_thresholds_go_down() -> TestResult {
    let mut equal = rule(&[SECRET_CHECK]);
    equal.degraded_after = DOWN;
    let states = derive_states(&config_with(Some(equal)), &failing(DOWN), &[], NOW, &DEFAULT_LIMITS)?;
    assert_eq!(web_state(&states)?, ComponentState::MajorOutage);
    Ok(())
}


#[test]
fn components_without_rule_or_override_get_no_state() -> TestResult {
    let states = derived(&failing(1), &[])?;
    assert_eq!(states.len(), 1);
    assert!(states.iter().all(|state| state.tenant == TENANT));
    Ok(())
}


#[test]
fn override_wins_until_it_expires() -> TestResult {
    let results = failing(DOWN);
    let before = derived(&results, &[manual(ComponentState::Maintenance, NOW + 1)])?;
    assert_eq!(web_state(&before)?, ComponentState::Maintenance);
    let at_expiry = derived(&results, &[manual(ComponentState::Maintenance, NOW)])?;
    assert_eq!(web_state(&at_expiry)?, ComponentState::MajorOutage);
    let after = derived(&results, &[manual(ComponentState::Maintenance, NOW - 1)])?;
    assert_eq!(web_state(&after)?, ComponentState::MajorOutage);
    Ok(())
}


#[test]
fn latest_expiry_override_wins_and_other_services_are_ignored() -> TestResult {
    let mut other = manual(ComponentState::Degraded, NOW + FAR);
    other.service = "svc-static".to_string();
    let overrides = [
        manual(ComponentState::Degraded, NOW + 1),
        manual(ComponentState::Maintenance, NOW + PAIR_I64),
        other,
    ];
    let states = derived(&[], &overrides)?;
    assert_eq!(web_state(&states)?, ComponentState::Maintenance);
    assert_eq!(states.len(), PAIR);
    Ok(())
}


#[test]
fn missing_results_are_unknown_never_operational() -> TestResult {
    assert_eq!(web_state(&derived(&[], &[])?)?, ComponentState::Unknown);
    let stale = [result(SECRET_CHECK, "a", NOW - i64::from(WINDOW), true)];
    assert_eq!(web_state(&derived(&stale, &[])?)?, ComponentState::Unknown);
    let future = [result(SECRET_CHECK, "a", NOW + 1, true)];
    assert_eq!(web_state(&derived(&future, &[])?)?, ComponentState::Unknown);
    let fresh = [result(SECRET_CHECK, "a", NOW - i64::from(WINDOW) + 1, true)];
    assert_eq!(web_state(&derived(&fresh, &[])?)?, ComponentState::Operational);
    let mut declared = rule(&[SECRET_CHECK]);
    declared.unknown_state = Some(ComponentState::Degraded);
    let shown = derive_states(&config_with(Some(declared)), &[], &[], NOW, &DEFAULT_LIMITS)?;
    assert_eq!(web_state(&shown)?, ComponentState::Degraded);
    Ok(())
}


#[test]
fn one_unknown_check_keeps_the_component_unknown_but_outage_wins() -> TestResult {
    let both = config_with(Some(rule(&[SECRET_CHECK, "other"])));
    let one = [result(SECRET_CHECK, "a", NOW - 1, true), result("unrelated", "a", NOW - 1, false)];
    let states = derive_states(&both, &one, &[], NOW, &DEFAULT_LIMITS)?;
    assert_eq!(web_state(&states)?, ComponentState::Unknown);
    let outage = derive_states(&both, &failing(DOWN), &[], NOW, &DEFAULT_LIMITS)?;
    assert_eq!(web_state(&outage)?, ComponentState::MajorOutage);
    Ok(())
}


const FIRST: i64 = NOW - 5;


const SECOND: i64 = NOW - 4;


const THIRD: i64 = NOW - 3;


const FOURTH: i64 = NOW - 2;


fn history(location: &str, steps: &[(i64, bool)]) -> Vec<CheckResult> {
    steps.iter().map(|(at, passed)| result(SECRET_CHECK, location, *at, *passed)).collect()
}


#[test]
fn recovery_needs_consecutive_passes() -> TestResult {
    let steps = [(FIRST, false), (SECOND, true), (THIRD, true), (FOURTH, true)];
    let recovered: Vec<CheckResult> = (0..DOWN).flat_map(|location| history(&format!("loc-{location}"), &steps)).collect();
    assert_eq!(web_state(&derived(&recovered, &[])?)?, ComponentState::Operational);
    let partial: Vec<CheckResult> = (0..DOWN)
        .flat_map(|location| {
            history(
                &format!("loc-{location}"),
                &steps.iter().copied().filter(|step| step.0 != FOURTH).collect::<Vec<_>>(),
            )
        })
        .collect();
    assert_eq!(web_state(&derived(&partial, &[])?)?, ComponentState::MajorOutage);
    Ok(())
}


#[test]
fn one_good_sample_after_failure_does_not_flap() -> TestResult {
    let single_rule = config_with(Some(RuleConfig {
        degraded_after: 1,
        down_after: 1,
        ..rule(&[SECRET_CHECK])
    }));
    let mut samples = history("x", &[(THIRD, false), (FOURTH, true)]);
    let held = derive_states(&single_rule, &samples, &[], NOW, &DEFAULT_LIMITS)?;
    assert_eq!(web_state(&held)?, ComponentState::MajorOutage);
    samples.extend(history("x", &[(NOW - 1, true), (NOW, true)]));
    let back = derive_states(&single_rule, &samples, &[], NOW, &DEFAULT_LIMITS)?;
    assert_eq!(web_state(&back)?, ComponentState::Operational);
    Ok(())
}


#[test]
fn tenant_and_size_refusals() -> TestResult {
    let mut foreign = failing(1);
    foreign.push(CheckResult {
        tenant: "other".to_string(),
        ..result(SECRET_CHECK, "a", NOW - 1, true)
    });
    assert!(matches!(derived(&foreign, &[]), Err(StatusPageError::TenantMismatch)));
    let foreign_override = ManualOverride {
        tenant: "other".to_string(),
        ..manual(ComponentState::Degraded, NOW + 1)
    };
    assert!(matches!(derived(&[], &[foreign_override]), Err(StatusPageError::TenantMismatch)));
    let flood = vec![result(SECRET_CHECK, "a", NOW - 1, true); MAX_CHECK_RESULTS + 1];
    assert!(matches!(derived(&flood, &[]), Err(StatusPageError::TooMany { .. })));
    let two = [manual(ComponentState::Degraded, NOW + 1), manual(ComponentState::Degraded, NOW + 1)];
    let tight = Limits {
        max_components: PAIR,
        ..DEFAULT_LIMITS
    };
    let three: Vec<ManualOverride> = two.iter().chain(two.iter().take(1)).cloned().collect();
    assert!(matches!(
        derive_states(&config(), &[], &three, NOW, &tight),
        Err(StatusPageError::TooMany { what: "overrides", .. })
    ));
    Ok(())
}


#[test]
fn rules_are_validated() -> TestResult {
    let refused = |edit: &dyn Fn(&mut RuleConfig)| -> Result<StatusPageError, Box<dyn std::error::Error>> {
        let mut candidate = rule(&[SECRET_CHECK]);
        edit(&mut candidate);
        Ok(validate_config(&config_with(Some(candidate)), &DEFAULT_LIMITS).err().ok_or("accepted")?)
    };
    let reasons = [
        refused(&|candidate| candidate.checks = vec!["undeclared".to_string()])?,
        refused(&|candidate| candidate.checks = Vec::new())?,
        refused(&|candidate| candidate.degraded_after = 0)?,
        refused(&|candidate| candidate.down_after = 0)?,
        refused(&|candidate| candidate.recover_after = 0)?,
        refused(&|candidate| candidate.window_seconds = 0)?,
        refused(&|candidate| candidate.degraded_after = DOWN + 1)?,
        refused(&|candidate| candidate.unknown_state = Some(ComponentState::Operational))?,
    ];
    let texts: Vec<String> = reasons.iter().map(ToString::to_string).collect();
    assert!(texts.iter().all(|text| text.contains("svc-web")));
    assert!(texts.iter().any(|text| text.contains("unknown check id")));
    assert!(texts.iter().any(|text| text.contains("degraded_after above down_after")));
    assert!(reasons.iter().all(|reason| matches!(reason, StatusPageError::InvalidRule { .. })));
    let equal = RuleConfig {
        degraded_after: DOWN,
        unknown_state: Some(ComponentState::Maintenance),
        ..rule(&[SECRET_CHECK])
    };
    validate_config(&config_with(Some(equal)), &DEFAULT_LIMITS)?;
    Ok(())
}


#[test]
fn declared_check_bounds() -> TestResult {
    let few = Limits {
        max_components: 1,
        ..DEFAULT_LIMITS
    };
    assert!(matches!(validate_config(&config(), &few), Err(StatusPageError::TooMany { .. })));
    let one_component = PageConfig {
        components: config().components.into_iter().take(1).collect(),
        ..config()
    };
    assert!(matches!(
        validate_config(&one_component, &few),
        Err(StatusPageError::TooMany { what: "declared checks", .. })
    ));
    let many_rule_checks = PageConfig {
        checks: vec![SECRET_CHECK.to_string()],
        components: one_component.components.clone(),
        ..one_component.clone()
    };
    validate_config(&many_rule_checks, &few)?;
    let long = Limits {
        max_text_bytes: SHORT,
        ..DEFAULT_LIMITS
    };
    let short_texts = PageConfig {
        id: "a".to_string(),
        tenant: "b".to_string(),
        title: "c".to_string(),
        components: vec![ComponentConfig {
            name: "n".to_string(),
            service: "s".to_string(),
            objective_ppm: None,
            rule: Some(RuleConfig {
                checks: vec!["long-check-id".to_string()],
                ..rule(&[])
            }),
        }],
        checks: vec!["long-check-id".to_string()],
    };
    assert!(matches!(
        validate_config(&short_texts, &long),
        Err(StatusPageError::TextTooLong { field: "check id", .. })
    ));
    let long_rule = PageConfig {
        checks: vec!["a".to_string(), "b".to_string()],
        components: vec![ComponentConfig {
            name: "n".to_string(),
            service: "s".to_string(),
            objective_ppm: None,
            rule: Some(rule(&["a", "b"])),
        }],
        ..short_texts
    };
    let rule_cap = Limits {
        max_components: 1,
        ..DEFAULT_LIMITS
    };
    assert!(matches!(
        validate_config(&long_rule, &rule_cap),
        Err(StatusPageError::TooMany { what: "declared checks", .. })
    ));
    Ok(())
}


#[test]
fn rule_checks_count_is_bounded_separately() -> TestResult {
    let page = PageConfig {
        checks: vec!["a".to_string()],
        components: vec![ComponentConfig {
            name: "n".to_string(),
            service: "s".to_string(),
            objective_ppm: None,
            rule: Some(rule(&["a", "a"])),
        }],
        ..config()
    };
    let cap = Limits {
        max_components: 1,
        ..DEFAULT_LIMITS
    };
    assert!(matches!(
        validate_config(&page, &cap),
        Err(StatusPageError::TooMany { what: "rule checks", .. })
    ));
    Ok(())
}


#[test]
fn rendered_page_shows_only_public_names() -> TestResult {
    let states = derived(&failing(DOWN), &[])?;
    let page = render(&config(), &states, &[], &[], NOW, &DEFAULT_LIMITS)?;
    assert!(!page.json.contains(SECRET_CHECK) && !page.html.contains(SECRET_CHECK));
    assert!(!page.json.contains(SECRET_TARGET) && !page.html.contains(SECRET_TARGET));
    assert!(!page.json.contains(SERVICE));
    assert_eq!(
        page.json,
        "{\"id\":\"main\",\"title\":\"Acme status\",\"generated_at\":10000,\"state\":\"major_outage\",\"maintenance\":false,\
\"components\":[{\"name\":\"Website\",\"state\":\"major_outage\",\"figure\":null},{\"name\":\"Static\",\"state\":\"unknown\",\"figure\":null}],\
\"incidents\":[]}"
    );
    assert_eq!(page.dropped.states, 0);
    Ok(())
}


#[test]
fn rule_loads_from_yaml() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("page.yaml");
    std::fs::write(
        &path,
        "id: main\ntenant: acme\ntitle: t\nchecks: [c1]\ncomponents:\n  - name: W\n    service: s\n    rule:\n      checks: [c1]\n      \
degraded_after: 1\n      down_after: 2\n      recover_after: 2\n      window_seconds: 60\n      unknown_state: degraded\n",
    )?;
    let loaded = status_page::config::load_config(&path, &DEFAULT_LIMITS)?;
    let loaded_rule = loaded.components.first().ok_or("component")?.rule.clone().ok_or("rule")?;
    assert_eq!(loaded_rule.unknown_state, Some(ComponentState::Degraded));
    assert_eq!(loaded.checks, ["c1"]);
    Ok(())
}
