#[path = "common/types.rs"]
mod types;


use core_config::parse::parse_document;
use response_playbooks::catalogue::{catalogue_problems, find_entry, APPROVAL_ACTION};
use response_playbooks::error::{describe, DocumentProblems, ExprError, Problem};
use response_playbooks::expr::{
    check_template, evaluate, evaluate_condition, is_template, nesting_depth, on_worker, operator_count, refuse_blocks, render, resolve, sandbox,
    single_expression, PlaybookScope, Scope, MAX_NESTING, MAX_OPERATORS, MAX_SOURCE_LEN,
};
use response_playbooks::model::{Catalogue, ParamType, Playbook, Step};
use response_playbooks::params::{
    as_count, as_duration, as_ip, check_type, is_boolean, is_domain, is_empty, reduce_entity, resolve_one, resolve_params, type_label,
};
use response_playbooks::trigger::{lookup, mismatches, parse_comparison, satisfied, Comparison};
use response_playbooks::types::ParamMap;
use response_playbooks::validate::is_bare_entity;
use response_playbooks::validate::playbook_problems;
use response_playbooks::walk::{flatten, MAX_DEPTH};
use serde_json::{json, Value};
use types::TestResult;


const FIXTURE_CATALOGUE: &str = include_str!("../fixtures/catalogue.yaml");


const FIXTURE_PLAYBOOK: &str = include_str!("../fixtures/c2.yaml");


const FIRST_LEVEL_COUNT: usize = 2;


const NESTED_COUNT: usize = 3;


const HUNDRED: u64 = 100;


const TWO_PROBLEMS: usize = 2;


const FOUR: usize = 4;


const FIVE: u64 = 5;


const SEVEN: u64 = 7;


const TWO: u64 = 2;


const HIGH: f64 = 0.9;


const LOW: f64 = 0.5;


const THRESHOLD: f64 = 0.8;


const TWO_FLOAT: f64 = 2.0;


fn catalogue_of(text: &str) -> Result<Catalogue, Box<dyn std::error::Error>> {
    Ok(parse_document(text, "catalogue.yaml")?)
}


fn playbook_of(text: &str) -> Result<Playbook, Box<dyn std::error::Error>> {
    Ok(parse_document(text, "playbook.yaml")?)
}


const EXTRA_CATALOGUE: &str = "
actions:
  - action: notify
    params:
      text: { type: string }
      level: { type: integer, optional: true }
      flag: { type: boolean, optional: true }
  - action: wipe
    destructive: true
  - action: kill
    destructive: true
    compensate: revive
  - action: revive
  - action: lock_account
    destructive: true
    compensate: unlock_account
    breaker: { kind: disable_account, target: user }
    params:
      user: { type: string }
  - action: unlock_account
    params:
      user: { type: string }
  - action: run_script
    destructive: true
    compensate: revive
    breaker: { kind: rmm_script, target: host, machines: count }
    params:
      host: { type: string }
      count: { type: integer }
  - action: soft_isolate
    breaker: { kind: isolate_endpoint, target: host }
    params:
      host: { type: string }
  - action: block_name
    destructive: true
    compensate: revive
    breaker: { kind: block_domain, target: domain }
    params:
      domain: { type: domain }
";


fn steps_playbook(steps: &str) -> String {
    format!("name: test\nversion: 1\nmode: simulate\nsteps:\n{steps}\non_error:\n  - action: notify\n    params: {{ text: failed }}\n")
}


fn problems_of(steps: &str) -> Result<Vec<Problem>, Box<dyn std::error::Error>> {
    Ok(playbook_problems(&playbook_of(&steps_playbook(steps))?, &catalogue_of(EXTRA_CATALOGUE)?))
}


fn scope_over<'a>(alert: &'a Value, variables: &'a ParamMap, done: &'a [String]) -> Scope<'a> {
    Scope {
        alert,
        playbook: PlaybookScope {
            name: "test",
            version: 1,
            mode: response_playbooks::model::Mode::Simulate,
            variables,
            actions_done: done,
        },
    }
}


#[test]
fn the_fixture_playbook_and_catalogue_are_valid() -> TestResult {
    let catalogue = catalogue_of(FIXTURE_CATALOGUE)?;
    let playbook = playbook_of(FIXTURE_PLAYBOOK)?;
    assert!(catalogue_problems(&catalogue).is_empty());
    assert!(playbook_problems(&playbook, &catalogue).is_empty());
    assert!(find_entry(&catalogue, None, APPROVAL_ACTION).is_some());
    assert!(find_entry(&catalogue, Some("fortigate"), "block_ip").is_some());
    assert!(find_entry(&catalogue, Some("fortigate"), "nope").is_none());
    Ok(())
}


#[test]
fn unknown_keys_are_refused_with_file_line_and_path() -> TestResult {
    let text = "name: x\nversion: 1\nmode: simulate\nsteps:\n  - action: notify\n    bogus: 1\n";
    let failure = parse_document::<Playbook>(text, "pb.yaml").err().ok_or("expected a refusal")?;
    let message = failure.to_string();
    assert!(message.starts_with("pb.yaml:6:"), "{message}");
    assert!(message.contains("steps[0]"), "{message}");
    assert!(message.contains("bogus"), "{message}");
    let top = parse_document::<Playbook>("name: x\nversion: 1\nmode: bogus\nsteps: []\n", "pb.yaml")
        .err()
        .ok_or("expected a refusal")?;
    assert!(top.to_string().starts_with("pb.yaml:3:"), "{top}");
    let catalogue = parse_document::<Catalogue>("actions:\n  - action: a\n    destructive: maybe\n", "cat.yaml")
        .err()
        .ok_or("expected a refusal")?;
    assert!(catalogue.to_string().contains("actions[0].destructive"), "{catalogue}");
    Ok(())
}


#[test]
fn missing_fields_are_text_empty_and_falsy() -> TestResult {
    let alert = json!({ "host": { "value": "h" } });
    let variables = ParamMap::new();
    let scope = scope_over(&alert, &variables, &[]);
    assert!(!evaluate_condition("{{ alert.nothing.deeper.still }}", &scope)?);
    assert!(!evaluate_condition("{{ alert.user and not alert.user.is_privileged }}", &scope)?);
    assert!(evaluate_condition("{{ alert.host }}", &scope)?);
    assert!(evaluate_condition("{{ alert.host.criticality != 'critical' }}", &scope)?);
    assert_eq!(render("[{{ alert.nothing }}]", &scope)?, "[]");
    assert_eq!(resolve("{{ alert.nothing }}", &scope)?, Value::Null);
    Ok(())
}


#[test]
fn entities_print_their_value_and_other_maps_print_whole() -> TestResult {
    let alert = json!({ "host": { "value": "ws-1", "tags": ["a"] }, "plain": { "x": 1 }, "name": "text" });
    let variables = ParamMap::new();
    let done = vec!["one".to_owned(), "two".to_owned()];
    let scope = scope_over(&alert, &variables, &done);
    assert_eq!(render("{{ alert.host }}|{{ alert.name }}", &scope)?, "ws-1|text");
    assert!(render("{{ alert.plain }}", &scope)?.contains('x'));
    assert_eq!(
        render("{{ playbook.name }} {{ playbook.version }} {{ playbook.mode }}", &scope)?,
        "test 1 simulate"
    );
    assert_eq!(resolve("{{ alert.host }}", &scope)?, json!({ "value": "ws-1", "tags": ["a"] }));
    assert_eq!(resolve("{{ playbook.actions_done | length }}", &scope)?, json!(FIRST_LEVEL_COUNT));
    Ok(())
}


#[test]
fn the_sandbox_has_no_include_and_bounded_fuel() -> TestResult {
    let environment = sandbox();
    assert!(environment.render_str("{% include 'passwd' %}", ()).is_err());
    assert!(environment.render_str("{% extends 'base' %}", ()).is_err());
    let loops = "{% for a in range(100) %}{% for b in range(100) %}{{ a }}{% endfor %}{% endfor %}";
    let exhausted = environment.render_str(loops, ()).err().ok_or("expected exhaustion")?;
    assert!(exhausted.to_string().to_lowercase().contains("fuel"), "{exhausted}");
    Ok(())
}


#[test]
fn block_tags_and_bad_syntax_are_refused() -> TestResult {
    let alert = json!({});
    let variables = ParamMap::new();
    let scope = scope_over(&alert, &variables, &[]);
    assert!(matches!(render("{% include 'x' %}", &scope), Err(ExprError::Forbidden(_))));
    assert!(matches!(evaluate("{% x", &scope), Err(ExprError::Forbidden(_))));
    assert!(matches!(check_template("{# note #}"), Err(ExprError::Forbidden(_))));
    assert!(matches!(check_template("{{ alert. }}"), Err(ExprError::Engine(_))));
    assert!(matches!(check_template("a {{ alert. }} b"), Err(ExprError::Engine(_))));
    assert!(check_template("a {{ alert.x }} b").is_ok());
    assert!(check_template("{{ alert.x }}").is_ok());
    assert!(matches!(evaluate_condition("plain text", &scope), Err(ExprError::Forbidden(_))));
    assert!(matches!(
        evaluate_condition("{{ alert.x | nosuchfilter }}", &scope),
        Err(ExprError::Engine(_))
    ));
    assert!(matches!(resolve("{{ {none: 1} }}", &scope), Err(ExprError::Convert(_))));
    assert!(matches!(evaluate("alert.", &scope), Err(ExprError::Engine(_))));
    assert!(matches!(evaluate("1 / 0", &scope), Err(ExprError::Engine(_))));
    assert!(matches!(evaluate_condition("{{ 1 / 0 }}", &scope), Err(ExprError::Engine(_))));
    assert!(matches!(resolve("{{ 1 / 0 }}", &scope), Err(ExprError::Engine(_))));
    assert!(matches!(resolve("a {{ alert. }}", &scope), Err(ExprError::Engine(_))));
    assert!(matches!(resolve("a {% x %}", &scope), Err(ExprError::Forbidden(_))));
    assert!(refuse_blocks("fine").is_ok());
    assert!(refuse_blocks("{%").is_err());
    assert!(is_template("{{ x }}") && is_template("{% x") && is_template("{# x") && !is_template("plain"));
    assert_eq!(single_expression(" {{ a }} "), Some(" a "));
    assert_eq!(single_expression("{{ a }} and {{ b }}"), None);
    assert_eq!(single_expression("plain"), None);
    assert_eq!(single_expression("{{ a"), None);
    Ok(())
}


#[test]
fn parameter_types_are_checked() -> TestResult {
    assert!(check_type(ParamType::String, &json!("x")).is_ok());
    assert!(check_type(ParamType::String, &json!(1)).is_err());
    assert!(check_type(ParamType::Integer, &json!(HUNDRED)).is_ok());
    assert!(check_type(ParamType::Integer, &json!("12")).is_ok());
    assert!(check_type(ParamType::Integer, &json!("x")).is_err());
    assert!(check_type(ParamType::Boolean, &json!(true)).is_ok());
    assert!(check_type(ParamType::Boolean, &json!("false")).is_ok());
    assert!(check_type(ParamType::Boolean, &json!("maybe")).is_err());
    assert!(check_type(ParamType::Ip, &json!("10.0.0.1")).is_ok());
    assert!(check_type(ParamType::Ip, &json!("::1")).is_ok());
    assert!(check_type(ParamType::Ip, &json!("nope")).is_err());
    assert!(check_type(ParamType::Domain, &json!("a.example")).is_ok());
    assert!(check_type(ParamType::Domain, &json!("a b")).is_err());
    assert!(check_type(ParamType::Domain, &json!("")).is_err());
    assert!(check_type(ParamType::Domain, &json!(1)).is_err());
    assert!(check_type(ParamType::Duration, &json!("24h")).is_ok());
    assert!(check_type(ParamType::Duration, &json!("tomorrow")).is_err());
    assert!(as_ip(&json!(1)).is_none() && as_duration(&json!(1)).is_none() && as_count(&json!(true)).is_none());
    assert!(!is_boolean(&json!(1)) && !is_domain(&json!(null)));
    assert!(is_empty(&json!(null)) && is_empty(&json!("")) && !is_empty(&json!("x")) && !is_empty(&json!(0)));
    assert!(type_label(ParamType::Duration).contains("duration"));
    assert!(type_label(ParamType::String).contains("string"));
    assert!(type_label(ParamType::Integer).contains("integer"));
    assert!(type_label(ParamType::Boolean).contains("boolean"));
    assert!(type_label(ParamType::Ip).contains("IP"));
    assert!(type_label(ParamType::Domain).contains("domain"));
    Ok(())
}


#[test]
fn entities_reduce_to_value_and_tags() -> TestResult {
    let entity = reduce_entity(json!({ "value": "h", "tags": ["critical", 1] }));
    assert_eq!(entity.value, json!("h"));
    assert_eq!(entity.tags, vec!["critical".to_owned()]);
    assert!(reduce_entity(json!({ "value": "h" })).tags.is_empty());
    assert!(reduce_entity(json!({ "value": "h", "tags": "x" })).tags.is_empty());
    let whole = reduce_entity(json!({ "x": 1 }));
    assert_eq!(whole.value, json!({ "x": 1 }));
    assert_eq!(reduce_entity(json!("plain")).value, json!("plain"));
    Ok(())
}


#[test]
fn parameters_resolve_or_explain() -> TestResult {
    let catalogue = catalogue_of(EXTRA_CATALOGUE)?;
    let entry = find_entry(&catalogue, None, "notify").ok_or("no notify")?;
    let alert = json!({ "n": SEVEN, "who": { "value": "bob" } });
    let variables = ParamMap::new();
    let scope = scope_over(&alert, &variables, &[]);
    let params = |text: Value| -> Result<ParamMap, Box<dyn std::error::Error>> { Ok(serde_json::from_value(text)?) };
    let good = resolve_params(
        entry,
        &params(json!({ "text": "hi {{ alert.who }}", "level": "{{ alert.n }}", "flag": true }))?,
        &scope,
    )?;
    assert_eq!(good.get("text").map(|found| found.value.clone()), Some(json!("hi bob")));
    assert_eq!(good.get("level").map(|found| found.value.clone()), Some(json!(SEVEN)));
    assert!(resolve_params(entry, &params(json!({ "text": "x", "other": 1 }))?, &scope)
        .err()
        .ok_or("e")?
        .contains("unknown parameter"));
    assert!(resolve_params(entry, &params(json!({}))?, &scope)
        .err()
        .ok_or("e")?
        .contains("missing or empty"));
    assert!(resolve_params(entry, &params(json!({ "text": "{{ alert.nothing }}" }))?, &scope)
        .err()
        .ok_or("e")?
        .contains("missing or empty"));
    assert!(resolve_params(entry, &params(json!({ "text": FIVE }))?, &scope)
        .err()
        .ok_or("e")?
        .contains("expected a string"));
    assert!(resolve_params(entry, &params(json!({ "text": "{% x %}" }))?, &scope)
        .err()
        .ok_or("e")?
        .contains("`text`"));
    assert!(resolve_one(&json!(FIVE), &scope)? == json!(FIVE));
    assert!(resolve_one(&json!("plain"), &scope)? == json!("plain"));
    Ok(())
}


#[test]
fn triggers_compare_and_report() -> TestResult {
    let alert = json!({ "verdict": "malicious", "confidence": HIGH, "deep": { "n": FIVE } });
    assert_eq!(lookup(&alert, "alert.deep.n"), Some(&json!(FIVE)));
    assert!(lookup(&alert, "verdict").is_none());
    assert!(lookup(&alert, "alert.missing").is_none());
    assert_eq!(parse_comparison(">= 0.8"), Some((Comparison::AtLeast, THRESHOLD)));
    assert_eq!(parse_comparison("<= 2"), Some((Comparison::AtMost, TWO_FLOAT)));
    assert_eq!(parse_comparison("> 2"), Some((Comparison::Above, TWO_FLOAT)));
    assert_eq!(parse_comparison("< 2"), Some((Comparison::Below, TWO_FLOAT)));
    assert!(parse_comparison(">= abc").is_none() && parse_comparison("malicious").is_none());
    assert!(satisfied(&json!(">= 0.8"), &json!(HIGH)) && !satisfied(&json!(">= 0.8"), &json!(LOW)));
    assert!(satisfied(&json!("<= 1"), &json!(1)) && !satisfied(&json!("<= 1"), &json!(TWO)));
    assert!(satisfied(&json!("> 1"), &json!(TWO)) && !satisfied(&json!("> 1"), &json!(1)));
    assert!(satisfied(&json!("< 2"), &json!(1)) && !satisfied(&json!("< 2"), &json!(TWO)));
    assert!(!satisfied(&json!(">= 1"), &json!("text")));
    assert!(satisfied(&json!("malicious"), &json!("malicious")) && !satisfied(&json!("x"), &json!("y")));
    let trigger: ParamMap = serde_json::from_value(json!({ "alert.verdict": "malicious", "alert.gone": 1, "alert.confidence": "> 2" }))?;
    let unmet = mismatches(&trigger, &alert);
    assert_eq!(unmet.len(), TWO_PROBLEMS);
    assert!(mismatches(&ParamMap::new(), &alert).is_empty());
    Ok(())
}


#[test]
fn the_walk_lists_steps_in_level_order() -> TestResult {
    let playbook = playbook_of(&steps_playbook(
        "  - action: wipe\n  - if: \"{{ a }}\"\n    then:\n      - action: kill\n    else:\n      - action: request_approval\n        params: { role: r, timeout: 5m, action: kill }",
    ))?;
    let flattened = flatten(&playbook.steps, "steps");
    assert!(!flattened.truncated);
    let paths: Vec<&str> = flattened.steps.iter().map(|flat| flat.path.as_str()).collect();
    assert_eq!(paths, vec!["steps.0", "steps.1", "steps.1.then.0", "steps.1.else.0"]);
    assert_eq!(flattened.steps.len(), NESTED_COUNT + 1);
    Ok(())
}


#[test]
fn nesting_beyond_the_limit_is_cut_and_reported() -> TestResult {
    let innermost = Step {
        action: Some("notify".to_owned()),
        ..Step::default()
    };
    let nested = (0..=MAX_DEPTH).fold(vec![innermost], |inner, _| {
        vec![Step {
            condition: Some("{{ a }}".to_owned()),
            then: inner,
            ..Step::default()
        }]
    });
    let flattened = flatten(&nested, "steps");
    assert!(flattened.truncated);
    assert_eq!(flattened.steps.len(), MAX_DEPTH);
    let playbook = Playbook {
        steps: nested,
        ..playbook_of(&steps_playbook("  - action: notify\n    params: { text: a }"))?
    };
    assert!(playbook_problems(&playbook, &catalogue_of(EXTRA_CATALOGUE)?).contains(&Problem::TooDeep(MAX_DEPTH)));
    Ok(())
}


#[test]
fn every_static_refusal_is_listed() -> TestResult {
    let unknown = problems_of("  - connector: nope\n    action: x\n  - action: nothing")?;
    assert!(unknown.contains(&Problem::UnknownAction {
        path: "steps.0".to_owned(),
        connector: "nope".to_owned(),
        action: "x".to_owned()
    }));
    assert!(unknown.contains(&Problem::UnknownAction {
        path: "steps.1".to_owned(),
        connector: "(built-in)".to_owned(),
        action: "nothing".to_owned()
    }));
    let params = problems_of("  - action: notify\n    params: { level: x, extra: 1, flag: \"{{ alert. }}\" }")?;
    assert!(params
        .iter()
        .any(|found| matches!(found, Problem::MissingParam { param, .. } if param == "text")));
    assert!(params
        .iter()
        .any(|found| matches!(found, Problem::UnknownParam { param, .. } if param == "extra")));
    assert!(params
        .iter()
        .any(|found| matches!(found, Problem::ParamType { param, .. } if param == "level")));
    assert!(params
        .iter()
        .any(|found| matches!(found, Problem::BadExpression { path, .. } if path == "steps.0.params.flag")));
    let templated = problems_of("  - action: notify\n    params: { text: \"{{ alert.a }}\", level: \"{{ alert.b }}\" }")?;
    assert!(templated.is_empty(), "{templated:?}");
    let compensation = problems_of("  - action: wipe\n  - action: kill\n    compensate: nothing\n  - action: kill\n    compensate: revive")?;
    assert!(compensation.contains(&Problem::MissingCompensation {
        path: "steps.0".to_owned(),
        action: "wipe".to_owned()
    }));
    assert!(compensation.contains(&Problem::UnknownCompensation {
        path: "steps.1".to_owned(),
        action: "kill".to_owned(),
        compensate: "nothing".to_owned()
    }));
    assert_eq!(compensation.len(), TWO_PROBLEMS);
    Ok(())
}


#[test]
fn a_breaker_target_must_be_a_bare_entity_or_a_literal() -> TestResult {
    let accepted = problems_of(
        "  - action: lock_account\n    params: { user: \"{{ alert.user }}\" }\n  - action: soft_isolate\n    params: { host: dc-01 }\n  - action: soft_isolate\n    params: { host: \"{{alert.host_name}}\" }\n  - action: notify\n    params: { text: \"h-{{ alert.host }}\" }",
    )?;
    assert!(accepted.is_empty(), "{accepted:?}");
    for target in [
        "{{ alert.host.value }}",
        "h-{{ alert.host }}",
        "{{ alert.host }}{{ alert.user }}",
        "{{ playbook.variables.host }}",
        "{{ alert.host | upper }}",
        "{{ alert. }}",
        "{{ host }}",
    ] {
        let refused = problems_of(&format!("  - action: soft_isolate\n    params: {{ host: \"{target}\" }}"))?;
        assert!(
            refused
                .iter()
                .any(|found| matches!(found, Problem::BreakerTargetNotEntity { path, param } if path == "steps.0" && param == "host")),
            "{target}: {refused:?}"
        );
    }
    assert!(is_bare_entity("{{ alert.user }}"));
    assert!(!is_bare_entity("{{ alert.user.id }}"));
    assert!(!is_bare_entity("{{ alert. }}"));
    assert!(!is_bare_entity("alert.user"));
    Ok(())
}


#[test]
fn the_shape_of_every_step_is_checked() -> TestResult {
    let shapes = problems_of(
        "  - if: \"{{ a }}\"\n    action: notify\n    then:\n      - action: revive\n  - if: \"{{ a }}\"\n  - if: plain\n    then:\n      - action: revive\n  - if: \"{{ alert. }}\"\n    then:\n      - action: revive\n  - then:\n      - action: revive\n  - connector: edr\n  - if: \"{{ a }}\"\n    connector: edr\n    then:\n      - action: revive\n  - if: \"{{ a }}\"\n    params: { x: 1 }\n    then:\n      - action: revive\n  - if: \"{{ a }}\"\n    compensate: revive\n    then:\n      - action: revive",
    )?;
    let reasons: Vec<String> = shapes.iter().map(ToString::to_string).collect();
    assert_eq!(reasons.iter().filter(|reason| reason.contains("holds only")).count(), FOUR, "{reasons:?}");
    assert!(reasons.iter().any(|reason| reason.contains("non-empty `then`")), "{reasons:?}");
    assert!(reasons.iter().any(|reason| reason.contains("one `{{ expression }}`")), "{reasons:?}");
    assert!(shapes
        .iter()
        .any(|found| matches!(found, Problem::BadExpression { path, .. } if path == "steps.3.if")));
    assert!(reasons.iter().any(|reason| reason.contains("need an `if`")), "{reasons:?}");
    assert!(reasons.iter().any(|reason| reason.contains("needs an `action`")), "{reasons:?}");
    Ok(())
}


#[test]
fn the_playbook_header_is_checked() -> TestResult {
    let catalogue = catalogue_of(EXTRA_CATALOGUE)?;
    let broken = playbook_of("name: \" \"\nversion: 1\nmode: enforce\ntrigger:\n  verdict: x\nsteps: []\n")?;
    let found = playbook_problems(&broken, &catalogue);
    assert!(found.contains(&Problem::EmptyName));
    assert!(found.contains(&Problem::EmptySteps));
    assert!(found.contains(&Problem::MissingOnError));
    assert!(found.contains(&Problem::BadTrigger("verdict".to_owned())));
    let described = describe(&[DocumentProblems {
        document: "pb.yaml".to_owned(),
        problems: found,
    }]);
    assert!(described.contains("pb.yaml: the name is empty; pb.yaml: steps is empty"), "{described}");
    Ok(())
}


#[test]
fn the_catalogue_is_checked() -> TestResult {
    let catalogue = catalogue_of(
        "actions:\n  - action: a\n  - action: a\n  - action: request_approval\n  - action: b\n    compensate: gone\n  - action: c\n    breaker: { kind: block_ip, target: ip, duration: d, machines: m }\n    params:\n      ip: { type: ip }\n",
    )?;
    let found = catalogue_problems(&catalogue);
    let reasons: Vec<String> = found.iter().map(ToString::to_string).collect();
    assert!(
        reasons.iter().any(|reason| reason.contains("`a`") && reason.contains("more than once")),
        "{reasons:?}"
    );
    assert!(reasons.iter().any(|reason| reason.contains("reserved")), "{reasons:?}");
    assert!(reasons.iter().any(|reason| reason.contains("`gone`")), "{reasons:?}");
    assert!(reasons.iter().any(|reason| reason.contains("unknown parameter `d`")), "{reasons:?}");
    assert!(reasons.iter().any(|reason| reason.contains("unknown parameter `m`")), "{reasons:?}");
    let unbound = catalogue_of("actions:\n  - action: wipe\n    destructive: true\n    compensate: undo\n  - action: undo\n")?;
    assert!(catalogue_problems(&unbound)
        .iter()
        .any(|problem| problem.to_string().contains("`wipe`") && problem.to_string().contains("needs a `breaker` binding")));
    let with_connector = catalogue_of("actions:\n  - connector: x\n    action: a\n    compensate: gone\n")?;
    assert!(catalogue_problems(&with_connector)
        .iter()
        .any(|problem| problem.to_string().contains("x/a")));
    Ok(())
}


const PROBE_TERMS: usize = 12_000;


const DELIMITER_DEPTH: usize = 2;


const BALANCED_DEPTH: usize = 3;


const UNMATCHED_DEPTH: usize = 2;


fn long_sum(terms: usize) -> String {
    format!("{{{{ {}1 }}}}", "1 + ".repeat(terms))
}


fn nested(depth: usize) -> String {
    format!("{{{{ {}1{} }}}}", "(".repeat(depth), ")".repeat(depth))
}


#[test]
fn an_expression_beyond_the_size_caps_is_refused_before_compilation() -> TestResult {
    let alert = json!({});
    let variables = ParamMap::new();
    let scope = scope_over(&alert, &variables, &[]);
    let long = long_sum(PROBE_TERMS);
    assert!(matches!(check_template(&long), Err(ExprError::TooLong { .. })));
    assert!(matches!(render(&long, &scope), Err(ExprError::TooLong { .. })));
    assert!(matches!(evaluate_condition(&long, &scope), Err(ExprError::TooLong { .. })));
    assert!(matches!(resolve(&long, &scope), Err(ExprError::TooLong { .. })));
    assert!(matches!(evaluate(&long, &scope), Err(ExprError::TooLong { .. })));
    let refused = check_template(&nested(MAX_NESTING + 1)).err().ok_or("expected refusal")?;
    assert!(matches!(refused, ExprError::TooNested { .. }));
    assert!(refused.to_string().contains("limit is"), "{refused}");
    assert!(check_template(&nested(MAX_NESTING - DELIMITER_DEPTH)).is_ok());
    assert!(check_template(&"x".repeat(MAX_SOURCE_LEN)).is_ok());
    assert_eq!(nesting_depth("([{}])"), BALANCED_DEPTH);
    assert_eq!(nesting_depth("))(("), UNMATCHED_DEPTH);
    let problems = problems_of(&format!(
        "  - action: notify\n    params: {{ text: \"{}\" }}\n  - if: \"{}\"\n    then:\n      - action: notify\n        params: {{ text: x }}\n",
        long_sum(PROBE_TERMS),
        nested(MAX_NESTING + 1)
    ))?;
    assert_eq!(
        problems.iter().filter(|problem| matches!(problem, Problem::BadExpression { .. })).count(),
        TWO_PROBLEMS
    );
    Ok(())
}


#[test]
fn an_optional_parameter_that_resolves_empty_is_an_error() -> TestResult {
    let catalogue = catalogue_of(EXTRA_CATALOGUE)?;
    let entry = find_entry(&catalogue, None, "notify").ok_or("no notify")?;
    let alert = json!({});
    let variables = ParamMap::new();
    let scope = scope_over(&alert, &variables, &[]);
    let empty: ParamMap = serde_json::from_value(json!({ "text": "x", "level": "{{ alert.nothing }}" }))?;
    assert!(resolve_params(entry, &empty, &scope)
        .err()
        .ok_or("expected refusal")?
        .contains("`level` is missing or empty"));
    let absent: ParamMap = serde_json::from_value(json!({ "text": "x" }))?;
    assert!(resolve_params(entry, &absent, &scope).is_ok());
    Ok(())
}


const SMALL_STACK_BYTES: usize = 1_048_576;


const CHAIN_BUDGET: usize = 126;


const REVIEWER_PROBE: usize = 1985;


const OPERATOR_MIX: usize = 9;


const HALF: usize = 2;


const THIRD: usize = 3;


fn braces(expression: &str) -> String {
    format!("{{{{ {expression} }}}}")
}


fn chains(links: usize) -> Vec<(&'static str, String)> {
    vec![
        ("unary minus", braces(&format!("{}1", "-".repeat(links)))),
        ("attribute", braces(&format!("alert{}", ".b".repeat(links)))),
        ("filter", braces(&format!("1{}", "|abs".repeat(links / HALF)))),
        ("subscript", braces(&format!("alert{}", "[0]".repeat(links)))),
        ("power", braces(&format!("1{}", "**1".repeat(links / HALF)))),
        ("not", braces(&format!("{}true", "not ".repeat(links / HALF)))),
        ("concat", braces(&format!("1{}", "~1".repeat(links)))),
        ("comparison", braces(&format!("1{}", "<1".repeat(links)))),
        ("boolean", braces(&format!("true{}", " and true".repeat(links / THIRD)))),
    ]
}


fn checked_on_small_stack(text: String) -> Result<(), String> {
    std::thread::Builder::new()
        .stack_size(SMALL_STACK_BYTES)
        .spawn(move || {
            let alert = json!({});
            let variables = ParamMap::new();
            let scope = scope_over(&alert, &variables, &[]);
            check_template(&text).map_err(|failure| failure.to_string())?;
            let evaluated = evaluate_condition(&text, &scope).map(|_truth| ());
            let rendered = render(&text, &scope).map(|_text| ());
            [evaluated, rendered]
                .into_iter()
                .filter(|outcome| !matches!(outcome, Ok(()) | Err(ExprError::Engine(_))))
                .try_for_each(|outcome| outcome.map_err(|failure| failure.to_string()))
        })
        .map_err(|failure| failure.to_string())?
        .join()
        .map_err(|_panic| "the thread panicked".to_owned())?
}


#[test]
fn every_chain_kind_at_the_largest_size_checks_and_evaluates_on_a_one_mebibyte_stack() -> TestResult {
    chains(CHAIN_BUDGET)
        .into_iter()
        .try_for_each(|(kind, text)| checked_on_small_stack(text).map_err(|failure| format!("{kind}: {failure}")))?;
    Ok(())
}


#[test]
fn every_oversized_chain_is_refused_before_compilation() -> TestResult {
    let alert = json!({});
    let variables = ParamMap::new();
    let scope = scope_over(&alert, &variables, &[]);
    chains(REVIEWER_PROBE).into_iter().try_for_each(|(kind, text)| {
        let refused = check_template(&text).err().ok_or(format!("{kind} accepted"))?;
        assert!(
            matches!(
                refused,
                ExprError::TooLong { .. } | ExprError::TooNested { .. } | ExprError::TooComplex { .. }
            ),
            "{kind}: {refused}"
        );
        assert!(evaluate_condition(&text, &scope).is_err(), "{kind}");
        Ok::<(), String>(())
    })?;
    let compact = braces(&format!("{}1", "-".repeat(MAX_OPERATORS)));
    assert!(compact.len() < MAX_SOURCE_LEN);
    let refused = check_template(&compact).err().ok_or("expected refusal")?;
    assert!(matches!(refused, ExprError::TooComplex { .. }));
    assert!(refused.to_string().contains("limit is"), "{refused}");
    assert_eq!(operator_count("{{ not a and b or c if d else e is f in g }}"), OPERATOR_MIX);
    Ok(())
}


#[test]
fn the_worker_reports_a_thread_that_cannot_start_and_one_that_panics() -> TestResult {
    assert!(on_worker(SMALL_STACK_BYTES, || Ok(true))?);
    let refused = on_worker(usize::MAX, || Ok(true)).err().ok_or("expected refusal")?;
    assert!(matches!(refused, ExprError::Worker(_)), "{refused}");
    assert!(refused.to_string().contains("worker"));
    let panicked = on_worker(SMALL_STACK_BYTES, || -> Result<bool, ExprError> {
        std::panic::resume_unwind(Box::new(false))
    })
    .err()
    .ok_or("expected refusal")?;
    assert!(matches!(panicked, ExprError::WorkerPanicked), "{panicked}");
    assert!(panicked.to_string().contains("panicked"));
    Ok(())
}
