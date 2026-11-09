use crate::support::{
    audit, bench, connection, context, failed_login, feed, mapping, replace_file, rules_error, ruleset, BEACON, BRUTE_FORCE, DISTINCT_DESTINATIONS,
    LOGIN, MAPPING, SEC_2, SEC_3, SEC_4, SEC_5,
};
use crate::types::TestResult;
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_config::error::ConfigError;
use core_config::reload::{open_engine, reload, ReloadOutcome};
use core_config::types::SharedAuditFn;
use std::fs;
use std::io;
use std::sync::{Arc, Mutex};
use stream_correlation::cli::start_engine;
use stream_correlation::engine::snapshot;
use stream_correlation::error::CorrelationError;
use stream_correlation::reload::{load_rules, open_rules, read_texts, refusal, rules_loader, rules_state};


const STATE_KEYS: usize = 2;


fn lower_threshold() -> String {
    BRUTE_FORCE.replace("gte: 3", "gte: 2")
}


#[test]
fn a_changed_rule_keeps_the_state_of_unchanged_rules() -> TestResult {
    let bench = bench(&[LOGIN, BEACON, BRUTE_FORCE, DISTINCT_DESTINATIONS])?;
    feed(&bench.engine, &failed_login(0, "a", "h1"));
    feed(&bench.engine, &connection(1, "x", "h1", "10.0.0.1"));
    feed(&bench.engine, &connection(SEC_2, "y", "h1", "10.0.0.2"));
    let changed = [LOGIN, BEACON, &lower_threshold(), DISTINCT_DESTINATIONS].join("\n---\n");
    replace_file(&bench.rule_file, &changed)?;
    assert!(matches!(reload(&bench.engine.rules), ReloadOutcome::Applied { .. }));
    assert!(feed(&bench.engine, &failed_login(SEC_3, "b", "h1")).is_empty());
    let scan = feed(&bench.engine, &connection(SEC_4, "z", "h1", "10.0.0.3"));
    assert_eq!(
        scan.first().map(|alert| alert.event_ids.clone()),
        Some(vec!["x".to_string(), "y".to_string(), "z".to_string()])
    );
    let brute = feed(&bench.engine, &failed_login(SEC_5, "c", "h1"));
    assert_eq!(
        brute.first().map(|alert| alert.event_ids.clone()),
        Some(vec!["b".to_string(), "c".to_string()])
    );
    assert!(!snapshot(&bench.engine).rules.contains_key("nothing"));
    Ok(())
}


#[test]
fn removing_a_rule_drops_its_state() -> TestResult {
    let bench = bench(&[LOGIN, BEACON, BRUTE_FORCE, DISTINCT_DESTINATIONS])?;
    feed(&bench.engine, &failed_login(0, "a", "h1"));
    replace_file(&bench.rule_file, &[LOGIN, BRUTE_FORCE].join("\n---\n"))?;
    assert!(matches!(reload(&bench.engine.rules), ReloadOutcome::Applied { .. }));
    feed(&bench.engine, &failed_login(1, "b", "h1"));
    assert_eq!(snapshot(&bench.engine).rules.keys().collect::<Vec<_>>(), vec!["brute-force"]);
    Ok(())
}


#[test]
fn an_invalid_file_keeps_the_old_rules() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    replace_file(&bench.rule_file, "title: broken\ncorrelation:\n  type: sequence\n")?;
    assert!(matches!(reload(&bench.engine.rules), ReloadOutcome::Refused { .. }));
    feed(&bench.engine, &failed_login(0, "a", "h1"));
    feed(&bench.engine, &failed_login(1, "b", "h1"));
    assert_eq!(feed(&bench.engine, &failed_login(SEC_2, "c", "h1")).len(), 1);
    Ok(())
}


#[test]
fn an_unchanged_file_reloads_to_nothing() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    assert_eq!(reload(&bench.engine.rules), ReloadOutcome::Unchanged);
    Ok(())
}


#[test]
fn mapping_changes_are_picked_up_and_bad_ones_refused() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    fs::write(&bench.mapping_file, "products: {}\ncategories: {}\n")?;
    assert!(matches!(reload(&bench.engine.rules), ReloadOutcome::Refused { .. }));
    fs::write(&bench.mapping_file, "not: [valid")?;
    assert!(matches!(reload(&bench.engine.rules), ReloadOutcome::Refused { .. }));
    let message = rules_error(&bench.mapping_file, &bench.rule_file)?;
    assert!(message.contains("ecs.yaml"), "{message}");
    Ok(())
}


#[test]
fn loader_errors_name_the_file_and_keep_the_typed_message() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    fs::write(
        &bench.rule_file,
        "title: x\ncorrelation:\n  type: sequence\n  rules: [a]\n  timespan: 1m\n",
    )?;
    fs::write(&bench.mapping_file, MAPPING)?;
    let message = rules_error(&bench.mapping_file, &bench.rule_file)?;
    assert!(
        message.contains("correlation type") && !message.contains("sequence") && message.contains("rules.yml"),
        "{message}"
    );
    fs::remove_file(&bench.rule_file)?;
    assert!(matches!(
        start_engine(
            bench.mapping_file.clone(),
            vec![bench.rule_file.clone()],
            &bench.checkpoint,
            audit(),
            context()
        ),
        Err(CorrelationError::Config(ConfigError::Io { .. }))
    ));
    assert!(matches!(read_texts(std::slice::from_ref(&bench.rule_file)), Err(ConfigError::Io { .. })));
    let loader = rules_loader(bench.dir.path().join("absent.yaml"), vec![bench.rule_file.clone()]);
    assert!(matches!(loader(), Err(ConfigError::Io { .. })));
    assert!(matches!(
        open_engine(loader, rules_state, Vec::new(), audit(), context()),
        Err(ConfigError::Io { .. })
    ));
    Ok(())
}


#[test]
fn refusals_keep_the_cause_text() -> TestResult {
    let error = refusal("f.yml", &CorrelationError::Duplicate("x".to_string()));
    assert!(matches!(&error, ConfigError::Parse { message, file, .. } if message.contains("duplicate rule identifier x") && file == "f.yml"));
    Ok(())
}


#[test]
fn the_reload_state_names_bases_and_correlations() -> TestResult {
    let rules = ruleset(&[LOGIN, BRUTE_FORCE])?;
    let state = rules_state(&rules);
    assert_eq!(state.len(), STATE_KEYS);
    assert!(state.keys().any(|key| key.starts_with("base.Failed login.")));
    assert!(state.contains_key("correlation.brute-force"));
    mapping()?;
    Ok(())
}


const CANARY: &str = "canary-9";


fn capturing_audit(entries: Arc<Mutex<Vec<String>>>) -> Box<SharedAuditFn> {
    let log = genesis_log(io::sink());
    Box::new(move |entry| {
        entries.lock().map_err(|_| AuditError::LogPoisoned)?.push(format!("{entry:?}"));
        append(&log, entry)
    })
}


fn refusal_reason(outcome: ReloadOutcome) -> Result<String, String> {
    match outcome {
        ReloadOutcome::Refused { reason } => Ok(reason),
        other => Err(format!("expected a refusal, got {other:?}")),
    }
}


fn refused_without_marker(rule_text: &str) -> Result<String, Box<dyn std::error::Error>> {
    let entries = Arc::new(Mutex::new(Vec::new()));
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    let engine = open_rules(
        bench.mapping_file.clone(),
        vec![bench.rule_file.clone()],
        capturing_audit(Arc::clone(&entries)),
        context(),
    )?;
    replace_file(&bench.rule_file, rule_text)?;
    let reason = refusal_reason(reload(&engine))?;
    let audited = entries.lock().map_err(|_| "poisoned")?.join("\n");
    assert!(!reason.contains(CANARY), "{reason}");
    assert!(audited.contains("refused") && !audited.contains(CANARY), "{audited}");
    let message = rules_error(&bench.mapping_file, &bench.rule_file)?;
    assert!(!message.contains(CANARY), "{message}");
    Ok(message)
}


#[test]
fn a_duplicate_key_marker_stays_out_of_the_refusal_and_the_audit() -> TestResult {
    refused_without_marker("title: ok\ntitle: /srv/canary-9\n")?;
    Ok(())
}


#[test]
fn a_bad_tag_marker_stays_out_of_the_refusal_and_the_audit() -> TestResult {
    refused_without_marker("title: !/srv/canary-9 x\n")?;
    Ok(())
}


#[test]
fn a_valid_rule_file_still_loads() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    let rules = load_rules(&bench.mapping_file, std::slice::from_ref(&bench.rule_file))?;
    assert_eq!(rules.correlations.len(), 1);
    Ok(())
}


const VALID_BODY: &str = "  type: temporal\n  rules: [failed-login]\n  timespan: 1m\n";


fn correlation_refusal(correlation_body: &str, extra_keys: &str) -> Result<String, Box<dyn std::error::Error>> {
    let rule = format!("title: Variant\nid: variant\n{extra_keys}correlation:\n{correlation_body}");
    refused_without_marker(&[LOGIN, &rule].join("\n---\n"))
}


fn assert_names_file_and_rule(message: &str) {
    assert!(message.contains("rules.yml") && message.contains("Variant"), "{message}");
}


#[test]
fn wrong_type_fields_name_the_path_and_never_the_value() -> TestResult {
    let generate = correlation_refusal(&format!("{VALID_BODY}  generate: /srv/canary-9\n"), "")?;
    assert!(
        generate.contains("correlation.generate") && generate.contains("invalid type"),
        "{generate}"
    );
    assert_names_file_and_rule(&generate);
    let rules = correlation_refusal("  type: temporal\n  rules: /srv/canary-9\n  timespan: 1m\n", "")?;
    assert!(rules.contains("correlation.rules") && rules.contains("invalid type"), "{rules}");
    assert_names_file_and_rule(&rules);
    Ok(())
}


#[test]
fn unknown_keys_never_reach_the_refusal() -> TestResult {
    let nested = correlation_refusal(&format!("{VALID_BODY}  \"/srv/canary-9\": 1\n"), "")?;
    assert!(nested.contains("unknown field"), "{nested}");
    assert_names_file_and_rule(&nested);
    let top = correlation_refusal(VALID_BODY, "\"/srv/canary-9\": 1\n")?;
    assert!(top.contains("top-level key"), "{top}");
    assert_names_file_and_rule(&top);
    Ok(())
}


#[test]
fn constructs_are_named_without_their_values() -> TestResult {
    let kind = correlation_refusal("  type: /srv/canary-9\n  rules: [failed-login]\n  timespan: 1m\n", "")?;
    assert!(kind.contains("correlation type"), "{kind}");
    assert_names_file_and_rule(&kind);
    let reference = correlation_refusal("  type: temporal\n  rules: [/srv/canary-9]\n  timespan: 1m\n", "")?;
    assert!(reference.contains("unknown rule reference"), "{reference}");
    let span = correlation_refusal("  type: temporal\n  rules: [failed-login]\n  timespan: /srv/canary-9\n", "")?;
    assert!(span.contains("timespan"), "{span}");
    let digits = correlation_refusal("  type: temporal\n  rules: [failed-login]\n  timespan: /srv/canary-9s\n", "")?;
    assert!(digits.contains("timespan"), "{digits}");
    let condition = correlation_refusal(
        "  type: event_count\n  rules: [failed-login]\n  timespan: 1m\n  condition:\n    /srv/canary-9: 1\n",
        "",
    )?;
    assert!(condition.contains("condition key"), "{condition}");
    Ok(())
}


#[test]
fn base_rule_values_never_reach_the_refusal() -> TestResult {
    let base = |logsource: &str, detection: &str| format!("title: Base\nid: base\nlogsource:\n{logsource}detection:\n{detection}");
    let selection = |line: &str| format!("  selection:\n    {line}\n  condition: selection\n");
    let process = "  category: process_creation\n";
    let product = refused_without_marker(&base(
        "  category: process_creation\n  product: /srv/canary-9\n",
        &selection("CommandLine: x"),
    ))?;
    assert!(
        product.contains("logsource product") && product.contains("rules.yml") && product.contains("Base"),
        "{product}"
    );
    let category = refused_without_marker(&base("  category: /srv/canary-9\n", &selection("CommandLine: x")))?;
    assert!(category.contains("logsource category"), "{category}");
    let regex = refused_without_marker(&base(process, &selection("CommandLine|re: '(/srv/canary-9'")))?;
    assert!(regex.contains("invalid regular expression") && regex.contains("Base"), "{regex}");
    let cidr = refused_without_marker(&base(process, &selection("CommandLine|cidr: /srv/canary-9")))?;
    assert!(cidr.contains("invalid CIDR"), "{cidr}");
    Ok(())
}


fn marked_base(selection_line: &str, condition: &str) -> String {
    format!(
        "title: Base\nid: base\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    {selection_line}\n  condition: {condition}\n"
    )
}


fn assert_scrubbed(message: &str, class: &str) {
    assert!(
        message.contains("rules.yml") && message.contains("Base") && message.contains(class),
        "{message}"
    );
}


#[test]
fn sigma_rule_keys_never_reach_the_refusal() -> TestResult {
    let modifier = refused_without_marker(&marked_base("CommandLine|/srv/canary-9: x", "selection"))?;
    assert_scrubbed(&modifier, "unknown or unsupported modifier");
    let unmapped = refused_without_marker(&marked_base("/srv/canary-9: x", "selection"))?;
    assert_scrubbed(&unmapped, "has no mapping for category");
    let unmapped_re = refused_without_marker(&marked_base("/srv/canary-9|re: x", "selection"))?;
    assert_scrubbed(&unmapped_re, "has no mapping for category");
    let conflicting = refused_without_marker(&marked_base("/srv/canary-9|contains|startswith: x", "selection"))?;
    assert_scrubbed(&conflicting, "unsupported construct");
    let windash = refused_without_marker(&marked_base("/srv/canary-9|windash|re: x", "selection"))?;
    assert_scrubbed(&windash, "unsupported construct");
    let missing = refused_without_marker(&marked_base("CommandLine: x", "/srv/canary-9"))?;
    assert_scrubbed(&missing, "no selection named");
    let missing_glob = refused_without_marker(&marked_base("CommandLine: x", "1 of /srv/canary-9*"))?;
    assert_scrubbed(&missing_glob, "no selection named");
    Ok(())
}


#[test]
fn a_marked_mapping_identifier_never_reaches_the_refusal() -> TestResult {
    let entries = Arc::new(Mutex::new(Vec::new()));
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    let engine = open_rules(
        bench.mapping_file.clone(),
        vec![bench.rule_file.clone()],
        capturing_audit(Arc::clone(&entries)),
        context(),
    )?;
    let bad_column = "products: {}\ncategories:\n  c:\n    event_category: process\n    fields:\n      A: '/srv/canary-9 x'\n";
    replace_file(&bench.mapping_file, bad_column)?;
    let reason = refusal_reason(reload(&engine))?;
    let audited = entries.lock().map_err(|_| "poisoned")?.join("\n");
    let message = rules_error(&bench.mapping_file, &bench.rule_file)?;
    assert!(message.contains("ecs.yaml") && message.contains("bad identifier"), "{message}");
    assert!(
        !reason.contains(CANARY) && !audited.contains(CANARY) && !message.contains(CANARY),
        "{reason} {audited} {message}"
    );
    Ok(())
}
