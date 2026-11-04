use crate::support::{
    audit, bench, connection, context, failed_login, feed, mapping, replace_file, rules_error, ruleset, BEACON, BRUTE_FORCE, DISTINCT_DESTINATIONS,
    LOGIN, MAPPING, SEC_2, SEC_3, SEC_4, SEC_5,
};
use crate::types::TestResult;
use core_config::error::ConfigError;
use core_config::reload::{open_engine, reload, ReloadOutcome};
use std::fs;
use stream_correlation::cli::start_engine;
use stream_correlation::engine::snapshot;
use stream_correlation::error::CorrelationError;
use stream_correlation::reload::{read_texts, refusal, rules_loader, rules_state};


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
    assert!(message.contains("sequence") && message.contains("rules.yml"), "{message}");
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
