use crate::support::{bench, context, exclusion, hash, loaded, reasons_for, replace_file, HASH_LENGTH, RAISED_MIN};
use crate::types::TestResult;
use core_audit::model::Record;
use core_config::error::ConfigError;
use core_config::reload::{current_config, open_engine, reload, ReloadOutcome};
use policy_validator::model::{Reason, Scope, SelectorKind};
use policy_validator::policy::{Policy, PolicyError};
use policy_validator::reload::{load_policy, open_validator, policy_loader, policy_state, refusal};
use std::fs;


const MIN_AUDITED_RELOADS: usize = 2;


const MIN_TEN: &str = "min_benign_verdicts: 10\n";


#[test]
fn an_empty_mapping_gives_the_defaults() -> TestResult {
    let bench = bench("{}")?;
    let current = current_config(&bench.engine);
    assert_eq!(current.policy, Policy::default());
    assert_eq!(current.hash.len(), HASH_LENGTH);
    assert_eq!(current.hash, load_policy(&bench.policy_file)?.hash);
    Ok(())
}


#[test]
fn the_defaults_are_all_canonical_and_in_force() -> TestResult {
    let policy = loaded()?;
    assert_eq!(policy.policy, Policy::default());
    assert!(policy.protected.iter().any(|entry| entry.name == "/opt/ostyr"));
    assert!(policy.interpreter_stems.contains(&"powershell".to_owned()));
    Ok(())
}


#[test]
fn a_threshold_is_overridden_by_the_file() -> TestResult {
    let bench = bench(MIN_TEN)?;
    let current = current_config(&bench.engine);
    assert_eq!(current.policy.min_benign_verdicts, RAISED_MIN);
    assert_eq!(current.policy.min_distinct_days, Policy::default().min_distinct_days);
    Ok(())
}


#[test]
fn a_valid_change_is_applied_without_restart_and_audited() -> TestResult {
    let bench = bench("{}")?;
    assert!(reasons_for(exclusion(Scope::Global, SelectorKind::Hash, &hash()))?.is_empty());
    assert_eq!(reload(&bench.engine), ReloadOutcome::Unchanged);
    replace_file(&bench.policy_file, "interpreters: [tool]\n")?;
    let outcome = reload(&bench.engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Applied { keys } if keys.contains(&"interpreters".to_owned()) && keys.contains(&"config_hash".to_owned()))
    );
    let text = fs::read_to_string(&bench.audit_file)?;
    let record: Record = serde_json::from_str(text.lines().next().ok_or("no record")?)?;
    assert_eq!(record.action, "config.reload");
    assert_eq!(current_config(&bench.engine).policy.interpreters, vec!["tool".to_owned()]);
    Ok(())
}


#[test]
fn an_invalid_file_is_refused_and_the_old_one_kept() -> TestResult {
    let bench = bench(MIN_TEN)?;
    for bad in [
        "min_benign_verdicts: [",
        "surprise: true\n",
        "min_benign_verdicts: many\n",
        "user_writable_prefixes: [tmp]\n",
        "agent_paths: ['/a/../b']\n",
        "honeytoken_paths: ['C:Users']\n",
        "interpreters: ['']\n",
        "interpreters: ['.exe']\n",
    ] {
        replace_file(&bench.policy_file, bad)?;
        assert!(matches!(reload(&bench.engine), ReloadOutcome::Refused { .. }), "{bad}");
        assert_eq!(current_config(&bench.engine).policy.min_benign_verdicts, RAISED_MIN, "{bad}");
    }
    Ok(())
}


#[test]
fn a_refusal_names_the_entry_and_the_form() -> TestResult {
    let bench = bench("{}")?;
    replace_file(&bench.policy_file, "user_writable_prefixes: ['/a/*']\n")?;
    let outcome = reload(&bench.engine);
    assert!(matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("/a/*") && reason.contains("wildcard")));
    Ok(())
}


#[test]
fn a_whitespace_only_edit_changes_the_hash_and_so_the_version() -> TestResult {
    let bench = bench("{}")?;
    let before = current_config(&bench.engine).hash.clone();
    replace_file(&bench.policy_file, "{}\n")?;
    assert!(matches!(reload(&bench.engine), ReloadOutcome::Applied { .. }));
    assert_ne!(before, current_config(&bench.engine).hash);
    Ok(())
}


#[test]
fn the_state_has_one_key_per_setting() -> TestResult {
    let state = policy_state(&loaded()?);
    assert_eq!(state.get("config_hash").map(String::as_str), Some("test-hash"));
    assert!(state
        .get("critical_asr_rules")
        .is_some_and(|text| text.contains("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2")));
    assert_eq!(state.get("honeytoken_paths").map(String::as_str), Some("count=0 changed=false"));
    Ok(())
}


#[test]
fn a_missing_file_stops_the_start() -> TestResult {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("absent.yaml");
    assert!(matches!(load_policy(&missing), Err(ConfigError::Io { .. })));
    assert!(open_engine(
        policy_loader(missing.clone()),
        policy_state,
        Vec::new(),
        Box::new(|_| Err(core_audit::error::AuditError::LogPoisoned)),
        context()
    )
    .is_err());
    assert!(open_validator(missing, Box::new(|_| Err(core_audit::error::AuditError::LogPoisoned)), context()).is_err());
    Ok(())
}


#[test]
fn a_policy_error_travels_as_a_parse_error_with_its_message() -> TestResult {
    let error = refusal("policy.yaml", &PolicyError::EmptyInterpreter);
    assert!(matches!(&error, ConfigError::Parse { file, message, .. } if file == "policy.yaml" && message.contains("interpreter")));
    assert!(Reason::InvalidHash.to_string().contains("invalid_hash"));
    Ok(())
}


#[test]
fn the_list_digest_survives_redaction_in_the_audit_record() -> TestResult {
    let bench = bench("{}")?;
    replace_file(&bench.policy_file, "os_directories: [/edr]\n")?;
    assert!(matches!(reload(&bench.engine), ReloadOutcome::Applied { .. }));
    replace_file(&bench.policy_file, "os_directories: [/other]\n")?;
    assert!(matches!(reload(&bench.engine), ReloadOutcome::Applied { .. }));
    let text = fs::read_to_string(&bench.audit_file)?;
    let lines: Vec<&str> = text.lines().filter(|line| line.contains("sha256-salted=")).collect();
    assert!(lines.len() >= MIN_AUDITED_RELOADS, "{text}");
    assert!(!text.contains("[REDACTED]"), "{text}");
    let first = lines.first().ok_or("none")?;
    let last = lines.last().ok_or("none")?;
    assert_ne!(first, last);
    Ok(())
}


#[test]
fn sensitive_lists_reach_the_audit_as_count_and_changed_only() -> TestResult {
    let bench = bench("{}")?;
    replace_file(
        &bench.policy_file,
        "honeytoken_paths: [/srv/canary-9]\nsecurity_sensors: [edr]\nagent_paths: [/opt/agent-7]\n",
    )?;
    assert!(matches!(reload(&bench.engine), ReloadOutcome::Applied { .. }));
    let text = fs::read_to_string(&bench.audit_file)?;
    for entry in ["canary-9", "edr", "agent-7"] {
        assert!(!text.contains(entry), "{entry}: {text}");
    }
    assert!(text.contains("count=1 changed=true"), "{text}");
    assert!(!text.contains("sha256-salted"), "{text}");
    let state = policy_state(&loaded()?);
    for key in ["honeytoken_paths", "security_sensors", "agent_paths"] {
        assert!(
            state
                .get(key)
                .is_some_and(|value| value.contains("changed=") && !value.contains("sha256")),
            "{key}"
        );
    }
    Ok(())
}
