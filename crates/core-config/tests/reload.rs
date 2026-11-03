mod common;
#[path = "common/reload.rs"]
mod support;


use common::fixture;
use common::types::TestResult;
use core_audit::error::AuditError;
use core_audit::model::Outcome;
use core_config::model::ModuleConfig;
use core_config::reload::{current_config, layered_loader, module_state, open_engine, reload, ReloadOutcome, Subscriber};
use core_config::types::SharedAuditFn;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use support::{context, engine_for, entries, module_text, recording_audit, replace_file, retention};
use tempfile::tempdir;


const READS_PER_THREAD: usize = 20_000;


const READER_THREADS: usize = 4;


const SWAPS: usize = 200;


const PARITY: usize = 2;


fn failing_audit() -> Box<SharedAuditFn> {
    Box::new(|_entry| Err(AuditError::LogPoisoned))
}


fn refusing_subscriber(applied: Arc<AtomicUsize>) -> Subscriber<ModuleConfig> {
    Subscriber {
        section: "settings.retention".to_owned(),
        validate: Box::new(|config| match config.settings.get("retention").map(String::as_str) {
            Some("1d") => Err("retention too short".into()),
            _ => Ok(()),
        }),
        apply: Box::new(move |_config| {
            applied.fetch_add(1, Ordering::SeqCst);
        }),
    }
}


#[test]
fn valid_change_is_applied_and_audited_with_the_diff() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, recorded) = recording_audit();
    let engine = engine_for(&path, audit, Vec::new())?;
    replace_file(&path, &module_text("90d"))?;
    let outcome = reload(&engine);
    assert_eq!(
        outcome,
        ReloadOutcome::Applied {
            keys: vec!["settings.retention".to_owned()]
        }
    );
    assert_eq!(retention(&engine).as_deref(), Some("90d"));
    let written = entries(&recorded)?;
    let entry = written.first().ok_or("no audit entry")?;
    assert_eq!(written.len(), 1);
    assert_eq!(entry.action, "config.reload");
    assert_eq!(entry.outcome, Outcome::Success);
    assert_eq!(entry.parameters.get("result").map(String::as_str), Some("applied"));
    let diff = entry.parameters.get("diff").ok_or("no diff")?;
    assert!(diff.contains("-30d") && diff.contains("+90d"), "{diff}");
    assert!(!diff.contains("vault://"), "unchanged secret reference must not appear: {diff}");
    Ok(())
}


#[test]
fn invalid_files_keep_the_old_value_and_audit_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, recorded) = recording_audit();
    let engine = engine_for(&path, audit, Vec::new())?;
    let broken = [
        "name: [\n".to_owned(),
        format!("{}extra: 1\n", module_text("90d")),
        "name: siem\nversion: 1\nsecrets:\n  db: hunter2\n".to_owned(),
    ];
    let reasons = broken
        .iter()
        .map(|text| {
            replace_file(&path, text)?;
            match reload(&engine) {
                ReloadOutcome::Refused { reason } => Ok(reason),
                other => Err(format!("expected a refusal, got {other:?}").into()),
            }
        })
        .collect::<Result<Vec<String>, Box<dyn std::error::Error>>>()?;
    assert_eq!(retention(&engine).as_deref(), Some("30d"));
    assert!(reasons.iter().all(|reason| reason.contains("module.yaml:")), "{reasons:?}");
    assert!(reasons.iter().all(|reason| !reason.contains("hunter2")), "{reasons:?}");
    assert!(reasons.iter().any(|reason| reason.contains("secrets.db")), "{reasons:?}");
    let written = entries(&recorded)?;
    assert_eq!(written.len(), broken.len());
    assert!(written.iter().all(|entry| entry.outcome == Outcome::Denied));
    assert!(written
        .iter()
        .all(|entry| entry.parameters.get("result").map(String::as_str) == Some("refused")));
    assert!(written
        .iter()
        .zip(&reasons)
        .all(|(entry, reason)| entry.parameters.get("reason") == Some(reason)));
    Ok(())
}


#[test]
fn subscriber_refusal_swaps_nothing_and_is_audited() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, recorded) = recording_audit();
    let applied = Arc::new(AtomicUsize::new(0));
    let engine = engine_for(&path, audit, vec![refusing_subscriber(Arc::clone(&applied))])?;
    replace_file(&path, &module_text("1d"))?;
    let outcome = reload(&engine);
    assert!(matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("settings.retention") && reason.contains("too short")));
    assert_eq!(retention(&engine).as_deref(), Some("30d"));
    assert_eq!(applied.load(Ordering::SeqCst), 0);
    let written = entries(&recorded)?;
    assert_eq!(written.len(), 1);
    assert_eq!(written.first().ok_or("no entry")?.outcome, Outcome::Denied);
    replace_file(&path, &module_text("60d"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(applied.load(Ordering::SeqCst), 1);
    assert_eq!(retention(&engine).as_deref(), Some("60d"));
    Ok(())
}


#[test]
fn reload_without_change_audits_nothing() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, recorded) = recording_audit();
    let engine = engine_for(&path, audit, Vec::new())?;
    let before = current_config(&engine);
    replace_file(&path, &format!("# same\n{}", module_text("30d")))?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    assert!(Arc::ptr_eq(&before, &current_config(&engine)));
    assert!(entries(&recorded)?.is_empty());
    Ok(())
}


#[test]
fn failing_audit_refuses_the_reload_and_keeps_the_old_value() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let engine = engine_for(&path, failing_audit(), Vec::new())?;
    replace_file(&path, &module_text("90d"))?;
    let outcome = reload(&engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("cannot audit")),
        "{outcome:?}"
    );
    assert_eq!(retention(&engine).as_deref(), Some("30d"));
    Ok(())
}


#[test]
fn readers_never_see_a_partial_configuration() -> TestResult {
    let counter = Arc::new(AtomicUsize::new(0));
    let loader_counter = Arc::clone(&counter);
    let loader = Box::new(move || {
        let tag = if loader_counter.fetch_add(1, Ordering::SeqCst).is_multiple_of(PARITY) {
            "even"
        } else {
            "odd"
        };
        Ok(ModuleConfig {
            name: tag.to_owned(),
            version: tag.to_owned(),
            tenant: None,
            listen: Some(tag.to_owned()),
            secrets: Default::default(),
            settings: [("retention".to_owned(), tag.to_owned())].into(),
        })
    });
    let (audit, _recorded) = recording_audit();
    let engine = Arc::new(open_engine(loader, module_state, Vec::new(), audit, context())?);
    let readers: Vec<_> = (0..READER_THREADS)
        .map(|_| {
            let shared = Arc::clone(&engine);
            thread::spawn(move || {
                (0..READS_PER_THREAD)
                    .filter(|_| {
                        let seen = current_config(&shared);
                        let tag = seen.name.as_str();
                        seen.version != tag || seen.listen.as_deref() != Some(tag) || seen.settings.get("retention").map(String::as_str) != Some(tag)
                    })
                    .count()
            })
        })
        .collect();
    (0..SWAPS).for_each(|_| {
        reload(&engine);
    });
    let torn: usize = readers
        .into_iter()
        .map(|reader| reader.join().map_err(|_| "reader panicked"))
        .collect::<Result<Vec<usize>, _>>()?
        .into_iter()
        .sum();
    assert_eq!(torn, 0);
    Ok(())
}


#[test]
fn layered_loader_feeds_the_engine_and_a_bad_start_is_an_error() -> TestResult {
    let (audit, _recorded) = recording_audit();
    let engine = open_engine(
        layered_loader(fixture("base/module.yaml"), fixture("tenant/module.yaml")),
        module_state,
        Vec::new(),
        audit,
        context(),
    )?;
    assert!(module_state(&current_config(&engine)).contains_key("name"));
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    let dir = tempdir()?;
    let missing = dir.path().join("absent.yaml");
    let (second_audit, _second) = recording_audit();
    assert!(engine_for(&missing, second_audit, Vec::new()).is_err());
    let path = dir.path().join("module.yaml");
    fs::write(&path, "name: [\n")?;
    let (third_audit, _third) = recording_audit();
    assert!(engine_for(&path, third_audit, Vec::new()).is_err());
    Ok(())
}


#[test]
fn state_lists_every_present_field() -> TestResult {
    let config = ModuleConfig {
        name: "siem".to_owned(),
        version: "1".to_owned(),
        tenant: Some("acme".to_owned()),
        listen: None,
        secrets: [("db".to_owned(), core_config::secret::SecretRef("vault://x".to_owned()))].into(),
        settings: [("region".to_owned(), "eu".to_owned())].into(),
    };
    let state = module_state(&config);
    let keys: Vec<&str> = state.keys().map(String::as_str).collect();
    assert_eq!(keys, ["name", "secrets.db", "settings.region", "tenant", "version"]);
    assert_eq!(state.get("secrets.db").map(String::as_str), Some("vault://x"));
    Ok(())
}
