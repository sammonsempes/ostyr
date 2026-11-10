#[path = "common/types.rs"]
mod types;


use core_audit::log::open_file_log;
use core_audit::model::Outcome;
use core_config::reload::{reload_entry, ReloadContext, MAX_DIFF_CHARS};
use core_export::cli::audit_into;
use std::fs;
use tempfile::tempdir;
use types::TestResult;


const SECRET: &str = "s3cret-value";


const EXTRA_CHARS: usize = 10;


#[test]
fn audit_into_keeps_declared_keys_redacts_the_rest_and_marks_cuts() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("export.audit");
    let context = ReloadContext {
        actor_id: "a".to_string(),
        tenant: "acme".to_string(),
        module: "core-export".to_string(),
        target: "t".to_string(),
        request_id: "r".to_string(),
    };
    let long = "x".repeat(MAX_DIFF_CHARS + EXTRA_CHARS);
    let mut entry = reload_entry(&context, Outcome::Success, [("result", "ok".to_string()), ("diff", long)]);
    entry.parameters.insert("token".to_string(), SECRET.to_string());
    let record = audit_into(open_file_log(&file)?)(entry)?;
    assert_eq!(record.parameters.get("token").map(String::as_str), Some("[REDACTED]"));
    assert_eq!(record.parameters.get("result").map(String::as_str), Some("ok"));
    assert!(record
        .parameters
        .get("diff")
        .is_some_and(|diff| diff.contains("truncated, 10 characters omitted")));
    assert!(!fs::read_to_string(&file)?.contains(SECRET));
    Ok(())
}
