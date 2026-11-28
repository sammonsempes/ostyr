#[path = "support/types.rs"]
mod types;


use attack_paths::settings::MAX_TENANTS;
use attack_paths::store::MIGRATIONS;
use attack_paths::tags::{TRAILER_BYTES, TRAILER_PREFIX};
use core_pg::migrate::{MIGRATION_CLIENT_MARGIN, MIGRATION_DEADLINE};
use core_pg::query::{CLIENT_DEADLINE_MARGIN, QUERY_WINDOWS};
use std::fs;
use types::TestResult;


const FIXED_QUERIES: usize = 3;


fn readme() -> Result<String, std::io::Error> {
    fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
}


#[test]
fn the_documented_round_bound_is_built_from_the_code_constants() -> TestResult {
    let margin = CLIENT_DEADLINE_MARGIN.as_secs();
    let bound = format!("tenants (at most {MAX_TENANTS}) x ({QUERY_WINDOWS} x deadline_seconds + {margin}) + connect_timeout_secs");
    let text = readme()?;
    assert!(text.contains(&bound), "README lacks: {bound}");
    Ok(())
}


#[test]
fn the_documented_start_bound_is_built_from_the_code_constants() -> TestResult {
    let margin = CLIENT_DEADLINE_MARGIN.as_secs();
    let migrations = MIGRATIONS.len();
    let queries = FIXED_QUERIES + migrations + 1;
    let scripts = 1 + migrations * (migrations + 1);
    let deadline = MIGRATION_DEADLINE.as_secs();
    let script_margin = MIGRATION_CLIENT_MARGIN.as_secs();
    let bound = format!(
        "connect_timeout_secs + {queries} x ({QUERY_WINDOWS} x statement_timeout_secs + {margin}) + {scripts} x ({deadline} + {script_margin})"
    );
    let text = readme()?;
    assert!(text.contains(&bound), "README lacks: {bound}");
    Ok(())
}


#[test]
fn the_readme_tells_the_deployer_what_to_set_and_what_stays_unbounded() -> TestResult {
    let text = readme()?;
    assert!(text.contains("TimeoutStopSec=<bound + compute time + 30>"));
    assert!(text.contains("have no deadline of their own"));
    assert!(text.contains("A SIGKILL from the supervisor"));
    Ok(())
}


#[test]
fn the_readme_documents_the_seal_command_and_the_trailer() -> TestResult {
    let text = readme()?;
    assert!(text.contains(&format!("`{TRAILER_PREFIX}`")));
    assert!(text.contains(&format!("({TRAILER_BYTES} bytes)")));
    [
        "ostyr-attack-paths seal-tags [--reseal]",
        "check the body, then run seal-tags --reseal",
        "`.tmp*` name",
        "-text",
        "CR line endings: write the file with LF",
        "not authentication",
        "a file holding only the trailer (82 bytes) means no manual tags",
    ]
    .iter()
    .try_for_each(|phrase| -> TestResult {
        assert!(text.to_lowercase().contains(&phrase.to_lowercase()), "README lacks: {phrase}");
        Ok(())
    })
}
