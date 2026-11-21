#[path = "common/types.rs"]
mod types;


use compliance::alerting::{is_grammar, is_id, ASSET_PUNCTUATION, ID_PUNCTUATION, MAX_ASSET_CHARS, MAX_ID_CHARS};
use compliance::store::MIGRATIONS;
use core_pg::migrate::digest_of;
use regex::Regex;
use types::TestResult;


const THIRD_MIGRATION: usize = 2;


const PUBLISHED_THIRD_DIGEST: &str = "ce724e63f46673883868f7d32d6535132f198062e8ad74c559e04a175d8f1dba";


const ID_CHECKS: usize = 4;


const ASSET_CHECKS: usize = 2;


const OCTET_CHECKS: usize = 6;


fn pattern(max: usize, punctuation: &str) -> String {
    let (dash, others): (Vec<char>, Vec<char>) = punctuation.chars().partition(|found| *found == '-');
    let class: String = others.iter().chain(dash.iter()).collect();
    format!("^[0-9A-Za-z][0-9A-Za-z{class}]{{0,{}}}$", max - 1)
}


fn third() -> Result<&'static str, Box<dyn std::error::Error>> {
    Ok(MIGRATIONS.get(THIRD_MIGRATION).ok_or("no third migration")?.sql)
}


#[test]
fn the_third_migration_carries_the_write_grammar_and_its_indexes() -> TestResult {
    let sql = third()?;
    assert_eq!(
        MIGRATIONS.get(THIRD_MIGRATION).map(|migration| migration.version),
        Some("compliance_0003")
    );
    let id = pattern(MAX_ID_CHARS, ID_PUNCTUATION);
    let asset = pattern(MAX_ASSET_CHARS, ASSET_PUNCTUATION);
    assert_eq!(sql.matches(&format!("'{id}'")).count(), ID_CHECKS, "{id}");
    assert_eq!(sql.matches(&format!("'{asset}'")).count(), ASSET_CHECKS, "{asset}");
    for needle in [
        "DELETE FROM compliance_state",
        "UPDATE compliance_state_count",
        "ADD CONSTRAINT compliance_state_keys CHECK",
        "CREATE INDEX compliance_state_verdict ON compliance_state (tenant, verdict, baseline, control, asset)",
        "CREATE INDEX compliance_state_asset ON compliance_state (tenant, asset, baseline, control)",
    ] {
        assert!(sql.contains(needle), "{needle}");
    }
    assert_eq!(sql.matches("octet_length").count(), OCTET_CHECKS);
    Ok(())
}


#[test]
fn the_pattern_accepts_what_the_write_grammar_accepts() -> TestResult {
    let id = Regex::new(&pattern(MAX_ID_CHARS, ID_PUNCTUATION))?;
    let asset = Regex::new(&pattern(MAX_ASSET_CHARS, ASSET_PUNCTUATION))?;
    let long_id = "a".repeat(MAX_ID_CHARS + 1);
    let full_id = "a".repeat(MAX_ID_CHARS);
    let long_asset = "a".repeat(MAX_ASSET_CHARS + 1);
    let samples = [
        "base",
        "a.b_c-1",
        "-x",
        "",
        "h\u{212a}",
        "h\u{e9}",
        "a b",
        "host/a:b@c~1^2+3",
        "^a",
        "a\n",
        long_id.as_str(),
        long_asset.as_str(),
        full_id.as_str(),
    ];
    for sample in samples {
        assert_eq!(id.is_match(sample), is_id(sample), "{sample:?}");
        assert_eq!(
            asset.is_match(sample),
            is_grammar(sample, MAX_ASSET_CHARS, ASSET_PUNCTUATION),
            "{sample:?}"
        );
    }
    Ok(())
}


#[test]
fn the_published_third_migration_is_never_edited() -> TestResult {
    assert_eq!(digest_of(third()?), PUBLISHED_THIRD_DIGEST);
    Ok(())
}


const PINNED_SEARCH_PATH: &str = "SET search_path = pg_catalog, public, pg_temp;";


const FUNCTION_PREFIX: &str = "ALTER FUNCTION compliance_record(text, jsonb, bigint, bigint, bigint, bigint, bigint) ";


#[test]
fn every_live_function_ends_its_search_path_with_pg_temp() -> TestResult {
    let all: String = MIGRATIONS.iter().map(|migration| migration.sql).collect();
    let live = all.matches("CREATE FUNCTION").count() - all.matches("DROP FUNCTION").count();
    let fixed: Vec<&str> = all.lines().filter(|line| line.starts_with("ALTER FUNCTION ")).collect();
    assert_eq!(fixed.len(), live);
    assert!(live > 0);
    for line in fixed {
        assert!(line.starts_with(FUNCTION_PREFIX), "{line}");
        assert!(line.ends_with(PINNED_SEARCH_PATH), "{line}");
    }
    Ok(())
}
