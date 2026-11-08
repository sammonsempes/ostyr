#[path = "common/types.rs"]
mod types;


use compliance::evaluate::{evaluate, MAX_OFFENDING_ROWS};
use compliance::model::{Control, Exception, Expectation, Scope, Severity, Target, Verdict};
use compliance::types::Row;
use time::OffsetDateTime;
use types::TestResult;


const EXPIRY: i64 = 1_800_000_000;


const EXTRA: usize = 1;


fn control(expect: Expectation) -> Control {
    Control {
        id: "c1".to_string(),
        query: "SELECT 1".to_string(),
        expect,
        severity: Severity::High,
        frameworks: Vec::new(),
        correction: None,
    }
}


fn row(column: &str, value: &str) -> Row {
    Row::from([(column.to_string(), value.to_string())])
}


fn target() -> Target {
    Target {
        device: "web1".to_string(),
        tags: vec!["lab".to_string()],
    }
}


fn at(timestamp: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(timestamp)
}


fn exception(scope: Scope, expires: OffsetDateTime) -> Exception {
    Exception {
        control: "c1".to_string(),
        scope,
        owner: "alice".to_string(),
        reason: "legacy".to_string(),
        expires,
    }
}


fn run(expect: Expectation, rows: &[Row]) -> Result<Verdict, time::error::ComponentRange> {
    Ok(evaluate(&control(expect), &[], &target(), at(0)?, Ok(rows)))
}


fn equals(value: &str) -> Expectation {
    Expectation::ColumnEquals {
        column: "v".to_string(),
        value: value.to_string(),
    }
}


fn matches_pattern(pattern: &str) -> Expectation {
    Expectation::ColumnMatches {
        column: "v".to_string(),
        pattern: pattern.to_string(),
    }
}


#[test]
fn row_count_passes_and_fails() -> TestResult {
    assert_eq!(run(Expectation::RowCount(0), &[])?, Verdict::Pass);
    let rows = [row("u", "mallory")];
    assert_eq!(
        run(Expectation::RowCount(0), &rows)?,
        Verdict::Fail {
            offending: rows.to_vec(),
            total: 1
        }
    );
    Ok(())
}


#[test]
fn offending_rows_are_bounded() -> TestResult {
    let rows: Vec<Row> = (0..MAX_OFFENDING_ROWS + EXTRA).map(|index| row("u", &index.to_string())).collect();
    let verdict = run(Expectation::RowCount(0), &rows)?;
    let (offending, total) = match verdict {
        Verdict::Fail { offending, total } => Ok((offending, total)),
        other => Err(format!("expected fail, got {other:?}")),
    }?;
    assert_eq!(offending.len(), MAX_OFFENDING_ROWS);
    assert_eq!(total, MAX_OFFENDING_ROWS + EXTRA);
    Ok(())
}


#[test]
fn column_equals_every_row() -> TestResult {
    assert_eq!(run(equals("no"), &[row("v", "no"), row("v", "no")])?, Verdict::Pass);
    let bad = row("v", "yes");
    assert_eq!(
        run(equals("no"), &[row("v", "no"), bad.clone()])?,
        Verdict::Fail {
            offending: vec![bad],
            total: 1
        }
    );
    Ok(())
}


#[test]
fn column_expectation_on_no_rows_fails() -> TestResult {
    let empty = Verdict::Fail {
        offending: Vec::new(),
        total: 0,
    };
    assert_eq!(run(equals("no"), &[])?, empty);
    assert_eq!(run(matches_pattern("x"), &[])?, empty);
    Ok(())
}


#[test]
fn column_matches_uses_the_pattern() -> TestResult {
    assert_eq!(run(matches_pattern("^Auth"), &[row("v", "Authorized use only")])?, Verdict::Pass);
    let bad = row("v", "welcome");
    assert_eq!(
        run(matches_pattern("^Auth"), std::slice::from_ref(&bad))?,
        Verdict::Fail {
            offending: vec![bad],
            total: 1
        }
    );
    Ok(())
}


#[test]
fn unreadable_result_is_error_never_pass() -> TestResult {
    let missing_column = run(equals("no"), &[row("other", "no")])?;
    assert!(matches!(missing_column, Verdict::Error { .. }), "{missing_column:?}");
    let bad_pattern = run(matches_pattern("("), &[row("v", "x")])?;
    assert!(
        matches!(bad_pattern, Verdict::Error { ref reason } if reason.contains("invalid pattern")),
        "{bad_pattern:?}"
    );
    Ok(())
}


#[test]
fn failed_query_is_error() -> TestResult {
    let verdict = evaluate(&control(Expectation::RowCount(0)), &[], &target(), at(0)?, Err("no such table"));
    assert_eq!(
        verdict,
        Verdict::Error {
            reason: "no such table".to_string()
        }
    );
    Ok(())
}


#[test]
fn exception_applies_by_device_and_tag() -> TestResult {
    let expires = at(EXPIRY)?;
    let rows = [row("u", "mallory")];
    let by_device = [exception(Scope::Device("web1".to_string()), expires)];
    let by_tag = [exception(Scope::Tag("lab".to_string()), expires)];
    let excepted = Verdict::Excepted {
        owner: "alice".to_string(),
        reason: "legacy".to_string(),
    };
    let now = at(0)?;
    let check = |exceptions: &[Exception]| evaluate(&control(Expectation::RowCount(0)), exceptions, &target(), now, Ok(&rows));
    assert_eq!(check(&by_device), excepted);
    assert_eq!(check(&by_tag), excepted);
    Ok(())
}


#[test]
fn exception_does_not_apply_to_other_scope_or_control() -> TestResult {
    let expires = at(EXPIRY)?;
    let rows = [row("u", "mallory")];
    let mut other_control = exception(Scope::Device("web1".to_string()), expires);
    other_control.control = "c2".to_string();
    let exceptions = [
        exception(Scope::Device("web2".to_string()), expires),
        exception(Scope::Tag("prod".to_string()), expires),
        other_control,
    ];
    let verdict = evaluate(&control(Expectation::RowCount(0)), &exceptions, &target(), at(0)?, Ok(&rows));
    assert!(matches!(verdict, Verdict::Fail { total: 1, .. }), "{verdict:?}");
    Ok(())
}


#[test]
fn exception_expires_at_the_boundary() -> TestResult {
    let expires = at(EXPIRY)?;
    let exceptions = [exception(Scope::Device("web1".to_string()), expires)];
    let rows = [row("u", "mallory")];
    let verdict_at = |now: OffsetDateTime| evaluate(&control(Expectation::RowCount(0)), &exceptions, &target(), now, Ok(&rows));
    assert!(matches!(verdict_at(at(EXPIRY - 1)?), Verdict::Excepted { .. }));
    assert!(matches!(verdict_at(expires), Verdict::Fail { .. }));
    assert!(matches!(verdict_at(at(EXPIRY + 1)?), Verdict::Fail { .. }));
    Ok(())
}


#[test]
fn exception_covers_a_failed_query() -> TestResult {
    let exceptions = [exception(Scope::Device("web1".to_string()), at(EXPIRY)?)];
    let verdict = evaluate(&control(Expectation::RowCount(0)), &exceptions, &target(), at(0)?, Err("boom"));
    assert!(matches!(verdict, Verdict::Excepted { .. }));
    Ok(())
}
