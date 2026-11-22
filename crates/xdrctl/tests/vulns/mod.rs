use super::{
    alerts_stub, store_alerts_session, ASSET_LONG, ASSET_REFUSED, FAILURE, LAST_PAGE, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OK, STATUS_TOO_MANY,
    STATUS_UNAUTHORIZED, SUCCESS, USAGE_FAILURE,
};
use crate::support::{invoke, offline_args, TestResult};
use serde_json::Value;
use std::cell::RefCell;
use tempfile::tempdir;


const VULN_PREFIX: &str = "https://example.test/vulnerabilities";


const VULN_CURSOR: &str = "7 host&limit=1 npm b%2F+?#/\\ ~c";


const VULN_CURSOR_ENCODED: &str = "7%20host%26limit%3D1%20npm%20b%252F%2B%3F%23%2F%5C%20~c";


const VULN_REFUSED_CURSORS: [&str; 10] = [
    "",
    "x",
    "5 a b c",
    "5 a b c d e",
    "05 a b c d",
    "5  a b c",
    "5 -a b c d",
    "5 a\u{202e} b c d",
    "5 \u{e9} b c d",
    "43949672950 a b c d",
];


const OVERLONG_FIELD: usize = 129;


const SEVEN: f64 = 7.0;


const HALF: f64 = 0.5;


const FOUR: usize = 4;


const SKIPPED_LIST: usize = 3;


const SKIPPED_SHOW: usize = 2;


const VULN_ITEM: &str = "{\"asset\":\"h1\",\"ecosystem\":\"npm\",\"package\":\"left-pad\",\"record_id\":\"CVE-1\",\"installed_version\":\"1.0\",\
\"fixed_version\":null,\"cvss\":9.8,\"epss\":0.12345,\"kev\":true,\"priority\":90,\"first_seen\":\"2026-11-01T00:00:00Z\",\
\"last_seen\":\"2026-11-02T00:00:00Z\"}";


const NO_MORE: &str = "\"next_cursor\":null";


const NOT_TRUNCATED: &str = "\"truncated\":false";


const TRUNCATED: &str = "\"truncated\":true";


fn vuln_body(items: &str, skipped: usize, tail: &str) -> &'static str {
    Box::leak(format!("{{\"items\":[{items}],\"skipped\":{skipped},{tail}}}").into_boxed_str())
}


#[test]
fn vulns_list_paths_and_cursor_round_trip() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let first = vuln_body(VULN_ITEM, 0, "\"next_cursor\":\"7 h&limit=1 npm b\\\\c d\"");
    let page = invoke(
        &offline_args(dir.path(), &["vulns", "list", "--limit", "2"]),
        "",
        &alerts_stub(&seen, STATUS_OK, first),
    )?;
    assert_eq!(page.code, SUCCESS);
    assert!(page
        .out
        .starts_with("asset\tecosystem\tpackage\trecord\tinstalled\tfixed\tcvss\tepss\tkev\tpriority\tfirst seen\tlast seen\n"));
    assert!(page.out.contains("h1\tnpm\tleft-pad\tCVE-1\t1.0\t-\t9.8\t0.1235\ttrue\t90\t"));
    let printed = page
        .out
        .lines()
        .last()
        .and_then(|line| line.strip_prefix("next cursor: "))
        .ok_or("no cursor line")?;
    assert_eq!(printed, "7%20h%26limit%3D1%20npm%20b%5Cc%20d");
    let again = invoke(
        &offline_args(dir.path(), &["vulns", "list", "--cursor", printed]),
        "",
        &alerts_stub(&seen, STATUS_OK, vuln_body("", 0, NO_MORE)),
    )?;
    assert!(again.out.ends_with("no more findings\n"));
    invoke(
        &offline_args(dir.path(), &["vulns", "list", "--limit", "5", "--cursor", VULN_CURSOR_ENCODED]),
        "",
        &alerts_stub(&seen, STATUS_OK, vuln_body("", 0, NO_MORE)),
    )?;
    assert_eq!(
        seen.borrow().clone(),
        vec![
            format!("{VULN_PREFIX}/findings?limit=2 Some(\"tok\")"),
            format!("{VULN_PREFIX}/findings?cursor=7%20h%26limit%3D1%20npm%20b%5Cc%20d Some(\"tok\")"),
            format!("{VULN_PREFIX}/findings?limit=5&cursor={VULN_CURSOR_ENCODED} Some(\"tok\")"),
        ]
    );
    assert_eq!(xdrctl::vulns::list_path(None, None)?, "/vulnerabilities/findings");
    Ok(())
}


#[test]
fn vulns_cursor_in_the_url_is_percent_encoded() -> TestResult {
    let path = xdrctl::vulns::list_path(None, Some(VULN_CURSOR))?;
    assert_eq!(path, format!("/vulnerabilities/findings?cursor={VULN_CURSOR_ENCODED}"));
    assert_eq!(path.matches('&').count(), 0);
    assert_eq!(path.matches('?').count(), 1);
    Ok(())
}


#[test]
fn vulns_bad_ids_cursors_and_limits_make_no_request() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let long = "a".repeat(ASSET_LONG);
    for id in ASSET_REFUSED.iter().copied().chain(std::iter::once(long.as_str())) {
        let outcome = invoke(
            &offline_args(dir.path(), &["vulns", "show", "--", id]),
            "",
            &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
        )?;
        assert_eq!(outcome.code, FAILURE);
        assert!(outcome.err.contains("invalid asset id"));
    }
    let overlong_field = format!("5 {} b c d", "a".repeat(OVERLONG_FIELD));
    for cursor in VULN_REFUSED_CURSORS.iter().copied().chain(std::iter::once(overlong_field.as_str())) {
        let outcome = invoke(
            &offline_args(dir.path(), &["vulns", "list", "--cursor", &xdrctl::vulns::cursor_text(cursor)]),
            "",
            &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
        )?;
        assert_eq!(outcome.code, FAILURE, "{cursor}");
        assert!(outcome.err.contains("invalid cursor"));
    }
    for limit in ["0", "501"] {
        let outcome = invoke(
            &offline_args(dir.path(), &["vulns", "list", "--limit", limit]),
            "",
            &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
        )?;
        assert_eq!(outcome.code, USAGE_FAILURE);
    }
    assert!(seen.borrow().is_empty());
    Ok(())
}


#[test]
fn vulns_show_ids_become_one_encoded_path_segment() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let body = vuln_body("", 0, NOT_TRUNCATED);
    ["a/b", "..", "x?y#z", "h1"].iter().try_for_each(|id| -> TestResult {
        let outcome = invoke(
            &offline_args(dir.path(), &["vulns", "show", "--", id]),
            "",
            &alerts_stub(&seen, STATUS_OK, body),
        )?;
        assert_eq!(outcome.code, SUCCESS);
        Ok(())
    })?;
    assert_eq!(
        seen.borrow().clone(),
        vec![
            format!("{VULN_PREFIX}/assets/a%2Fb Some(\"tok\")"),
            format!("{VULN_PREFIX}/assets/%2E%2E Some(\"tok\")"),
            format!("{VULN_PREFIX}/assets/x%3Fy%23z Some(\"tok\")"),
            format!("{VULN_PREFIX}/assets/h1 Some(\"tok\")"),
        ]
    );
    Ok(())
}


#[test]
fn vulns_gaps_are_named_lines() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let listed = invoke(
        &offline_args(dir.path(), &["vulns", "list"]),
        "",
        &alerts_stub(&seen, STATUS_OK, vuln_body("", SKIPPED_LIST, NO_MORE)),
    )?;
    assert!(listed.out.ends_with("skipped: 3 stored findings outside the grammar\nno more findings\n"));
    let cut = vuln_body(VULN_ITEM, SKIPPED_SHOW, TRUNCATED);
    let shown = invoke(
        &offline_args(dir.path(), &["vulns", "show", "h1"]),
        "",
        &alerts_stub(&seen, STATUS_OK, cut),
    )?;
    assert!(shown
        .out
        .ends_with("skipped: 2 stored findings outside the grammar\nTRUNCATED: the server cut this asset's findings\n"));
    let clean = invoke(
        &offline_args(dir.path(), &["vulns", "show", "h1"]),
        "",
        &alerts_stub(&seen, STATUS_OK, vuln_body(VULN_ITEM, 0, NOT_TRUNCATED)),
    )?;
    assert!(!clean.out.contains("skipped") && !clean.out.contains("TRUNCATED"));
    let json = invoke(
        &offline_args(dir.path(), &["--output", "json", "vulns", "show", "h1"]),
        "",
        &alerts_stub(&seen, STATUS_OK, cut),
    )?;
    assert_eq!(serde_json::from_str::<Value>(json.out.trim())?, serde_json::from_str::<Value>(cut)?);
    Ok(())
}


#[test]
fn vulns_numbers_have_a_fixed_precision_and_non_finite_is_a_dash() -> TestResult {
    assert_eq!(xdrctl::vulns::fixed(SEVEN, 1), "7.0");
    assert_eq!(xdrctl::vulns::fixed(HALF, FOUR), "0.5000");
    assert_eq!(xdrctl::vulns::fixed(f64::NAN, 1), "-");
    assert_eq!(xdrctl::vulns::fixed(f64::INFINITY, FOUR), "-");
    Ok(())
}


#[test]
fn vulns_hidden_characters_are_escaped_in_text_and_json() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let hostile: &'static str = Box::leak(
        VULN_ITEM
            .replace("left-pad", "p\\u001b[2J\\u202e\\u2066x\\\\u{202e}")
            .replace("CVE-1", "R\\u0007\\u05d0")
            .replace("\"h1\"", "\"h\\u001b\\u05d0\"")
            .into_boxed_str(),
    );
    let body = vuln_body(hostile, 0, "\"next_cursor\":\"5 a\\u001b b c d\"");
    let text = invoke(&offline_args(dir.path(), &["vulns", "list"]), "", &alerts_stub(&seen, STATUS_OK, body))?;
    assert!(text.out.contains("p\\u{1b}[2J\\u{202e}\\u{2066}x\\\\u{202e}"), "{}", text.out);
    assert!(text.out.contains("R\\u{7}\u{5d0}"));
    assert!(text.out.contains("h\\u{1b}\\u{5d0}\t"));
    assert!(text.out.contains("next cursor: 5%20a%1B%20b%20c%20d"));
    assert!(!text.out.contains('\u{1b}') && !text.out.contains('\u{202e}') && !text.out.contains('\u{7}'));
    let json = invoke(
        &offline_args(dir.path(), &["--output", "json", "vulns", "list"]),
        "",
        &alerts_stub(&seen, STATUS_OK, body),
    )?;
    assert!(json.out.contains("\\u001b") && !json.out.contains('\u{1b}') && !json.out.contains('\u{202e}'));
    assert_eq!(serde_json::from_str::<Value>(json.out.trim())?, serde_json::from_str::<Value>(body)?);
    Ok(())
}


#[test]
fn vulns_errors_are_the_fixed_messages() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let cases: [(u16, &str); FOUR] = [
        (STATUS_UNAUTHORIZED, "run `xdrctl login`"),
        (STATUS_FORBIDDEN, "permission denied"),
        (STATUS_NOT_FOUND, "not found"),
        (STATUS_TOO_MANY, "retry later"),
    ];
    for (status, expected) in cases {
        let body = "{\"error\":{\"code\":\"x\",\"message\":\"SECRET-V\"}}";
        for args in [&["vulns", "list"][..], &["vulns", "show", "h1"][..]] {
            let outcome = invoke(&offline_args(dir.path(), args), "", &alerts_stub(&seen, status, body))?;
            assert_eq!(outcome.code, FAILURE);
            assert!(outcome.err.contains(expected), "{}", outcome.err);
            assert!(!outcome.err.contains("SECRET"));
        }
    }
    let bad = invoke(
        &offline_args(dir.path(), &["vulns", "list"]),
        "",
        &alerts_stub(&seen, STATUS_OK, "{\"items\":1}"),
    )?;
    assert_eq!(bad.code, FAILURE);
    Ok(())
}


const SHELL_CURSORS: [&str; 4] = [
    "7 x';id;' `id`$(id) ${IFS} a|b&c;d",
    "7 a%b #c \\d \"q\"",
    "0 p p p p",
    "4294967295 ~ . _ a-",
];


const HALF_ESCAPE_CURSORS: [&str; 7] = ["7%20a", "7 a b c d", "7%27a", "7%2", "7%zz", "%", "7%20a%20b%20c%2"];


const MAX_PRINTED_BYTES: usize = 1578;


const MAX_FIELD: usize = 128;


#[test]
fn vulns_printed_cursor_is_shell_inert_and_round_trips() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    for cursor in SHELL_CURSORS {
        let escaped = cursor.replace('\\', "\\\\").replace('"', "\\\"");
        let body = vuln_body("", 0, &format!("\"next_cursor\":\"{escaped}\""));
        let page = invoke(&offline_args(dir.path(), &["vulns", "list"]), "", &alerts_stub(&seen, STATUS_OK, body))?;
        let printed = page
            .out
            .lines()
            .last()
            .and_then(|line| line.strip_prefix("next cursor: "))
            .ok_or("no cursor line")?;
        assert!(
            printed.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._~%-".contains(&byte)),
            "{printed}"
        );
        assert_eq!(xdrctl::vulns::decode_cursor(printed)?, cursor);
        invoke(
            &offline_args(dir.path(), &["vulns", "list", "--cursor", printed]),
            "",
            &alerts_stub(&seen, STATUS_OK, vuln_body("", 0, NO_MORE)),
        )?;
        let last = seen.borrow().last().cloned().ok_or("no request")?;
        let sent = last
            .strip_prefix(&format!("{VULN_PREFIX}/findings?cursor="))
            .ok_or("bad path")?
            .to_owned();
        assert_eq!(sent.matches('&').count() + sent.matches('?').count(), 0);
    }
    Ok(())
}


#[test]
fn vulns_cursor_outside_the_inert_alphabet_makes_no_request() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    for cursor in HALF_ESCAPE_CURSORS {
        let outcome = invoke(
            &offline_args(dir.path(), &["vulns", "list", &format!("--cursor={cursor}")]),
            "",
            &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
        )?;
        assert_eq!(outcome.code, FAILURE, "{cursor}");
        assert!(outcome.err.contains("invalid cursor"));
    }
    assert!(xdrctl::vulns::decode_cursor("%ff%fe").is_err());
    assert!(seen.borrow().is_empty());
    Ok(())
}


#[test]
fn vulns_longest_cursor_prints_within_the_stated_bound() -> TestResult {
    let field = "%".repeat(MAX_FIELD);
    let cursor = format!("4294967295 {field} {field} {field} {field}");
    assert!(xdrctl::vulns::valid_vuln_cursor(&cursor));
    let printed = xdrctl::vulns::cursor_text(&cursor);
    assert!(printed.len() <= MAX_PRINTED_BYTES);
    assert_eq!(xdrctl::vulns::decode_cursor(&printed)?, cursor);
    Ok(())
}
