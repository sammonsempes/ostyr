use super::{
    alerts_stub, store_alerts_session, FAILURE, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OK, STATUS_TOO_MANY, STATUS_UNAUTHORIZED, SUCCESS,
    USAGE_FAILURE,
};
use crate::support::{invoke, offline_args, Outcome, TestError, TestResult};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::error::Error;
use tempfile::tempdir;
use xdrctl::error::CliError;
use xdrctl::model::GrcBodyView;
use xdrctl::reports::{parse_reply, parse_report_id, shown, valid_framework, CUT_MARK, FRAMEWORK_MAX_BYTES, MAX_LIST_ROWS, MAX_SHOWN_CHARS};


const HOSTILE_ESCAPED: &str = "a\\u{1b}\\u{7}\\u{202e}";


const HOSTILE_JSON: &str = "a\\u001b\\u0007\\u202e\\u3164b";


const OVERSIZE: usize = 1_000_000;


const GRC_ITEM: &str = "{\"id\":7,\"framework\":\"iso\",\"version\":2,\"generated\":\"2026-11-01\",\"digest\":\"abc\",\"bytes\":10,\"stored_at\":0}";


const GRC_BODY: &str = "{\"tenant\":\"t\",\"framework\":\"iso\",\"version\":2,\"generated\":\"2026-11-01\",\
\"counts\":{\"compliant\":1,\"partially_compliant\":2,\"non_compliant\":3,\"not_assessable\":4},\"controls\":[{},{}],\"gaps\":[{}],\"plan\":[]}";


const ATTACK_ITEM: &str = "{\"id\":9,\"graph_digest\":\"g1\",\"generated\":\"2026-11-01T00:00:00Z\",\"digest\":\"d1\",\"bytes\":5,\
\"truncated\":true,\"budget_reached\":false,\"unsearched_count\":2,\"stored_at\":0}";


const ATTACK_BODY: &str = "{\"graph_digest\":\"g1\",\"truncated\":true,\"budget_reached\":false,\"unsearched\":[{}],\"paths\":[{},{}],\
\"choke_points\":[],\"recommendations\":[{}]}";


fn static_text(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}


fn run(words: &[&str], status: u16, body: &'static str) -> Result<(Outcome, Vec<String>), TestError> {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let outcome = invoke(&offline_args(dir.path(), words), "", &alerts_stub(&seen, status, body))?;
    let urls = seen.borrow().clone();
    Ok((outcome, urls))
}


#[test]
fn grc_list_and_show_text_json_and_paths() -> TestResult {
    let list = static_text(format!("{{\"items\":[{GRC_ITEM}]}}"));
    let (listed, urls) = run(&["grc", "list", "--framework", "iso-27001", "--limit", "5"], STATUS_OK, list)?;
    assert_eq!(listed.code, SUCCESS);
    assert!(listed.out.contains("7\tiso\t2\t2026-11-01\t10\t1970-01-01T00:00:00Z\tabc"));
    assert_eq!(urls, vec!["https://example.test/grc/reports?framework=iso-27001&limit=5 Some(\"tok\")"]);
    let (bare, urls_bare) = run(&["grc", "list"], STATUS_OK, list)?;
    assert_eq!(bare.code, SUCCESS);
    assert_eq!(urls_bare, vec!["https://example.test/grc/reports Some(\"tok\")"]);
    let (shown_body, urls_show) = run(&["grc", "show", "7"], STATUS_OK, GRC_BODY)?;
    assert!(shown_body.out.contains("id: 7\nframework: iso\nversion: 2\ngenerated: 2026-11-01\n"));
    assert!(shown_body
        .out
        .contains("compliant 1 partially compliant 2 non compliant 3 not assessable 4\ncontrols: 2\ngaps: 1\nplan items: 0"));
    assert_eq!(urls_show, vec!["https://example.test/grc/reports/7 Some(\"tok\")"]);
    let (json_out, _) = run(&["--output", "json", "grc", "show", "7"], STATUS_OK, GRC_BODY)?;
    let parsed: Value = serde_json::from_str(&json_out.out)?;
    assert_eq!(parsed.get("framework"), Some(&json!("iso")));
    Ok(())
}


#[test]
fn attack_paths_list_and_show_text_json_and_paths() -> TestResult {
    let list = static_text(format!("{{\"items\":[{ATTACK_ITEM}]}}"));
    let (listed, urls) = run(&["attack-paths", "list", "--limit", "3"], STATUS_OK, list)?;
    assert!(listed
        .out
        .contains("9\t2026-11-01T00:00:00Z\t5\ttrue\tfalse\t2\t1970-01-01T00:00:00Z\tg1\td1"));
    assert_eq!(urls, vec!["https://example.test/attack-paths/reports?limit=3 Some(\"tok\")"]);
    let (bare, urls_bare) = run(&["attack-paths", "list"], STATUS_OK, list)?;
    assert_eq!(bare.code, SUCCESS);
    assert_eq!(urls_bare, vec!["https://example.test/attack-paths/reports Some(\"tok\")"]);
    let (shown_body, urls_show) = run(&["attack-paths", "show", "9"], STATUS_OK, ATTACK_BODY)?;
    assert!(shown_body
        .out
        .contains("id: 9\ngraph digest: g1\ntruncated: true\nbudget reached: false\nunsearched entries: 1\npaths: 2\n"));
    assert!(shown_body.out.contains("choke points: 0\nrecommendations: 1"));
    assert_eq!(urls_show, vec!["https://example.test/attack-paths/reports/9 Some(\"tok\")"]);
    let (json_out, _) = run(&["--output", "json", "attack-paths", "show", "9"], STATUS_OK, ATTACK_BODY)?;
    assert!(json_out.out.contains("\"graph_digest\":\"g1\""));
    Ok(())
}


#[test]
fn hostile_text_is_escaped_and_bounded_in_both_outputs() -> TestResult {
    let long = "x".repeat(OVERSIZE);
    let grc_list = static_text(format!(
        "{{\"items\":[{{\"id\":1,\"framework\":\"{HOSTILE_JSON}{long}\",\"version\":1,\"generated\":\"g\",\"digest\":\"d\",\"bytes\":1,\"stored_at\":0}}]}}"
    ));
    let grc_body = static_text(format!(
        "{{\"framework\":\"{HOSTILE_JSON}{long}\",\"version\":1,\"generated\":\"g\",\"counts\":{{\"compliant\":0,\"partially_compliant\":0,\
         \"non_compliant\":0,\"not_assessable\":0}},\"controls\":[],\"gaps\":[],\"plan\":[]}}"
    ));
    let attack_list = static_text(format!(
        "{{\"items\":[{{\"id\":1,\"graph_digest\":\"{HOSTILE_JSON}{long}\",\"generated\":\"g\",\"digest\":\"d\",\"bytes\":1,\"truncated\":false,\
         \"budget_reached\":false,\"unsearched_count\":0,\"stored_at\":0}}]}}"
    ));
    let attack_body = static_text(format!(
        "{{\"graph_digest\":\"{HOSTILE_JSON}{long}\",\"truncated\":false,\"budget_reached\":false,\"unsearched\":[],\"paths\":[],\
         \"choke_points\":[],\"recommendations\":[]}}"
    ));
    let cases: [(&[&str], &'static str); FOUR] = [
        (&["grc", "list"], grc_list),
        (&["grc", "show", "1"], grc_body),
        (&["attack-paths", "list"], attack_list),
        (&["attack-paths", "show", "1"], attack_body),
    ];
    for (words, body) in cases {
        let (text, _) = run(words, STATUS_OK, body)?;
        assert!(!text.out.contains(['\u{1b}', '\u{7}', '\u{202e}']));
        assert!(text.out.contains(HOSTILE_ESCAPED));
        assert!(text.out.contains(CUT_MARK));
        assert!(text.out.len() < MAX_SHOWN_CHARS * TEN);
        let mut json_words = vec!["--output", "json"];
        json_words.extend(words.iter());
        let (json_out, _) = run(&json_words, STATUS_OK, body)?;
        assert!(!json_out.out.contains(['\u{1b}', '\u{7}', '\u{202e}']));
        assert!(json_out.out.contains("\\u001b"));
    }
    Ok(())
}


#[test]
fn rows_beyond_the_cap_are_announced() -> TestResult {
    let items = vec![GRC_ITEM; MAX_LIST_ROWS + TWO].join(",");
    let list = static_text(format!("{{\"items\":[{items}]}}"));
    let (listed, _) = run(&["grc", "list"], STATUS_OK, list)?;
    assert_eq!(listed.out.matches("\n7\tiso").count(), MAX_LIST_ROWS);
    assert!(listed.out.contains("TRUNCATED: showing 100 of 102 reports"));
    let items_attack = vec![ATTACK_ITEM; MAX_LIST_ROWS + 1].join(",");
    let attack = static_text(format!("{{\"items\":[{items_attack}]}}"));
    let (attack_listed, _) = run(&["attack-paths", "list"], STATUS_OK, attack)?;
    assert!(attack_listed.out.contains("TRUNCATED: showing 100 of 101 reports"));
    Ok(())
}


#[test]
fn bad_arguments_make_no_request() -> TestResult {
    let refused: [&[&str]; SEVEN] = [
        &["grc", "show", "1/../2"],
        &["grc", "show", "99999999999999999999"],
        &["grc", "show", "+1"],
        &["grc", "show", ""],
        &["attack-paths", "show", "1/../2"],
        &["attack-paths", "show", "x"],
        &["grc", "list", "--framework", "a&tenant=b"],
    ];
    for words in refused {
        let (outcome, urls) = run(words, STATUS_OK, "{}")?;
        assert_eq!(outcome.code, FAILURE);
        assert!(outcome.err.contains("invalid"));
        assert!(urls.is_empty());
    }
    let usage: [&[&str]; SIX] = [
        &["grc", "list", "--framework", "-x"],
        &["grc", "show", "-1"],
        &["grc", "list", "--limit", "0"],
        &["grc", "list", "--limit", "101"],
        &["attack-paths", "list", "--limit", "101"],
        &["attack-paths", "list", "--framework", "x"],
    ];
    for words in usage {
        let (outcome, urls) = run(words, STATUS_OK, "{}")?;
        assert_eq!(outcome.code, USAGE_FAILURE);
        assert!(urls.is_empty());
    }
    Ok(())
}


#[test]
fn grammar_helpers_match_the_server() -> TestResult {
    assert!(valid_framework("iso-27001.v2_x"));
    assert!(valid_framework(&"a".repeat(FRAMEWORK_MAX_BYTES)));
    assert!(!valid_framework(&"a".repeat(FRAMEWORK_MAX_BYTES + 1)));
    assert!(!valid_framework(""));
    assert!(!valid_framework("-a"));
    assert!(!valid_framework("a b"));
    assert_eq!(parse_report_id("9223372036854775807"), Some(i64::MAX));
    assert_eq!(parse_report_id("9223372036854775808"), None);
    assert_eq!(parse_report_id("-1"), None);
    assert_eq!(parse_report_id(""), None);
    assert_eq!(shown("plain"), "plain");
    Ok(())
}


#[test]
fn statuses_and_bad_replies_are_fixed() -> TestResult {
    let body = "{\"error\":{\"code\":\"c\",\"message\":\"MARKER\"}}";
    let commands: [&[&str]; FOUR] = [
        &["grc", "list"],
        &["grc", "show", "3"],
        &["attack-paths", "list"],
        &["attack-paths", "show", "3"],
    ];
    for (status, expected) in [
        (STATUS_UNAUTHORIZED, "not valid"),
        (STATUS_FORBIDDEN, "permission denied"),
        (STATUS_NOT_FOUND, "not found"),
        (STATUS_TOO_MANY, "too many"),
    ] {
        for words in commands {
            let (outcome, _) = run(words, status, body)?;
            assert!(outcome.err.contains(expected));
            assert!(!outcome.err.contains("MARKER"));
        }
    }
    for reply in ["[\"MARKER\"]", "not json MARKER", "{\"items\":\"MARKER\"}"] {
        for words in commands {
            let (outcome, _) = run(words, STATUS_OK, reply)?;
            assert!(outcome.err.contains("unexpected reply"));
            assert!(!outcome.err.contains("MARKER"));
        }
    }
    let value = json!({"framework": "MARKER"});
    let error = parse_reply::<GrcBodyView>(&value).err().ok_or("parsed")?;
    assert!(matches!(error, CliError::BadReply { .. }));
    assert!(!format!("{error} {error:?}").contains("MARKER"));
    assert!(error.source().is_none());
    Ok(())
}


const FOUR: usize = 4;


const SIX: usize = 6;


const SEVEN: usize = 7;


const TEN: usize = 10;


const TWO: usize = 2;
