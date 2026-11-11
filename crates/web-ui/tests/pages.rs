use serde_json::{json, Map};
use std::collections::BTreeSet;
use types::TestResult;
use web_ui::api::valid_case_id;
use web_ui::model::{Alert, AlertPage, CaseCountsView, CaseDetailView, CasePageView, CaseSummaryView, CaseTaskView, Language, Severity};
use web_ui::pages::{alert_page, alerts_page, case_page, cases_page, clip, display_value, error_page, format_time, login_page, optional};
use web_ui::strings::{
    case_severity_class, case_severity_key, language_tag, resolution_key, severity_class, severity_key, status_key, table, task_status_key, text,
    ENGLISH, FRENCH, MISSING_TEXT,
};


#[path = "support/types.rs"]
mod types;


const LANGUAGES: [Language; 2] = [Language::English, Language::French];


const SEVERITIES: [Severity; 4] = [Severity::Low, Severity::Medium, Severity::High, Severity::Critical];


const ERROR_KEYS: [&str; 7] = [
    "error_generic",
    "error_forbidden",
    "error_not_found",
    "error_csrf",
    "error_throttled",
    "error_bad_request",
    "error_unavailable",
];


const CLIP_LIMIT: usize = 5;


const ID_LENGTH: usize = 64;


const NUMBER: u32 = 3;


fn sample(severity: Severity, host: Option<&str>) -> Alert {
    Alert {
        id: "a".repeat(ID_LENGTH),
        rule_id: "r".to_owned(),
        rule_title: "title".to_owned(),
        severity,
        event_time: "t".to_owned(),
        created: "c".to_owned(),
        host_name: host.map(str::to_owned),
        user_name: None,
        event_ids: vec!["e".to_owned()],
        summary: Map::new(),
        summary_truncated: false,
    }
}


#[test]
fn both_language_tables_have_the_same_keys() -> TestResult {
    let english: BTreeSet<&str> = ENGLISH.iter().map(|(key, _)| *key).collect();
    let french: BTreeSet<&str> = FRENCH.iter().map(|(key, _)| *key).collect();
    assert_eq!(english, french);
    assert_eq!(english.len(), ENGLISH.len());
    assert!(ENGLISH.iter().chain(FRENCH.iter()).all(|(_, value)| !value.is_empty()));
    assert_eq!(table(Language::English).len(), table(Language::French).len());
    Ok(())
}


#[test]
fn text_lookup_and_tags() -> TestResult {
    assert_eq!(text(Language::French, "title_login"), "Connexion");
    assert_eq!(text(Language::English, "absent"), MISSING_TEXT);
    assert_eq!(language_tag(Language::French), "fr");
    assert_eq!(language_tag(Language::English), "en");
    Ok(())
}


#[test]
fn every_page_renders_in_both_languages_without_a_missing_text() -> TestResult {
    let page = AlertPage {
        items: SEVERITIES.iter().map(|severity| sample(*severity, Some("host"))).collect(),
        next_cursor: Some("c-_=".to_owned()),
    };
    let empty = AlertPage {
        items: vec![],
        next_cursor: None,
    };
    for language in LANGUAGES {
        let mut rendered = vec![
            login_page(language, "token", false),
            login_page(language, "token", true),
            alerts_page(language, "token", &page),
            alerts_page(language, "token", &empty),
            alert_page(language, "token", &sample(Severity::Low, None)),
            cases_page(language, "token", &case_page_view()),
            cases_page(
                language,
                "token",
                &CasePageView {
                    items: vec![],
                    next_cursor: None,
                },
            ),
            case_page(language, "token", &case_detail_view("critical", "closed", Some("duplicate"))),
            case_page(language, "token", &case_detail_view("x", "y", None)),
        ];
        rendered.extend(ERROR_KEYS.iter().map(|key| error_page(language, Some("token"), key)));
        rendered.extend(ERROR_KEYS.iter().map(|key| error_page(language, None, key)));
        for markup in rendered {
            assert!(!markup.0.contains(MISSING_TEXT), "{}", markup.0);
            assert!(markup.0.contains("<!DOCTYPE html>"));
        }
    }
    for severity in SEVERITIES {
        assert!(!severity_class(severity).is_empty());
        assert!(ENGLISH.iter().any(|(key, _)| *key == severity_key(severity)));
    }
    Ok(())
}


#[test]
fn the_pages_hold_no_script_and_no_inline_style() -> TestResult {
    let page = alerts_page(
        Language::English,
        "token",
        &AlertPage {
            items: vec![sample(Severity::High, None)],
            next_cursor: None,
        },
    );
    assert!(!page.0.contains("<script"));
    assert!(!page.0.contains("style="));
    assert!(!page.0.contains("<a "));
    Ok(())
}


#[test]
fn clip_drops_controls_and_marks_the_cut() -> TestResult {
    assert_eq!(clip(Language::English, "ab\ncd\u{202e}\u{2066}", CLIP_LIMIT), "abcd");
    assert_eq!(clip(Language::English, "abcdefgh", CLIP_LIMIT), "abcde... [3 omitted]");
    assert_eq!(clip(Language::French, "abcdefgh", CLIP_LIMIT), "abcde... [3 omis]");
    assert_eq!(optional(Language::English, None), "none");
    assert_eq!(optional(Language::French, Some(&"x".to_owned())), "x");
    Ok(())
}


#[test]
fn values_of_any_json_type_are_displayed() -> TestResult {
    assert_eq!(display_value(Language::English, &json!("text")), "text");
    assert_eq!(display_value(Language::English, &json!(NUMBER)), "3");
    assert_eq!(display_value(Language::English, &json!({"a": [1]})), "{\"a\":[1]}");
    Ok(())
}


const LONGEST_CASE_ID: usize = 128;


const BEFORE_YEAR_ZERO: i64 = -100_000_000_000;


fn case_summary(id: &str, severity: &str, status: &str) -> CaseSummaryView {
    CaseSummaryView {
        id: id.to_owned(),
        title: "t".to_owned(),
        severity: severity.to_owned(),
        status: status.to_owned(),
        assignee: None,
        case_type: None,
        created_at: 0,
        updated_at: 0,
        counts: CaseCountsView {
            tasks: 0,
            observables: 0,
            comments: 0,
            history: 0,
            alerts: 0,
        },
    }
}


fn case_page_view() -> CasePageView {
    CasePageView {
        items: vec![case_summary("ok-1", "low", "new"), case_summary("../x", "medium", "weird")],
        next_cursor: Some("c-_=".to_owned()),
    }
}


fn case_detail_view(severity: &str, status: &str, resolution: Option<&str>) -> CaseDetailView {
    CaseDetailView {
        summary: case_summary("ok-1", severity, status),
        description: resolution.map(str::to_owned),
        resolution: resolution.map(str::to_owned),
        template: None,
        tasks: vec![
            CaseTaskView {
                title: "a".to_owned(),
                status: "todo".to_owned(),
                due: None,
            },
            CaseTaskView {
                title: "b".to_owned(),
                status: "done".to_owned(),
                due: Some(0),
            },
        ],
    }
}


#[test]
fn case_ids_follow_the_link_grammar() -> TestResult {
    let longest = "a".repeat(LONGEST_CASE_ID);
    let too_long = "a".repeat(LONGEST_CASE_ID + 1);
    for good in ["a", "A1", "case-1", "a.b_c", longest.as_str()] {
        assert!(valid_case_id(good), "{good}");
    }
    for bad in ["", "-x", ".x", "_x", "a/b", "a b", "a\n", "é", "%2e", too_long.as_str()] {
        assert!(!valid_case_id(bad), "{bad}");
    }
    Ok(())
}


#[test]
fn times_are_utc_rfc3339_or_unknown() -> TestResult {
    assert_eq!(format_time(Language::English, 0), "1970-01-01T00:00:00Z");
    assert_eq!(format_time(Language::English, i64::MAX), "unknown");
    assert_eq!(format_time(Language::French, BEFORE_YEAR_ZERO), "inconnu");
    Ok(())
}


#[test]
fn case_enums_map_to_fixed_texts() -> TestResult {
    for (value, key) in [
        ("new", "status_new"),
        ("in_progress", "status_in_progress"),
        ("closed", "status_closed"),
        ("weird", "unknown"),
    ] {
        assert_eq!(status_key(value), key);
    }
    for (value, key) in [
        ("todo", "task_todo"),
        ("in_progress", "status_in_progress"),
        ("done", "task_done"),
        ("weird", "unknown"),
    ] {
        assert_eq!(task_status_key(value), key);
    }
    for (value, key) in [
        ("true_positive", "res_true_positive"),
        ("false_positive", "res_false_positive"),
        ("benign", "res_benign"),
        ("duplicate", "res_duplicate"),
        ("other", "res_other"),
        ("weird", "unknown"),
    ] {
        assert_eq!(resolution_key(value), key);
    }
    for (value, key, class) in [
        ("low", "sev_low", "sev-low"),
        ("medium", "sev_medium", "sev-medium"),
        ("high", "sev_high", "sev-high"),
        ("critical", "sev_critical", "sev-critical"),
        ("weird", "unknown", "sev-unknown"),
    ] {
        assert_eq!(case_severity_key(value), key);
        assert_eq!(case_severity_class(value), class);
    }
    Ok(())
}
