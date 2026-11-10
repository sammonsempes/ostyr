use serde_json::{json, Map};
use std::collections::BTreeSet;
use types::TestResult;
use web_ui::model::{Alert, AlertPage, Language, Severity};
use web_ui::pages::{alert_page, alerts_page, clip, display_value, error_page, login_page, optional};
use web_ui::strings::{language_tag, severity_class, severity_key, table, text, ENGLISH, FRENCH, MISSING_TEXT};


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
