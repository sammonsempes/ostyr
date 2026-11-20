use serde_json::{json, Map};
use types::TestResult;
use web_ui::model::{
    Alert, AlertPage, AssetAttributeView, AssetCountsView, AssetDetailView, AssetKeyView, AssetPageView, AssetSummaryView, CaseCountsView,
    CaseDetailView, CasePageView, CaseSummaryView, CertDetailView, CertListView, CertView, CommentView, Language, Severity, SightingView,
};
use web_ui::pages::{
    alert_page, alerts_page, asset_page, assets_page, case_page_with, cases_page, cert_page, certs_page, clip_dns, clip_identity, comment_notice,
    display_identity, display_value, optional, optional_identity,
};


#[path = "support/types.rs"]
mod types;


const LIMIT: usize = 64;


const SHORT_LIMIT: usize = 4;


const ID_LENGTH: usize = 64;


const NUMBER: u32 = 7;


const UNREADABLE: &str = "Unreadable asset.";


const MARK: char = '\u{fffd}';


const GENUINE: &str = "admin.corp";


const LOOK_ALIKES: [&str; 8] = [
    "admin.corp\u{13441}",
    "admin.corp\u{1D159}",
    "admin.corp ",
    "admin.corp\u{a0}",
    "\u{3000}admin.corp",
    "admin\u{2009}.corp",
    "admin\u{a0}.corp",
    " admin.corp",
];


fn alert_with(host: &str, user: &str, rule: &str, event: &str, name: &str, value: &str) -> Alert {
    let mut summary = Map::new();
    summary.insert(name.to_owned(), json!(value));
    Alert {
        id: "a".repeat(ID_LENGTH),
        rule_id: rule.to_owned(),
        rule_title: "title".to_owned(),
        severity: Severity::Low,
        event_time: "t".to_owned(),
        created: "c".to_owned(),
        host_name: Some(host.to_owned()),
        user_name: Some(user.to_owned()),
        event_ids: vec![event.to_owned()],
        summary,
        summary_truncated: false,
    }
}


fn alert_list(alert: Alert) -> String {
    alerts_page(
        Language::English,
        "t",
        &AlertPage {
            items: vec![alert],
            next_cursor: None,
        },
    )
    .into_string()
}


fn alert_pages(value: &str) -> Vec<String> {
    let other = "x";
    let language = Language::English;
    vec![
        alert_page(language, "t", &alert_with(value, other, other, other, other, other)).into_string(),
        alert_page(language, "t", &alert_with(other, value, other, other, other, other)).into_string(),
        alert_page(language, "t", &alert_with(other, other, value, other, other, other)).into_string(),
        alert_page(language, "t", &alert_with(other, other, other, value, other, other)).into_string(),
        alert_page(language, "t", &alert_with(other, other, other, other, value, other)).into_string(),
        alert_page(language, "t", &alert_with(other, other, other, other, other, value)).into_string(),
        alert_list(alert_with(value, other, other, other, other, other)),
        alert_list(alert_with(other, value, other, other, other, other)),
    ]
}


fn case_summary(assignee: &str, title: &str) -> CaseSummaryView {
    CaseSummaryView {
        id: "ok-1".to_owned(),
        title: title.to_owned(),
        severity: "low".to_owned(),
        status: "new".to_owned(),
        assignee: Some(assignee.to_owned()),
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


fn case_list(summary: CaseSummaryView) -> String {
    cases_page(
        Language::English,
        "t",
        &CasePageView {
            items: vec![summary],
            next_cursor: None,
        },
        None,
    )
    .into_string()
}


fn case_pages(value: &str) -> Vec<String> {
    let language = Language::English;
    let detail = CaseDetailView {
        summary: case_summary(value, "t"),
        description: None,
        resolution: None,
        template: None,
        tasks: Vec::new(),
    };
    let comment = CommentView {
        author: value.to_owned(),
        at: 0,
        text: "note".to_owned(),
    };
    vec![
        case_list(case_summary(value, "t")),
        case_page_with(language, "t", &detail, None).into_string(),
        comment_notice(language, &comment).into_string(),
    ]
}


fn asset_summary(kind: &str, lifecycle: &str) -> AssetSummaryView {
    AssetSummaryView {
        id: "web01".to_owned(),
        kind: kind.to_owned(),
        lifecycle: lifecycle.to_owned(),
        counts: AssetCountsView {
            keys: 0,
            attributes: 0,
            open_conflicts: 0,
        },
    }
}


fn asset_detail(kind: &str, lifecycle: &str, key: &str, name: &str, value: &str, source: &str) -> AssetDetailView {
    AssetDetailView {
        summary: asset_summary(kind, lifecycle),
        keys: vec![AssetKeyView {
            key: key.to_owned(),
            value: value.to_owned(),
        }],
        attributes: vec![AssetAttributeView {
            name: name.to_owned(),
            value: value.to_owned(),
            source: source.to_owned(),
        }],
        truncated: false,
    }
}


fn asset_list(summary: AssetSummaryView) -> String {
    assets_page(
        Language::English,
        "t",
        &AssetPageView {
            items: vec![summary],
            next_cursor: None,
        },
        None,
    )
    .into_string()
}


fn asset_pages(value: &str) -> Vec<String> {
    let other = "x";
    let language = Language::English;
    vec![
        asset_list(asset_summary(value, other)),
        asset_list(asset_summary(other, value)),
        asset_page(language, "t", &asset_detail(value, other, other, other, other, other)).into_string(),
        asset_page(language, "t", &asset_detail(other, value, other, other, other, other)).into_string(),
        asset_page(language, "t", &asset_detail(other, other, value, other, other, other)).into_string(),
        asset_page(language, "t", &asset_detail(other, other, other, value, other, other)).into_string(),
        asset_page(language, "t", &asset_detail(other, other, other, other, value, other)).into_string(),
        asset_page(language, "t", &asset_detail(other, other, other, other, other, value)).into_string(),
    ]
}


fn cert_with(subject: &str, issuer: &str, key_type: &str, dns: &str) -> CertView {
    CertView {
        fingerprint: "a".repeat(ID_LENGTH),
        subject: subject.to_owned(),
        issuer: issuer.to_owned(),
        dns_names: vec![dns.to_owned()],
        not_before: "b".to_owned(),
        not_after: "c".to_owned(),
        first_seen: "d".to_owned(),
        last_seen: "e".to_owned(),
        key_type: key_type.to_owned(),
        key_bits: None,
        self_signed: false,
        expiry: "ok".to_owned(),
    }
}


fn cert_detail(subject: &str, issuer: &str, key_type: &str, dns: &str, kind: &str, reference: &str) -> CertDetailView {
    CertDetailView {
        cert: cert_with(subject, issuer, key_type, dns),
        sightings: vec![SightingView {
            kind: kind.to_owned(),
            reference: reference.to_owned(),
            last_seen: "f".to_owned(),
        }],
        sightings_skipped: 0,
        sightings_truncated: false,
    }
}


fn cert_list(cert: CertView) -> String {
    certs_page(
        Language::English,
        "t",
        &CertListView {
            items: vec![cert],
            skipped: 0,
            next_cursor: None,
        },
        "all",
    )
    .into_string()
}


fn cert_pages(value: &str) -> Vec<String> {
    let other = "x";
    let language = Language::English;
    vec![
        cert_list(cert_with(value, other, other, other)),
        cert_list(cert_with(other, value, other, other)),
        cert_list(cert_with(other, other, value, other)),
        cert_page(language, "t", &cert_detail(value, other, other, other, other, other)).into_string(),
        cert_page(language, "t", &cert_detail(other, value, other, other, other, other)).into_string(),
        cert_page(language, "t", &cert_detail(other, other, value, other, other, other)).into_string(),
        cert_page(language, "t", &cert_detail(other, other, other, other, value, other)).into_string(),
        cert_page(language, "t", &cert_detail(other, other, other, other, other, value)).into_string(),
    ]
}


fn every_page(value: &str) -> Vec<String> {
    [alert_pages(value), case_pages(value), asset_pages(value), cert_pages(value)].concat()
}


fn assert_all_differ(genuine: &str, forged: &str) {
    let left = every_page(genuine);
    let right = every_page(forged);
    assert_eq!(left.len(), right.len());
    left.iter().zip(right.iter()).enumerate().for_each(|(position, (real, fake))| {
        assert!(!real.contains(MARK), "page {position} marks the genuine {genuine:?}");
        assert!(
            fake.contains(MARK) || fake.contains(UNREADABLE),
            "page {position} renders {forged:?} like {genuine:?}"
        );
    });
}


#[test]
fn every_look_alike_renders_differently_in_every_identity_field() -> TestResult {
    LOOK_ALIKES.iter().for_each(|forged| assert_all_differ(GENUINE, forged));
    Ok(())
}


#[test]
fn a_run_of_spaces_renders_differently_from_one_space() -> TestResult {
    assert_all_differ("admin corp", "admin  corp");
    assert_all_differ("admin corp", "admin   corp");
    Ok(())
}


#[test]
fn clip_identity_keeps_a_lone_inner_space_and_marks_the_rest() -> TestResult {
    let cases = [
        ("admin corp", "admin corp"),
        ("admin  corp", "admin\u{fffd}\u{fffd}corp"),
        ("admin\u{2009}corp", "admin\u{fffd}corp"),
        (" admin", "\u{fffd}admin"),
        ("admin ", "admin\u{fffd}"),
        ("\u{a0}", "\u{fffd}"),
        (" ", "\u{fffd}"),
        ("", ""),
        ("a\u{3164}b", "a\u{fffd}b"),
        ("a b c", "a b c"),
        ("a \u{3164}", "a \u{fffd}"),
    ];
    cases
        .iter()
        .for_each(|(input, shown)| assert_eq!(clip_identity(Language::English, input, LIMIT), *shown, "{input:?}"));
    assert_eq!(
        clip_identity(Language::English, "\u{3000}\u{3000}\u{3000}abc", SHORT_LIMIT),
        "\u{fffd}\u{fffd}\u{fffd}a... [2 omitted]"
    );
    Ok(())
}


#[test]
fn a_dns_name_is_ascii_or_marked() -> TestResult {
    assert_eq!(clip_dns(Language::English, "\u{430}dmin.corp", LIMIT), "\u{fffd}dmin.corp");
    assert_ne!(
        clip_dns(Language::English, "\u{430}dmin.corp", LIMIT),
        clip_dns(Language::English, "admin.corp", LIMIT)
    );
    assert_eq!(clip_dns(Language::English, "xn--e1awd7f.example", LIMIT), "xn--e1awd7f.example");
    assert_eq!(clip_dns(Language::English, "caf\u{e9}.corp", LIMIT), "caf\u{fffd}.corp");
    let genuine = cert_list(cert_with("s", "i", "k", "admin.corp"));
    let cyrillic = cert_list(cert_with("s", "i", "k", "\u{430}dmin.corp"));
    assert_ne!(genuine, cyrillic);
    assert!(cyrillic.contains("\u{fffd}dmin.corp"));
    let detail = cert_page(Language::English, "t", &cert_detail("s", "i", "k", "\u{430}dmin.corp", "k", "r")).into_string();
    assert!(detail.contains("\u{fffd}dmin.corp"));
    Ok(())
}


#[test]
fn optional_and_display_identity_mark_what_the_free_text_forms_keep() -> TestResult {
    let value = "a\u{a0}b".to_owned();
    assert_eq!(optional_identity(Language::English, Some(&value)), "a\u{fffd}b");
    assert_eq!(optional(Language::English, Some(&value)), "a\u{a0}b");
    assert_eq!(optional_identity(Language::English, None), optional(Language::English, None));
    assert_eq!(display_identity(Language::English, &json!("a\u{a0}b")), "a\u{fffd}b");
    assert_eq!(display_value(Language::English, &json!("a\u{a0}b")), "a\u{a0}b");
    assert_eq!(display_identity(Language::English, &json!(NUMBER)), "7");
    Ok(())
}


#[test]
fn free_text_keeps_a_no_break_space_before_a_colon() -> TestResult {
    let language = Language::English;
    let detail = CaseDetailView {
        summary: case_summary("alice", "Note\u{a0}: texte"),
        description: Some("Note\u{a0}: texte".to_owned()),
        resolution: None,
        template: None,
        tasks: Vec::new(),
    };
    let page = case_page_with(language, "t", &detail, None).into_string();
    assert!(page.contains("Note\u{a0}: texte"));
    assert!(!page.contains("Note\u{fffd}"));
    assert!(case_list(case_summary("alice", "Note\u{a0}: texte")).contains("Note\u{a0}: texte"));
    Ok(())
}
