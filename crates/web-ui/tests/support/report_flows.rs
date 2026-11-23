use super::{assert_hardened, assert_no_hidden_characters, set_mode};
use crate::harness::{fire, get, get_with, harness, location_of, sign_in, without_tokens, Harness, Req};
use crate::stub::{Mode, LEAK, ONCALL_MISSING_ID, REPORT_HOSTILE_TEXT};
use crate::types::{TestError, TestResult};
use axum::http::StatusCode;
use web_ui::api::{parse_report_id, valid_report_framework, MAX_REPORT_FRAMEWORK_CHARS};


fn report_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.report_paths.lock().map_err(|_| "poisoned")?.clone())
}


const HOSTILE_ESCAPED: &str = "&lt;script&gt;alert(1)&lt;/script&gt;&quot;&gt;&lt;img src=x onerror=alert(2)&gt;\u{fffd}[31m\u{fffd}\u{fffd}";


const FRAMEWORK_REFUSED_CALLS: usize = 0;


const ONE_CALL: usize = 1;


const TWO_CALLS: usize = 2;


const THREE_CALLS: usize = 3;


const ATTACK_DETAIL_CALLS: usize = 6;


const ATTACK_UNREADABLE_ROWS: usize = 2;


fn assert_hostile_text_is_inert(body: &str) {
    let page = without_tokens(body);
    assert!(page.contains(HOSTILE_ESCAPED), "{page}");
    assert!(page.contains("omitted]"), "{page}");
    for forbidden in ["<script", "<img", REPORT_HOSTILE_TEXT, "onerror=alert(2)>", "\u{3164}"] {
        assert!(!page.contains(forbidden), "{forbidden}");
    }
    assert_no_hidden_characters(body);
}


#[tokio::test]
async fn the_grc_list_shows_rows_the_filter_and_both_languages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/grc\"") && alerts.body.contains("action=\"/attack-paths\""));
    let list = fire(&rig, get_with("/grc?limit=5&tenant=b", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_hardened(&list);
    for expected in [
        "Compliance reports",
        "action=\"/grc/5\"",
        "action=\"/grc/4\"",
        "<td>iso27001</td>",
        "<td>cis-v8</td>",
        "<td>2026-03-01</td>",
        "<td>1234</td>",
        "<td>2026-02-25T",
        "name=\"framework\" value=\"\"",
    ] {
        assert!(list.body.contains(expected), "{expected}: {}", list.body);
    }
    let filtered = fire(&rig, get_with("/grc?framework=cis-v8", &session)).await?;
    assert_eq!(filtered.status, StatusCode::OK);
    assert!(filtered.body.contains("name=\"framework\" value=\"cis-v8\""));
    let empty_filter = fire(&rig, get_with("/grc?framework=", &session)).await?;
    assert_eq!(empty_filter.status, StatusCode::OK);
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/grc", &session)
    };
    let french = fire(&rig, french_request).await?;
    for expected in ["Rapports de conformité", "Référentiel", "Taille en octets"] {
        assert!(french.body.contains(expected), "{expected}");
    }
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/grc", &session)).await?;
    assert!(empty.body.contains("No stored report.") && !empty.body.contains("<table"));
    let anonymous = fire(&rig, get("/grc")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    let paths = report_requests(&rig)?;
    assert_eq!(
        paths,
        [
            "/grc/reports?limit=100",
            "/grc/reports?limit=100&framework=cis-v8",
            "/grc/reports?limit=100",
            "/grc/reports?limit=100",
            "/grc/reports?limit=100",
        ]
    );
    Ok(())
}


#[tokio::test]
async fn a_framework_outside_the_grammar_is_refused_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let long = "a".repeat(MAX_REPORT_FRAMEWORK_CHARS + 1);
    for path in [
        "/grc?framework=a%26tenant%3Db".to_owned(),
        "/grc?framework=-x".to_owned(),
        "/grc?framework=a%2Fb".to_owned(),
        "/grc?framework=%E2%84%AA".to_owned(),
        "/grc?framework=a%20b".to_owned(),
        format!("/grc?framework={long}"),
    ] {
        let reply = fire(&rig, get_with(&path, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
        assert_hardened(&reply);
    }
    assert_eq!(report_requests(&rig)?.len(), FRAMEWORK_REFUSED_CALLS);
    let longest = "a".repeat(MAX_REPORT_FRAMEWORK_CHARS);
    assert_eq!(
        fire(&rig, get_with(&format!("/grc?framework={longest}"), &session)).await?.status,
        StatusCode::OK
    );
    assert_eq!(report_requests(&rig)?.len(), ONE_CALL);
    Ok(())
}


#[test]
fn the_report_grammars_accept_only_the_apis_rules() -> TestResult {
    for good in ["a", "iso27001", "cis-v8.1_x", "9"] {
        assert!(valid_report_framework(good), "{good}");
    }
    for bad in ["", "-a", ".a", "_a", "a b", "a/b", "a&b", "\u{e9}", "a\u{3164}"] {
        assert!(!valid_report_framework(bad), "{bad:?}");
    }
    assert_eq!(parse_report_id("0"), Some(0));
    assert_eq!(parse_report_id("9223372036854775807"), Some(i64::MAX));
    for bad in ["", "-1", "+1", "1e3", "9223372036854775808", "a", "1 ", "\u{661}"] {
        assert!(parse_report_id(bad).is_none(), "{bad:?}");
    }
    Ok(())
}


#[tokio::test]
async fn a_hostile_grc_list_is_escaped_clipped_and_a_negative_id_is_unreadable() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/grc", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_hostile_text_is_inert(&list.body);
    assert_eq!(list.body.matches("Unreadable row.").count(), 1);
    assert!(!list.body.contains("negative") && list.body.contains("fine-one"));
    Ok(())
}


#[tokio::test]
async fn the_grc_report_shows_counts_never_the_body_and_refuses_a_bad_id_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let detail = fire(&rig, get_with("/grc/7", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_hardened(&detail);
    for expected in [
        "Compliance report 7",
        "<td>iso27001</td>",
        "<td>2026-03-01</td>",
        "<th>Compliant controls</th><td>11</td>",
        "<th>Partially compliant controls</th><td>12</td>",
        "<th>Non-compliant controls</th><td>13</td>",
        "<th>Controls not assessable</th><td>14</td>",
        "<th>Control rows</th><td>3</td>",
        "<th>Gaps</th><td>1</td>",
        "<th>Plan items</th><td>0</td>",
        "action=\"/grc\"",
    ] {
        assert!(detail.body.contains(expected), "{expected}: {}", detail.body);
    }
    assert!(!detail.body.contains("\"id\"") && !detail.body.contains("tenant"));
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/grc/007", &session)
    };
    assert!(fire(&rig, french_request).await?.body.contains("Rapport de conformité 7"));
    assert_eq!(report_requests(&rig)?, ["/grc/reports/7", "/grc/reports/7"]);
    for path in [
        "/grc/1%2F..%2F2",
        "/grc/-1",
        "/grc/99999999999999999999",
        "/grc/+1",
        "/grc/1e3",
        "/grc/a%20b",
        "/grc/%E0%A5%A7",
    ] {
        let reply = fire(&rig, get_with(path, &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert_hardened(&reply);
    }
    assert_eq!(report_requests(&rig)?.len(), TWO_CALLS);
    let missing = fire(&rig, get_with(&format!("/grc/{ONCALL_MISSING_ID}"), &session)).await?;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(!missing.body.contains(LEAK));
    set_mode(&rig, Mode::Hostile)?;
    let hostile = fire(&rig, get_with("/grc/7", &session)).await?;
    assert_eq!(hostile.status, StatusCode::OK);
    assert_hostile_text_is_inert(&hostile.body);
    Ok(())
}


#[tokio::test]
async fn the_attack_path_list_shows_rows_and_the_incomplete_columns() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/attack-paths?limit=5&tenant=b", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_hardened(&list);
    for expected in [
        "Attack path reports",
        "action=\"/attack-paths/5\"",
        "action=\"/attack-paths/4\"",
        "<td>2026-03-01T10:00:00Z</td>",
        "<td>777</td>",
        "<td>no</td>",
        "<td>yes</td>",
        "<td>3</td>",
    ] {
        assert!(list.body.contains(expected), "{expected}: {}", list.body);
    }
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/attack-paths", &session)
    };
    let french = fire(&rig, french_request).await?;
    for expected in ["Rapports de chemins d'attaque", "Chemins coupés", "Entrées non explorées"] {
        assert!(french.body.contains(expected), "{expected}");
    }
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/attack-paths", &session)).await?;
    assert!(empty.body.contains("No stored report.") && !empty.body.contains("<table"));
    let anonymous = fire(&rig, get("/attack-paths")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    let paths = report_requests(&rig)?;
    assert!(paths.iter().all(|path| path == "/attack-paths/reports?limit=100"), "{paths:?}");
    assert_eq!(paths.len(), THREE_CALLS);
    Ok(())
}


#[tokio::test]
async fn a_hostile_attack_path_list_is_unreadable_rows_never_printed() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/attack-paths", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    let page = without_tokens(&list.body);
    for forbidden in ["<script", "<img", "onerror", "\u{3164}", "zzzz"] {
        assert!(!page.contains(forbidden), "{forbidden}");
    }
    assert_no_hidden_characters(&list.body);
    assert_eq!(list.body.matches("Unreadable row.").count(), ATTACK_UNREADABLE_ROWS);
    assert!(list.body.contains("<td>2026-03-01T09:00:00Z</td>"));
    Ok(())
}


#[tokio::test]
async fn the_attack_path_report_shows_counts_and_names_an_incomplete_search() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let detail = fire(&rig, get_with("/attack-paths/7", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_hardened(&detail);
    for expected in [
        "Attack path report 7",
        "class=\"notice\">The search is incomplete",
        "<th>Graph digest</th><td>0123456789abcdef",
        "<th>Paths cut</th><td>yes</td>",
        "<th>Step budget reached</th><td>no</td>",
        "<th>Entries not searched</th><td>1</td>",
        "<th>Paths</th><td>2</td>",
        "<th>Choke points</th><td>1</td>",
        "<th>Recommendations</th><td>0</td>",
        "action=\"/attack-paths\"",
    ] {
        assert!(detail.body.contains(expected), "{expected}: {}", detail.body);
    }
    assert!(!detail.body.contains("path_cap") && !detail.body.contains("paths_through"));
    set_mode(&rig, Mode::BadId)?;
    let budget = fire(&rig, get_with("/attack-paths/7", &session)).await?;
    assert!(budget.body.contains("The search is incomplete") && budget.body.contains("<th>Step budget reached</th><td>yes</td>"));
    set_mode(&rig, Mode::StoredValue)?;
    let clean = fire(&rig, get_with("/attack-paths/7", &session)).await?;
    assert!(!clean.body.contains("The search is incomplete") && clean.body.contains("<th>Paths cut</th><td>no</td>"));
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/attack-paths/7", &session)
    };
    assert!(fire(&rig, french_request).await?.body.contains("Rapport de chemins d'attaque 7"));
    set_mode(&rig, Mode::Hostile)?;
    let hostile = fire(&rig, get_with("/attack-paths/7", &session)).await?;
    assert_eq!(hostile.status, StatusCode::OK);
    assert_hostile_text_is_inert(&hostile.body);
    assert!(hostile.body.contains("The search is incomplete") && hostile.body.contains("<th>Paths cut</th><td>no</td>"));
    for path in [
        "/attack-paths/1%2F..%2F2",
        "/attack-paths/-1",
        "/attack-paths/99999999999999999999",
        "/attack-paths/a%20b",
    ] {
        assert_eq!(fire(&rig, get_with(path, &session)).await?.status, StatusCode::NOT_FOUND, "{path}");
    }
    let missing = fire(&rig, get_with(&format!("/attack-paths/{ONCALL_MISSING_ID}"), &session)).await?;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(report_requests(&rig)?.len(), ATTACK_DETAIL_CALLS);
    Ok(())
}


#[tokio::test]
async fn report_api_failures_render_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for path in ["/grc", "/grc/7", "/attack-paths", "/attack-paths/7"] {
        for (mode, status) in [
            (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
            (Mode::Status(StatusCode::TOO_MANY_REQUESTS), StatusCode::TOO_MANY_REQUESTS),
            (Mode::Status(StatusCode::NOT_FOUND), StatusCode::NOT_FOUND),
            (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
            (Mode::Oversize, StatusCode::BAD_GATEWAY),
            (Mode::BadCursor, StatusCode::BAD_GATEWAY),
        ] {
            set_mode(&rig, mode)?;
            let reply = fire(&rig, get_with(path, &session)).await?;
            assert_eq!(reply.status, status, "{path}");
            assert!(!reply.body.contains(LEAK));
            assert_hardened(&reply);
        }
    }
    for path in ["/grc", "/attack-paths"] {
        set_mode(&rig, Mode::TooMany)?;
        assert_eq!(fire(&rig, get_with(path, &session)).await?.status, StatusCode::BAD_GATEWAY, "{path}");
    }
    for path in ["/grc", "/grc/7", "/attack-paths", "/attack-paths/7"] {
        set_mode(&rig, Mode::Normal)?;
        let second = sign_in(&rig).await?;
        set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
        let ended = fire(&rig, get_with(path, &second)).await?;
        assert_eq!(location_of(&ended).as_deref(), Some("/login"), "{path}");
        assert!(ended.headers.get("set-cookie").is_some());
    }
    Ok(())
}
