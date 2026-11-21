use super::{assert_hardened, assert_no_hidden_characters, set_mode, HUGE_CURSOR_CHARS, THREE_CALLS, TWO_VALID_CALLS};
use crate::harness::{fire, get, get_with, harness, location_of, sign_in, without_tokens, Harness, Req};
use crate::stub::{Mode, LEAK};
use crate::types::{TestError, TestResult};
use axum::http::StatusCode;
use web_ui::api::MAX_VULN_FIELD_BYTES;


pub fn vuln_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.vuln_paths.lock().map_err(|_| "poisoned")?.clone())
}


const VULN_LIST_UNREADABLE_ROWS: usize = 9;


const VULN_DETAIL_UNREADABLE_ROWS: usize = 10;


const VULN_MAX_PRIORITY: &str = "4294967295";


#[tokio::test]
async fn the_vulnerability_list_shows_rows_badges_notices_and_the_next_page() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/vulnerabilities\""));
    let list = fire(&rig, get_with("/vulnerabilities", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_hardened(&list);
    for expected in [
        "Vulnerabilities",
        "lodash",
        "CVE-2021-23337",
        "<td>4.17.21</td>",
        "<td>-</td>",
        "<td>7.5</td>",
        "<td>0.250</td>",
        "<strong class=\"badge\">KEV</strong>",
        "<td>900</td>",
        "<td>2026-03-01T09:00:00Z</td>",
        "action=\"/vulnerabilities/host-1\"",
        "action=\"/vulnerabilities/a%2Fb%2Bc\"",
        "1 row could not be read.",
        "name=\"cursor\" value=\"900 host-1 npm lodash CVE-1\"",
        "Next findings",
    ] {
        assert!(list.body.contains(expected), "{expected}: {}", list.body);
    }
    assert_eq!(list.body.matches("class=\"badge\"").count(), 1);
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/vulnerabilities", &session)
    };
    let french = fire(&rig, french_request).await?;
    for expected in [
        "Vulnérabilités",
        "Corrigée en",
        "Vulnérabilités suivantes",
        "1 ligne n'a pas pu être lue.",
    ] {
        assert!(french.body.contains(expected), "{expected}");
    }
    let walked = "/vulnerabilities?cursor=900%20host-1%20npm%20lodash%20CVE-1&limit=500&tenant=b";
    assert_eq!(fire(&rig, get_with(walked, &session)).await?.status, StatusCode::OK);
    assert_eq!(
        vuln_requests(&rig)?,
        [
            "/vulnerabilities/findings?limit=100".to_owned(),
            "/vulnerabilities/findings?limit=100".to_owned(),
            "/vulnerabilities/findings?limit=100&cursor=900+host-1+npm+lodash+CVE-1".to_owned(),
        ]
    );
    let anonymous = fire(&rig, get("/vulnerabilities")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/vulnerabilities", &session)).await?;
    assert!(empty.body.contains("No open finding.") && !empty.body.contains("could not be read") && !empty.body.contains("Next findings"));
    set_mode(&rig, Mode::BadId)?;
    let none_readable = fire(&rig, get_with("/vulnerabilities", &session)).await?;
    assert!(none_readable.body.contains("No readable finding on this page.") && none_readable.body.contains("1 row could not be read."));
    assert!(none_readable.body.contains("Next findings"));
    set_mode(&rig, Mode::BadSeverity)?;
    let many = fire(&rig, get_with("/vulnerabilities", &session)).await?;
    assert!(many.body.contains("3 rows could not be read."));
    Ok(())
}


#[tokio::test]
async fn a_hostile_vulnerability_row_is_an_unreadable_row_and_never_printed_raw() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/vulnerabilities", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_no_hidden_characters(&list.body);
    let list_page = without_tokens(&list.body);
    for forbidden in ["evil", "\u{3164}", "not a time", "-x", "NaN", "<script>x"] {
        assert!(!list_page.contains(forbidden), "{forbidden}");
    }
    assert!(list.body.contains("&lt;script&gt;x&lt;/script&gt;"));
    assert_eq!(list.body.matches("Unreadable row.").count(), VULN_LIST_UNREADABLE_ROWS);
    assert!(list.body.contains("fine") && list.body.contains("foreign") && list.body.contains("1 row could not be read."));
    let detail = fire(&rig, get_with("/vulnerabilities/web01", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_no_hidden_characters(&detail.body);
    let detail_page = without_tokens(&detail.body);
    for forbidden in ["evil", "\u{3164}", "not a time", "foreign", "other-asset", "NaN"] {
        assert!(!detail_page.contains(forbidden), "{forbidden}");
    }
    assert_eq!(detail.body.matches("Unreadable row.").count(), VULN_DETAIL_UNREADABLE_ROWS);
    assert!(detail.body.contains("fine") && detail.body.contains("Results cut at 1000.") && detail.body.contains("1 row could not be read."));
    Ok(())
}


#[tokio::test]
async fn the_vulnerability_detail_shows_the_asset_rows_the_notices_and_both_languages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let detail = fire(&rig, get_with("/vulnerabilities/a%2Fb%2Bc", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_hardened(&detail);
    for expected in [
        "Vulnerabilities of a/b+c",
        "lodash",
        "2 rows could not be read.",
        "Results cut at 1000.",
        "action=\"/vulnerabilities\"",
    ] {
        assert!(detail.body.contains(expected), "{expected}: {}", detail.body);
    }
    assert!(!detail.body.contains("<th>Asset</th>"));
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/vulnerabilities/host-1", &session)
    };
    let french = fire(&rig, french_request).await?;
    assert!(french.body.contains("Vulnérabilités de host-1") && french.body.contains("Résultats coupés à 1000."));
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/vulnerabilities/host-1", &session)).await?;
    assert!(empty.body.contains("No open finding.") && !empty.body.contains("Results cut"));
    set_mode(&rig, Mode::BadId)?;
    let none_readable = fire(&rig, get_with("/vulnerabilities/host-1", &session)).await?;
    assert!(none_readable.body.contains("No readable finding on this page.") && none_readable.body.contains("1 row could not be read."));
    assert_eq!(
        vuln_requests(&rig)?,
        [
            "/vulnerabilities/assets/a%2Fb%2Bc".to_owned(),
            "/vulnerabilities/assets/host-1".to_owned(),
            "/vulnerabilities/assets/host-1".to_owned(),
            "/vulnerabilities/assets/host-1".to_owned(),
        ]
    );
    Ok(())
}


#[tokio::test]
async fn a_malformed_vulnerability_cursor_or_asset_is_refused_before_any_api_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let long_cursor = format!("/vulnerabilities?cursor={}", "a".repeat(HUGE_CURSOR_CHARS));
    let long_asset = format!("/vulnerabilities/{}", "a".repeat(MAX_VULN_FIELD_BYTES + 1));
    let overflow = format!("/vulnerabilities?cursor={VULN_MAX_PRIORITY}0%20a%20b%20c%20d");
    for query in [
        "/vulnerabilities?cursor=",
        "/vulnerabilities?cursor=zz",
        "/vulnerabilities?cursor=900%20a%20b%20c",
        "/vulnerabilities?cursor=900%20a%20b%20c%20d%20e",
        "/vulnerabilities?cursor=-1%20a%20b%20c%20d",
        "/vulnerabilities?cursor=0900%20a%20b%20c%20d",
        "/vulnerabilities?cursor=900%20-x%20b%20c%20d",
        "/vulnerabilities?cursor=900%20a%20b%20c%20d%00",
        "/vulnerabilities?cursor=900%20a%E3%85%A4%20b%20c%20d",
        "/vulnerabilities?cursor=900%20a%20b%20c%20d%1b",
        long_cursor.as_str(),
        overflow.as_str(),
    ] {
        let reply = fire(&rig, get_with(query, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", query.len());
    }
    for path in [
        "/vulnerabilities/-x",
        "/vulnerabilities/a%00b",
        "/vulnerabilities/a%20b",
        "/vulnerabilities/%2e%2e",
        "/vulnerabilities/%2e",
        "/vulnerabilities/a%0Ab",
        "/vulnerabilities/%E2%80%AEx",
        "/vulnerabilities/a%E3%85%A4",
        long_asset.as_str(),
    ] {
        let reply = fire(&rig, get_with(path, &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert!(vuln_requests(&rig)?.is_empty());
    let longest = "a".repeat(MAX_VULN_FIELD_BYTES);
    let longest_cursor = format!("/vulnerabilities?cursor={VULN_MAX_PRIORITY}%20{longest}%20{longest}%20{longest}%20{longest}");
    assert_eq!(fire(&rig, get_with(&longest_cursor, &session)).await?.status, StatusCode::OK);
    let longest_asset = format!("/vulnerabilities/{longest}");
    assert_eq!(fire(&rig, get_with(&longest_asset, &session)).await?.status, StatusCode::OK);
    assert_eq!(vuln_requests(&rig)?.len(), TWO_VALID_CALLS);
    let other = fire(&rig, get_with("/vulnerabilities/elsewhere", &session)).await?;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
    assert!(!other.body.contains(LEAK));
    assert_eq!(vuln_requests(&rig)?.len(), THREE_CALLS);
    Ok(())
}


#[tokio::test]
async fn vulnerability_api_failures_render_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for path in ["/vulnerabilities", "/vulnerabilities/host-1"] {
        for (mode, status) in [
            (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
            (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
            (Mode::Oversize, StatusCode::BAD_GATEWAY),
            (Mode::TooMany, StatusCode::BAD_GATEWAY),
        ] {
            set_mode(&rig, mode)?;
            let reply = fire(&rig, get_with(path, &session)).await?;
            assert_eq!(reply.status, status, "{path}");
            assert!(!reply.body.contains(LEAK));
            assert_hardened(&reply);
        }
    }
    set_mode(&rig, Mode::BadCursor)?;
    assert_eq!(fire(&rig, get_with("/vulnerabilities", &session)).await?.status, StatusCode::BAD_GATEWAY);
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/vulnerabilities", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Normal)?;
    let second = sign_in(&rig).await?;
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended_detail = fire(&rig, get_with("/vulnerabilities/host-1", &second)).await?;
    assert_eq!(location_of(&ended_detail).as_deref(), Some("/login"));
    Ok(())
}
