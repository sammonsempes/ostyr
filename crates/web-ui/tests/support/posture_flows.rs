use super::{assert_hardened, assert_no_hidden_characters, set_mode};
use crate::harness::{fire, get, get_with, harness, location_of, sign_in, without_tokens, Harness, Req};
use crate::stub::{posture_run, posture_view, posture_worst_items, Mode, LEAK, POSTURE_CURSOR, POSTURE_HOSTILE_BYTES};
use crate::types::{TestError, TestResult};
use axum::http::StatusCode;
use serde_json::json;
use web_ui::api::{
    MAX_BODY_BYTES, MAX_POSTURE_ACCOUNT_BYTES, MAX_POSTURE_RUN_ID_BYTES, POSTURE_HEADER_BYTES, POSTURE_LIMIT, POSTURE_WORST_FINDING_BYTES,
};
use web_ui::pages::MAX_FIELD_CHARS;


const PROBE: &str = "/posture/accounts/probe/findings?limit=1";


const FIRST_PAGE: &str = "/posture/accounts/acct/findings?limit=33";


const IDENTITY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";


const ACCEPTED_REQUESTS: usize = 2;


const OVERLONG_ACCOUNT_BYTES: usize = 2_048;


const OVERLONG_CURSOR_BYTES: usize = 600;


fn posture_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.posture_paths.lock().map_err(|_| "poisoned")?.clone())
}


fn set_conflict(rig: &Harness, code: Option<&str>) -> TestResult {
    *rig.stub.state.conflict.lock().map_err(|_| "poisoned")? = code.map(str::to_owned);
    Ok(())
}


#[tokio::test]
async fn the_posture_screen_shows_the_run_the_findings_and_the_next_page_in_both_languages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/posture\""));
    let form = fire(&rig, get_with("/posture", &session)).await?;
    assert_eq!(form.status, StatusCode::OK);
    assert_hardened(&form);
    assert!(form.body.contains("name=\"account\"") && !form.body.contains("<table>"));
    assert_eq!(posture_requests(&rig)?, [PROBE.to_owned()]);
    let page = fire(&rig, get_with("/posture/acct", &session)).await?;
    assert_eq!(page.status, StatusCode::OK);
    assert_hardened(&page);
    for expected in [
        "<td>check-1</td>",
        "<td>acct</td>",
        "<td>Critical</td>",
        "<td>Informational</td>",
        "<td>Fatal</td>",
        "<td>Fail</td>",
        "<td>Pass</td>",
        "<td>Manual</td>",
        "Title one",
        "Detail two",
        "(12 bytes cut)",
        "2026-02-25T06:13:20Z",
        "<dd>2026-02-25T06:13:20Z</dd>",
        "<dd>-</dd>",
        "2 findings on this page could not be shown.",
        "A refusal is pending",
        "action=\"/posture/acct\"",
        "name=\"cursor\" value=\"run1 1772000000000000 4 ",
    ] {
        assert!(page.body.contains(expected), "{expected}: {}", page.body);
    }
    let next = fire(
        &rig,
        get_with(&format!("/posture/acct?cursor={}", POSTURE_CURSOR.replace(' ', "%20")), &session),
    )
    .await?;
    assert_eq!(next.status, StatusCode::OK);
    let forged = fire(&rig, get_with("/posture/acct?limit=500&tenant=b", &session)).await?;
    assert_eq!(forged.status, StatusCode::OK);
    let by_form = fire(&rig, get_with("/posture?account=acct&limit=500&tenant=b&cursor=x", &session)).await?;
    assert_eq!(by_form.status, StatusCode::OK);
    let odd = fire(&rig, get_with("/posture/a%2Fb%23c", &session)).await?;
    assert!(odd.body.contains("action=\"/posture/a%2Fb%23c\""));
    assert_eq!(
        posture_requests(&rig)?,
        [
            PROBE.to_owned(),
            FIRST_PAGE.to_owned(),
            format!("/posture/accounts/acct/findings?limit=33&cursor={}", POSTURE_CURSOR.replace(' ', "+")),
            FIRST_PAGE.to_owned(),
            FIRST_PAGE.to_owned(),
            "/posture/accounts/a%2Fb%23c/findings?limit=33".to_owned(),
        ]
    );
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/posture/acct", &session)
    };
    let french = fire(&rig, french_request).await?;
    for expected in [
        "Posture cloud",
        "(12 octets coupés)",
        "Constats suivants",
        "2 constats de cette page n'ont pas pu être affichés.",
    ] {
        assert!(french.body.contains(expected), "{expected}");
    }
    let anonymous = fire(&rig, get("/posture/acct")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Chunked)?;
    let none = fire(&rig, get_with("/posture/acct", &session)).await?;
    assert!(none.body.contains("No posture run stored for this account.") && !none.body.contains("<table>") && !none.body.contains("Next findings"));
    set_mode(&rig, Mode::BadId)?;
    let unservable = fire(&rig, get_with("/posture/acct", &session)).await?;
    assert!(unservable.body.contains("No finding on this page.") && unservable.body.contains("2 findings on this page could not be shown."));
    assert!(!unservable.body.contains("<table>") && !unservable.body.contains("Next findings"));
    Ok(())
}


#[tokio::test]
async fn a_hostile_finding_is_clipped_never_printed_raw_and_its_cut_marker_stays_ours() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let page = fire(&rig, get_with("/posture/acct", &session)).await?;
    assert_eq!(page.status, StatusCode::OK);
    assert_no_hidden_characters(&page.body);
    let shown = without_tokens(&page.body);
    for forbidden in ["\u{3164}", "<script>", &"a".repeat(MAX_FIELD_CHARS + 1)] {
        assert!(!shown.contains(forbidden), "{forbidden}");
    }
    for expected in [
        "&lt;script&gt;",
        "\u{fffd}[31m",
        "forged \\[12 bytes cut]",
        &format!("... [{} omitted]", POSTURE_HOSTILE_BYTES - MAX_FIELD_CHARS),
        "<td>unknown</td>",
        "<span class=\"notice\">(12 bytes cut)</span>",
        "1 finding on this page could not be shown.",
        "<dd>2026-02-25T06:13:20Z</dd><dt>Refusal recorded</dt><dd>2026-02-25T06:13:20Z</dd>",
    ] {
        assert!(page.body.contains(expected), "{expected}");
    }
    assert!(!page.body.contains("A refusal is pending"));
    Ok(())
}


#[tokio::test]
async fn a_forged_account_or_cursor_is_our_400_before_any_api_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let long_account = format!("/posture/{}", "a".repeat(OVERLONG_ACCOUNT_BYTES));
    let long_cursor = format!("/posture/acct?cursor={}", "a".repeat(OVERLONG_CURSOR_BYTES));
    let bad_rank = format!("/posture/acct?cursor=run1%201%2004%20{IDENTITY}");
    let negative = format!("/posture/acct?cursor=run1%20-1%204%20{IDENTITY}");
    let short_hex = "/posture/acct?cursor=run1%201%204%20abc";
    let upper_hex = format!("/posture/acct?cursor=run1%201%204%20{}", IDENTITY.to_uppercase());
    let extra_field = format!("/posture/acct?cursor=run1%201%204%20{IDENTITY}%20x");
    let big_rank = format!("/posture/acct?cursor=run1%201%2099999%20{IDENTITY}");
    let bad_run = format!("/posture/acct?cursor=-x%201%204%20{IDENTITY}");
    for path in [
        "/posture/-x",
        "/posture/a%00",
        "/posture/%2E%2E",
        "/posture/%2E",
        "/posture/%2E%2E%2F",
        "/posture/%2E%2E%2Fx",
        "/posture/a%2F%2E%2E",
        "/posture?account=../",
        "/posture/%E3%85%A4",
        "/posture/a%20b",
        "/posture/a%5Cb",
        "/posture/%3Cscript%3E",
        "/posture?account=",
        "/posture?account=-x",
        "/posture?account=a%00",
        "/posture/acct?cursor=",
        "/posture/acct?cursor=bad",
        "/posture/acct?cursor=run1%201%204",
        short_hex,
        long_account.as_str(),
        long_cursor.as_str(),
        bad_rank.as_str(),
        negative.as_str(),
        upper_hex.as_str(),
        extra_field.as_str(),
        big_rank.as_str(),
        bad_run.as_str(),
    ] {
        let reply = fire(&rig, get_with(path, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", path.len());
        assert!(!reply.body.contains(LEAK));
    }
    assert!(posture_requests(&rig)?.is_empty());
    let longest_account = format!("/posture/{}", "a".repeat(MAX_POSTURE_ACCOUNT_BYTES));
    assert_eq!(fire(&rig, get_with(&longest_account, &session)).await?.status, StatusCode::OK);
    let accepted = format!("/posture/acct?cursor={}%201%204%20{IDENTITY}", "r".repeat(MAX_POSTURE_RUN_ID_BYTES));
    assert_eq!(fire(&rig, get_with(&accepted, &session)).await?.status, StatusCode::OK);
    assert_eq!(posture_requests(&rig)?.len(), ACCEPTED_REQUESTS);
    Ok(())
}


#[tokio::test]
async fn posture_api_failures_render_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (mode, status) in [
        (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
        (Mode::Status(StatusCode::TOO_MANY_REQUESTS), StatusCode::TOO_MANY_REQUESTS),
        (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
        (Mode::Status(StatusCode::CONFLICT), StatusCode::BAD_GATEWAY),
        (Mode::TooMany, StatusCode::BAD_GATEWAY),
        (Mode::BadCursor, StatusCode::BAD_GATEWAY),
        (Mode::BadSeverity, StatusCode::BAD_GATEWAY),
    ] {
        set_mode(&rig, mode)?;
        let reply = fire(&rig, get_with("/posture/acct", &session)).await?;
        assert_eq!(reply.status, status);
        assert!(!reply.body.contains(LEAK));
        assert_hardened(&reply);
    }
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/posture/acct", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn a_changed_run_shows_our_text_and_a_link_to_the_first_page() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    set_conflict(&rig, Some("run_changed"))?;
    let reply = fire(
        &rig,
        get_with(&format!("/posture/a%2Fb?cursor={}", POSTURE_CURSOR.replace(' ', "%20")), &session),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert!(reply.body.contains("The stored run changed: restart from the first page."));
    assert!(reply.body.contains("action=\"/posture/a%2Fb\"") && !reply.body.contains("name=\"cursor\"") && !reply.body.contains(LEAK));
    assert_hardened(&reply);
    set_conflict(&rig, Some("case_changed"))?;
    let other_key = fire(&rig, get_with("/posture/acct", &session)).await?;
    assert_eq!(other_key.status, StatusCode::CONFLICT);
    assert!(!other_key.body.contains("restart from the first page") && !other_key.body.contains(LEAK));
    set_conflict(&rig, Some("other"))?;
    assert_eq!(fire(&rig, get_with("/posture/acct", &session)).await?.status, StatusCode::BAD_GATEWAY);
    Ok(())
}


#[tokio::test]
async fn the_form_less_posture_page_shows_the_permission_page_when_the_api_refuses_the_probe() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    set_mode(&rig, Mode::Status(StatusCode::FORBIDDEN))?;
    let refused = fire(&rig, get_with("/posture", &session)).await?;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert!(refused.body.contains("You do not have the permission") && !refused.body.contains("name=\"account\"") && !refused.body.contains(LEAK));
    assert_eq!(posture_requests(&rig)?, [PROBE.to_owned()]);
    set_mode(&rig, Mode::Status(StatusCode::INTERNAL_SERVER_ERROR))?;
    assert_eq!(fire(&rig, get_with("/posture", &session)).await?.status, StatusCode::BAD_GATEWAY);
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/posture", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn a_page_of_worst_case_findings_fits_the_cap_and_keeps_its_next_link() -> TestResult {
    let rig = harness(Mode::PostureWorst).await?;
    let session = sign_in(&rig).await?;
    let body_bytes = serde_json::to_vec(&posture_view(posture_run(), posture_worst_items(POSTURE_LIMIT), 0, json!(POSTURE_CURSOR)))?.len();
    assert!(body_bytes <= MAX_BODY_BYTES, "{body_bytes}");
    let bytes_of = |count: usize| count * POSTURE_WORST_FINDING_BYTES + POSTURE_HEADER_BYTES;
    assert!(bytes_of(POSTURE_LIMIT) <= MAX_BODY_BYTES && bytes_of(POSTURE_LIMIT + 1) > MAX_BODY_BYTES);
    let page = fire(&rig, get_with("/posture/acct", &session)).await?;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("name=\"cursor\" value=\"run1 1772000000000000 4 "), "{}", page.body);
    Ok(())
}


#[tokio::test]
async fn a_page_over_the_body_cap_shows_its_own_text_and_a_link_to_the_first_page() -> TestResult {
    let rig = harness(Mode::Oversize).await?;
    let session = sign_in(&rig).await?;
    let reply = fire(&rig, get_with("/posture/a%2Fb", &session)).await?;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert!(reply.body.contains("This page of findings is too large to show."));
    assert!(reply.body.contains("action=\"/posture/a%2Fb\"") && !reply.body.contains("The service is not available"));
    assert_hardened(&reply);
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/posture/acct", &session)
    };
    let french = fire(&rig, french_request).await?;
    assert!(french.body.contains("Cette page de constats est trop volumineuse"));
    Ok(())
}
