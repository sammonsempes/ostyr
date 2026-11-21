use super::{assert_hardened, assert_no_hidden_characters, set_mode, HUGE_CURSOR_CHARS, THREE_CALLS, TWO_VALID_CALLS};
use crate::harness::{fire, get, get_with, harness, location_of, sign_in, without_tokens, Harness, Req};
use crate::stub::{Mode, LEAK, SHELL_HOSTILE_REQUESTER, SHELL_HOSTILE_TICKET};
use crate::types::{TestError, TestResult};
use axum::http::StatusCode;
use web_ui::api::{MAX_SHELL_CURSOR_BYTES, MAX_SHELL_REFERENCE_BYTES, MAX_SHELL_SUBJECT_BYTES};


fn shell_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.shell_paths.lock().map_err(|_| "poisoned")?.clone())
}


const SHELL_LIST_UNREADABLE_ROWS: usize = 17;


const WALKED: &str = "/remote-shell?cursor=1772000000.s-2&asset=host%2F1&requester=auth0%7Ca%2Bb%2Fc%3Dd&open=true&limit=500&tenant=b";


#[tokio::test]
async fn the_register_list_shows_rows_filters_notices_and_the_next_page_in_both_languages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/remote-shell\""));
    let list = fire(&rig, get_with("/remote-shell", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_hardened(&list);
    for expected in [
        "Remote shell sessions",
        "auth0|a+b/c=d",
        "<td>host/1</td>",
        "<td>T-1</td>",
        "action=\"/remote-shell/s-1\"",
        "<td>2026-03-01T09:00:00Z</td>",
        "<td>2026-03-01T11:00:00Z</td>",
        "<td>Closed by the user</td>",
        "<td>-</td>",
        "<td>Open</td>",
        "1 row could not be read.",
        "name=\"cursor\" value=\"1772000000.s-2\"",
        "Next sessions",
        "name=\"asset\"",
        "name=\"requester\"",
        "name=\"open\"",
    ] {
        assert!(list.body.contains(expected), "{expected}: {}", list.body);
    }
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/remote-shell", &session)
    };
    let french = fire(&rig, french_request).await?;
    for expected in [
        "Sessions de shell distant",
        "Fermée par l'utilisateur",
        "Ouverte",
        "Sessions suivantes",
        "1 ligne n'a pas pu être lue.",
    ] {
        assert!(french.body.contains(expected), "{expected}");
    }
    let walked = fire(&rig, get_with(WALKED, &session)).await?;
    assert_eq!(walked.status, StatusCode::OK);
    for expected in [
        "value=\"host/1\"",
        "value=\"auth0|a+b/c=d\"",
        "<option value=\"true\" selected>",
        "<input type=\"hidden\" name=\"asset\" value=\"host/1\">",
        "<input type=\"hidden\" name=\"open\" value=\"true\">",
    ] {
        assert!(walked.body.contains(expected), "{expected}: {}", walked.body);
    }
    let blanks = fire(&rig, get_with("/remote-shell?asset=&requester=&open=", &session)).await?;
    assert_eq!(blanks.status, StatusCode::OK);
    let every = fire(&rig, get_with("/remote-shell?open=false", &session)).await?;
    assert_eq!(every.status, StatusCode::OK);
    assert_eq!(
        shell_requests(&rig)?,
        [
            "/remote-shell/sessions?limit=100".to_owned(),
            "/remote-shell/sessions?limit=100".to_owned(),
            "/remote-shell/sessions?limit=100&asset=host%2F1&requester=auth0%7Ca%2Bb%2Fc%3Dd&open=true&cursor=1772000000.s-2".to_owned(),
            "/remote-shell/sessions?limit=100".to_owned(),
            "/remote-shell/sessions?limit=100&open=false".to_owned(),
        ]
    );
    let anonymous = fire(&rig, get("/remote-shell")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/remote-shell", &session)).await?;
    assert!(empty.body.contains("No session found.") && !empty.body.contains("could not be read") && !empty.body.contains("Next sessions"));
    set_mode(&rig, Mode::BadId)?;
    let none_readable = fire(&rig, get_with("/remote-shell", &session)).await?;
    assert!(none_readable.body.contains("No readable session on this page.") && none_readable.body.contains("1 row could not be read."));
    assert!(none_readable.body.contains("Next sessions"));
    set_mode(&rig, Mode::BadSeverity)?;
    let many = fire(&rig, get_with("/remote-shell", &session)).await?;
    assert!(many.body.contains("3 rows could not be read."));
    Ok(())
}


#[tokio::test]
async fn a_hostile_stored_row_is_an_unreadable_row_and_never_printed_raw() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/remote-shell", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_no_hidden_characters(&list.body);
    let page = without_tokens(&list.body);
    for forbidden in [
        SHELL_HOSTILE_REQUESTER,
        SHELL_HOSTILE_TICKET,
        "evil",
        "\u{3164}",
        "<script>",
        "not a time",
        "-x",
        "ABCDEF",
    ] {
        assert!(!page.contains(forbidden), "{forbidden}");
    }
    assert_eq!(list.body.matches("Unreadable row.").count(), SHELL_LIST_UNREADABLE_ROWS);
    assert!(list.body.contains("action=\"/remote-shell/fine\"") && list.body.contains("1 row could not be read."));
    let detail = fire(&rig, get_with("/remote-shell/s-1", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_no_hidden_characters(&detail.body);
    assert!(!without_tokens(&detail.body).contains("evil") && detail.body.contains("Unreadable row."));
    Ok(())
}


#[tokio::test]
async fn a_forged_filter_or_cursor_is_refused_before_any_api_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let long_cursor = format!("/remote-shell?cursor={}", "1".repeat(HUGE_CURSOR_CHARS));
    let long_asset = format!("/remote-shell?asset={}", "a".repeat(MAX_SHELL_REFERENCE_BYTES + 1));
    let long_requester = format!("/remote-shell?requester={}", "a".repeat(MAX_SHELL_SUBJECT_BYTES + 1));
    let long_id = format!("/remote-shell?cursor=1.{}", "a".repeat(MAX_SHELL_REFERENCE_BYTES + 1));
    let just_over = format!("/remote-shell?cursor={}.s", "1".repeat(MAX_SHELL_CURSOR_BYTES));
    for query in [
        "/remote-shell?requester=-x",
        "/remote-shell?requester=a%00b",
        "/remote-shell?requester=a%20b",
        "/remote-shell?requester=a%E3%85%A4",
        "/remote-shell?requester=a%1B",
        "/remote-shell?asset=-x",
        "/remote-shell?asset=a%00",
        "/remote-shell?asset=a%20b",
        "/remote-shell?asset=%E2%80%AEx",
        "/remote-shell?open=yes",
        "/remote-shell?open=TRUE",
        "/remote-shell?open=%20true",
        "/remote-shell?cursor=",
        "/remote-shell?cursor=zz",
        "/remote-shell?cursor=1772000000",
        "/remote-shell?cursor=1772000000.",
        "/remote-shell?cursor=01.s-1",
        "/remote-shell?cursor=%2B1.s-1",
        "/remote-shell?cursor=-0.s-1",
        "/remote-shell?cursor=9223372036854775808.s-1",
        "/remote-shell?cursor=1.-x",
        "/remote-shell?cursor=1.s%00",
        "/remote-shell?cursor=1.s%E3%85%A4",
        "/remote-shell?cursor=1.s%1B",
        long_cursor.as_str(),
        long_asset.as_str(),
        long_requester.as_str(),
        long_id.as_str(),
        just_over.as_str(),
    ] {
        let reply = fire(&rig, get_with(query, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", query.len());
        assert!(!reply.body.contains(LEAK));
    }
    assert!(shell_requests(&rig)?.is_empty());
    let longest = "a".repeat(MAX_SHELL_REFERENCE_BYTES);
    let longest_subject = "a".repeat(MAX_SHELL_SUBJECT_BYTES);
    let longest_query = format!("/remote-shell?asset={longest}&requester={longest_subject}&cursor=-1.{longest}");
    assert_eq!(fire(&rig, get_with(&longest_query, &session)).await?.status, StatusCode::OK);
    let min_cursor = "/remote-shell?cursor=-9223372036854775808.s";
    assert_eq!(fire(&rig, get_with(min_cursor, &session)).await?.status, StatusCode::OK);
    assert_eq!(shell_requests(&rig)?.len(), TWO_VALID_CALLS);
    Ok(())
}


#[tokio::test]
async fn the_register_detail_shows_the_session_in_both_languages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let detail = fire(&rig, get_with("/remote-shell/a%2Fb%3Ac", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_hardened(&detail);
    for expected in [
        "Remote shell session",
        "<td>a/b:c</td>",
        "<td>auth0|a+b/c=d</td>",
        "<td>2026-03-01T11:00:00Z</td>",
        "<td>Closed by the user</td>",
        "<td>12</td>",
        "<td>4096</td>",
        "<td>0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</td>",
        "action=\"/remote-shell\"",
    ] {
        assert!(detail.body.contains(expected), "{expected}: {}", detail.body);
    }
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/remote-shell/s-1", &session)
    };
    let french = fire(&rig, french_request).await?;
    assert!(french.body.contains("Empreinte de l'enregistrement") && french.body.contains("Fermée par l'utilisateur"));
    set_mode(&rig, Mode::Chunked)?;
    let open = fire(&rig, get_with("/remote-shell/s-2", &session)).await?;
    assert!(open.body.contains("<td>Open</td>") && !open.body.contains("<td>12</td>"));
    assert_eq!(
        shell_requests(&rig)?,
        [
            "/remote-shell/sessions/a%2Fb%3Ac".to_owned(),
            "/remote-shell/sessions/s-1".to_owned(),
            "/remote-shell/sessions/s-2".to_owned(),
        ]
    );
    Ok(())
}


#[tokio::test]
async fn a_malformed_session_id_is_a_404_without_an_api_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let long_id = format!("/remote-shell/{}", "a".repeat(MAX_SHELL_REFERENCE_BYTES + 1));
    for path in [
        "/remote-shell/-x",
        "/remote-shell/a%00b",
        "/remote-shell/a%20b",
        "/remote-shell/%2e%2e",
        "/remote-shell/%2e",
        "/remote-shell/a%0Ab",
        "/remote-shell/%E2%80%AEx",
        "/remote-shell/a%E3%85%A4",
        long_id.as_str(),
    ] {
        let reply = fire(&rig, get_with(path, &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert!(shell_requests(&rig)?.is_empty());
    let longest = format!("/remote-shell/{}", "a".repeat(MAX_SHELL_REFERENCE_BYTES));
    assert_eq!(fire(&rig, get_with(&longest, &session)).await?.status, StatusCode::OK);
    let other = fire(&rig, get_with("/remote-shell/elsewhere", &session)).await?;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
    assert!(!other.body.contains(LEAK));
    assert_eq!(shell_requests(&rig)?.len(), TWO_VALID_CALLS);
    set_mode(&rig, Mode::BadId)?;
    let foreign = fire(&rig, get_with("/remote-shell/s-1", &session)).await?;
    assert_eq!(foreign.status, StatusCode::BAD_GATEWAY);
    assert_eq!(shell_requests(&rig)?.len(), THREE_CALLS);
    Ok(())
}


#[tokio::test]
async fn register_api_failures_render_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for path in ["/remote-shell", "/remote-shell/s-1"] {
        for (mode, status) in [
            (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
            (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
            (Mode::StoredValue, StatusCode::BAD_GATEWAY),
            (Mode::Oversize, StatusCode::BAD_GATEWAY),
        ] {
            set_mode(&rig, mode)?;
            let reply = fire(&rig, get_with(path, &session)).await?;
            assert_eq!(reply.status, status, "{path}");
            assert!(!reply.body.contains(LEAK) && !reply.body.contains("stored_value") && !reply.body.contains("cannot be served"));
            assert_hardened(&reply);
        }
    }
    set_mode(&rig, Mode::TooMany)?;
    assert_eq!(fire(&rig, get_with("/remote-shell", &session)).await?.status, StatusCode::BAD_GATEWAY);
    set_mode(&rig, Mode::BadCursor)?;
    assert_eq!(fire(&rig, get_with("/remote-shell", &session)).await?.status, StatusCode::BAD_GATEWAY);
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/remote-shell", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Normal)?;
    let second = sign_in(&rig).await?;
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended_detail = fire(&rig, get_with("/remote-shell/s-1", &second)).await?;
    assert_eq!(location_of(&ended_detail).as_deref(), Some("/login"));
    Ok(())
}
