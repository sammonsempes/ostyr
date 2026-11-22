use super::{assert_hardened, assert_no_hidden_characters, set_mode};
use crate::harness::{fire, get, get_with, harness, location_of, sign_in, without_tokens, Harness, Req};
use crate::stub::{Mode, DHCP_HOSTILE_BYTES, LEAK};
use crate::types::{TestError, TestResult};
use axum::http::StatusCode;


const HOSTILE_UNREADABLE_ROWS: usize = 8;


const AT_QUERY: &str = "/dhcp?address=10.0.0.5&at=1772000000";


const PROBE: &str = "/dhcp/leases/at?address=0.0.0.0&at=0";


const MAC_QUERY: &str = "/dhcp?mac=aa:bb:cc:dd:ee:ff&from=1772000000&to=1772003600";


fn dhcp_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.dhcp_paths.lock().map_err(|_| "poisoned")?.clone())
}


#[tokio::test]
async fn the_dhcp_screen_shows_both_forms_and_both_lookups_in_both_languages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/dhcp\""));
    let forms = fire(&rig, get_with("/dhcp", &session)).await?;
    assert_eq!(forms.status, StatusCode::OK);
    assert_hardened(&forms);
    for expected in [
        "name=\"address\"",
        "name=\"at\"",
        "name=\"mac\"",
        "name=\"from\"",
        "name=\"to\"",
        "Who held this address",
    ] {
        assert!(forms.body.contains(expected), "{expected}");
    }
    assert!(!forms.body.contains("<table>") && !forms.body.contains("Unreadable row.") && !forms.body.contains("could not be read"));
    assert_eq!(dhcp_requests(&rig)?, [PROBE.to_owned()]);
    let by_address = fire(&rig, get_with(AT_QUERY, &session)).await?;
    assert_eq!(by_address.status, StatusCode::OK);
    for expected in [
        "host-1.example.com",
        "AA-BB-CC-DD-EE-FF",
        "<td>2026-03-01T09:00:00Z</td>",
        "<td>2001:db8::1</td>",
        "<td>AA-BB-CC-DD-EE-00</td>",
        "<td>Assigned</td>",
        "<td>Expired and reclaimed</td>",
        "<td>Other</td>",
        "<td>7</td>",
        "<td>-</td>",
        "1 row could not be read.",
        "Results cut at 100",
    ] {
        assert!(by_address.body.contains(expected), "{expected}: {}", by_address.body);
    }
    assert_eq!(by_address.body.matches("Hostname refused (unreadable text)").count(), 1);
    assert!(by_address.body.contains("<td>AA-BB-CC-DD-EE-01</td>"));
    let by_mac = fire(&rig, get_with(MAC_QUERY, &session)).await?;
    assert_eq!(by_mac.status, StatusCode::OK);
    assert!(by_mac.body.contains("host-1.example.com"));
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with(AT_QUERY, &session)
    };
    let french = fire(&rig, french_request).await?;
    for expected in [
        "Baux DHCP",
        "Attribué",
        "1 ligne n'a pas pu être lue.",
        "Résultats coupés à 100",
        "Nom d'hôte refusé (texte illisible)",
    ] {
        assert!(french.body.contains(expected), "{expected}");
    }
    let forged = format!("{AT_QUERY}&tenant=b&limit=500");
    assert_eq!(fire(&rig, get_with(&forged, &session)).await?.status, StatusCode::OK);
    assert_eq!(
        dhcp_requests(&rig)?,
        [
            PROBE.to_owned(),
            "/dhcp/leases/at?address=10.0.0.5&at=1772000000".to_owned(),
            "/dhcp/leases/mac?mac=AA-BB-CC-DD-EE-FF&from=1772000000&to=1772003600".to_owned(),
            "/dhcp/leases/at?address=10.0.0.5&at=1772000000".to_owned(),
            "/dhcp/leases/at?address=10.0.0.5&at=1772000000".to_owned(),
        ]
    );
    let anonymous = fire(&rig, get(AT_QUERY)).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with(AT_QUERY, &session)).await?;
    assert!(empty.body.contains("No lease found.") && !empty.body.contains("could not be read") && !empty.body.contains("Results cut"));
    set_mode(&rig, Mode::BadId)?;
    let none_readable = fire(&rig, get_with(AT_QUERY, &session)).await?;
    assert!(none_readable.body.contains("No readable lease in this answer.") && none_readable.body.contains("1 row could not be read."));
    set_mode(&rig, Mode::BadSeverity)?;
    let many = fire(&rig, get_with(AT_QUERY, &session)).await?;
    assert!(many.body.contains("3 rows could not be read."));
    Ok(())
}


#[tokio::test]
async fn a_hostile_hostname_or_row_is_an_unreadable_row_and_never_printed_raw() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with(AT_QUERY, &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_no_hidden_characters(&list.body);
    let page = without_tokens(&list.body);
    for forbidden in ["evil", "\u{3164}", "<script>", "not a time", "-x", &"a".repeat(DHCP_HOSTILE_BYTES)] {
        assert!(!page.contains(forbidden), "{forbidden}");
    }
    assert_eq!(list.body.matches("Unreadable row.").count(), HOSTILE_UNREADABLE_ROWS);
    assert!(list.body.contains("<td>fine</td>") && list.body.contains("<td>Other</td>") && list.body.contains("1 row could not be read."));
    Ok(())
}


#[tokio::test]
async fn a_forged_lookup_is_refused_before_any_api_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let long_address = format!("/dhcp?address={}&at=1", "1".repeat(DHCP_HOSTILE_BYTES));
    let long_mac = format!("/dhcp?mac={}&from=1&to=2", "a".repeat(DHCP_HOSTILE_BYTES));
    for query in [
        "/dhcp?address=-x&at=1",
        "/dhcp?address=1.2.3.4%00&at=1",
        "/dhcp?address=fe80::1%25eth0&at=1",
        "/dhcp?address=[::1]&at=1",
        "/dhcp?address=&at=1",
        "/dhcp?address=10.0.0.5",
        "/dhcp?at=1",
        "/dhcp?address=10.0.0.5&at=",
        "/dhcp?address=10.0.0.5&at=-",
        "/dhcp?address=10.0.0.5&at=%2B1",
        "/dhcp?address=10.0.0.5&at=1e3",
        "/dhcp?address=10.0.0.5&at=-1",
        "/dhcp?address=10.0.0.5&at=253402300800",
        "/dhcp?address=10.0.0.5&at=000000000000000000001",
        "/dhcp?mac=aa:bb:cc:dd:ee&from=1&to=2",
        "/dhcp?mac=aa:bb:cc:dd:ee:gg&from=1&to=2",
        "/dhcp?mac=a:bb:cc:dd:ee:ff&from=1&to=2",
        "/dhcp?mac=aaa:bb:cc:dd:ee:ff&from=1&to=2",
        "/dhcp?mac=aa:bb:cc:dd:ee:ff:00&from=1&to=2",
        "/dhcp?mac=aabb.ccdd.eeff&from=1&to=2",
        "/dhcp?mac=aa:bb:cc:dd:ee:ff&from=1",
        "/dhcp?mac=aa:bb:cc:dd:ee:ff&to=1",
        "/dhcp?mac=aa:bb:cc:dd:ee:ff&from=2&to=1",
        "/dhcp?mac=aa:bb:cc:dd:ee:ff&from=0&to=34560001",
        "/dhcp?from=1&to=2",
        "/dhcp?address=10.0.0.5&at=1&mac=aa:bb:cc:dd:ee:ff",
        "/dhcp?address=10.0.0.5&at=1&from=1",
        long_address.as_str(),
        long_mac.as_str(),
    ] {
        let reply = fire(&rig, get_with(query, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", query.len());
        assert!(!reply.body.contains(LEAK));
    }
    assert!(dhcp_requests(&rig)?.is_empty());
    let longest = "/dhcp?mac=AA-BB-CC-DD-EE-FF&from=0&to=34560000";
    assert_eq!(fire(&rig, get_with(longest, &session)).await?.status, StatusCode::OK);
    let latest = "/dhcp?address=::1&at=253402300799";
    assert_eq!(fire(&rig, get_with(latest, &session)).await?.status, StatusCode::OK);
    assert_eq!(
        dhcp_requests(&rig)?,
        [
            "/dhcp/leases/mac?mac=AA-BB-CC-DD-EE-FF&from=0&to=34560000".to_owned(),
            "/dhcp/leases/at?address=%3A%3A1&at=253402300799".to_owned(),
        ]
    );
    Ok(())
}


#[tokio::test]
async fn dhcp_api_failures_render_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (mode, status) in [
        (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
        (Mode::Status(StatusCode::TOO_MANY_REQUESTS), StatusCode::TOO_MANY_REQUESTS),
        (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
        (Mode::Oversize, StatusCode::BAD_GATEWAY),
        (Mode::TooMany, StatusCode::BAD_GATEWAY),
        (Mode::BadCursor, StatusCode::BAD_GATEWAY),
    ] {
        set_mode(&rig, mode)?;
        let reply = fire(&rig, get_with(AT_QUERY, &session)).await?;
        assert_eq!(reply.status, status);
        assert!(!reply.body.contains(LEAK));
        assert_hardened(&reply);
    }
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with(MAC_QUERY, &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn the_form_less_dhcp_page_shows_the_permission_page_when_the_api_refuses_the_probe() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    set_mode(&rig, Mode::Status(StatusCode::FORBIDDEN))?;
    let refused = fire(&rig, get_with("/dhcp", &session)).await?;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert!(refused.body.contains("You do not have the permission") && !refused.body.contains("name=\"address\"") && !refused.body.contains(LEAK));
    assert_eq!(dhcp_requests(&rig)?, [PROBE.to_owned()]);
    set_mode(&rig, Mode::Status(StatusCode::INTERNAL_SERVER_ERROR))?;
    assert_eq!(fire(&rig, get_with("/dhcp", &session)).await?.status, StatusCode::BAD_GATEWAY);
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/dhcp", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    Ok(())
}
