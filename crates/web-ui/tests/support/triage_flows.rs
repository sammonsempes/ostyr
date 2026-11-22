use super::{assert_hardened, csrf_of, encoded, requests_of, set_conflict, set_mode, write_form, writes_of, SESSION_COOKIE};
use crate::harness::{fire, get_with, harness, location_of, post_form, sign_in, without_tokens, Harness, Req};
use crate::stub::{id_of, triage_view, Mode, ReadFault, LEAK};
use crate::types::TestResult;
use axum::http::StatusCode;
use serde_json::json;


const NOTE_CAP: usize = 2048;


const LONG_NOTE_CHARS: usize = 5000;


const ID_CHARS: usize = 64;


const BAD_IDS: usize = 3;


const FRENCH_VERSION: i64 = 4;


fn alert_path() -> String {
    format!("/alerts/{}", id_of('a'))
}


fn triage_path() -> String {
    format!("{}/triage", alert_path())
}


fn set_triage(rig: &Harness, value: Option<serde_json::Value>) -> TestResult {
    *rig.stub.state.triage.lock().map_err(|_| "poisoned")? = value;
    Ok(())
}


#[tokio::test]
async fn each_status_is_posted_with_the_version_read_with_the_page() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let new_page = fire(&rig, get_with(&alert_path(), &session)).await?;
    assert!(new_page.body.contains("not triaged yet") && !new_page.body.contains("name=\"version\""));
    assert!(new_page.body.contains(&format!("action=\"{}\"", triage_path())) && new_page.body.contains(&format!("maxlength=\"{NOTE_CAP}\"")));
    for status in ["acknowledged", "closed", "false_positive"] {
        assert!(new_page.body.contains(&format!("<option value=\"{status}\">")), "{status}");
    }
    let first = write_form(&rig, &session, &triage_path(), &[("status", "acknowledged"), ("note", "looking")]).await?;
    assert_eq!(first.status, StatusCode::OK);
    assert_hardened(&first);
    assert!(first.body.contains("Acknowledged") && first.body.contains("looking") && first.body.contains("name=\"version\" value=\"1\""));
    let second = write_form(&rig, &session, &triage_path(), &[("status", "closed"), ("version", "1"), ("note", "")]).await?;
    assert_eq!(second.status, StatusCode::OK);
    assert!(second.body.contains("Closed") && second.body.contains("name=\"version\" value=\"2\""));
    let third = write_form(
        &rig,
        &session,
        &triage_path(),
        &[("status", "false_positive"), ("version", "2"), ("note", "noise")],
    )
    .await?;
    assert_eq!(third.status, StatusCode::OK);
    assert!(third.body.contains("False positive") && third.body.contains("noise"));
    let id = id_of('a');
    assert_eq!(
        writes_of(&rig)?,
        vec![
            format!("/alerts/{id}/triage {{\"note\":\"looking\",\"status\":\"acknowledged\"}}"),
            format!("/alerts/{id}/triage {{\"status\":\"closed\",\"version\":1}}"),
            format!("/alerts/{id}/triage {{\"note\":\"noise\",\"status\":\"false_positive\",\"version\":2}}"),
        ]
    );
    Ok(())
}


#[tokio::test]
async fn a_french_page_shows_the_triage_in_french() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    set_triage(&rig, Some(triage_view("false_positive", &json!(null), FRENCH_VERSION)))?;
    let reply = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with(&alert_path(), &session)
        },
    )
    .await?;
    assert!(
        reply.body.contains("Faux positif")
            && reply.body.contains("Enregistrer le tri")
            && reply.body.contains(&format!("name=\"version\" value=\"{FRENCH_VERSION}\""))
    );
    Ok(())
}


#[tokio::test]
async fn a_hostile_triage_from_the_api_is_rendered_escaped_and_clipped() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let long = "n".repeat(LONG_NOTE_CHARS);
    let note = format!("<script>alert(1)</script>\u{202e}{long}");
    let view = json!({"status": "closed", "actor": "<b>eve</b>\u{202e}", "note": note, "updated_at": "t", "version": 1});
    set_triage(&rig, Some(view))?;
    let reply = fire(&rig, get_with(&alert_path(), &session)).await?;
    assert_eq!(reply.status, StatusCode::OK);
    let body = without_tokens(&reply.body);
    assert!(!body.contains("<script>") && !body.contains('\u{202e}') && !body.contains("<b>eve"));
    assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;\u{fffd}") && body.contains("&lt;b&gt;eve&lt;/b&gt;\u{fffd}"));
    assert!(body.contains("... [") && !body.contains(&long));
    Ok(())
}


#[tokio::test]
async fn an_unknown_triage_status_or_version_from_the_api_is_unavailable() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for view in [
        triage_view("Closed", &json!(null), 1),
        triage_view("closed", &json!(null), 0),
        triage_view("", &json!("LEAK-TRIAGE"), 1),
    ] {
        set_triage(&rig, Some(view))?;
        let reply = fire(&rig, get_with(&alert_path(), &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
        assert!(!reply.body.contains("LEAK-TRIAGE"));
    }
    Ok(())
}


#[tokio::test]
async fn a_forged_status_is_refused_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let before = requests_of(&rig);
    let bad = [
        "",
        "Closed",
        "closed\n",
        "false_positive ",
        " closed",
        "delete",
        "acknowledged\u{0}",
        "CLOSED",
    ];
    for status in bad {
        let reply = write_form(&rig, &session, &triage_path(), &[("status", status), ("note", "a note")]).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{status:?}");
    }
    let missing = write_form(&rig, &session, &triage_path(), &[("note", "a note")]).await?;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, bad.len() + 1);
    Ok(())
}


#[tokio::test]
async fn a_bad_version_is_refused_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let before = requests_of(&rig);
    let bad = ["", "abc", "0", "-1", "+1", "1.5", " 1", "1 ", "99999999999999999999"];
    for version in bad {
        let reply = write_form(
            &rig,
            &session,
            &triage_path(),
            &[("status", "closed"), ("version", version), ("note", "n")],
        )
        .await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{version:?}");
    }
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, bad.len());
    let forged = write_form(&rig, &session, &triage_path(), &[("status", "closed"), ("version", "9")]).await?;
    assert_eq!(forged.status, StatusCode::OK);
    assert_eq!(writes_of(&rig)?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_note_is_bounded_in_characters_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let before = requests_of(&rig);
    let over = "é".repeat(NOTE_CAP + 1);
    let reply = write_form(&rig, &session, &triage_path(), &[("status", "closed"), ("note", &over)]).await?;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, 1);
    let exact = "é".repeat(NOTE_CAP);
    let accepted = write_form(&rig, &session, &triage_path(), &[("status", "closed"), ("note", &exact)]).await?;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(writes_of(&rig)?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_write_without_the_session_token_is_refused_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let other = sign_in(&rig).await?;
    let foreign = csrf_of(&rig, &other).await?;
    let before = requests_of(&rig);
    let cookie = vec![format!("{SESSION_COOKIE}={session}")];
    let fields = "status=closed&note=hello";
    for body in [
        fields.to_owned(),
        format!("csrf=&{fields}"),
        format!("csrf=wrong&{fields}"),
        format!("csrf={foreign}&{fields}"),
    ] {
        let reply = fire(&rig, post_form(&triage_path(), cookie.clone(), &body)).await?;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{body}");
        assert!(reply.body.contains("no longer valid"));
    }
    let anonymous = fire(&rig, post_form(&triage_path(), vec![], &format!("csrf={foreign}&{fields}"))).await?;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, 0);
    Ok(())
}


#[tokio::test]
async fn an_invalid_alert_id_is_not_found_without_a_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let before = requests_of(&rig);
    let upper = "A".repeat(ID_CHARS);
    for bad in ["short", "..%2Fx", upper.as_str()] {
        let reply = write_form(&rig, &session, &format!("/alerts/{bad}/triage"), &[("status", "closed"), ("note", "n")]).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{bad}");
    }
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, BAD_IDS);
    Ok(())
}


#[tokio::test]
async fn a_changed_triage_is_our_own_conflict_page() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    set_conflict(&rig, Some("triage_changed"))?;
    let reply = write_form(
        &rig,
        &session,
        &triage_path(),
        &[("status", "closed"), ("version", "1"), ("note", "SUBMITTED-MARKER")],
    )
    .await?;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert!(reply.body.contains("changed meanwhile") && !reply.body.contains(LEAK) && !reply.body.contains("triage_changed"));
    assert!(!reply.body.contains("SUBMITTED-MARKER"));
    assert_hardened(&reply);
    let token = csrf_of(&rig, &session).await?;
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..post_form(
                &triage_path(),
                vec![format!("{SESSION_COOKIE}={session}")],
                &encoded(&[("csrf", &token), ("status", "closed")]),
            )
        },
    )
    .await?;
    assert_eq!(french.status, StatusCode::CONFLICT);
    assert!(french.body.contains("a changé entre-temps"));
    Ok(())
}


#[tokio::test]
async fn api_failures_on_a_triage_render_our_own_pages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (mode, status) in [
        (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
        (Mode::Status(StatusCode::NOT_FOUND), StatusCode::NOT_FOUND),
        (Mode::Status(StatusCode::BAD_REQUEST), StatusCode::BAD_REQUEST),
        (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
        (Mode::BadId, StatusCode::BAD_GATEWAY),
    ] {
        let token = csrf_of(&rig, &session).await?;
        set_mode(&rig, mode)?;
        let reply = fire(
            &rig,
            post_form(
                &triage_path(),
                vec![format!("{SESSION_COOKIE}={session}")],
                &encoded(&[("csrf", &token), ("status", "closed"), ("note", "n")]),
            ),
        )
        .await?;
        let reread_failed = mode == Mode::BadId;
        assert_eq!(reply.status, if reread_failed { StatusCode::BAD_GATEWAY } else { status });
        assert!(!reply.body.contains(LEAK));
        set_mode(&rig, Mode::Normal)?;
    }
    Ok(())
}


#[tokio::test]
async fn a_401_on_the_write_ends_the_session() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let token = csrf_of(&rig, &session).await?;
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let body = encoded(&[("csrf", &token), ("status", "closed")]);
    let ended = fire(&rig, post_form(&triage_path(), vec![format!("{SESSION_COOKIE}={session}")], &body)).await?;
    assert_eq!(ended.status, StatusCode::SEE_OTHER);
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Normal)?;
    let gone = fire(&rig, get_with(&alert_path(), &session)).await?;
    assert_eq!(location_of(&gone).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn a_401_on_the_reread_after_a_stored_triage_ends_the_session() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let token = csrf_of(&rig, &session).await?;
    *rig.stub.state.read_fault.lock().map_err(|_| "poisoned")? = Some(ReadFault::Status(StatusCode::UNAUTHORIZED));
    let body = encoded(&[("csrf", &token), ("status", "closed"), ("note", "n")]);
    let ended = fire(&rig, post_form(&triage_path(), vec![format!("{SESSION_COOKIE}={session}")], &body)).await?;
    assert_eq!(ended.status, StatusCode::SEE_OTHER);
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    assert_eq!(writes_of(&rig)?.len(), 1);
    let gone = fire(&rig, get_with(&alert_path(), &session)).await?;
    assert_eq!(location_of(&gone).as_deref(), Some("/login"));
    Ok(())
}
