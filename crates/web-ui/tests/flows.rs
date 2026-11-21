#[path = "support/harness.rs"]
mod harness;
#[path = "support/logging.rs"]
mod logging;
#[cfg(unix)]
#[path = "support/served.rs"]
mod served;
#[path = "support/stub.rs"]
mod stub;
#[path = "support/types.rs"]
mod types;
#[path = "support/vuln_flows.rs"]
mod vuln_flows;


use axum::body::Body;
use axum::http::StatusCode;
use data_encoding::HEXLOWER;
use harness::{
    cookie_value_of, csrf_in, fire, fire_body, get, get_with, harness, harness_custom, location_of, login_body, login_csrf, post_form, post_login,
    set_cookie_of, sign_in, without_tokens, Harness, Reply, Req, LIMITS, WALL_NOW,
};
use secrecy::SecretString;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use stub::{
    cert_fingerprint, id_of, Mode, ReadFault, BIG_ASSET, CERT_BAD_FINGERPRINT_COUNT, CERT_CURSOR_TIME, CERT_MANY_NAMES, CERT_SKIPPED, FIRST_CURSOR,
    HOSTILE, HUNT_NEXT_CURSOR, HUNT_OVERSIZED, HUNT_SKIPPED, LEAK, LOCK_AFTER, ODD_ASSET_ID, RISK_ALERTS_READ, RISK_CAP, RISK_ODD_ID,
    RISK_UNREADABLE_IDS, STATE_NEXT_CURSOR, TOKEN,
};
use tokio::sync::Semaphore;
use tokio::time::{sleep, Instant};
use tokio_stream::pending;
use types::TestError;
use types::TestResult;
use web_ui::api::{
    encode_asset_id, forwarded_value, header_from_text, list_alerts, login, MAX_ASSET_CURSOR_CHARS, MAX_ASSET_ID_BYTES, MAX_HUNT_CURSOR_CHARS,
    MAX_STATE_ASSET_CHARS, MAX_STATE_ID_CHARS,
};
use web_ui::client::{build_client, login_slots};
use web_ui::error::ApiFailure;
use web_ui::model::{ApiClient, ApiSection, Session};
use web_ui::model::{Language, WebLimits};
use web_ui::routes::{accept_language, api_refusal, cookie_header, failure_class};
use web_ui::session::evict_oldest;


const UPSTREAM_STATUS: u16 = 500;


const HOSTILE_TITLED_CASES: usize = 3;


const HOSTILE_LIST_SITES: usize = 4;


const DETAIL_HOSTILE_SITES: usize = 69;


const SESSION_COOKIE: &str = "__Host-ostyr_session";


const LOGIN_COOKIE: &str = "__Host-ostyr_login";


const CLOCK_STEP: u64 = 101;


const WINDOW_STEP: u64 = 61;


const LOGIN_MAX: u32 = 3;


const LONG_USERNAME: usize = 300;


const LONG_LOGOUT: usize = 200;


const LONG_PASSWORD: usize = 2000;


const SECOND_SOURCE: u8 = 2;


const THIRD_SOURCE: u8 = 3;


const ID_LENGTH: usize = 64;


const MANY_ATTEMPTS: u32 = 100;


const BIG_FORM: usize = 8192;


const TINY_FORM: usize = 16;


const SHORT_TIMEOUT: Duration = Duration::from_secs(2);


fn session_cookie(value: &str) -> Vec<String> {
    vec![format!("{SESSION_COOKIE}={value}")]
}


fn assert_hardened(reply: &Reply) {
    let header = |name: &str| reply.headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("");
    assert_eq!(
        header("content-security-policy"),
        "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    );
    assert_eq!(header("x-frame-options"), "DENY");
    assert_eq!(header("x-content-type-options"), "nosniff");
    assert_eq!(header("cache-control"), "no-store");
    assert_eq!(header("referrer-policy"), "no-referrer");
    assert!(header("strict-transport-security").starts_with("max-age="));
}


fn assert_flags(set_cookie: &str) {
    assert!(set_cookie.contains("; Secure"), "{set_cookie}");
    assert!(set_cookie.contains("; HttpOnly"), "{set_cookie}");
    assert!(set_cookie.contains("; SameSite=Strict"), "{set_cookie}");
    assert!(set_cookie.contains("; Path=/"), "{set_cookie}");
}


#[tokio::test]
async fn login_page_sets_a_flagged_cookie_and_the_form() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let reply = fire(&rig, get("/login")).await?;
    assert_eq!(reply.status, StatusCode::OK);
    assert_hardened(&reply);
    let cookie = set_cookie_of(&reply, LOGIN_COOKIE).ok_or("no cookie")?;
    assert_flags(&cookie);
    assert_eq!(csrf_in(&reply.body), cookie_value_of(&cookie));
    assert!(reply.body.contains("action=\"/login\""));
    assert!(reply.body.contains("lang=\"en\""));
    Ok(())
}


#[tokio::test]
async fn full_session_flow() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let signed = post_login(&rig, "alice", "secret").await?;
    assert_eq!(signed.status, StatusCode::SEE_OTHER);
    assert_eq!(location_of(&signed).as_deref(), Some("/alerts"));
    let session_line = set_cookie_of(&signed, SESSION_COOKIE).ok_or("no session")?;
    assert_flags(&session_line);
    let cleared = set_cookie_of(&signed, LOGIN_COOKIE).ok_or("login cookie not cleared")?;
    assert!(cleared.contains("Max-Age=0"));
    let session = cookie_value_of(&session_line).ok_or("no value")?;
    let first = fire(&rig, get_with("/alerts", &session)).await?;
    assert_eq!(first.status, StatusCode::OK);
    assert_hardened(&first);
    assert!(first.body.contains("Brute force") && first.body.contains("Malware"));
    assert!(first.body.contains(&format!("name=\"cursor\" value=\"{FIRST_CURSOR}\"")));
    assert!(first.body.contains(&format!("/alerts/{}", id_of('a'))));
    assert!(first.body.contains("srv-1"));
    let second = fire(&rig, get_with(&format!("/alerts?cursor={FIRST_CURSOR}"), &session)).await?;
    assert!(second.body.contains("Beacon") && !second.body.contains("Older alerts"));
    let empty_cursor_query = rig.stub.state.last_query.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(empty_cursor_query, "cursor=abc_-%3D");
    let detail = fire(&rig, get_with(&format!("/alerts/{}", id_of('a')), &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.body.contains("Brute force") && detail.body.contains("ev-1") && detail.body.contains("count"));
    let csrf = csrf_in(&first.body).ok_or("no csrf in page")?;
    let out = fire(&rig, post_form("/logout", session_cookie(&session), &format!("csrf={csrf}"))).await?;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert_eq!(location_of(&out).as_deref(), Some("/login"));
    assert!(set_cookie_of(&out, SESSION_COOKIE).ok_or("no clearing")?.contains("Max-Age=0"));
    assert_eq!(rig.stub.state.logouts.load(Ordering::SeqCst), 1);
    let after = fire(&rig, get_with("/alerts", &session)).await?;
    assert_eq!(after.status, StatusCode::SEE_OTHER);
    assert_eq!(location_of(&after).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn limit_and_cursor_are_validated_and_forwarded() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let forwarded = fire(&rig, get_with("/alerts?limit=5", &session)).await?;
    assert_eq!(forwarded.status, StatusCode::OK);
    assert_eq!(rig.stub.state.last_query.lock().map_err(|_| "poisoned")?.as_str(), "limit=5");
    let before = rig.stub.state.last_query.lock().map_err(|_| "poisoned")?.clone();
    for query in [
        "limit=0",
        "limit=101",
        "limit=abc",
        "cursor=%3Cscript%3E",
        "cursor=",
        "cursor=a%26limit%3D1",
    ] {
        let refused = fire(&rig, get_with(&format!("/alerts?{query}"), &session)).await?;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{query}");
    }
    assert_eq!(*rig.stub.state.last_query.lock().map_err(|_| "poisoned")?, before);
    let api_refuses = fire(&rig, get_with("/alerts?cursor=unknown", &session)).await?;
    assert_eq!(api_refuses.status, StatusCode::BAD_REQUEST);
    assert!(!api_refuses.body.contains(LEAK));
    Ok(())
}


#[tokio::test]
async fn login_csrf_is_enforced() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let csrf = login_csrf(&rig).await?;
    let cookie = vec![format!("{LOGIN_COOKIE}={csrf}")];
    let cases = [
        post_form("/login", vec![], &login_body(&csrf, "alice", "secret")),
        post_form("/login", cookie.clone(), "username=alice&password=secret"),
        post_form("/login", cookie.clone(), &login_body("other", "alice", "secret")),
        post_form("/login", vec![format!("{LOGIN_COOKIE}=")], &login_body("", "alice", "secret")),
    ];
    for request in cases {
        let refused = fire(&rig, request).await?;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        assert!(set_cookie_of(&refused, SESSION_COOKIE).is_none());
    }
    assert_eq!(rig.stub.state.logins.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn failed_logins_show_a_generic_message() -> TestResult {
    let limits = WebLimits {
        login_max: MANY_ATTEMPTS,
        form_bytes: BIG_FORM,
        ..LIMITS
    };
    let rig = harness_custom(Mode::Normal, core_auth::random::os_random, limits).await?;
    for (user, status) in [
        ("bob", StatusCode::UNAUTHORIZED),
        ("mfa", StatusCode::UNAUTHORIZED),
        ("limited", StatusCode::TOO_MANY_REQUESTS),
        ("broken", StatusCode::BAD_GATEWAY),
        ("spacey", StatusCode::BAD_GATEWAY),
        ("garbage", StatusCode::BAD_GATEWAY),
    ] {
        let reply = post_login(&rig, user, "x").await?;
        assert_eq!(reply.status, status, "{user}");
        assert!(!reply.body.contains(LEAK), "{user}");
        assert!(set_cookie_of(&reply, SESSION_COOKIE).is_none());
    }
    let bad = post_login(&rig, "bob", "x").await?;
    assert!(bad.body.contains("Sign-in failed"));
    assert!(csrf_in(&bad.body).is_some());
    let calls = rig.stub.state.logins.load(Ordering::SeqCst);
    for (user, password) in [
        ("", "x"),
        ("alice", ""),
        (&"u".repeat(LONG_USERNAME), "x"),
        ("alice", &"p".repeat(LONG_PASSWORD)),
    ] {
        let reply = post_login(&rig, user, password).await?;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let long_totp = fire(
        &rig,
        post_form(
            "/login",
            vec![format!("{LOGIN_COOKIE}=abc")],
            "csrf=abc&username=alice&password=secret&totp_code=12345678901234567",
        ),
    )
    .await?;
    assert_eq!(long_totp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(rig.stub.state.logins.load(Ordering::SeqCst), calls);
    Ok(())
}


#[tokio::test]
async fn totp_code_is_sent_when_given() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let reply = fire(
        &rig,
        post_form(
            "/login",
            vec![format!("{LOGIN_COOKIE}=abc")],
            "csrf=abc&username=alice&password=secret&totp_code=123456",
        ),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    Ok(())
}


#[tokio::test]
async fn a_session_id_set_before_login_is_never_reused() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let first = sign_in(&rig).await?;
    let csrf = login_csrf(&rig).await?;
    let reply = fire(
        &rig,
        post_form(
            "/login",
            vec![format!("{LOGIN_COOKIE}={csrf}"), format!("{SESSION_COOKIE}={first}")],
            &login_body(&csrf, "alice", "secret"),
        ),
    )
    .await?;
    let second = cookie_value_of(&set_cookie_of(&reply, SESSION_COOKIE).ok_or("no session")?).ok_or("no value")?;
    assert_ne!(first, second);
    let stale = fire(&rig, get_with("/alerts", &first)).await?;
    assert_eq!(stale.status, StatusCode::SEE_OTHER);
    let fresh = fire(&rig, get_with("/alerts", &second)).await?;
    assert_eq!(fresh.status, StatusCode::OK);
    let invented = fire(&rig, get_with("/alerts", "invented-by-an-attacker")).await?;
    assert_eq!(invented.status, StatusCode::SEE_OTHER);
    Ok(())
}


#[tokio::test]
async fn sessions_expire_and_are_capped() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let first = sign_in(&rig).await?;
    let _second = sign_in(&rig).await?;
    let full = post_login(&rig, "alice", "secret").await?;
    assert_eq!(full.status, StatusCode::SERVICE_UNAVAILABLE);
    rig.clock.store(CLOCK_STEP, Ordering::SeqCst);
    let expired = fire(&rig, get_with("/alerts", &first)).await?;
    assert_eq!(expired.status, StatusCode::SEE_OTHER);
    let again = post_login(&rig, "alice", "secret").await?;
    assert_eq!(again.status, StatusCode::SEE_OTHER);
    assert_eq!(rig.state.sessions.lock().map_err(|_| "poisoned")?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn login_attempts_are_limited_per_source_and_in_number_of_sources() -> TestResult {
    let limits = WebLimits {
        login_max: LOGIN_MAX,
        ..LIMITS
    };
    let rig = harness_custom(Mode::Normal, core_auth::random::os_random, limits).await?;
    for _attempt in 0..LOGIN_MAX {
        assert_eq!(post_login(&rig, "bob", "x").await?.status, StatusCode::UNAUTHORIZED);
    }
    let throttled = post_login(&rig, "alice", "secret").await?;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(set_cookie_of(&throttled, SESSION_COOKIE).is_none());
    let other = Req {
        source: SECOND_SOURCE,
        ..post_form("/login", vec![], "")
    };
    assert_eq!(fire(&rig, other).await?.status, StatusCode::FORBIDDEN);
    let third_source = Req {
        source: THIRD_SOURCE,
        ..post_form("/login", vec![], "")
    };
    assert_eq!(fire(&rig, third_source).await?.status, StatusCode::TOO_MANY_REQUESTS);
    rig.clock.store(WINDOW_STEP, Ordering::SeqCst);
    let later = Req {
        source: THIRD_SOURCE,
        ..post_form("/login", vec![], "")
    };
    assert_eq!(fire(&rig, later).await?.status, StatusCode::FORBIDDEN);
    Ok(())
}


fn no_randomness(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


#[tokio::test]
async fn missing_randomness_is_a_generic_server_error() -> TestResult {
    let rig = harness_custom(Mode::Normal, no_randomness, LIMITS).await?;
    let page = fire(&rig, get("/login")).await?;
    assert_eq!(page.status, StatusCode::INTERNAL_SERVER_ERROR);
    let posted = fire(
        &rig,
        post_form("/login", vec![format!("{LOGIN_COOKIE}=abc")], "csrf=abc&username=alice&password=secret"),
    )
    .await?;
    assert_eq!(posted.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(set_cookie_of(&posted, SESSION_COOKIE).is_none());
    Ok(())
}


#[tokio::test]
async fn logout_needs_a_session_and_the_session_csrf() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let anonymous = fire(&rig, post_form("/logout", vec![], "csrf=x")).await?;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    let session = sign_in(&rig).await?;
    let page = fire(&rig, get_with("/alerts", &session)).await?;
    let csrf = csrf_in(&page.body).ok_or("no csrf")?;
    for body in ["csrf=wrong", "", "csrf="] {
        let refused = fire(&rig, post_form("/logout", session_cookie(&session), body)).await?;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{body}");
    }
    let login_csrf_value = login_csrf(&rig).await?;
    let cross = fire(&rig, post_form("/logout", session_cookie(&session), &format!("csrf={login_csrf_value}"))).await?;
    assert_eq!(cross.status, StatusCode::FORBIDDEN);
    assert_eq!(rig.stub.state.logouts.load(Ordering::SeqCst), 0);
    let still = fire(&rig, get_with("/alerts", &session)).await?;
    assert_eq!(still.status, StatusCode::OK);
    let oversize = fire(&rig, post_form("/logout", session_cookie(&session), &"a=b&".repeat(LONG_LOGOUT))).await?;
    assert_eq!(oversize.status, StatusCode::PAYLOAD_TOO_LARGE);
    *rig.stub.state.mode.lock().map_err(|_| "poisoned")? = Mode::Status(StatusCode::INTERNAL_SERVER_ERROR);
    let out = fire(&rig, post_form("/logout", session_cookie(&session), &format!("csrf={csrf}"))).await?;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert_eq!(rig.stub.state.logouts.load(Ordering::SeqCst), 1);
    let after = fire(&rig, get_with("/alerts", &session)).await?;
    assert_eq!(after.status, StatusCode::SEE_OTHER);
    Ok(())
}


#[tokio::test]
async fn forms_are_bounded_in_size() -> TestResult {
    let limits = WebLimits {
        form_bytes: TINY_FORM,
        ..LIMITS
    };
    let rig = harness_custom(Mode::Normal, core_auth::random::os_random, limits).await?;
    let big = fire(&rig, post_form("/login", vec![], &"a=b&".repeat(TINY_FORM))).await?;
    assert_eq!(big.status, StatusCode::PAYLOAD_TOO_LARGE);
    let language = fire(&rig, post_form("/language/fr", vec![], &"a=b&".repeat(TINY_FORM))).await?;
    assert_eq!(language.status, StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_form_that_never_ends_times_out() -> TestResult {
    let limits = WebLimits {
        form_timeout: SHORT_TIMEOUT,
        ..LIMITS
    };
    let rig = harness_custom(Mode::Normal, core_auth::random::os_random, limits).await?;
    let stream = pending::<Result<axum::body::Bytes, std::convert::Infallible>>();
    let reply = fire_body(&rig.router, post_form("/login", vec![], ""), Body::from_stream(stream)).await?;
    assert_eq!(reply.status, StatusCode::REQUEST_TIMEOUT);
    Ok(())
}


#[tokio::test]
async fn api_failures_render_generic_pages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (mode, status) in [
        (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
        (Mode::Status(StatusCode::TOO_MANY_REQUESTS), StatusCode::TOO_MANY_REQUESTS),
        (Mode::Status(StatusCode::BAD_REQUEST), StatusCode::BAD_REQUEST),
        (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
        (Mode::Oversize, StatusCode::BAD_GATEWAY),
        (Mode::Chunked, StatusCode::BAD_GATEWAY),
        (Mode::TooMany, StatusCode::BAD_GATEWAY),
        (Mode::BadSeverity, StatusCode::BAD_GATEWAY),
        (Mode::BadId, StatusCode::BAD_GATEWAY),
        (Mode::BadCursor, StatusCode::BAD_GATEWAY),
    ] {
        *rig.stub.state.mode.lock().map_err(|_| "poisoned")? = mode;
        let reply = fire(&rig, get_with("/alerts", &session)).await?;
        assert_eq!(reply.status, status);
        assert!(!reply.body.contains(LEAK));
        assert_hardened(&reply);
    }
    *rig.stub.state.mode.lock().map_err(|_| "poisoned")? = Mode::Status(StatusCode::UNAUTHORIZED);
    let ended = fire(&rig, get_with("/alerts", &session)).await?;
    assert_eq!(ended.status, StatusCode::SEE_OTHER);
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    let gone = fire(&rig, get_with("/alerts", &session)).await?;
    assert_eq!(location_of(&gone).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn detail_failures_and_bad_ids() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let anonymous = fire(&rig, get(&format!("/alerts/{}", id_of('a')))).await?;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    let session = sign_in(&rig).await?;
    for bad in ["zzz", &"A".repeat(ID_LENGTH), &id_of('a').replace('a', "g"), "..%2F..%2Fauth%2Fme"] {
        let reply = fire(&rig, get_with(&format!("/alerts/{bad}"), &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{bad}");
    }
    assert_eq!(rig.stub.state.details.load(Ordering::SeqCst), 0);
    let missing = fire(&rig, get_with(&format!("/alerts/{}", id_of('d')), &session)).await?;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(!missing.body.contains(LEAK));
    *rig.stub.state.mode.lock().map_err(|_| "poisoned")? = Mode::BadId;
    let swapped = fire(&rig, get_with(&format!("/alerts/{}", id_of('a')), &session)).await?;
    assert_eq!(swapped.status, StatusCode::BAD_GATEWAY);
    Ok(())
}


#[tokio::test]
async fn hostile_alert_fields_are_escaped_and_bounded() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/alerts", &session)).await?;
    let detail = fire(&rig, get_with(&format!("/alerts/{}", id_of('a')), &session)).await?;
    for reply in [&list, &detail] {
        assert_eq!(reply.status, StatusCode::OK);
        assert!(!reply.body.contains("<script>"), "{}", reply.body);
        assert!(!reply.body.contains("</td>&amp;"));
        assert!(!reply.body.contains('\u{202e}'));
        assert!(reply.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;'&lt;/td&gt;&amp;amp;"));
        assert!(reply.body.contains("omitted"));
    }
    assert!(detail.body.contains("The summary was cut by the server."));
    assert!(detail.body.contains("6 omitted"));
    assert!(detail.body.contains("10 omitted"));
    assert!(!detail.body.contains(&format!("e55{HOSTILE}")));
    Ok(())
}


#[tokio::test]
async fn language_follows_the_header_then_the_explicit_switch() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let french = fire(
        &rig,
        Req {
            language: Some("de;q=0.9, fr-CA;q=0.8, en;q=0.1".to_owned()),
            ..get("/login")
        },
    )
    .await?;
    assert!(french.body.contains("lang=\"fr\"") && french.body.contains("Se connecter"));
    let english = fire(
        &rig,
        Req {
            language: Some("fr;q=0, en".to_owned()),
            ..get("/login")
        },
    )
    .await?;
    assert!(english.body.contains("lang=\"en\""));
    let token = login_csrf(&rig).await?;
    let login_cookie = vec![format!("__Host-ostyr_login={token}")];
    let forged = fire(&rig, post_form("/language/fr", login_cookie.clone(), "csrf=wrong")).await?;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let missing = fire(&rig, post_form("/language/fr", Vec::new(), "")).await?;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);
    let by_get = fire(&rig, get("/language/fr")).await?;
    assert_eq!(by_get.status, StatusCode::METHOD_NOT_ALLOWED);
    let switch = fire(&rig, post_form("/language/fr", login_cookie.clone(), &format!("csrf={token}"))).await?;
    assert_eq!(switch.status, StatusCode::SEE_OTHER);
    assert_eq!(location_of(&switch).as_deref(), Some("/alerts"));
    let cookie = set_cookie_of(&switch, "__Host-ostyr_lang").ok_or("no language cookie")?;
    assert_flags(&cookie);
    let chosen = fire(
        &rig,
        Req {
            cookies: vec!["__Host-ostyr_lang=fr".to_owned()],
            language: Some("en".to_owned()),
            ..get("/login")
        },
    )
    .await?;
    assert!(chosen.body.contains("lang=\"fr\""));
    let invalid = fire(
        &rig,
        Req {
            cookies: vec!["__Host-ostyr_lang=xx".to_owned()],
            language: Some("fr".to_owned()),
            ..get("/login")
        },
    )
    .await?;
    assert!(invalid.body.contains("lang=\"fr\""));
    let unknown = fire(&rig, post_form("/language/xx", login_cookie, &format!("csrf={token}"))).await?;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    let session = sign_in(&rig).await?;
    let page = fire(&rig, get_with("/alerts", &session)).await?;
    let session_token = csrf_in(&page.body).ok_or("no session token")?;
    assert!(page.body.contains("action=\"/language/fr\""));
    let own = format!("__Host-ostyr_session={session}");
    let by_session = fire(&rig, post_form("/language/fr", vec![own.clone()], &format!("csrf={session_token}"))).await?;
    assert_eq!(by_session.status, StatusCode::SEE_OTHER);
    let stale = fire(&rig, post_form("/language/fr", vec![own], &format!("csrf={token}"))).await?;
    assert_eq!(stale.status, StatusCode::FORBIDDEN);
    let sign_in_page = fire(&rig, get("/login")).await?;
    assert!(sign_in_page.body.contains("action=\"/language/en\""));
    Ok(())
}


#[test]
fn accept_language_parsing() -> TestResult {
    assert_eq!(accept_language("fr"), Some(Language::French));
    assert_eq!(accept_language("en-GB,fr;q=0.5"), Some(Language::English));
    assert_eq!(accept_language("fr;q=0.5, en;q=0.9"), Some(Language::English));
    assert_eq!(accept_language("fr, en"), Some(Language::French));
    assert_eq!(accept_language("de, *;q=0.5"), None);
    assert_eq!(accept_language("fr;q=abc"), None);
    assert_eq!(accept_language("fr;level=1"), None);
    assert_eq!(accept_language("fr;q=0"), None);
    assert_eq!(accept_language(""), None);
    Ok(())
}


#[tokio::test]
async fn static_and_fallback_routes() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let root = fire(&rig, get("/")).await?;
    assert_eq!(location_of(&root).as_deref(), Some("/alerts"));
    let css = fire(&rig, get("/style.css")).await?;
    assert_eq!(css.status, StatusCode::OK);
    assert_eq!(
        css.headers.get("content-type").and_then(|value| value.to_str().ok()),
        Some("text/css; charset=utf-8")
    );
    let unknown = fire(&rig, get("/nope")).await?;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_hardened(&unknown);
    let wrong_method = fire(&rig, get("/logout")).await?;
    assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_hardened(&wrong_method);
    let anonymous = fire(&rig, get("/alerts")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    Ok(())
}


#[test]
fn an_invalid_cookie_becomes_an_empty_header() -> TestResult {
    assert_eq!(cookie_header("a=b\n").as_bytes(), b"");
    assert_eq!(cookie_header("a=b").as_bytes(), b"a=b");
    Ok(())
}


#[test]
fn every_failure_class_has_a_page() -> TestResult {
    let unauthorised = api_refusal(Language::English, None, &ApiFailure::Unauthorized);
    assert_eq!(unauthorised.status(), StatusCode::FORBIDDEN);
    Ok(())
}


#[tokio::test]
async fn an_unreachable_api_gives_the_generic_page() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let dead = web_ui::client::build_client(&web_ui::model::ApiSection {
        base_url: "http://127.0.0.1:1/".to_owned(),
        ca: None,
        timeout_seconds: 1,
        max_connections: POOL,
    })?;
    rig.state.api.store(std::sync::Arc::new(dead));
    let list = fire(&rig, get_with("/alerts", &session)).await?;
    assert_eq!(list.status, StatusCode::BAD_GATEWAY);
    let login = post_login(&rig, "alice", "secret").await?;
    assert_eq!(login.status, StatusCode::BAD_GATEWAY);
    Ok(())
}


const FIRST: u8 = 1;


const SECOND: u8 = 2;


const CAP: usize = 2;


const SESSIONS: usize = 10;


const BLOCKED_WAIT: Duration = Duration::from_millis(20);


const POOL: usize = 3;


const HALF_POOL: usize = 8;


const FULL_POOL: usize = 16;


const API_CALLS: usize = 4;


const OLDEST_FIRST: u64 = 10;


const NEWEST: u64 = 30;


const MIDDLE: u64 = 20;


const LOGINS: u64 = 3;


const DOCUMENTATION_ADDRESS: [u8; 4] = [192, 0, 2, 9];


fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}


fn session_of(username: &str, token: &str, expires: u64) -> Session {
    Session {
        username: username.to_owned(),
        token: secret(token),
        csrf: String::new(),
        expires,
    }
}


async fn login_from(rig: &Harness, source: u8, cookies: Vec<String>, username: &str, password: &str) -> Result<Reply, TestError> {
    let page = fire(rig, Req { source, ..get("/login") }).await?;
    let csrf = cookie_value_of(&set_cookie_of(&page, "__Host-ostyr_login").ok_or("no login cookie")?).ok_or("no value")?;
    let mut all = cookies;
    all.push(format!("__Host-ostyr_login={csrf}"));
    let body = format!("csrf={csrf}&username={username}&password={password}&totp_code=");
    fire(
        rig,
        Req {
            source,
            ..post_form("/login", all, &body)
        },
    )
    .await
}


fn session_value(reply: &Reply) -> Result<String, TestError> {
    Ok(cookie_value_of(&set_cookie_of(reply, "__Host-ostyr_session").ok_or("no session cookie")?).ok_or("no value")?)
}


fn forwarded_seen(rig: &Harness) -> Vec<Option<String>> {
    rig.stub.state.forwarded.lock().unwrap_or_else(PoisonError::into_inner).clone()
}


fn logged_out(rig: &Harness) -> Vec<String> {
    rig.stub.state.logged_out.lock().unwrap_or_else(PoisonError::into_inner).clone()
}


#[tokio::test]
async fn every_api_call_carries_the_browser_peer() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let reply = login_from(&rig, SECOND, Vec::new(), "alice", "secret").await?;
    let session = session_value(&reply)?;
    let list = fire(
        &rig,
        Req {
            source: SECOND,
            ..get_with("/alerts", &session)
        },
    )
    .await?;
    let token = csrf_in(&list.body).ok_or("no token")?;
    let detail_path = format!("/alerts/{}", stub::id_of('a'));
    fire(
        &rig,
        Req {
            source: SECOND,
            ..get_with(&detail_path, &session)
        },
    )
    .await?;
    let cookies = vec![format!("__Host-ostyr_session={session}")];
    fire(
        &rig,
        Req {
            source: SECOND,
            ..post_form("/logout", cookies, &format!("csrf={token}"))
        },
    )
    .await?;
    let seen = forwarded_seen(&rig);
    assert_eq!(seen.len(), API_CALLS);
    assert!(seen.iter().all(|value| value.as_deref() == Some("for=127.0.0.2")));
    Ok(())
}


#[tokio::test]
async fn one_locked_source_does_not_lock_another() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    for _ in 0..LOCK_AFTER {
        let failed = login_from(&rig, FIRST, Vec::new(), "alice", "wrong").await?;
        assert_eq!(failed.status, StatusCode::UNAUTHORIZED);
    }
    let locked = login_from(&rig, FIRST, Vec::new(), "alice", "secret").await?;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    let other = login_from(&rig, SECOND, Vec::new(), "alice", "secret").await?;
    assert_eq!(other.status, StatusCode::SEE_OTHER);
    assert_eq!(location_of(&other).as_deref(), Some("/alerts"));
    Ok(())
}


#[tokio::test]
async fn a_relogin_ends_the_previous_session_at_the_api() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let first = session_value(&login_from(&rig, FIRST, Vec::new(), "multi", "secret").await?)?;
    let own = vec![format!("__Host-ostyr_session={first}")];
    let second = session_value(&login_from(&rig, FIRST, own, "multi", "secret").await?)?;
    assert_ne!(first, second);
    let gone = fire(&rig, get_with("/alerts", &first)).await?;
    assert_eq!(location_of(&gone).as_deref(), Some("/login"));
    assert_eq!(logged_out(&rig), vec!["Bearer tok-multi-0".to_owned()]);
    Ok(())
}


#[tokio::test]
async fn a_failed_remote_logout_of_the_previous_session_is_only_logged() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let first = session_value(&login_from(&rig, FIRST, Vec::new(), "multi", "secret").await?)?;
    *rig.stub.state.mode.lock().unwrap_or_else(PoisonError::into_inner) = Mode::Status(StatusCode::INTERNAL_SERVER_ERROR);
    let own = vec![format!("__Host-ostyr_session={first}")];
    let second = login_from(&rig, FIRST, own, "multi", "secret").await?;
    assert_eq!(second.status, StatusCode::SEE_OTHER);
    assert_eq!(rig.stub.state.logouts.load(Ordering::SeqCst), 1);
    Ok(())
}


#[tokio::test]
async fn the_oldest_session_of_an_account_is_dropped_and_logged_out() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    rig.state.sessions_max.store(SESSIONS, Ordering::SeqCst);
    rig.state.user_sessions_max.store(CAP, Ordering::SeqCst);
    let mut sessions = Vec::new();
    for tick in 0..LOGINS {
        rig.clock.store(tick, Ordering::SeqCst);
        sessions.push(session_value(&login_from(&rig, FIRST, Vec::new(), "multi", "secret").await?)?);
    }
    let oldest = sessions.first().ok_or("no session")?;
    let newest = sessions.last().ok_or("no session")?;
    let dropped = fire(&rig, get_with("/alerts", oldest)).await?;
    assert_eq!(location_of(&dropped).as_deref(), Some("/login"));
    let kept = fire(&rig, get_with("/alerts", newest)).await?;
    assert_eq!(kept.status, StatusCode::OK);
    assert_eq!(logged_out(&rig), vec!["Bearer tok-multi-0".to_owned()]);
    Ok(())
}


#[test]
fn eviction_removes_only_the_oldest_of_the_same_account() -> TestResult {
    let mut table = BTreeMap::new();
    table.insert("a".to_owned(), session_of("bob", "t-old", OLDEST_FIRST));
    table.insert("b".to_owned(), session_of("bob", "t-new", NEWEST));
    table.insert("c".to_owned(), session_of("bob", "t-mid", MIDDLE));
    table.insert("d".to_owned(), session_of("eve", "t-eve", 1));
    assert!(evict_oldest(&mut table, "bob", CAP + CAP).is_empty());
    let dropped = evict_oldest(&mut table, "bob", CAP);
    assert_eq!(dropped.len(), CAP);
    assert_eq!(table.len(), CAP);
    assert!(table.contains_key("b") && table.contains_key("d"));
    assert!(evict_oldest(&mut table, "nobody", 1).is_empty());
    Ok(())
}


#[test]
fn the_forwarded_element_is_an_address_literal() -> TestResult {
    let documentation = Ipv4Addr::from(DOCUMENTATION_ADDRESS);
    assert_eq!(forwarded_value(IpAddr::V4(documentation)), "for=192.0.2.9");
    assert_eq!(forwarded_value(IpAddr::V6(Ipv6Addr::LOCALHOST)), "for=\"[::1]\"");
    assert_eq!(forwarded_value(IpAddr::V6(documentation.to_ipv6_mapped())), "for=192.0.2.9");
    assert!(header_from_text("for=1.2.3.4").is_ok());
    assert!(matches!(header_from_text("for=1\n"), Err(ApiFailure::Malformed(_))));
    Ok(())
}


#[tokio::test]
async fn the_api_pool_is_bounded_and_released() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let base = build_client(&ApiSection {
        base_url: format!("http://{}/", rig.stub.address),
        ca: None,
        timeout_seconds: 1,
        max_connections: POOL,
    })?;
    let token = secret(TOKEN);
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert_eq!(base.permits.available_permits(), POOL);
    assert!(list_alerts(&base, source, &token, None, None).await.is_ok());
    assert_eq!(base.permits.available_permits(), POOL);
    let starved = ApiClient {
        permits: Arc::new(Semaphore::new(0)),
        deadline: BLOCKED_WAIT,
        ..base
    };
    assert!(matches!(
        list_alerts(&starved, source, &token, None, None).await,
        Err(ApiFailure::Throttled)
    ));
    starved.permits.close();
    assert!(matches!(
        list_alerts(&starved, source, &token, None, None).await,
        Err(ApiFailure::Throttled)
    ));
    Ok(())
}


#[tokio::test]
async fn logins_hold_at_most_half_of_the_pool() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let base = build_client(&ApiSection {
        base_url: format!("http://{}/", rig.stub.address),
        ca: None,
        timeout_seconds: 1,
        max_connections: POOL,
    })?;
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert_eq!((login_slots(1), login_slots(POOL), login_slots(FULL_POOL)), (1, 1, HALF_POOL));
    assert_eq!(base.login_permits.available_permits(), 1);
    assert!(login(&base, source, "alice", "secret", None).await.is_ok());
    assert_eq!((base.login_permits.available_permits(), base.permits.available_permits()), (1, POOL));
    let held = base.login_permits.clone().acquire_owned().await?;
    let patient = ApiClient {
        http: base.http.clone(),
        base: base.base.clone(),
        permits: base.permits.clone(),
        login_permits: base.login_permits.clone(),
        deadline: base.deadline,
    };
    let starved = ApiClient {
        deadline: BLOCKED_WAIT,
        ..base
    };
    assert!(matches!(
        login(&starved, source, "alice", "secret", None).await,
        Err(ApiFailure::Throttled)
    ));
    assert!(list_alerts(&patient, source, &secret(TOKEN), None, None).await.is_ok());
    drop(held);
    starved.login_permits.close();
    assert!(matches!(
        login(&starved, source, "alice", "secret", None).await,
        Err(ApiFailure::Throttled)
    ));
    Ok(())
}


#[tokio::test]
async fn accounts_that_differ_only_by_case_never_evict_each_other() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    rig.state.sessions_max.store(SESSIONS, Ordering::SeqCst);
    rig.state.user_sessions_max.store(CAP, Ordering::SeqCst);
    let lower = session_value(&login_from(&rig, FIRST, Vec::new(), "alice", "secret").await?)?;
    let mut upper = Vec::new();
    for tick in 0..LOGINS {
        rig.clock.store(tick, Ordering::SeqCst);
        upper.push(session_value(&login_from(&rig, FIRST, Vec::new(), "Alice", "secret").await?)?);
    }
    assert_eq!(fire(&rig, get_with("/alerts", &lower)).await?.status, StatusCode::OK);
    let first_upper = upper.first().ok_or("no session")?;
    assert_eq!(
        location_of(&fire(&rig, get_with("/alerts", first_upper)).await?).as_deref(),
        Some("/login")
    );
    assert_eq!(logged_out(&rig), vec!["Bearer tok-upper-1".to_owned()]);
    Ok(())
}


#[tokio::test]
async fn a_full_session_table_logs_the_new_token_out_at_the_api() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    sign_in(&rig).await?;
    sign_in(&rig).await?;
    let full = login_from(&rig, FIRST, Vec::new(), "multi", "secret").await?;
    assert_eq!(full.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(logged_out(&rig), vec!["Bearer tok-multi-2".to_owned()]);
    Ok(())
}


const DEADLINE_SECONDS: u64 = 4;


const RELEASE_SECONDS: u64 = 2;


const WHOLE_POOL: u32 = 3;


#[tokio::test(start_paused = true)]
async fn a_login_waits_one_deadline_for_its_slot_and_its_request() -> TestResult {
    let client = build_client(&ApiSection {
        base_url: "http://127.0.0.1:1/".to_owned(),
        ca: None,
        timeout_seconds: DEADLINE_SECONDS,
        max_connections: POOL,
    })?;
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let all_calls = client.permits.clone().acquire_many_owned(WHOLE_POOL).await?;
    let slot = client.login_permits.clone().acquire_owned().await?;
    let releaser = tokio::spawn(async move {
        sleep(Duration::from_secs(RELEASE_SECONDS)).await;
        drop(slot);
    });
    let started = Instant::now();
    let outcome = login(&client, source, "alice", "secret", None).await;
    releaser.await?;
    assert!(matches!(outcome, Err(ApiFailure::Throttled)));
    assert_eq!(started.elapsed(), client.deadline);
    drop(all_calls);
    Ok(())
}


const HOLD_SECONDS: u64 = 1;


#[tokio::test(start_paused = true)]
async fn the_request_gets_only_the_time_left_after_the_slots() -> TestResult {
    let silent = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let client = build_client(&ApiSection {
        base_url: format!("http://{}/", silent.local_addr()?),
        ca: None,
        timeout_seconds: DEADLINE_SECONDS,
        max_connections: POOL,
    })?;
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let slot = client.login_permits.clone().acquire_owned().await?;
    let releaser = tokio::spawn(async move {
        sleep(Duration::from_secs(HOLD_SECONDS)).await;
        drop(slot);
    });
    let started = Instant::now();
    let outcome = login(&client, source, "alice", "secret", None).await;
    releaser.await?;
    assert!(matches!(outcome, Err(ApiFailure::Unavailable(_))));
    assert_eq!(started.elapsed(), client.deadline);
    Ok(())
}


const LONGEST_CASE_ID: usize = 128;


const CLIPPED_RUN: usize = 300;


const UNLINKED_CASES: usize = 6;


fn case_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.case_paths.lock().map_err(|_| "poisoned")?.clone())
}


fn set_mode(rig: &Harness, mode: Mode) -> TestResult {
    *rig.stub.state.mode.lock().map_err(|_| "poisoned")? = mode;
    Ok(())
}


#[tokio::test]
async fn case_list_and_detail_are_rendered() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/cases\""));
    let first = fire(&rig, get_with("/cases", &session)).await?;
    assert_eq!(first.status, StatusCode::OK);
    assert_hardened(&first);
    assert!(first.body.contains("Phishing wave") && first.body.contains("Ransomware"));
    assert!(first.body.contains("action=\"/cases/case-1\"") && first.body.contains("action=\"/cases/case-2\""));
    assert!(first.body.contains(&format!("name=\"cursor\" value=\"{FIRST_CURSOR}\"")));
    assert!(first.body.contains("In progress") && first.body.contains("2023-11-14T22:13:20Z") && first.body.contains("bob"));
    assert!(!first.body.contains("name=\"limit\""));
    let limited = fire(&rig, get_with("/cases?limit=5", &session)).await?;
    assert!(limited.body.contains("name=\"limit\" value=\"5\""));
    let second = fire(&rig, get_with(&format!("/cases?cursor={FIRST_CURSOR}&limit=5"), &session)).await?;
    assert!(second.body.contains("Old case") && !second.body.contains("Older cases"));
    let detail = fire(&rig, get_with("/cases/case-1", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_hardened(&detail);
    for expected in [
        "Phishing wave",
        "Initial description",
        "Benign",
        "phishing",
        "Isolate host",
        "(In progress)",
        "due 2023-11-14T22:13:20Z",
        "<dd>6</dd>",
        "<dd>3</dd>",
        "Back to the cases",
    ] {
        assert!(detail.body.contains(expected), "{expected}: {}", detail.body);
    }
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with("/cases/case-1", &session)
        },
    )
    .await?;
    assert!(french.body.contains("Résolution") && french.body.contains("Bénin") && french.body.contains("Retour aux dossiers"));
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/cases", &session)).await?;
    assert!(empty.body.contains("No case."));
    let empty_french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with("/cases", &session)
        },
    )
    .await?;
    assert!(empty_french.body.contains("Aucun dossier."));
    Ok(())
}


#[tokio::test]
async fn hostile_case_list_is_escaped_clipped_and_unlinked() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/cases", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert!(!list.body.contains("<script>") && !list.body.contains("<img") && !list.body.contains("</style>"));
    assert!(!list.body.contains('\u{202e}'));
    assert!(list.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;'&lt;/td&gt;&amp;amp;"));
    assert!(list.body.contains("&lt;img src=x&gt;&lt;/style&gt;"));
    assert!(list.body.contains("omitted") && !list.body.contains(&"h".repeat(CLIPPED_RUN)));
    assert_eq!(list.body.matches("&lt;img src=x&gt;&lt;/style&gt;").count(), HOSTILE_TITLED_CASES);
    assert_eq!(list.body.matches("... [").count(), HOSTILE_TITLED_CASES);
    assert_eq!(
        list.body
            .matches("&lt;script&gt;alert(1)&lt;/script&gt;&quot;'&lt;/td&gt;&amp;amp;")
            .count(),
        HOSTILE_LIST_SITES
    );
    assert!(list.body.contains("action=\"/cases/case-1\""));
    for forbidden in ["/cases/../x", "/cases/-x", "/cases/a/b", "/cases/%2e%2e", "/cases/line"] {
        assert!(!list.body.contains(forbidden), "{forbidden}");
    }
    assert!(!list.body.contains(&"i".repeat(stub::LONG_CASE_ID_CHARS)));
    assert_eq!(list.body.matches("not linkable").count(), UNLINKED_CASES);
    assert!(list.body.contains("unknown") && !without_tokens(&list.body).contains("weird"));
    assert_eq!(case_requests(&rig)?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn ids_outside_the_grammar_are_not_found_without_a_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let anonymous = fire(&rig, get("/cases/case-1")).await?;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    let session = sign_in(&rig).await?;
    let long = "i".repeat(stub::LONG_CASE_ID_CHARS);
    for bad in ["-x", "_x", ".x", &long, "..%2Fx", "a%2Fb", "%2e%2e", "line%0Afeed", "a%20b", "caf%C3%A9"] {
        let reply = fire(&rig, get_with(&format!("/cases/{bad}"), &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{bad}");
    }
    assert!(case_requests(&rig)?.is_empty());
    let edge = "a".repeat(LONGEST_CASE_ID);
    let accepted = fire(&rig, get_with(&format!("/cases/{edge}"), &session)).await?;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(case_requests(&rig)?, vec![format!("/cases/{edge}")]);
    Ok(())
}


#[tokio::test]
async fn hostile_case_detail_is_escaped_and_bounded() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let detail = fire(&rig, get_with("/cases/case-1", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(!detail.body.contains("<script>") && !detail.body.contains('\u{202e}'));
    assert!(detail.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;'&lt;/td&gt;&amp;amp;"));
    assert!({
        let cleaned = without_tokens(&detail.body);
        ["weird", "mystery", "odd", "urgent"].iter().all(|word| !cleaned.contains(word))
    });
    assert!(detail.body.contains("unknown"));
    assert!(detail.body.contains("6 omitted"));
    assert!(!detail.body.contains("<img") && !detail.body.contains("</style>"));
    assert_eq!(detail.body.matches("&lt;script&gt;alert(1)&lt;/script&gt;").count(), DETAIL_HOSTILE_SITES);
    assert!(!without_tokens(&detail.body).contains("task69"));
    assert!(!detail.body.contains("9223372036854775807"));
    Ok(())
}


#[tokio::test]
async fn case_api_failures_render_our_own_pages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (mode, path, status) in [
        (Mode::Status(StatusCode::FORBIDDEN), "/cases", StatusCode::FORBIDDEN),
        (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), "/cases", StatusCode::BAD_GATEWAY),
        (Mode::Oversize, "/cases", StatusCode::BAD_GATEWAY),
        (Mode::TooMany, "/cases", StatusCode::BAD_GATEWAY),
        (Mode::BadCursor, "/cases", StatusCode::BAD_GATEWAY),
        (Mode::Status(StatusCode::FORBIDDEN), "/cases/case-1", StatusCode::FORBIDDEN),
        (Mode::Status(StatusCode::NOT_FOUND), "/cases/case-1", StatusCode::NOT_FOUND),
        (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), "/cases/case-1", StatusCode::BAD_GATEWAY),
        (Mode::Oversize, "/cases/case-1", StatusCode::BAD_GATEWAY),
        (Mode::BadId, "/cases/case-1", StatusCode::BAD_GATEWAY),
        (Mode::Normal, "/cases/missing", StatusCode::NOT_FOUND),
        (Mode::Normal, "/cases?cursor=a%20b", StatusCode::BAD_REQUEST),
        (Mode::Normal, "/cases?limit=0", StatusCode::BAD_REQUEST),
    ] {
        set_mode(&rig, mode)?;
        let reply = fire(&rig, get_with(path, &session)).await?;
        assert_eq!(reply.status, status, "{path}");
        assert!(!reply.body.contains(LEAK));
        assert_hardened(&reply);
    }
    for path in ["/cases", "/cases/case-1"] {
        let again = sign_in(&rig).await?;
        set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
        let ended = fire(&rig, get_with(path, &again)).await?;
        assert_eq!(ended.status, StatusCode::SEE_OTHER);
        assert_eq!(location_of(&ended).as_deref(), Some("/login"));
        let gone = fire(&rig, get_with(path, &again)).await?;
        assert_eq!(location_of(&gone).as_deref(), Some("/login"));
        set_mode(&rig, Mode::Normal)?;
    }
    Ok(())
}


const COMMENT_CAP: usize = 8192;


const WRITES_AFTER_BLANK: usize = 2;


const OVER_THE_FORM: usize = 120_000;


fn writes_of(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.writes.lock().map_err(|_| "poisoned")?.clone())
}


fn requests_of(rig: &Harness) -> usize {
    rig.stub.state.requests.load(Ordering::SeqCst)
}


fn set_conflict(rig: &Harness, code: Option<&str>) -> TestResult {
    *rig.stub.state.conflict.lock().map_err(|_| "poisoned")? = code.map(str::to_owned);
    Ok(())
}


fn encoded(fields: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    fields.iter().for_each(|(name, value)| {
        serializer.append_pair(name, value);
    });
    serializer.finish()
}


async fn csrf_of(rig: &Harness, session: &str) -> Result<String, TestError> {
    let page = fire(rig, get_with("/cases/case-1", session)).await?;
    Ok(csrf_in(&page.body).ok_or("no token in the page")?)
}


async fn write_form(rig: &Harness, session: &str, path: &str, fields: &[(&str, &str)]) -> Result<Reply, TestError> {
    let token = csrf_of(rig, session).await?;
    let mut all = vec![("csrf", token.as_str())];
    all.extend_from_slice(fields);
    fire(rig, post_form(path, vec![format!("{SESSION_COOKIE}={session}")], &encoded(&all))).await
}


#[tokio::test]
async fn case_pages_offer_the_forms_of_their_status() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (id, offered, refused) in [
        ("case-new", vec!["start", "close"], vec!["reopen"]),
        ("case-1", vec!["close"], vec!["start", "reopen"]),
        ("case-closed", vec!["reopen"], vec!["start", "close"]),
    ] {
        let page = fire(&rig, get_with(&format!("/cases/{id}"), &session)).await?;
        assert!(page.body.contains(&format!("action=\"/cases/{id}/comment\"")), "{id}");
        assert!(page.body.contains(&format!("maxlength=\"{COMMENT_CAP}\"")) && page.body.contains("<textarea"));
        offered.iter().for_each(|action| {
            assert!(page.body.contains(&format!("name=\"action\" value=\"{action}\"")), "{id} {action}");
        });
        refused.iter().for_each(|action| {
            assert!(!page.body.contains(&format!("name=\"action\" value=\"{action}\"")), "{id} {action}");
        });
        assert_eq!(page.body.contains("<select name=\"resolution\""), offered.contains(&"close"), "{id}");
    }
    let page = fire(&rig, get_with("/cases/case-new", &session)).await?;
    for resolution in ["true_positive", "false_positive", "benign", "duplicate", "other"] {
        assert!(page.body.contains(&format!("<option value=\"{resolution}\">")), "{resolution}");
    }
    assert!(page.body.contains("action=\"/cases/case-new/action\"") && page.body.contains("Add comment"));
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with("/cases/case-closed", &session)
        },
    )
    .await?;
    assert!(french.body.contains("Rouvrir") && french.body.contains("Ajouter le commentaire"));
    set_mode(&rig, Mode::Hostile)?;
    let weird = fire(&rig, get_with("/cases/case-1", &session)).await?;
    assert!(!weird.body.contains("name=\"action\"") && weird.body.contains("action=\"/cases/case-1/comment\""));
    assert!(writes_of(&rig)?.is_empty());
    Ok(())
}


#[tokio::test]
async fn every_action_runs_from_its_status() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let started = write_form(&rig, &session, "/cases/case-new/action", &[("action", "start")]).await?;
    assert_eq!(started.status, StatusCode::OK);
    assert_hardened(&started);
    assert!(started.body.contains("In progress") && started.body.contains("Phishing wave") && location_of(&started).is_none());
    let closed = write_form(
        &rig,
        &session,
        "/cases/case-1/action",
        &[("action", "close"), ("resolution", "false_positive")],
    )
    .await?;
    assert_eq!(closed.status, StatusCode::OK);
    assert!(closed.body.contains("Closed") && closed.body.contains("False positive"));
    let reopened = write_form(&rig, &session, "/cases/case-closed/action", &[("action", "reopen")]).await?;
    assert_eq!(reopened.status, StatusCode::OK);
    assert!(reopened.body.contains("In progress"));
    let from_new = write_form(&rig, &session, "/cases/case-new/action", &[("action", "close"), ("resolution", "other")]).await?;
    assert_eq!(from_new.status, StatusCode::OK);
    assert_eq!(
        writes_of(&rig)?,
        vec![
            "/cases/case-new/actions {\"action\":\"start\",\"resolution\":null}".to_owned(),
            "/cases/case-1/actions {\"action\":\"close\",\"resolution\":\"false_positive\"}".to_owned(),
            "/cases/case-closed/actions {\"action\":\"reopen\",\"resolution\":null}".to_owned(),
            "/cases/case-new/actions {\"action\":\"close\",\"resolution\":\"other\"}".to_owned(),
        ]
    );
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..post_form(
                "/cases/case-1/action",
                vec![format!("{SESSION_COOKIE}={session}")],
                &encoded(&[("csrf", &csrf_of(&rig, &session).await?), ("action", "close"), ("resolution", "benign")]),
            )
        },
    )
    .await?;
    assert!(french.body.contains("Clos"));
    Ok(())
}


#[tokio::test]
async fn a_write_without_the_session_token_is_refused_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let other = sign_in(&rig).await?;
    let foreign = csrf_of(&rig, &other).await?;
    let cookie = vec![format!("{SESSION_COOKIE}={session}")];
    for path in ["/cases/case-1/action", "/cases/case-1/comment"] {
        let fields = if path.ends_with("action") { "action=start" } else { "text=hello" };
        for body in [
            fields.to_owned(),
            format!("csrf=&{fields}"),
            format!("csrf=wrong&{fields}"),
            format!("csrf={foreign}&{fields}"),
        ] {
            let reply = fire(&rig, post_form(path, cookie.clone(), &body)).await?;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{path} {body}");
            assert!(reply.body.contains("no longer valid"));
        }
        let anonymous = fire(&rig, post_form(path, vec![], &format!("csrf={foreign}&{fields}"))).await?;
        assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
        assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    }
    assert!(writes_of(&rig)?.is_empty());
    Ok(())
}


#[tokio::test]
async fn ids_outside_the_grammar_are_not_found_on_a_write() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let before = requests_of(&rig);
    let mut attempts = 0;
    for bad in ["bad%2Fid", "..%2Fx", "-x", "a%20b", "%2e%2e"] {
        for (leaf, fields) in [("action", ("action", "start")), ("comment", ("text", "hello"))] {
            let reply = write_form(&rig, &session, &format!("/cases/{bad}/{leaf}"), &[fields]).await?;
            attempts += 1;
            assert_eq!(reply.status, StatusCode::NOT_FOUND, "{bad} {leaf}");
        }
    }
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, attempts);
    Ok(())
}


#[tokio::test]
async fn an_action_outside_the_fixed_tables_is_refused_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for fields in [
        vec![],
        vec![("action", "")],
        vec![("action", "delete")],
        vec![("action", "Start")],
        vec![("action", "close")],
        vec![("action", "close"), ("resolution", "mystery")],
        vec![("action", "close"), ("resolution", "")],
        vec![("action", "start"), ("resolution", "benign")],
        vec![("action", "reopen"), ("resolution", "mystery")],
    ] {
        let reply = write_form(&rig, &session, "/cases/case-1/action", &fields).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{fields:?}");
    }
    assert!(writes_of(&rig)?.is_empty());
    let started = write_form(&rig, &session, "/cases/case-new/action", &[("action", "start"), ("resolution", "")]).await?;
    assert_eq!(started.status, StatusCode::OK);
    assert_eq!(writes_of(&rig)?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_comment_is_bounded_in_characters_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let over = "é".repeat(COMMENT_CAP + 1);
    for text in ["", over.as_str()] {
        let reply = write_form(&rig, &session, "/cases/case-1/comment", &[("text", text)]).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", text.len());
    }
    let missing = write_form(&rig, &session, "/cases/case-1/comment", &[]).await?;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    let huge = "x".repeat(OVER_THE_FORM);
    let too_large = write_form(&rig, &session, "/cases/case-1/comment", &[("text", &huge)]).await?;
    assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(writes_of(&rig)?.is_empty());
    let exact = "é".repeat(COMMENT_CAP);
    let accepted = write_form(&rig, &session, "/cases/case-1/comment", &[("text", &exact)]).await?;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(writes_of(&rig)?.len(), 1);
    assert!(accepted.body.contains("Comment added") && accepted.body.contains("... ["));
    let blank = write_form(&rig, &session, "/cases/case-1/comment", &[("text", "  ")]).await?;
    assert_eq!(blank.status, StatusCode::OK);
    assert_eq!(writes_of(&rig)?.len(), WRITES_AFTER_BLANK);
    Ok(())
}


#[tokio::test]
async fn a_comment_is_shown_as_the_api_stored_it() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let reply = write_form(&rig, &session, "/cases/case-1/comment", &[("text", "first note\nsecond")]).await?;
    assert_eq!(reply.status, StatusCode::OK);
    assert_hardened(&reply);
    assert!(reply.body.contains("first note<br>second<br>"));
    assert!(reply.body.contains("Comment added") && reply.body.contains("alice") && reply.body.contains("2023-11-14T22:13:20Z"));
    assert!(reply.body.contains("Phishing wave") && reply.body.contains("action=\"/cases/case-1/comment\""));
    assert_eq!(
        writes_of(&rig)?,
        vec!["/cases/case-1/comments {\"text\":\"first note\\nsecond\"}".to_owned()]
    );
    Ok(())
}


#[tokio::test]
async fn a_hostile_comment_from_the_api_is_rendered_escaped() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    set_mode(&rig, Mode::Hostile)?;
    let reply = write_form(&rig, &session, "/cases/case-1/comment", &[("text", "<script>alert(2)</script>\u{202e}")]).await?;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(!reply.body.contains("<script>") && !reply.body.contains('\u{202e}') && !reply.body.contains("alert(2)"));
    assert!(reply.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;'&lt;/td&gt;&amp;amp;"));
    assert!(!reply.body.contains("<img src=x>") && reply.body.contains("&quot;&gt;&lt;img src=x&gt;\u{fffd}aaa"));
    assert!(reply.body.contains("... ["));
    Ok(())
}


#[tokio::test]
async fn a_submitted_comment_is_never_echoed_from_the_form() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    set_conflict(&rig, Some("full"))?;
    let refused = write_form(&rig, &session, "/cases/case-1/comment", &[("text", "SUBMITTED-MARKER")]).await?;
    assert!(!refused.body.contains("SUBMITTED-MARKER"));
    let bad = write_form(&rig, &session, "/cases/case-1/comment", &[("text", "")]).await?;
    assert!(!bad.body.contains("SUBMITTED-MARKER"));
    Ok(())
}


fn set_read_fault(rig: &Harness, fault: ReadFault) -> TestResult {
    *rig.stub.state.read_fault.lock().map_err(|_| "poisoned")? = Some(fault);
    Ok(())
}


fn clear_read_fault(rig: &Harness) -> TestResult {
    *rig.stub.state.read_fault.lock().map_err(|_| "poisoned")? = None;
    Ok(())
}


fn assert_stored_notice(reply: &Reply, language_text: &str) {
    assert_eq!(reply.status, StatusCode::OK);
    assert_hardened(reply);
    assert!(reply.body.contains(language_text), "{}", reply.body);
    assert!(reply.body.contains("Comment added") && reply.body.contains("STORED-REPLY") && reply.body.contains("alice"));
    assert!(!reply.body.contains(LEAK) && !reply.body.contains("SUBMITTED-MARKER") && !reply.body.contains("Phishing wave"));
}


async fn failed_reread(fault: ReadFault) -> Result<(Harness, String, Reply), TestError> {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let token = csrf_of(&rig, &session).await?;
    set_read_fault(&rig, fault)?;
    let body = encoded(&[("csrf", token.as_str()), ("text", "STORED-REPLY")]);
    let reply = fire(
        &rig,
        post_form("/cases/case-1/comment", vec![format!("{SESSION_COOKIE}={session}")], &body),
    )
    .await?;
    Ok((rig, session, reply))
}


#[tokio::test]
async fn a_failed_reread_shows_the_stored_comment_and_our_text() -> TestResult {
    for status in [StatusCode::INTERNAL_SERVER_ERROR, StatusCode::BAD_GATEWAY, StatusCode::NOT_FOUND] {
        let (rig, session, reply) = failed_reread(ReadFault::Status(status)).await?;
        assert_stored_notice(&reply, "Comment stored; the case could not be reloaded.");
        assert!(reply.body.contains("action=\"/cases/case-1\"") && reply.body.contains("Reload the case"));
        assert!(reply.body.contains("name=\"csrf\"") || reply.body.contains("/language/"));
        assert_eq!(writes_of(&rig)?, vec!["/cases/case-1/comments {\"text\":\"STORED-REPLY\"}".to_owned()]);
        clear_read_fault(&rig)?;
        let next = fire(&rig, get_with("/cases/case-1", &session)).await?;
        assert_eq!(next.status, StatusCode::OK);
    }
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_timed_out_reread_shows_the_stored_comment_and_our_text() -> TestResult {
    let (rig, _session, reply) = failed_reread(ReadFault::Hang).await?;
    assert_stored_notice(&reply, "Comment stored; the case could not be reloaded.");
    assert_eq!(writes_of(&rig)?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn an_unauthorised_reread_ends_the_session_after_the_stored_notice() -> TestResult {
    let (rig, session, reply) = failed_reread(ReadFault::Status(StatusCode::UNAUTHORIZED)).await?;
    assert_stored_notice(&reply, "Comment stored; sign in again to continue.");
    assert!(reply.body.contains("action=\"/login\"") && !reply.body.contains("action=\"/cases/case-1\""));
    let cleared = set_cookie_of(&reply, SESSION_COOKIE).ok_or("no cleared cookie")?;
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert_eq!(writes_of(&rig)?.len(), 1);
    clear_read_fault(&rig)?;
    let next = fire(&rig, get_with("/cases/case-1", &session)).await?;
    assert_eq!(next.status, StatusCode::SEE_OTHER);
    Ok(())
}


#[tokio::test]
async fn a_failed_reread_page_renders_the_stored_comment_escaped() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let token = csrf_of(&rig, &session).await?;
    set_mode(&rig, Mode::Hostile)?;
    set_read_fault(&rig, ReadFault::Status(StatusCode::BAD_GATEWAY))?;
    let body = encoded(&[("csrf", token.as_str()), ("text", "SUBMITTED-MARKER")]);
    let reply = fire(
        &rig,
        post_form("/cases/case-1/comment", vec![format!("{SESSION_COOKIE}={session}")], &body),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(!reply.body.contains("<script>") && !reply.body.contains("SUBMITTED-MARKER") && !reply.body.contains('\u{202e}'));
    assert!(reply.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;'&lt;/td&gt;&amp;amp;"));
    assert!(reply.body.contains("&quot;&gt;&lt;img src=x&gt;\u{fffd}aaa"));
    Ok(())
}


#[tokio::test]
async fn each_conflict_code_is_rendered_with_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (code, expected) in [
        ("transition_not_allowed", "not allowed in the current status"),
        ("resolution_required", "Choose a resolution"),
        ("case_changed", "changed meanwhile"),
        ("full", "maximum number of comments"),
    ] {
        set_conflict(&rig, Some(code))?;
        let action = write_form(&rig, &session, "/cases/case-1/action", &[("action", "reopen")]).await?;
        let comment = write_form(&rig, &session, "/cases/case-1/comment", &[("text", "hello")]).await?;
        for reply in [action, comment] {
            assert_eq!(reply.status, StatusCode::CONFLICT, "{code}");
            assert!(
                reply.body.contains(expected) && !reply.body.contains(LEAK) && !reply.body.contains(code),
                "{code}"
            );
            assert_hardened(&reply);
        }
    }
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..post_form(
                "/cases/case-1/comment",
                vec![format!("{SESSION_COOKIE}={session}")],
                &encoded(&[("csrf", &csrf_of(&rig, &session).await?), ("text", "bonjour")]),
            )
        },
    )
    .await?;
    assert!(french.body.contains("nombre maximal"));
    for code in ["something_else", stub::RAW_CONFLICT] {
        set_conflict(&rig, Some(code))?;
        let reply = write_form(&rig, &session, "/cases/case-1/action", &[("action", "reopen")]).await?;
        assert_eq!(reply.status, StatusCode::BAD_GATEWAY, "{code}");
        assert!(!reply.body.contains(LEAK));
    }
    Ok(())
}


#[tokio::test]
async fn api_failures_on_a_write_render_our_own_pages() -> TestResult {
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
        for (path, fields) in [
            ("/cases/case-1/action", ("action", "reopen")),
            ("/cases/case-1/comment", ("text", "hello")),
        ] {
            let reply = fire(
                &rig,
                post_form(path, vec![format!("{SESSION_COOKIE}={session}")], &encoded(&[("csrf", &token), fields])),
            )
            .await?;
            let stored_then_unreadable = mode == Mode::BadId && path.ends_with("comment");
            assert_eq!(reply.status, if stored_then_unreadable { StatusCode::OK } else { status }, "{path}");
            assert!(!reply.body.contains(LEAK));
        }
        set_mode(&rig, Mode::Normal)?;
    }
    for (path, fields) in [
        ("/cases/case-1/action", ("action", "reopen")),
        ("/cases/case-1/comment", ("text", "hello")),
    ] {
        let again = sign_in(&rig).await?;
        let token = csrf_of(&rig, &again).await?;
        set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
        let ended = fire(
            &rig,
            post_form(path, vec![format!("{SESSION_COOKIE}={again}")], &encoded(&[("csrf", &token), fields])),
        )
        .await?;
        assert_eq!(ended.status, StatusCode::SEE_OTHER);
        assert_eq!(location_of(&ended).as_deref(), Some("/login"));
        set_mode(&rig, Mode::Normal)?;
        let gone = fire(&rig, get_with("/cases/case-1", &again)).await?;
        assert_eq!(location_of(&gone).as_deref(), Some("/login"));
    }
    Ok(())
}


#[tokio::test]
async fn the_api_calls_refuse_an_invalid_id_without_a_request() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let client = rig.state.api.load_full();
    let token = SecretString::from("tok-x".to_owned());
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let long = "i".repeat(stub::LONG_CASE_ID_CHARS);
    for bad in ["../x", "-x", "a b", "x?y", "", long.as_str()] {
        let action = web_ui::api::post_case_action(&client, source, &token, bad, "start", None).await;
        assert!(matches!(action, Err(ApiFailure::NotFound)), "{bad}");
        let comment = web_ui::api::post_case_comment(&client, source, &token, bad, "hello").await;
        assert!(matches!(comment, Err(ApiFailure::NotFound)), "{bad}");
        let detail = web_ui::api::get_case(&client, source, &token, bad).await;
        assert!(matches!(detail, Err(ApiFailure::NotFound)), "{bad}");
    }
    assert_eq!(requests_of(&rig), 0);
    assert!(writes_of(&rig)?.is_empty());
    let accepted = web_ui::api::post_case_comment(&client, source, &token, "x.y_z-1", "hello").await;
    assert!(accepted.is_ok());
    assert_eq!(requests_of(&rig), 1);
    Ok(())
}


#[tokio::test]
async fn each_failure_has_a_fixed_class_name() -> TestResult {
    let client = build_client(&ApiSection {
        base_url: "http://127.0.0.1:1/".to_owned(),
        ca: None,
        timeout_seconds: 1,
        max_connections: 1,
    })?;
    let token = SecretString::from("t".to_owned());
    let unavailable = web_ui::api::get_case(&client, IpAddr::V4(Ipv4Addr::LOCALHOST), &token, "ok-1")
        .await
        .err()
        .ok_or("no failure")?;
    let json = serde_json::from_str::<u8>("x").err().ok_or("no json error")?;
    let classes = [
        (ApiFailure::Unauthorized, "unauthorized"),
        (ApiFailure::Forbidden, "forbidden"),
        (ApiFailure::NotFound, "not_found"),
        (ApiFailure::Throttled, "throttled"),
        (ApiFailure::BadRequest, "bad_request"),
        (unavailable, "unavailable"),
        (ApiFailure::Conflict("full"), "conflict"),
        (ApiFailure::Status(UPSTREAM_STATUS), "status"),
        (ApiFailure::Unreadable, "unreadable"),
        (ApiFailure::TooLarge, "too_large"),
        (ApiFailure::Malformed("x"), "malformed"),
        (ApiFailure::from(json), "json"),
    ];
    for (failure, expected) in &classes {
        assert_eq!(failure_class(failure), *expected);
    }
    Ok(())
}


#[derive(Clone, Default)]
struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);


impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn capture_logs(buffer: &LogBuffer) -> tracing::dispatcher::DefaultGuard {
    let writer = buffer.clone();
    tracing::dispatcher::set_default(&logging::capture_dispatch(move || writer.clone()))
}


fn logged_text(buffer: &LogBuffer) -> String {
    String::from_utf8_lossy(&buffer.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
}


fn kill_api(rig: &Harness) -> TestResult {
    let dead = build_client(&ApiSection {
        base_url: "http://127.0.0.1:1/".to_owned(),
        ca: None,
        timeout_seconds: 1,
        max_connections: POOL,
    })?;
    rig.state.api.store(Arc::new(dead));
    Ok(())
}


fn assert_class_only(logs: &str, class: &str) {
    assert!(logs.contains("did not confirm the logout"), "{logs}");
    assert!(logs.contains(&format!("class=\"{class}\"")), "{logs}");
    assert!(!logs.contains("127.0.0.1"), "{logs}");
    assert!(!logs.contains("failure="), "{logs}");
}


#[tokio::test]
async fn a_failed_logout_logs_the_failure_class_only() -> TestResult {
    for (class, dead) in [("status", false), ("unavailable", true)] {
        let rig = harness(Mode::Normal).await?;
        let session = sign_in(&rig).await?;
        let page = fire(&rig, get_with("/alerts", &session)).await?;
        let csrf = csrf_in(&page.body).ok_or("no csrf")?;
        *rig.stub.state.mode.lock().map_err(|_| "poisoned")? = Mode::Status(StatusCode::INTERNAL_SERVER_ERROR);
        if dead {
            kill_api(&rig)?;
        }
        let buffer = LogBuffer::default();
        let guard = capture_logs(&buffer);
        let out = fire(&rig, post_form("/logout", session_cookie(&session), &format!("csrf={csrf}"))).await?;
        drop(guard);
        assert_eq!(out.status, StatusCode::SEE_OTHER);
        assert_class_only(&logged_text(&buffer), class);
    }
    Ok(())
}


#[tokio::test]
async fn a_failed_relogin_logout_logs_the_failure_class_only() -> TestResult {
    for (class, dead) in [("status", false), ("unavailable", true)] {
        let rig = harness(Mode::Normal).await?;
        let first = session_value(&login_from(&rig, FIRST, Vec::new(), "multi", "secret").await?)?;
        *rig.stub.state.mode.lock().map_err(|_| "poisoned")? = Mode::Status(StatusCode::INTERNAL_SERVER_ERROR);
        let own = vec![format!("__Host-ostyr_session={first}")];
        let buffer = LogBuffer::default();
        let guard = capture_logs(&buffer);
        if dead {
            let state_tokens = vec![SecretString::from("tok-multi-0".to_owned())];
            kill_api(&rig)?;
            web_ui::routes::end_remote(&rig.state.api.load_full(), IpAddr::V4(Ipv4Addr::LOCALHOST), &state_tokens).await;
        } else {
            let second = login_from(&rig, FIRST, own, "multi", "secret").await?;
            assert_eq!(second.status, StatusCode::SEE_OTHER);
        }
        drop(guard);
        assert_class_only(&logged_text(&buffer), class);
    }
    Ok(())
}


const PAIR: usize = 2;


const SHOWN_VALUE_CHARS: usize = 400;


const CLIP_CHARS: usize = 512;


const HOSTILE_UNREADABLE_ROWS: usize = 8;


fn asset_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.asset_paths.lock().map_err(|_| "poisoned")?.clone())
}


fn api_requests(rig: &Harness) -> usize {
    rig.stub.state.requests.load(Ordering::SeqCst)
}


#[tokio::test]
async fn asset_list_and_detail_are_rendered() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/assets\""));
    let first = fire(&rig, get_with("/assets", &session)).await?;
    assert_eq!(first.status, StatusCode::OK);
    assert_hardened(&first);
    let odd_link = format!("action=\"/assets/{}\"", encode_asset_id(ODD_ASSET_ID));
    assert_eq!(encode_asset_id(ODD_ASSET_ID), "serial%3AA%2FB%3Fc%23d%20%25e%20%C3%A9");
    assert!(first.body.contains(&odd_link), "{}", first.body);
    assert!(first.body.contains("action=\"/assets/srv-1\"") && first.body.contains("switch") && first.body.contains("active"));
    assert!(first.body.contains(&format!("name=\"cursor\" value=\"{FIRST_CURSOR}\"")) && !first.body.contains("name=\"limit\""));
    let limited = fire(&rig, get_with("/assets?limit=5", &session)).await?;
    assert!(limited.body.contains("name=\"limit\" value=\"5\""));
    let second = fire(&rig, get_with(&format!("/assets?cursor={FIRST_CURSOR}&limit=5"), &session)).await?;
    assert!(second.body.contains("laptop") && !second.body.contains("Next assets"));
    let detail = fire(&rig, get_with(&format!("/assets/{}", encode_asset_id(ODD_ASSET_ID)), &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_hardened(&detail);
    for expected in ["serial", "A1", "hostname", "os", "linux", "agent", "Open conflicts", "Back to the assets"] {
        assert!(detail.body.contains(expected), "{expected}: {}", detail.body);
    }
    assert!(!detail.body.contains("Some attributes are not shown."));
    let seen = asset_requests(&rig)?;
    let tail = seen.get(seen.len().saturating_sub(PAIR)..).ok_or("no requests")?;
    assert_eq!(tail, [format!("/assets/{}", encode_asset_id(ODD_ASSET_ID)), format!("id={ODD_ASSET_ID}")]);
    let big = fire(&rig, get_with(&format!("/assets/{BIG_ASSET}"), &session)).await?;
    assert_eq!(big.status, StatusCode::OK);
    assert!(big.body.contains("Some attributes are not shown.") && big.body.contains("n499"));
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with(&format!("/assets/{BIG_ASSET}"), &session)
        },
    )
    .await?;
    assert!(french.body.contains("Certains attributs ne sont pas affichés.") && french.body.contains("Retour aux actifs"));
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/assets", &session)).await?;
    assert!(empty.body.contains("No asset."));
    Ok(())
}


#[tokio::test]
async fn asset_inputs_are_refused_before_any_api_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let baseline = api_requests(&rig);
    let long_id = "x".repeat(MAX_ASSET_ID_BYTES + 1);
    let long_cursor = "a".repeat(MAX_ASSET_CURSOR_CHARS + 1);
    for path in [
        "/assets?cursor=a%20b".to_owned(),
        "/assets?cursor=".to_owned(),
        "/assets?limit=0".to_owned(),
        "/assets?limit=101".to_owned(),
        format!("/assets?cursor={long_cursor}"),
    ] {
        let reply = fire(&rig, get_with(&path, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
    }
    for bad in [
        "..",
        ".",
        "%2e%2e",
        "%2E",
        "a%E2%80%AEb",
        "a%E2%80%8Bb",
        "a%0Ab",
        "a%00b",
        "%E3%85%A4",
        &long_id,
    ] {
        let reply = fire(&rig, get_with(&format!("/assets/{bad}"), &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{bad}");
    }
    let anonymous = fire(&rig, get("/assets")).await?;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    let anonymous_detail = fire(&rig, get("/assets/srv-1")).await?;
    assert_eq!(anonymous_detail.status, StatusCode::SEE_OTHER);
    assert_eq!(api_requests(&rig), baseline);
    let edge_cursor = "a".repeat(MAX_ASSET_CURSOR_CHARS);
    let accepted = fire(&rig, get_with(&format!("/assets?cursor={edge_cursor}"), &session)).await?;
    assert_eq!(accepted.status, StatusCode::BAD_REQUEST);
    assert_eq!(api_requests(&rig), baseline + 1);
    Ok(())
}


#[tokio::test]
async fn asset_ids_never_change_the_api_path() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (raw, id) in [
        ("..%2Falerts", "../alerts"),
        ("x%3Ftenant%3Db", "x?tenant=b"),
        ("%252e%252e", "%2e%2e"),
        ("a%23b%20c", "a#b c"),
    ] {
        let reply = fire(&rig, get_with(&format!("/assets/{raw}"), &session)).await?;
        assert_eq!(reply.status, StatusCode::OK, "{raw}");
        let seen = asset_requests(&rig)?;
        let tail = seen.get(seen.len().saturating_sub(PAIR)..).ok_or("no requests")?;
        assert_eq!(tail, [format!("/assets/{}", encode_asset_id(id)), format!("id={id}")]);
        assert!(!tail.iter().any(|entry| entry.contains("tenant=") && !entry.starts_with("id=")));
    }
    assert!(!asset_requests(&rig)?
        .iter()
        .any(|entry| entry == "/assets" || entry.starts_with("/alerts")));
    Ok(())
}


#[tokio::test]
async fn hostile_asset_values_are_escaped_and_bounded() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/assets", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert!(!list.body.contains("<script>") && !list.body.contains('\u{202e}') && list.body.contains("&lt;script&gt;"));
    assert_eq!(list.body.matches("Unreadable asset.").count(), HOSTILE_UNREADABLE_ROWS);
    for hidden in ['\u{e0041}', '\u{61c}', '\u{115f}', '\u{2800}', '\u{ffa0}', '\u{180e}'] {
        assert!(!list.body.contains(hidden), "{hidden:?}");
    }
    assert!(!list.body.contains("gap:victim") && !list.body.contains("gap:kind-tag"));
    assert!(list.body.contains("action=\"/assets/gap%3Akept\""));
    let before = api_requests(&rig);
    for hidden in ["%F3%A0%81%81", "%D8%9C", "%E1%85%9F", "%E2%A0%80", "%EF%BE%A0", "%E1%A0%8E"] {
        let refused = fire(&rig, get_with(&format!("/assets/gap%3Avictim{hidden}"), &session)).await?;
        assert_eq!(refused.status, StatusCode::NOT_FOUND, "{hidden}");
    }
    assert_eq!(api_requests(&rig), before);
    let id = format!("a{HOSTILE}");
    let detail = fire(&rig, get_with(&format!("/assets/{}", encode_asset_id(&id)), &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(!detail.body.contains("<script>") && !detail.body.contains('\u{202e}'));
    assert!(detail.body.contains("&lt;script&gt;alert(2)&lt;/script&gt;") && detail.body.contains("omitted]"));
    for hidden in ['\u{e0041}', '\u{61c}', '\u{115f}', '\u{2800}', '\u{ffa0}', '\u{180e}'] {
        assert!(!detail.body.contains(hidden), "{hidden:?}");
    }
    assert!(detail.body.contains(&"v".repeat(SHOWN_VALUE_CHARS)) && !detail.body.contains(&"v".repeat(CLIP_CHARS + 1)));
    Ok(())
}


#[tokio::test]
async fn asset_api_failures_render_the_page_of_their_class() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for path in ["/assets", "/assets/srv-1"] {
        for (mode, status) in [
            (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
            (Mode::Status(StatusCode::NOT_FOUND), StatusCode::NOT_FOUND),
            (Mode::Status(StatusCode::TOO_MANY_REQUESTS), StatusCode::TOO_MANY_REQUESTS),
            (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
            (Mode::Oversize, StatusCode::BAD_GATEWAY),
            (Mode::TooMany, StatusCode::BAD_GATEWAY),
            (Mode::BadId, StatusCode::BAD_GATEWAY),
        ] {
            set_mode(&rig, mode)?;
            let reply = fire(&rig, get_with(path, &session)).await?;
            let expected = if mode == Mode::BadId && path == "/assets" {
                StatusCode::OK
            } else {
                status
            };
            assert_eq!(reply.status, expected, "{path}");
            assert!(!reply.body.contains(LEAK));
            assert_hardened(&reply);
        }
    }
    set_mode(&rig, Mode::BadCursor)?;
    let cursor = fire(&rig, get_with("/assets", &session)).await?;
    assert_eq!(cursor.status, StatusCode::BAD_GATEWAY);
    set_mode(&rig, Mode::Normal)?;
    let missing = fire(&rig, get_with("/assets/missing", &session)).await?;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/assets", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    let gone = fire(&rig, get_with("/assets/srv-1", &session)).await?;
    assert_eq!(location_of(&gone).as_deref(), Some("/login"));
    assert!(!without_tokens(&gone.body).contains("srv-1"));
    Ok(())
}


#[tokio::test]
async fn a_non_composed_asset_id_is_not_found_without_an_api_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for id in [
        "cafe\u{301}",
        "\u{212b}X",
        "a\u{307}\u{323}z",
        "\u{212a}1",
        "serial_number:\u{5d0}12",
        "serial_number:12\u{5d0}",
    ] {
        let reply = fire(&rig, get_with(&format!("/assets/{}", encode_asset_id(id)), &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{id:?}");
    }
    assert!(asset_requests(&rig)?.is_empty());
    Ok(())
}


const RISK_EXTRA_UNREADABLE: usize = 2;


fn risk_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.risk_paths.lock().map_err(|_| "poisoned")?.clone())
}


#[tokio::test]
async fn the_risk_list_shows_scores_and_the_truncation_banner() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/risk\""));
    let all = fire(&rig, get_with("/risk", &session)).await?;
    assert_eq!(all.status, StatusCode::OK);
    assert_hardened(&all);
    for expected in [
        "web01",
        "db01",
        "alice",
        "value=\"80\"",
        "Scores are partial.",
        "alerts",
        "Hosts",
        "Users",
    ] {
        assert!(all.body.contains(expected), "{expected}: {}", all.body);
    }
    assert!(all.body.contains(&RISK_ALERTS_READ.to_string()) && all.body.contains(&RISK_CAP.to_string()));
    assert!(all.body.contains("action=\"/risk/host/web01\"") && all.body.contains("action=\"/risk/user/alice\""));
    assert!(all.body.contains(">web01</button>") && all.body.contains(">alice</button>"));
    let users = fire(&rig, get_with("/risk?kind=user", &session)).await?;
    assert!(users.body.contains("alice") && !without_tokens(&users.body).contains("web01"));
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with("/risk?kind=host", &session)
        },
    )
    .await?;
    assert!(french.body.contains("Scores partiels.") && french.body.contains("Machines"));
    let seen = risk_requests(&rig)?;
    assert_eq!(
        seen,
        [
            "/risk/entities?limit=100",
            "/risk/entities?limit=100&kind=user",
            "/risk/entities?limit=100&kind=host"
        ]
    );
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/risk", &session)).await?;
    assert!(empty.body.contains("No scored entity.") && !empty.body.contains("Scores are partial."));
    Ok(())
}


#[tokio::test]
async fn a_bad_risk_kind_is_refused_before_any_api_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for query in ["/risk?kind=group", "/risk?kind=", "/risk?kind=host%20"] {
        let reply = fire(&rig, get_with(query, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
    }
    let anonymous = fire(&rig, get("/risk")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    assert!(risk_requests(&rig)?.is_empty());
    Ok(())
}


#[tokio::test]
async fn risk_ids_that_do_not_render_as_themselves_are_unreadable_rows() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/risk", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(
        list.body.matches("Unreadable entity.").count(),
        RISK_UNREADABLE_IDS.len() + RISK_EXTRA_UNREADABLE
    );
    assert!(!list.body.contains("two  spaces") && !without_tokens(&list.body).contains("hole") && !without_tokens(&list.body).contains("over"));
    let odd = format!("action=\"/risk/host/{}\"", encode_asset_id(RISK_ODD_ID));
    assert_eq!(encode_asset_id(RISK_ODD_ID), "a%2Fb%3Fc%23d%25e");
    assert!(list.body.contains(&odd), "{}", list.body);
    assert!(list.body.contains(&format!(">{RISK_ODD_ID}</button>")), "{}", list.body);
    Ok(())
}


#[tokio::test]
async fn a_risk_detail_reaches_the_exact_entity_and_never_another_route() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let detail = fire(&rig, get_with("/risk/host/web01", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_hardened(&detail);
    for expected in [
        "web01",
        "value=\"55\"",
        "Hosts",
        "Scores are partial.",
        "unknown",
        "Back to the risk list",
    ] {
        assert!(detail.body.contains(expected), "{expected}: {}", detail.body);
    }
    let encoded = encode_asset_id(RISK_ODD_ID);
    let odd = fire(&rig, get_with(&format!("/risk/user/{encoded}"), &session)).await?;
    assert_eq!(odd.status, StatusCode::OK);
    let seen = risk_requests(&rig)?;
    let tail = seen.get(seen.len().saturating_sub(PAIR)..).ok_or("no requests")?;
    assert_eq!(tail, [format!("/risk/entities/user/{encoded}"), format!("id={RISK_ODD_ID}")]);
    let before = api_requests(&rig);
    for path in [
        "/risk/group/web01",
        "/risk/host/cafe%CC%81",
        "/risk/host/..",
        "/risk/host/%2e%2e",
        "/risk/host/a%20%20b",
        "/risk/host/x%E3%85%A4",
    ] {
        let reply = fire(&rig, get_with(path, &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(api_requests(&rig), before);
    Ok(())
}


#[tokio::test]
async fn risk_api_failures_render_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for path in ["/risk", "/risk/host/web01"] {
        for (mode, status) in [
            (Mode::Status(StatusCode::SERVICE_UNAVAILABLE), StatusCode::SERVICE_UNAVAILABLE),
            (Mode::Status(StatusCode::NOT_FOUND), StatusCode::NOT_FOUND),
            (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
            (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
            (Mode::Oversize, StatusCode::BAD_GATEWAY),
            (Mode::TooMany, StatusCode::BAD_GATEWAY),
            (Mode::BadId, StatusCode::BAD_GATEWAY),
            (Mode::Hostile, StatusCode::BAD_GATEWAY),
        ] {
            set_mode(&rig, mode)?;
            let reply = fire(&rig, get_with(path, &session)).await?;
            let list_served = path == "/risk" && matches!(mode, Mode::BadId | Mode::Hostile);
            let detail_served = path == "/risk/host/web01" && mode == Mode::TooMany;
            let expected = if list_served || detail_served { StatusCode::OK } else { status };
            assert_eq!(reply.status, expected, "{path}");
            assert!(!reply.body.contains(LEAK));
            assert_hardened(&reply);
        }
    }
    set_mode(&rig, Mode::Status(StatusCode::SERVICE_UNAVAILABLE))?;
    let busy = fire(&rig, get_with("/risk", &session)).await?;
    assert!(busy.body.contains("Scores are being computed. Retry in a moment."));
    set_mode(&rig, Mode::Normal)?;
    let swapped = fire(&rig, get_with("/risk/host/swapped", &session)).await?;
    assert_eq!(swapped.status, StatusCode::BAD_GATEWAY);
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/risk", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    let gone = fire(&rig, get_with("/risk/host/web01", &session)).await?;
    assert_eq!(location_of(&gone).as_deref(), Some("/login"));
    Ok(())
}


const HUNT_UNREADABLE_ROWS: usize = 4;


const HUGE_CURSOR_CHARS: usize = 10_000;


const STATE_LIST_UNREADABLE_ROWS: usize = 8;


const STATE_DETAIL_UNREADABLE_ROWS: usize = 9;


const TWO_VALID_CALLS: usize = 2;


const THREE_CALLS: usize = 3;


const CERT_THIRTY_DAYS: i64 = 30 * 86_400;


const CERT_NINETY_DAYS: i64 = 90 * 86_400;


const CERT_ROW_NAMES: usize = 20;


const CERT_ROW_TOTAL_NAMES: usize = 30;


const CERT_DETAIL_NAMES: usize = 100;


fn cert_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.cert_paths.lock().map_err(|_| "poisoned")?.clone())
}


fn assert_no_hidden_characters(body: &str) {
    assert!(!body.chars().any(|character| character == '\u{1b}' || character == '\u{202e}'), "{body}");
}


#[tokio::test]
async fn the_certificate_list_shows_rows_the_skipped_line_and_the_next_page() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/certificates\""));
    let list = fire(&rig, get_with("/certificates", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_hardened(&list);
    for fill in ['a', 'b', 'c'] {
        let link = format!("action=\"/certificates/{}\"", cert_fingerprint(fill));
        assert!(list.body.contains(&link), "{link}");
    }
    assert_eq!(list.body.matches("action=\"/certificates/").count(), CERT_LIST_ROWS);
    for expected in ["CN=one", "Expired", "Expires soon", "Valid", "rsa 2048", "host1.example.test"] {
        assert!(list.body.contains(expected), "{expected}");
    }
    assert!(list.body.contains(&format!("{CERT_SKIPPED} certificates could not be shown.")));
    let cursor = format!("name=\"cursor\" value=\"{CERT_CURSOR_TIME}:{}\"", cert_fingerprint('c'));
    assert!(list.body.contains(&cursor) && list.body.contains("name=\"expiring\" value=\"all\"") && list.body.contains("Next certificates"));
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with("/certificates", &session)
        },
    )
    .await?;
    assert!(french.body.contains("Expiré") && french.body.contains("n'ont pas pu être affichés"));
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/certificates", &session)).await?;
    assert!(empty.body.contains("No certificate.") && !empty.body.contains("could not be shown") && !empty.body.contains("Next certificates"));
    assert_eq!(cert_requests(&rig)?, ["/certificates?limit=100"; CERT_LIST_ROWS]);
    Ok(())
}


#[tokio::test]
async fn a_hostile_certificate_is_clipped_and_bad_fingerprints_are_unreadable_rows() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/certificates", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_no_hidden_characters(&list.body);
    assert!(
        list.body.contains("evil\u{fffd}[31m\u{fffd}cn\u{fffd}next") && list.body.contains("omitted]"),
        "{}",
        list.body
    );
    assert_eq!(list.body.matches("Unreadable certificate.").count(), CERT_BAD_FINGERPRINT_COUNT);
    assert_eq!(list.body.matches("action=\"/certificates/").count(), 1);
    assert!(!list.body.contains("../x") && !list.body.contains(&format!("A{}", "a".repeat(CERT_SHORT_FINGERPRINT))));
    assert!(list.body.contains("unknown"));
    assert!(list.body.contains(&format!("host{}.example.test", CERT_ROW_NAMES - 1)));
    assert!(!list.body.contains(&format!("host{CERT_ROW_NAMES}.example")));
    assert!(list.body.contains(&format!("{} more", CERT_ROW_TOTAL_NAMES - CERT_ROW_NAMES)));
    Ok(())
}


#[tokio::test]
async fn the_expiry_filter_is_computed_from_the_injected_clock() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for query in ["/certificates?expiring=30", "/certificates?expiring=90", "/certificates?expiring=all"] {
        let reply = fire(&rig, get_with(query, &session)).await?;
        assert_eq!(reply.status, StatusCode::OK, "{query}");
    }
    let forged = fire(&rig, get_with("/certificates?expiring_before=5&limit=500&tenant=b", &session)).await?;
    assert_eq!(forged.status, StatusCode::OK);
    let cursor = format!("{CERT_CURSOR_TIME}:{}", cert_fingerprint('c'));
    let next = fire(&rig, get_with(&format!("/certificates?expiring=30&cursor={cursor}"), &session)).await?;
    assert_eq!(next.status, StatusCode::OK);
    let thirty = WALL_NOW + CERT_THIRTY_DAYS;
    assert_eq!(
        cert_requests(&rig)?,
        [
            format!("/certificates?limit=100&expiring_before={thirty}"),
            format!("/certificates?limit=100&expiring_before={}", WALL_NOW + CERT_NINETY_DAYS),
            "/certificates?limit=100".to_owned(),
            "/certificates?limit=100".to_owned(),
            format!(
                "/certificates?limit=100&expiring_before={thirty}&cursor={CERT_CURSOR_TIME}%3A{}",
                cert_fingerprint('c')
            ),
        ]
    );
    let before = cert_requests(&rig)?.len();
    for query in [
        "/certificates?expiring=7",
        "/certificates?expiring=",
        "/certificates?expiring=ALL",
        "/certificates?expiring=30%20",
        "/certificates?cursor=a%20b",
        "/certificates?cursor=",
        "/certificates?cursor=12:XYZ",
        "/certificates?cursor=%3A",
        "/certificates?cursor=1x:aaaa",
    ] {
        let reply = fire(&rig, get_with(query, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
    }
    let long = format!("/certificates?cursor=1:{}0", cert_fingerprint('a'));
    assert_eq!(fire(&rig, get_with(&long, &session)).await?.status, StatusCode::BAD_REQUEST);
    assert_eq!(cert_requests(&rig)?.len(), before);
    let negative = format!("/certificates?cursor=-5:{}", cert_fingerprint('a'));
    assert_eq!(fire(&rig, get_with(&negative, &session)).await?.status, StatusCode::OK);
    assert_eq!(cert_requests(&rig)?.len(), before + 1);
    let anonymous = fire(&rig, get("/certificates?expiring=30")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn a_certificate_detail_shows_its_sightings_and_never_another_route() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let path = format!("/certificates/{}", cert_fingerprint('a'));
    let detail = fire(&rig, get_with(&path, &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_hardened(&detail);
    for expected in [
        "CN=one",
        "Expires soon",
        "Sightings",
        "/etc/ssl/1.pem",
        "Back to the certificates",
        &cert_fingerprint('a'),
    ] {
        assert!(detail.body.contains(expected), "{expected}");
    }
    assert!(!detail.body.contains("could not be shown") && !detail.body.contains("Sightings cut"));
    assert_eq!(cert_requests(&rig)?, [path]);
    let before = api_requests(&rig);
    let upper = format!("/certificates/A{}", "a".repeat(CERT_SHORT_FINGERPRINT));
    let short = format!("/certificates/{}", "a".repeat(CERT_SHORT_FINGERPRINT));
    for bad in [
        upper.as_str(),
        short.as_str(),
        "/certificates/..%2Fx",
        "/certificates/a%2Fb",
        "/certificates/%2e%2e",
        "/certificates/aa%3Fb%23c",
    ] {
        let reply = fire(&rig, get_with(bad, &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{bad}");
    }
    assert_eq!(api_requests(&rig), before);
    assert_eq!(cert_requests(&rig)?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_hostile_certificate_detail_is_clipped_and_every_bound_is_visible() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let path = format!("/certificates/{}", cert_fingerprint('a'));
    let detail = fire(&rig, get_with(&path, &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_no_hidden_characters(&detail.body);
    assert!(detail.body.contains("omitted]") && detail.body.contains("unknown"));
    assert!(detail.body.contains(&format!("host{}.example.test", CERT_DETAIL_NAMES - 1)));
    assert!(!detail.body.contains(&format!("host{CERT_DETAIL_NAMES}.example")));
    assert!(detail.body.contains(&format!("{} more", CERT_MANY_NAMES - CERT_DETAIL_NAMES)));
    assert!(detail.body.contains(&format!("{CERT_SKIPPED} sightings could not be shown.")) && detail.body.contains("Sightings cut at 500."));
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with(&path, &session)
        },
    )
    .await?;
    assert!(french.body.contains("Observations coupées à 500.") && french.body.contains("Auto-signé"));
    Ok(())
}


#[tokio::test]
async fn certificate_api_failures_render_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let detail_path = format!("/certificates/{}", cert_fingerprint('a'));
    for path in ["/certificates", detail_path.as_str()] {
        for (mode, status) in [
            (Mode::Status(StatusCode::NOT_FOUND), StatusCode::NOT_FOUND),
            (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
            (Mode::Status(StatusCode::BAD_REQUEST), StatusCode::BAD_REQUEST),
            (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
            (Mode::Oversize, StatusCode::BAD_GATEWAY),
            (Mode::TooMany, StatusCode::BAD_GATEWAY),
            (Mode::BadCursor, StatusCode::BAD_GATEWAY),
            (Mode::BadId, StatusCode::BAD_GATEWAY),
        ] {
            set_mode(&rig, mode)?;
            let reply = fire(&rig, get_with(path, &session)).await?;
            let served = (path == "/certificates" && mode == Mode::BadId) || (path != "/certificates" && mode == Mode::BadCursor);
            let expected = if served { StatusCode::OK } else { status };
            assert_eq!(reply.status, expected, "{path}");
            assert!(!reply.body.contains(LEAK));
            assert_hardened(&reply);
        }
    }
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/certificates", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    let gone = fire(&rig, get_with(&detail_path, &session)).await?;
    assert_eq!(location_of(&gone).as_deref(), Some("/login"));
    Ok(())
}


const CERT_LIST_ROWS: usize = 3;


const CERT_SHORT_FINGERPRINT: usize = 63;


fn hunt_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.hunt_paths.lock().map_err(|_| "poisoned")?.clone())
}


#[tokio::test]
async fn the_hunt_list_shows_rows_the_notices_and_the_next_page() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/hunts\""));
    let list = fire(&rig, get_with("/hunts", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_hardened(&list);
    for expected in [
        "baseline-1",
        "lateral.move",
        "2026-03-01T00:00:00Z",
        "2026-03-02T00:00:00Z",
        "<td>7</td>",
        "<td>500</td>",
        "Hunt findings",
    ] {
        assert!(list.body.contains(expected), "{expected}: {}", list.body);
    }
    assert!(list.body.contains(&format!("{HUNT_SKIPPED} rows could not be read.")));
    assert!(list.body.contains(&format!("{HUNT_OVERSIZED} findings have an over-long pack id.")));
    assert!(!list.body.contains("At least"));
    assert!(list.body.contains(&format!("name=\"cursor\" value=\"{HUNT_NEXT_CURSOR}\"")) && list.body.contains("Next findings"));
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with("/hunts", &session)
        },
    )
    .await?;
    assert!(
        french.body.contains("Résultats de chasse") && french.body.contains("n'ont pas pu être lues") && french.body.contains("Résultats suivants")
    );
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/hunts", &session)).await?;
    assert!(empty.body.contains("No finding.") && !empty.body.contains("could not be read") && !empty.body.contains("Next findings"));
    assert!(!empty.body.contains("over-long"));
    let forged = format!("/hunts?cursor={HUNT_NEXT_CURSOR}&limit=500&tenant=b&expiring=30");
    assert_eq!(fire(&rig, get_with(&forged, &session)).await?.status, StatusCode::OK);
    assert_eq!(
        hunt_requests(&rig)?,
        [
            "/hunts/findings?limit=100".to_owned(),
            "/hunts/findings?limit=100".to_owned(),
            "/hunts/findings?limit=100".to_owned(),
            format!("/hunts/findings?limit=100&cursor={HUNT_NEXT_CURSOR}"),
        ]
    );
    let anonymous = fire(&rig, get("/hunts")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn a_hostile_finding_is_an_unreadable_row_and_never_printed() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/hunts", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_no_hidden_characters(&list.body);
    let list_page = without_tokens(&list.body);
    assert!(!list_page.contains('\u{3164}') && !list_page.contains("evil") && !list_page.contains("Upper") && !list_page.contains("not a time"));
    assert_eq!(list.body.matches("Unreadable row.").count(), HUNT_UNREADABLE_ROWS);
    assert_eq!(list.body.matches("<td>7</td>").count(), 1);
    assert!(list.body.contains("fine.pack_1") && list.body.contains("2026-03-02T00:00:00Z"));
    assert!(list.body.contains("At least 4 findings have an over-long pack id."));
    assert!(list.body.contains("2 rows could not be read."));
    Ok(())
}


#[tokio::test]
async fn a_malformed_hunt_cursor_is_refused_before_any_api_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let long = format!("/hunts?cursor={}", "A".repeat(MAX_HUNT_CURSOR_CHARS + 1));
    for query in [
        "/hunts?cursor=",
        "/hunts?cursor=a%20b",
        "/hunts?cursor=a.b",
        "/hunts?cursor=12:abc",
        "/hunts?cursor=A",
        "/hunts?cursor=MTgwMDAwMDAwMDpwYWNrLWM%3D",
        long.as_str(),
    ] {
        let reply = fire(&rig, get_with(query, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
    }
    assert!(hunt_requests(&rig)?.is_empty());
    let longest = format!("/hunts?cursor={}", "A".repeat(MAX_HUNT_CURSOR_CHARS));
    assert_eq!(fire(&rig, get_with(&longest, &session)).await?.status, StatusCode::OK);
    assert_eq!(hunt_requests(&rig)?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn hunt_api_failures_render_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (mode, status) in [
        (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
        (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
        (Mode::Oversize, StatusCode::BAD_GATEWAY),
        (Mode::TooMany, StatusCode::BAD_GATEWAY),
        (Mode::BadCursor, StatusCode::BAD_GATEWAY),
    ] {
        set_mode(&rig, mode)?;
        let reply = fire(&rig, get_with("/hunts", &session)).await?;
        assert_eq!(reply.status, status);
        assert!(!reply.body.contains(LEAK));
        assert_hardened(&reply);
    }
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/hunts", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn hunt_notices_are_singular_for_one_and_an_unreadable_page_says_so() -> TestResult {
    let rig = harness(Mode::BadId).await?;
    let session = sign_in(&rig).await?;
    let none_readable = fire(&rig, get_with("/hunts", &session)).await?;
    assert!(none_readable.body.contains("1 row could not be read.") && none_readable.body.contains("1 finding has an over-long pack id."));
    assert!(none_readable.body.contains("No readable finding on this page.") && !none_readable.body.contains("No finding."));
    assert!(none_readable.body.contains("Next findings"));
    set_mode(&rig, Mode::BadSeverity)?;
    let capped = fire(&rig, get_with("/hunts", &session)).await?;
    assert!(capped.body.contains("At least 1 finding has an over-long pack id."));
    let french = Req {
        language: Some("fr".to_owned()),
        ..get_with("/hunts", &session)
    };
    assert!(fire(&rig, french)
        .await?
        .body
        .contains("Au moins 1 résultat a un identifiant de pack trop long."));
    set_mode(&rig, Mode::BadId)?;
    let french_none = Req {
        language: Some("fr".to_owned()),
        ..get_with("/hunts", &session)
    };
    let body = fire(&rig, french_none).await?.body;
    assert!(body.contains("1 ligne n'a pas pu être lue.") && body.contains("1 résultat a un identifiant") && body.contains("Aucun résultat lisible"));
    Ok(())
}


fn state_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.state_paths.lock().map_err(|_| "poisoned")?.clone())
}


#[tokio::test]
async fn the_compliance_list_shows_rows_notices_filters_and_the_next_page() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/compliance\""));
    let list = fire(&rig, get_with("/compliance", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_hardened(&list);
    for expected in [
        "Compliance drift",
        "ctl-1",
        "ctl-2",
        "<td>Failed</td>",
        "<td>Passed</td>",
        "<td>2026-03-01T09:00:00Z</td>",
        "<td>-</td>",
        "<td>2026-03-02T00:00:00Z</td>",
        "action=\"/compliance/host-1\"",
        "action=\"/compliance/a%2Fb%2Bc\"",
        "1 row could not be read.",
        "<option value=\"fail\" selected>",
        "name=\"cursor\" value=\"626173650063746c00686f73742d31\"",
        "name=\"verdict\" value=\"fail\"",
        "Next controls",
    ] {
        assert!(list.body.contains(expected), "{expected}: {}", list.body);
    }
    assert!(!list.body.contains("name=\"baseline\" value=\"base\"") && !list.body.contains("truncated"));
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/compliance", &session)
    };
    let french = fire(&rig, french_request).await?;
    for expected in [
        "Dérive de conformité",
        "En échec",
        "Contrôles suivants",
        "1 ligne n'a pas pu être lue.",
        "Référentiel",
    ] {
        assert!(french.body.contains(expected), "{expected}");
    }
    let filtered = format!("/compliance?verdict=all&baseline=base&cursor={STATE_NEXT_CURSOR}&limit=500&tenant=b");
    let reply = fire(&rig, get_with(&filtered, &session)).await?;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("<option value=\"all\" selected>") && reply.body.contains("name=\"baseline\" value=\"base\""));
    let nameless = fire(&rig, get_with("/compliance?verdict=pass&baseline=", &session)).await?;
    assert_eq!(nameless.status, StatusCode::OK);
    assert_eq!(
        state_requests(&rig)?,
        [
            "/compliance/state?verdict=fail&limit=100".to_owned(),
            "/compliance/state?verdict=fail&limit=100".to_owned(),
            format!("/compliance/state?verdict=all&limit=100&baseline=base&cursor={STATE_NEXT_CURSOR}"),
            "/compliance/state?verdict=pass&limit=100".to_owned(),
        ]
    );
    let anonymous = fire(&rig, get("/compliance")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/compliance", &session)).await?;
    assert!(empty.body.contains("No control in this state.") && !empty.body.contains("could not be read") && !empty.body.contains("Next controls"));
    set_mode(&rig, Mode::BadId)?;
    let none_readable = fire(&rig, get_with("/compliance", &session)).await?;
    assert!(none_readable.body.contains("No readable control on this page.") && none_readable.body.contains("1 row could not be read."));
    assert!(none_readable.body.contains("Next controls"));
    set_mode(&rig, Mode::BadSeverity)?;
    let many = fire(&rig, get_with("/compliance", &session)).await?;
    assert!(many.body.contains("3 rows could not be read."));
    Ok(())
}


#[tokio::test]
async fn a_hostile_state_row_is_an_unreadable_row_and_never_printed() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/compliance", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_no_hidden_characters(&list.body);
    for forbidden in ["evil", "script", "\u{3164}", "bogus", "not a time", "-x"] {
        assert!(!without_tokens(&list.body).contains(forbidden), "{forbidden}");
    }
    assert_eq!(list.body.matches("Unreadable row.").count(), STATE_LIST_UNREADABLE_ROWS);
    assert!(list.body.contains("fine.1") && list.body.contains("other-asset") && list.body.contains("1 row could not be read."));
    let detail = fire(&rig, get_with("/compliance/web01", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_no_hidden_characters(&detail.body);
    for forbidden in ["evil", "script", "\u{3164}", "bogus", "not a time", "other-asset"] {
        assert!(!without_tokens(&detail.body).contains(forbidden), "{forbidden}");
    }
    assert_eq!(detail.body.matches("Unreadable row.").count(), STATE_DETAIL_UNREADABLE_ROWS);
    assert!(detail.body.contains("fine.1") && detail.body.contains("<td>Excepted</td>"));
    assert!(detail.body.contains("Results cut at 1000.") && detail.body.contains("1 row could not be read."));
    Ok(())
}


#[tokio::test]
async fn the_compliance_detail_shows_the_asset_rows_the_notices_and_both_languages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let detail = fire(&rig, get_with("/compliance/a%2Fb%2Bc", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_hardened(&detail);
    for expected in [
        "Compliance of a/b+c",
        "ctl-1",
        "<td>Failed</td>",
        "<td>Error</td>",
        "2 rows could not be read.",
        "Results cut at 1000.",
        "action=\"/compliance\"",
    ] {
        assert!(detail.body.contains(expected), "{expected}: {}", detail.body);
    }
    assert!(!detail.body.contains("<th>Asset</th>"));
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/compliance/host-1", &session)
    };
    let french = fire(&rig, french_request).await?;
    assert!(
        french.body.contains("Conformité de host-1") && french.body.contains("Résultats coupés à 1000.") && french.body.contains("En échec depuis")
    );
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/compliance/host-1", &session)).await?;
    assert!(empty.body.contains("No control in this state.") && !empty.body.contains("Results cut"));
    set_mode(&rig, Mode::BadId)?;
    let none_readable = fire(&rig, get_with("/compliance/host-1", &session)).await?;
    assert!(none_readable.body.contains("No readable control on this page.") && none_readable.body.contains("1 row could not be read."));
    assert_eq!(
        state_requests(&rig)?,
        [
            "/compliance/assets/a%2Fb%2Bc".to_owned(),
            "/compliance/assets/host-1".to_owned(),
            "/compliance/assets/host-1".to_owned(),
            "/compliance/assets/host-1".to_owned(),
        ]
    );
    Ok(())
}


#[tokio::test]
async fn a_malformed_compliance_query_or_asset_is_refused_before_any_api_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let long_cursor = format!("/compliance?cursor={}", "a".repeat(HUGE_CURSOR_CHARS));
    let long_baseline = format!("/compliance?baseline={}", "a".repeat(MAX_STATE_ID_CHARS + 1));
    let long_asset = format!("/compliance/{}", "a".repeat(MAX_STATE_ASSET_CHARS + 1));
    let wrong_fields = format!("/compliance?cursor={}", HEXLOWER.encode(b"a\0b"));
    let bad_key = format!("/compliance?cursor={}", HEXLOWER.encode(b"-x\0c\0d"));
    let not_text = format!("/compliance?cursor={}", HEXLOWER.encode(b"\xff\0\xff\0\xff"));
    let upper = format!("/compliance?cursor={}", STATE_NEXT_CURSOR.to_ascii_uppercase());
    let odd = format!("/compliance?cursor={}", STATE_NEXT_CURSOR.trim_end_matches('1'));
    for query in [
        "/compliance?verdict=fail%00",
        "/compliance?verdict=FAIL",
        "/compliance?verdict=",
        "/compliance?verdict=x",
        "/compliance?baseline=-x",
        "/compliance?baseline=a%20b",
        "/compliance?baseline=a%00",
        "/compliance?cursor=",
        "/compliance?cursor=zz",
        long_cursor.as_str(),
        long_baseline.as_str(),
        wrong_fields.as_str(),
        bad_key.as_str(),
        not_text.as_str(),
        upper.as_str(),
        odd.as_str(),
    ] {
        let reply = fire(&rig, get_with(query, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", query.len());
    }
    for path in [
        "/compliance/-x",
        "/compliance/a%00b",
        "/compliance/a%20b",
        "/compliance/..%2Fx",
        "/compliance/%2e%2e",
        "/compliance/.hidden",
        "/compliance/a%0Ab",
        "/compliance/%E2%80%AEx",
        long_asset.as_str(),
    ] {
        let reply = fire(&rig, get_with(path, &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert!(state_requests(&rig)?.is_empty());
    let longest = "a".repeat(MAX_STATE_ID_CHARS);
    let max_key = format!("{longest}\0{longest}\0{}", "z".repeat(MAX_STATE_ASSET_CHARS));
    let longest_cursor = format!("/compliance?baseline={longest}&cursor={}", HEXLOWER.encode(max_key.as_bytes()));
    assert_eq!(fire(&rig, get_with(&longest_cursor, &session)).await?.status, StatusCode::OK);
    let longest_asset = format!("/compliance/{}", "a".repeat(MAX_STATE_ASSET_CHARS));
    assert_eq!(fire(&rig, get_with(&longest_asset, &session)).await?.status, StatusCode::OK);
    assert_eq!(state_requests(&rig)?.len(), TWO_VALID_CALLS);
    let other = fire(&rig, get_with("/compliance/elsewhere", &session)).await?;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
    assert!(!other.body.contains(LEAK));
    assert_eq!(state_requests(&rig)?.len(), THREE_CALLS);
    Ok(())
}


#[tokio::test]
async fn compliance_api_failures_render_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for path in ["/compliance", "/compliance/host-1"] {
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
    assert_eq!(fire(&rig, get_with("/compliance", &session)).await?.status, StatusCode::BAD_GATEWAY);
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/compliance", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Normal)?;
    let second = sign_in(&rig).await?;
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended_detail = fire(&rig, get_with("/compliance/host-1", &second)).await?;
    assert_eq!(location_of(&ended_detail).as_deref(), Some("/login"));
    assert!(ended_detail.headers.get("set-cookie").is_some());
    Ok(())
}


fn oncall_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.oncall_paths.lock().map_err(|_| "poisoned")?.clone())
}


const ONCALL_HOSTILE_UNREADABLE_ROWS: usize = 14;


const ONCALL_LIST_CALLS: usize = 5;


#[tokio::test]
async fn the_oncall_list_shows_rows_notices_and_both_languages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/oncall\""));
    let list = fire(&rig, get_with("/oncall?limit=5&tenant=b", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_hardened(&list);
    for expected in [
        "On-call alerts",
        "fp one",
        "fp-two",
        "action=\"/oncall/7\"",
        "<td>Open</td>",
        "<td>Acknowledged</td>",
        "<td>2026-03-01T09:00:00Z</td>",
        "<td>2026-03-02T00:00:00Z</td>",
        "<td>-</td>",
        "1 row could not be read.",
    ] {
        assert!(list.body.contains(expected), "{expected}: {}", list.body);
    }
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/oncall", &session)
    };
    let french = fire(&rig, french_request).await?;
    for expected in ["Alertes d'astreinte", "Prise en compte", "1 ligne n'a pas pu être lue."] {
        assert!(french.body.contains(expected), "{expected}");
    }
    set_mode(&rig, Mode::Chunked)?;
    let empty = fire(&rig, get_with("/oncall", &session)).await?;
    assert!(empty.body.contains("No open alert.") && !empty.body.contains("could not be read"));
    set_mode(&rig, Mode::BadId)?;
    let none_readable = fire(&rig, get_with("/oncall", &session)).await?;
    assert!(none_readable.body.contains("No readable alert on this page.") && none_readable.body.contains("1 row could not be read."));
    set_mode(&rig, Mode::BadSeverity)?;
    let many = fire(&rig, get_with("/oncall", &session)).await?;
    assert!(many.body.contains("3 rows could not be read."));
    let anonymous = fire(&rig, get("/oncall")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    let paths = oncall_requests(&rig)?;
    assert!(paths.iter().all(|path| path == "/oncall/alerts?limit=1000"), "{paths:?}");
    assert_eq!(paths.len(), ONCALL_LIST_CALLS);
    Ok(())
}


#[tokio::test]
async fn a_hostile_oncall_row_is_an_unreadable_row_and_never_printed() -> TestResult {
    let rig = harness(Mode::Hostile).await?;
    let session = sign_in(&rig).await?;
    let list = fire(&rig, get_with("/oncall", &session)).await?;
    assert_eq!(list.status, StatusCode::OK);
    assert_no_hidden_characters(&list.body);
    for forbidden in ["evil", "script", "\u{3164}", "bogus", "not a time", "two  spaces", "aaaaaaaaaa", "\u{e9}"] {
        assert!(!without_tokens(&list.body).contains(forbidden), "{forbidden}");
    }
    assert_eq!(list.body.matches("Unreadable row.").count(), ONCALL_HOSTILE_UNREADABLE_ROWS);
    assert!(list.body.contains("fine.fp 1") && list.body.contains("<td>Escalated</td>") && list.body.contains("1 row could not be read."));
    let detail = fire(&rig, get_with("/oncall/3", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_no_hidden_characters(&detail.body);
    assert!(!without_tokens(&detail.body).contains("evil") && detail.body.contains("Unreadable row."));
    Ok(())
}


#[tokio::test]
async fn the_oncall_detail_shows_the_alert_and_refuses_a_bad_id_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let detail = fire(&rig, get_with("/oncall/7", &session)).await?;
    assert_eq!(detail.status, StatusCode::OK);
    assert_hardened(&detail);
    for expected in [
        "On-call alert 7",
        "fp one",
        "<td>Resolved</td>",
        "<td>2026-03-03T00:00:00Z</td>",
        "action=\"/oncall\"",
    ] {
        assert!(detail.body.contains(expected), "{expected}: {}", detail.body);
    }
    assert!(!detail.body.contains("action=\"/oncall/7\""));
    let french_request = Req {
        language: Some("fr".to_owned()),
        ..get_with("/oncall/7", &session)
    };
    assert!(fire(&rig, french_request).await?.body.contains("Alerte d'astreinte 7"));
    assert_eq!(oncall_requests(&rig)?, ["/oncall/alerts/7", "/oncall/alerts/7"]);
    for path in [
        "/oncall/-1",
        "/oncall/1e3",
        "/oncall/99999999999999999999",
        "/oncall/+1",
        "/oncall/a%20b",
        "/oncall/%E0%A5%A7",
    ] {
        let reply = fire(&rig, get_with(path, &session)).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(oncall_requests(&rig)?.len(), TWO_VALID_CALLS);
    let other_tenant = fire(&rig, get_with("/oncall/99", &session)).await?;
    assert_eq!(other_tenant.status, StatusCode::NOT_FOUND);
    assert!(!other_tenant.body.contains(LEAK));
    set_mode(&rig, Mode::BadId)?;
    assert_eq!(fire(&rig, get_with("/oncall/7", &session)).await?.status, StatusCode::BAD_GATEWAY);
    Ok(())
}


#[tokio::test]
async fn oncall_api_failures_render_our_own_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for path in ["/oncall", "/oncall/7"] {
        for (mode, status) in [
            (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
            (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
            (Mode::Oversize, StatusCode::BAD_GATEWAY),
        ] {
            set_mode(&rig, mode)?;
            let reply = fire(&rig, get_with(path, &session)).await?;
            assert_eq!(reply.status, status, "{path}");
            assert!(!reply.body.contains(LEAK));
            assert_hardened(&reply);
        }
    }
    for mode in [Mode::TooMany, Mode::BadCursor] {
        set_mode(&rig, mode)?;
        assert_eq!(fire(&rig, get_with("/oncall", &session)).await?.status, StatusCode::BAD_GATEWAY);
    }
    for other in [Mode::Status(StatusCode::UNPROCESSABLE_ENTITY), Mode::Oversize422] {
        set_mode(&rig, other)?;
        let generic = fire(&rig, get_with("/oncall/7", &session)).await?;
        assert_eq!(generic.status, StatusCode::BAD_GATEWAY);
        assert!(!generic.body.contains("Unreadable row.") && !generic.body.contains(LEAK));
    }
    set_mode(&rig, Mode::UnreadableAlert)?;
    let unreadable = fire(&rig, get_with("/oncall/7", &session)).await?;
    assert_eq!(unreadable.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(unreadable.body.contains("Unreadable row.") && !unreadable.body.contains(LEAK));
    assert_hardened(&unreadable);
    set_mode(&rig, Mode::Status(StatusCode::UNPROCESSABLE_ENTITY))?;
    assert_eq!(fire(&rig, get_with("/oncall", &session)).await?.status, StatusCode::BAD_GATEWAY);
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/oncall", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Normal)?;
    let second = sign_in(&rig).await?;
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended_detail = fire(&rig, get_with("/oncall/7", &second)).await?;
    assert_eq!(location_of(&ended_detail).as_deref(), Some("/login"));
    Ok(())
}


#[test]
fn a_token_holding_a_forbidden_text_is_blanked_before_the_scan() -> TestResult {
    let page = "<input name=\"csrf\" value=\"ab-xNaNevil\"><p>x</p><input name=\"csrf\" value=\"q-x\">";
    assert!(page.contains("-x") && page.contains("NaN") && page.contains("evil"));
    let cleaned = without_tokens(page);
    assert!(
        !cleaned.contains("-x") && !cleaned.contains("NaN") && !cleaned.contains("evil"),
        "{cleaned}"
    );
    assert!(cleaned.contains("<p>x</p>"));
    Ok(())
}
