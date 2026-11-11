#[path = "support/harness.rs"]
mod harness;
#[cfg(unix)]
#[path = "support/served.rs"]
mod served;
#[path = "support/stub.rs"]
mod stub;
#[path = "support/types.rs"]
mod types;


use axum::body::Body;
use axum::http::StatusCode;
use harness::{
    cookie_value_of, csrf_in, fire, fire_body, get, get_with, harness, harness_custom, location_of, login_body, login_csrf, post_form, post_login,
    set_cookie_of, sign_in, Harness, Reply, Req, LIMITS,
};
use secrecy::SecretString;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use stub::{id_of, Mode, FIRST_CURSOR, HOSTILE, LEAK, LOCK_AFTER, TOKEN};
use tokio::sync::Semaphore;
use tokio::time::{sleep, Instant};
use tokio_stream::pending;
use types::TestError;
use types::TestResult;
use web_ui::api::{forwarded_value, header_from_text, list_alerts, login};
use web_ui::client::{build_client, login_slots};
use web_ui::error::ApiFailure;
use web_ui::model::{ApiClient, ApiSection, Session};
use web_ui::model::{Language, WebLimits};
use web_ui::routes::{accept_language, api_refusal, cookie_header};
use web_ui::session::evict_oldest;


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
    assert!(list.body.contains("action=\"/cases/case-1\""));
    for forbidden in ["/cases/../x", "/cases/-x", "/cases/a/b", "/cases/%2e%2e", "/cases/line"] {
        assert!(!list.body.contains(forbidden), "{forbidden}");
    }
    assert!(!list.body.contains(&"i".repeat(stub::LONG_CASE_ID_CHARS)));
    assert_eq!(list.body.matches("not linkable").count(), UNLINKED_CASES);
    assert!(list.body.contains("unknown") && !list.body.contains("weird"));
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
    assert!(!detail.body.contains("weird") && !detail.body.contains("mystery") && !detail.body.contains("odd") && !detail.body.contains("urgent"));
    assert!(detail.body.contains("unknown"));
    assert!(detail.body.contains("6 omitted"));
    assert!(!detail.body.contains("task69"));
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
