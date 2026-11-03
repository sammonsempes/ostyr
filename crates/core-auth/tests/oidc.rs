#[path = "support/limited_writer.rs"]
mod limited_writer;
#[path = "support/oidc_provider.rs"]
mod oidc_provider;
#[path = "support/types.rs"]
mod types;


use core_audit::log::{genesis_log, AuditLog};
use core_audit::verify::verify;
use core_auth::error::{AuthError, OidcDenial};
use core_auth::oidc::{
    begin_login, claims_denial, complete_login, denial_reason, groups_of, http_call, map_roles, new_agent, parse_oidc_config, payload_of, Callback,
    OidcConfig, OidcContext, PENDING_MAX, RESPONSE_MAX_BYTES,
};
use core_auth::password::verify_password;
use core_auth::random::os_random;
use core_auth::rbac::{builtin_catalog, PERMISSION_ALERTS_TRIAGE, PERMISSION_USERS_MANAGE};
use core_auth::service::{authorize, create_account, Context, State};
use core_auth::store::load_accounts;
use core_auth::types::{CompromisedSet, PendingMap, RoleCatalog, StoreKey};
use core_config::secret::SecretRef;
use limited_writer::LimitedWriter;
use oidc_provider::{challenge_of, jwks, make_jwt, metadata, provider, respond, Provider, CLIENT_ID, GOOD_KEY, ISSUER, OTHER_KEY, STATUS_ERROR};
use openidconnect::http::{HeaderValue, Request};
use openidconnect::url::Url;
use openidconnect::{ClaimsVerificationError, HttpRequest};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use time::OffsetDateTime;
use types::TestResult;


const BASE_TIME: i64 = 1_700_000_010;


const TOKEN_TTL: i64 = 3600;


const KEY_FILL: u8 = 9;


const KEY_LENGTH: usize = 32;


const AUDIT_BUDGET: usize = 10;


const REQUEST_BUFFER: usize = 1024;


const HTTP_OK: u16 = 200;


const PLUS_TWO: i64 = 2;


const PROVIDER_REFUSALS: usize = 6;


const NON_UTF8_BYTE: u8 = 255;


const REASON_COUNT: usize = 13;


const GROUP_COUNT: usize = 2;


const CHALLENGE_LENGTH: usize = 43;


const SOURCE: &str = "10.0.0.7";


const SUBJECT: &str = "user-1";


const ANALYST_GROUP: &str = "soc-analysts";


const ADMIN_GROUP: &str = "soc-admins";


const CONFIG_TEXT: &str = "issuer: https://idp.example\nclient_id: test-client\nclient_secret: vault://kv/oidc\nredirect_url: https://ostyr.example/callback\nrole_map:\n  soc-analysts: [analyst]\n  soc-admins: [administrator, responder]\nmfa_amr: [mfa, otp]\nmfa_acr: [\"urn:mfa\"]\n";


const CONFIG_WITHOUT_MFA: &str = "issuer: https://idp.example\nclient_id: test-client\nclient_secret: vault://kv/oidc\nredirect_url: https://ostyr.example/callback\nrole_map:\n  soc-analysts: [analyst]\n  soc-admins: [administrator, responder]\n";


struct Fixture<Output> {
    audit: AuditLog<Output>,
    key: StoreKey,
    catalog: RoleCatalog,
    compromised: CompromisedSet,
    config: OidcConfig,
}


struct Spec {
    iss: String,
    aud: String,
    sub: String,
    nonce: Option<String>,
    exp_offset: i64,
    groups: Value,
    amr: Value,
    acr: Option<String>,
    pem: &'static str,
    state: Option<String>,
    include_token: bool,
    token_status: u16,
    with_token_endpoint: bool,
    discoveries: usize,
}


struct Prepared {
    state: String,
    nonce: String,
    challenge: String,
}


fn config() -> Result<OidcConfig, Box<dyn std::error::Error>> {
    Ok(parse_oidc_config(CONFIG_TEXT, "oidc.yaml", &builtin_catalog())?)
}


fn fixture_over<Output: Write>(output: Output) -> Result<Fixture<Output>, Box<dyn std::error::Error>> {
    fixture_text(output, CONFIG_TEXT)
}


fn fixture_text<Output: Write>(output: Output, text: &str) -> Result<Fixture<Output>, Box<dyn std::error::Error>> {
    Ok(Fixture {
        audit: genesis_log(output),
        key: SecretSlice::from(vec![KEY_FILL; KEY_LENGTH]),
        catalog: builtin_catalog(),
        compromised: CompromisedSet::new(),
        config: parse_oidc_config(text, "oidc.yaml", &builtin_catalog())?,
    })
}


fn context<Output>(fixture: &Fixture<Output>) -> Context<'_, Output> {
    context_with(fixture, os_random)
}


fn context_with<Output>(fixture: &Fixture<Output>, random: core_auth::types::RandomFn) -> Context<'_, Output> {
    Context {
        audit: &fixture.audit,
        random,
        verify: &verify_password,
        key: &fixture.key,
        compromised: &fixture.compromised,
        catalog: &fixture.catalog,
        tenant: "tenant-a",
        request_id: "request-1",
    }
}


fn at(offset: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(BASE_TIME + offset)
}


fn resolve(reference: &SecretRef) -> Result<SecretString, io::Error> {
    if reference.0 == "vault://kv/oidc" {
        Ok(SecretString::from(oidc_provider::CLIENT_SECRET))
    } else {
        Err(io::Error::other("unknown reference"))
    }
}


fn spec() -> Spec {
    Spec {
        iss: ISSUER.to_owned(),
        aud: CLIENT_ID.to_owned(),
        sub: SUBJECT.to_owned(),
        nonce: None,
        exp_offset: TOKEN_TTL,
        groups: json!([ANALYST_GROUP]),
        amr: Value::Null,
        acr: None,
        pem: GOOD_KEY,
        state: None,
        include_token: true,
        token_status: oidc_provider::STATUS_OK,
        with_token_endpoint: true,
        discoveries: usize::MAX,
    }
}


fn audit_text(fixture: &Fixture<Vec<u8>>) -> Result<String, Box<dyn std::error::Error>> {
    let state = fixture.audit.state.lock().map_err(|_| "poisoned")?;
    verify(state.writer.as_slice(), None)?;
    Ok(String::from_utf8(state.writer.clone())?)
}


fn prepare<Output: Write>(fixture: &Fixture<Output>, pending: &mut PendingMap) -> Result<Prepared, Box<dyn std::error::Error>> {
    let idle = provider(None, None);
    let http = |request: HttpRequest| respond(&idle, request);
    let oidc = OidcContext {
        config: &fixture.config,
        http: &http,
        resolve: &resolve,
    };
    let url = Url::parse(&begin_login(&context(fixture), &oidc, pending, at(0)?, SOURCE)?)?;
    let pairs: BTreeMap<String, String> = url.query_pairs().map(|(name, value)| (name.into_owned(), value.into_owned())).collect();
    let field = |name: &str| pairs.get(name).cloned().ok_or(format!("missing {name}"));
    assert_eq!(field("code_challenge_method")?, "S256");
    assert_eq!(field("client_id")?, CLIENT_ID);
    assert_eq!(field("response_type")?, "code");
    assert!(field("scope")?.contains("openid"));
    Ok(Prepared {
        state: field("state")?,
        nonce: field("nonce")?,
        challenge: field("code_challenge")?,
    })
}


fn token_for(prepared: &Prepared, spec: &Spec) -> Result<String, Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = json!({
        "iss": spec.iss,
        "aud": [spec.aud],
        "sub": spec.sub,
        "exp": now + spec.exp_offset,
        "iat": now,
        "nonce": spec.nonce.clone().unwrap_or_else(|| prepared.nonce.clone()),
        "groups": spec.groups,
        "amr": spec.amr,
        "acr": spec.acr,
    });
    make_jwt(spec.pem, &claims)
}


fn complete<Output: Write>(
    fixture: &Fixture<Output>,
    state: &mut State,
    pending: &mut PendingMap,
    prepared: &Prepared,
    spec: &Spec,
) -> Result<Result<SecretString, AuthError>, Box<dyn std::error::Error>> {
    complete_with(fixture, &context(fixture), state, pending, prepared, spec)
}


fn complete_with<Output: Write>(
    fixture: &Fixture<Output>,
    ctx: &Context<Output>,
    state: &mut State,
    pending: &mut PendingMap,
    prepared: &Prepared,
    spec: &Spec,
) -> Result<Result<SecretString, AuthError>, Box<dyn std::error::Error>> {
    let mut mock: Provider = provider(
        spec.include_token.then(|| token_for(prepared, spec)).transpose()?,
        Some(prepared.challenge.clone()),
    );
    mock.token_status = spec.token_status;
    mock.with_token_endpoint = spec.with_token_endpoint;
    mock.discoveries_left.set(spec.discoveries);
    let http = |request: HttpRequest| respond(&mock, request);
    let oidc = OidcContext {
        config: &fixture.config,
        http: &http,
        resolve: &resolve,
    };
    let callback = Callback {
        state: spec.state.clone().unwrap_or_else(|| prepared.state.clone()),
        code: SecretString::from("code-1"),
        source: SOURCE.to_owned(),
    };
    Ok(complete_login(state, pending, ctx, &oidc, at(1)?, &callback))
}


fn refused(fixture: &Fixture<Vec<u8>>, spec: &Spec, reason: &str) -> TestResult {
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let prepared = prepare(fixture, &mut pending)?;
    let result = complete(fixture, &mut state, &mut pending, &prepared, spec)?;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    assert!(state.sessions.is_empty());
    assert!(state.accounts.is_empty());
    let text = audit_text(fixture)?;
    assert!(text.contains(&format!("\"reason\":\"{reason}\"")), "{text}");
    assert!(text.contains("\"outcome\":\"failure\""));
    Ok(())
}


#[test]
fn happy_path_creates_a_session_and_audits() -> TestResult {
    let fixture = fixture_over(Vec::new())?;
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let prepared = prepare(&fixture, &mut pending)?;
    let token = complete(&fixture, &mut state, &mut pending, &prepared, &spec())??;
    assert!(pending.is_empty());
    let user = authorize(
        &mut state,
        &fixture.catalog,
        token.expose_secret(),
        at(PLUS_TWO)?,
        PERMISSION_ALERTS_TRIAGE,
    )?;
    assert_eq!(user, "oidc:user-1");
    assert!(matches!(
        authorize(
            &mut state,
            &fixture.catalog,
            token.expose_secret(),
            at(PLUS_TWO)?,
            PERMISSION_USERS_MANAGE
        ),
        Err(AuthError::PermissionDenied)
    ));
    let text = audit_text(&fixture)?;
    assert!(text.contains("authz.oidc.map") && text.contains("auth.login") && text.contains("\"method\":\"oidc\""));
    assert!(text.contains("\"roles\":\"analyst\""));
    assert!(!text.contains(token.expose_secret()));
    Ok(())
}


#[test]
fn replayed_callback_is_refused() -> TestResult {
    let fixture = fixture_over(Vec::new())?;
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let prepared = prepare(&fixture, &mut pending)?;
    complete(&fixture, &mut state, &mut pending, &prepared, &spec())??;
    let replay = complete(&fixture, &mut state, &mut pending, &prepared, &spec())?;
    assert!(matches!(replay, Err(AuthError::InvalidCredentials)));
    assert_eq!(state.sessions.len(), 1);
    assert!(audit_text(&fixture)?.contains("bad_state"));
    Ok(())
}


#[test]
fn bad_state_is_refused() -> TestResult {
    refused(
        &fixture_over(Vec::new())?,
        &Spec {
            state: Some("forged".to_owned()),
            ..spec()
        },
        "bad_state",
    )
}


#[test]
fn expired_pending_login_is_refused() -> TestResult {
    let fixture = fixture_over(Vec::new())?;
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let prepared = prepare(&fixture, &mut pending)?;
    pending
        .values_mut()
        .for_each(|login| login.created_at -= time::Duration::seconds(core_auth::oidc::PENDING_TTL_SECONDS));
    let result = complete(&fixture, &mut state, &mut pending, &prepared, &spec())?;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    assert!(audit_text(&fixture)?.contains("bad_state"));
    Ok(())
}


#[test]
fn bad_nonce_is_refused() -> TestResult {
    refused(
        &fixture_over(Vec::new())?,
        &Spec {
            nonce: Some("other".to_owned()),
            ..spec()
        },
        "bad_nonce",
    )
}


#[test]
fn expired_token_is_refused() -> TestResult {
    refused(
        &fixture_over(Vec::new())?,
        &Spec {
            exp_offset: -TOKEN_TTL,
            ..spec()
        },
        "expired",
    )
}


#[test]
fn wrong_audience_is_refused() -> TestResult {
    refused(
        &fixture_over(Vec::new())?,
        &Spec {
            aud: "someone-else".to_owned(),
            ..spec()
        },
        "wrong_audience",
    )
}


#[test]
fn wrong_issuer_is_refused() -> TestResult {
    refused(
        &fixture_over(Vec::new())?,
        &Spec {
            iss: "https://evil.example".to_owned(),
            ..spec()
        },
        "wrong_issuer",
    )
}


#[test]
fn unknown_signing_key_is_refused() -> TestResult {
    refused(&fixture_over(Vec::new())?, &Spec { pem: OTHER_KEY, ..spec() }, "bad_signature")
}


#[test]
fn missing_id_token_is_refused() -> TestResult {
    refused(
        &fixture_over(Vec::new())?,
        &Spec {
            include_token: false,
            ..spec()
        },
        "missing_id_token",
    )
}


#[test]
fn token_endpoint_failure_is_refused() -> TestResult {
    refused(
        &fixture_over(Vec::new())?,
        &Spec {
            token_status: STATUS_ERROR,
            ..spec()
        },
        "provider_error",
    )
}


#[test]
fn missing_token_endpoint_is_refused() -> TestResult {
    refused(
        &fixture_over(Vec::new())?,
        &Spec {
            with_token_endpoint: false,
            ..spec()
        },
        "provider_error",
    )
}


#[test]
fn discovery_failure_at_completion_is_refused() -> TestResult {
    refused(&fixture_over(Vec::new())?, &Spec { discoveries: 0, ..spec() }, "provider_error")
}


#[test]
fn invalid_subject_is_refused() -> TestResult {
    refused(
        &fixture_over(Vec::new())?,
        &Spec {
            sub: "bad subject".to_owned(),
            ..spec()
        },
        "invalid_subject",
    )
}


#[test]
fn unmapped_user_gets_no_role_and_no_session() -> TestResult {
    let fixture = fixture_over(Vec::new())?;
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let prepared = prepare(&fixture, &mut pending)?;
    let unmapped = Spec {
        groups: json!(["nobody"]),
        ..spec()
    };
    let result = complete(&fixture, &mut state, &mut pending, &prepared, &unmapped)?;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    assert!(state.sessions.is_empty() && state.accounts.is_empty());
    let text = audit_text(&fixture)?;
    assert!(text.contains("\"reason\":\"unmapped\"") && text.contains("\"outcome\":\"denied\"") && text.contains("authz.oidc.map"));
    Ok(())
}


#[test]
fn user_without_groups_claim_is_unmapped() -> TestResult {
    let fixture = fixture_over(Vec::new())?;
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let prepared = prepare(&fixture, &mut pending)?;
    let none = Spec {
        groups: json!("single-string"),
        ..spec()
    };
    let result = complete(&fixture, &mut state, &mut pending, &prepared, &none)?;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    Ok(())
}


#[test]
fn object_groups_and_role_changes_revoke_old_sessions() -> TestResult {
    let fixture = fixture_over(Vec::new())?;
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let first = prepare(&fixture, &mut pending)?;
    let analyst = complete(&fixture, &mut state, &mut pending, &first, &spec())??;
    let second = prepare(&fixture, &mut pending)?;
    let same = complete(&fixture, &mut state, &mut pending, &second, &spec())??;
    assert!(authorize(
        &mut state,
        &fixture.catalog,
        analyst.expose_secret(),
        at(PLUS_TWO)?,
        PERMISSION_ALERTS_TRIAGE
    )
    .is_ok());
    let third = prepare(&fixture, &mut pending)?;
    let promoted = Spec {
        groups: json!({ ADMIN_GROUP: {"org": "domain"} }),
        amr: json!(["mfa"]),
        ..spec()
    };
    let admin = complete(&fixture, &mut state, &mut pending, &third, &promoted)??;
    assert!(authorize(
        &mut state,
        &fixture.catalog,
        analyst.expose_secret(),
        at(PLUS_TWO)?,
        PERMISSION_ALERTS_TRIAGE
    )
    .is_err());
    assert!(authorize(
        &mut state,
        &fixture.catalog,
        same.expose_secret(),
        at(PLUS_TWO)?,
        PERMISSION_ALERTS_TRIAGE
    )
    .is_err());
    assert!(authorize(
        &mut state,
        &fixture.catalog,
        admin.expose_secret(),
        at(PLUS_TWO)?,
        PERMISSION_USERS_MANAGE
    )
    .is_ok());
    Ok(())
}


#[test]
fn external_accounts_cannot_be_created_or_logged_in_locally() -> TestResult {
    let fixture = fixture_over(Vec::new())?;
    let mut state = State::default();
    let created = create_account(
        &mut state,
        &context(&fixture),
        at(0)?,
        "none",
        "oidc:x",
        &SecretString::from("a long enough passphrase"),
        BTreeSet::new(),
    );
    assert!(created.is_err());
    Ok(())
}


#[test]
fn session_creation_failure_is_audited() -> TestResult {
    let fixture = fixture_over(Vec::new())?;
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let prepared = prepare(&fixture, &mut pending)?;
    let failing = context_with(&fixture, |_| Err(getrandom::Error::UNSUPPORTED));
    let result = complete_with(&fixture, &failing, &mut state, &mut pending, &prepared, &spec())?;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    assert!(state.sessions.is_empty());
    assert!(audit_text(&fixture)?.contains("provider_error"));
    Ok(())
}


fn budget_run(budget: usize, spec: &Spec) -> Result<&'static str, Box<dyn std::error::Error>> {
    let fixture = fixture_over(LimitedWriter {
        operations_left: usize::MAX,
        bytes: Vec::new(),
    })?;
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let prepared = prepare(&fixture, &mut pending)?;
    fixture.audit.state.lock().map_err(|_| "poisoned")?.writer.operations_left = budget;
    let result = complete(&fixture, &mut state, &mut pending, &prepared, spec)?;
    assert!(result.is_ok() || (state.sessions.is_empty() && state.accounts.is_empty()));
    match &result {
        Ok(_) => Ok("ok"),
        Err(AuthError::Audit(_)) => Ok("audit"),
        Err(AuthError::InvalidCredentials) => Ok("denied"),
        Err(other) => Err(format!("unexpected {other:?}").into()),
    }
}


#[test]
fn audit_failures_leave_state_unchanged() -> TestResult {
    let denied = [
        Spec {
            groups: json!(["nobody"]),
            ..spec()
        },
        Spec {
            sub: "bad subject".to_owned(),
            ..spec()
        },
        Spec {
            state: Some("forged".to_owned()),
            ..spec()
        },
    ];
    let runs = |variant: &Spec| {
        (0..=AUDIT_BUDGET)
            .map(|budget| budget_run(budget, variant))
            .collect::<Result<Vec<_>, _>>()
    };
    let happy = runs(&spec())?;
    assert!(happy.contains(&"ok") && happy.contains(&"audit"));
    denied.iter().try_for_each(|variant| {
        let labels = runs(variant)?;
        assert!(labels.contains(&"denied") && labels.contains(&"audit"));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn session_creation_failure_with_failing_audit_is_an_audit_error() -> TestResult {
    let fixture = fixture_over(LimitedWriter {
        operations_left: 0,
        bytes: Vec::new(),
    })?;
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let prepared = prepare(&fixture, &mut pending)?;
    let failing = context_with(&fixture, |_| Err(getrandom::Error::UNSUPPORTED));
    let result = complete_with(&fixture, &failing, &mut state, &mut pending, &prepared, &spec())?;
    assert!(matches!(result, Err(AuthError::Audit(_))));
    Ok(())
}


#[test]
fn begin_login_reports_failures() -> TestResult {
    let fixture = fixture_over(Vec::new())?;
    let healthy = provider(None, None);
    let healthy_http = |request: HttpRequest| respond(&healthy, request);
    let broken = provider(None, None);
    broken.discoveries_left.set(0);
    let broken_http = |request: HttpRequest| respond(&broken, request);
    let mut pending = PendingMap::new();
    let with = |config: &OidcConfig, http: &dyn Fn(HttpRequest) -> Result<openidconnect::HttpResponse, io::Error>, queue: &mut PendingMap| {
        let oidc = OidcContext {
            config,
            http,
            resolve: &resolve,
        };
        begin_login(
            &context(&fixture),
            &oidc,
            queue,
            at(0).map_err(|error| AuthError::Usage(error.to_string()))?,
            SOURCE,
        )
    };
    let insecure_issuer = OidcConfig {
        issuer: "http://idp.example".to_owned(),
        ..fixture.config.clone()
    };
    let insecure_redirect = OidcConfig {
        redirect_url: "http://ostyr.example/callback".to_owned(),
        ..fixture.config.clone()
    };
    let bad_issuer = OidcConfig {
        issuer: "not a url".to_owned(),
        ..fixture.config.clone()
    };
    let bad_redirect = OidcConfig {
        redirect_url: "not a url".to_owned(),
        ..fixture.config.clone()
    };
    let bad_secret = OidcConfig {
        client_secret: SecretRef("vault://missing".to_owned()),
        ..fixture.config.clone()
    };
    let scoped = OidcConfig {
        scopes: vec!["profile".to_owned()],
        ..fixture.config.clone()
    };
    assert!(matches!(
        with(&bad_issuer, &healthy_http, &mut pending),
        Err(AuthError::Oidc(OidcDenial::Provider))
    ));
    assert!(matches!(
        with(&bad_redirect, &healthy_http, &mut pending),
        Err(AuthError::Oidc(OidcDenial::Provider))
    ));
    assert!(matches!(
        with(&bad_secret, &healthy_http, &mut pending),
        Err(AuthError::Oidc(OidcDenial::Provider))
    ));
    assert!(matches!(
        with(&fixture.config, &broken_http, &mut pending),
        Err(AuthError::Oidc(OidcDenial::Provider))
    ));
    assert!(matches!(
        with(&insecure_issuer, &healthy_http, &mut pending),
        Err(AuthError::Oidc(OidcDenial::Provider))
    ));
    assert!(matches!(
        with(&insecure_redirect, &healthy_http, &mut pending),
        Err(AuthError::Oidc(OidcDenial::Provider))
    ));
    assert!(pending.is_empty());
    let refusals = audit_text(&fixture)?;
    assert_eq!(refusals.matches("\"reason\":\"provider_error\"").count(), PROVIDER_REFUSALS);
    assert!(refusals.contains("\"source\":\"10.0.0.7\""));
    let scoped_url = with(&scoped, &healthy_http, &mut pending)?;
    assert!(scoped_url.contains("scope=openid+profile"), "{scoped_url}");
    let oidc = OidcContext {
        config: &fixture.config,
        http: &healthy_http,
        resolve: &resolve,
    };
    let failing = context_with(&fixture, |_| Err(getrandom::Error::UNSUPPORTED));
    let failing_random = begin_login(&failing, &oidc, &mut PendingMap::new(), at(0)?, SOURCE);
    assert!(matches!(failing_random, Err(AuthError::Random(_))));
    Ok(())
}


#[test]
fn begin_login_refusal_with_failing_audit_is_an_audit_error() -> TestResult {
    let fixture = fixture_over(LimitedWriter {
        operations_left: 0,
        bytes: Vec::new(),
    })?;
    let broken = provider(None, None);
    broken.discoveries_left.set(0);
    let http = |request: HttpRequest| respond(&broken, request);
    let oidc = OidcContext {
        config: &fixture.config,
        http: &http,
        resolve: &resolve,
    };
    let result = begin_login(&context(&fixture), &oidc, &mut PendingMap::new(), at(0)?, SOURCE);
    assert!(matches!(result, Err(AuthError::Audit(_))));
    Ok(())
}


#[test]
fn pending_logins_are_capped_and_pruned() -> TestResult {
    let fixture = fixture_over(Vec::new())?;
    let mut pending = PendingMap::new();
    let first = prepare(&fixture, &mut pending)?;
    let template = pending.values().next().cloned().ok_or("no pending")?;
    (0..PENDING_MAX).for_each(|index| {
        pending.insert(format!("filler-{index}"), template.clone());
    });
    let idle = provider(None, None);
    let http = |request: HttpRequest| respond(&idle, request);
    let oidc = OidcContext {
        config: &fixture.config,
        http: &http,
        resolve: &resolve,
    };
    assert!(matches!(
        begin_login(&context(&fixture), &oidc, &mut pending, at(0)?, SOURCE),
        Err(AuthError::Oidc(OidcDenial::TooManyPending))
    ));
    assert!(audit_text(&fixture)?.contains("\"reason\":\"too_many_pending\""));
    let later = at(core_auth::oidc::PENDING_TTL_SECONDS + 1)?;
    begin_login(&context(&fixture), &oidc, &mut pending, later, SOURCE)?;
    assert_eq!(pending.len(), 1);
    assert!(!first.state.is_empty());
    Ok(())
}


#[test]
fn config_loading_checks_secret_and_roles() -> TestResult {
    let catalog = builtin_catalog();
    let loaded = parse_oidc_config(CONFIG_TEXT, "oidc.yaml", &catalog)?;
    assert_eq!(loaded.groups_claim, "groups");
    assert!(loaded.scopes.is_empty());
    let plaintext = CONFIG_TEXT.replace("vault://kv/oidc", "hunter2-plaintext");
    let rejected = parse_oidc_config(&plaintext, "oidc.yaml", &catalog);
    assert!(matches!(&rejected, Err(AuthError::Config(_))));
    assert!(!format!("{rejected:?}").contains("hunter2"));
    let unknown_role = CONFIG_TEXT.replace("[analyst]", "[ghost]");
    assert!(matches!(
        parse_oidc_config(&unknown_role, "oidc.yaml", &catalog),
        Err(AuthError::UnknownRole(_))
    ));
    let insecure_issuer = CONFIG_TEXT.replace("https://idp.example", "http://idp.example");
    assert!(matches!(
        parse_oidc_config(&insecure_issuer, "oidc.yaml", &catalog),
        Err(AuthError::InsecureUrl(_))
    ));
    let insecure_redirect = CONFIG_TEXT.replace("https://ostyr.example", "http://ostyr.example");
    assert!(matches!(
        parse_oidc_config(&insecure_redirect, "oidc.yaml", &catalog),
        Err(AuthError::InsecureUrl(_))
    ));
    let garbage = CONFIG_TEXT.replace("https://idp.example", "not a url");
    assert!(matches!(
        parse_oidc_config(&garbage, "oidc.yaml", &catalog),
        Err(AuthError::InvalidUrl(_))
    ));
    Ok(())
}


#[test]
fn claims_and_groups_helpers() -> TestResult {
    let expected = [
        (ClaimsVerificationError::Other("x".to_owned()), OidcDenial::InvalidToken),
        (ClaimsVerificationError::Expired("x".to_owned()), OidcDenial::Expired),
    ];
    expected.into_iter().for_each(|(error, denial)| assert_eq!(claims_denial(error), denial));
    let reasons: BTreeSet<&str> = [
        OidcDenial::BadState,
        OidcDenial::Provider,
        OidcDenial::MissingIdToken,
        OidcDenial::Expired,
        OidcDenial::WrongAudience,
        OidcDenial::WrongIssuer,
        OidcDenial::BadNonce,
        OidcDenial::BadSignature,
        OidcDenial::InvalidToken,
        OidcDenial::InvalidSubject,
        OidcDenial::Unmapped,
        OidcDenial::TooManyPending,
        OidcDenial::MfaMissing,
    ]
    .into_iter()
    .map(denial_reason)
    .collect();
    assert_eq!(reasons.len(), REASON_COUNT);
    assert!(groups_of(&json!({"g": 1}), "g").is_empty());
    assert_eq!(groups_of(&json!({"g": ["a", true, "b"]}), "g").len(), GROUP_COUNT);
    let mapped = map_roles(&config()?, &BTreeSet::from([ANALYST_GROUP.to_owned(), "other".to_owned()]));
    assert_eq!(mapped, BTreeSet::from(["analyst".to_owned()]));
    Ok(())
}


#[test]
fn payload_decoding_rejects_malformed_tokens() -> TestResult {
    assert!(matches!(payload_of("nodots"), Err(OidcDenial::InvalidToken)));
    assert!(matches!(payload_of("a.!!!.c"), Err(OidcDenial::Provider)));
    assert!(matches!(payload_of("a.bm90LWpzb24.c"), Err(OidcDenial::Provider)));
    assert_eq!(payload_of("a.eyJnIjoxfQ.c")?, json!({"g": 1}));
    assert_eq!(challenge_of("abc").len(), CHALLENGE_LENGTH);
    assert!(metadata(false).get("token_endpoint").is_none());
    assert!(jwks()?.get("keys").is_some());
    Ok(())
}


fn serve_once(response: String) -> Result<(u16, std::thread::JoinHandle<io::Result<()>>), io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let mut buffer = [u8::MIN; REQUEST_BUFFER];
        let count = stream.read(&mut buffer)?;
        assert!(count > 0);
        stream.write_all(response.as_bytes())?;
        stream.flush()
    });
    Ok((port, handle))
}


#[test]
fn http_adapter_talks_to_a_server_and_reports_failures() -> TestResult {
    let (port, handle) =
        serve_once("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_owned())?;
    let request = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{port}/x"))
        .body(Vec::new())?;
    let response = http_call(&new_agent(), request)?;
    handle.join().map_err(|_| "server thread panicked")??;
    assert_eq!(response.status().as_u16(), HTTP_OK);
    assert_eq!(response.body(), b"{}");
    let closed = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let refused = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{closed}/x"))
        .body(Vec::new())?;
    assert!(http_call(&new_agent(), refused).is_err());
    Ok(())
}


fn reply_text(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}


fn get_request(port: u16) -> Result<openidconnect::HttpRequest, Box<dyn std::error::Error>> {
    Ok(Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{port}/x"))
        .header("x-test", "value")
        .body(Vec::new())?)
}


#[test]
fn http_adapter_refuses_oversized_bodies_and_error_statuses() -> TestResult {
    let limit = usize::try_from(RESPONSE_MAX_BYTES)?;
    let exact = "a".repeat(limit);
    let (exact_port, exact_handle) = serve_once(reply_text("200 OK", &exact))?;
    let accepted = http_call(&new_agent(), get_request(exact_port)?)?;
    exact_handle.join().map_err(|_| "server thread panicked")??;
    assert_eq!(accepted.body().len(), limit);
    let (big_port, big_handle) = serve_once(reply_text("200 OK", &"a".repeat(limit + 1)))?;
    let oversized = http_call(&new_agent(), get_request(big_port)?);
    big_handle.join().map_err(|_| "server thread panicked")??;
    assert!(oversized.is_err());
    let (status_port, status_handle) = serve_once(reply_text("500 Internal Server Error", "{}"))?;
    let failed = http_call(&new_agent(), get_request(status_port)?);
    status_handle.join().map_err(|_| "server thread panicked")??;
    assert!(failed.is_err());
    let binary = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:1/x")
        .header("x-test", HeaderValue::from_bytes(&[NON_UTF8_BYTE])?)
        .body(Vec::new())?;
    assert!(http_call(&new_agent(), binary).is_err());
    Ok(())
}


fn login_with(fixture: &Fixture<Vec<u8>>, state: &mut State, spec: &Spec) -> Result<Result<SecretString, AuthError>, Box<dyn std::error::Error>> {
    let mut pending = PendingMap::new();
    let prepared = prepare(fixture, &mut pending)?;
    complete(fixture, state, &mut pending, &prepared, spec)
}


fn admin(amr: Value, acr: Option<&str>) -> Spec {
    Spec {
        groups: json!([ADMIN_GROUP]),
        amr,
        acr: acr.map(str::to_owned),
        ..spec()
    }
}


#[test]
fn privileged_roles_need_a_configured_mfa_claim() -> TestResult {
    let cases = [
        (json!(["pwd"]), None, false),
        (Value::Null, None, false),
        (json!(["pwd", "otp"]), None, true),
        (json!(["mfa"]), None, true),
        (Value::Null, Some("urn:mfa"), true),
        (json!(["pwd"]), Some("urn:mfa"), true),
        (Value::Null, Some("urn:other"), false),
    ];
    cases.into_iter().try_for_each(|(amr, acr, granted)| {
        let fixture = fixture_over(Vec::new())?;
        let mut state = State::default();
        let result = login_with(&fixture, &mut state, &admin(amr, acr))?;
        assert_eq!(result.is_ok(), granted);
        assert_eq!(state.sessions.len(), usize::from(granted));
        assert_eq!(state.accounts.len(), usize::from(granted));
        let text = audit_text(&fixture)?;
        assert_eq!(text.contains("\"reason\":\"mfa_missing\""), !granted);
        assert_eq!(text.contains("\"outcome\":\"denied\""), !granted);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn privileged_roles_are_never_granted_without_configured_mfa() -> TestResult {
    let fixture = fixture_text(Vec::new(), CONFIG_WITHOUT_MFA)?;
    let mut state = State::default();
    let strong = admin(json!(["mfa", "otp", "hwk"]), Some("urn:mfa"));
    let result = login_with(&fixture, &mut state, &strong)?;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    assert!(state.sessions.is_empty() && state.accounts.is_empty());
    let analyst = login_with(&fixture, &mut state, &spec())?;
    assert!(analyst.is_ok());
    Ok(())
}


#[test]
fn losing_mapping_or_mfa_clears_roles_and_sessions() -> TestResult {
    let lost = [
        Spec {
            groups: json!(["nobody"]),
            ..admin(json!(["mfa"]), None)
        },
        admin(json!(["pwd"]), None),
    ];
    lost.iter().try_for_each(|downgrade| {
        let fixture = fixture_over(Vec::new())?;
        let mut state = State::default();
        let token = login_with(&fixture, &mut state, &admin(json!(["mfa"]), None))??;
        assert_eq!(state.sessions.len(), 1);
        let result = login_with(&fixture, &mut state, downgrade)?;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
        assert!(state.sessions.is_empty());
        let account = state.accounts.get("oidc:user-1").ok_or("account missing")?;
        assert!(account.roles.is_empty());
        assert!(authorize(
            &mut state,
            &fixture.catalog,
            token.expose_secret(),
            at(PLUS_TWO)?,
            PERMISSION_ALERTS_TRIAGE
        )
        .is_err());
        let text = audit_text(&fixture)?;
        assert!(text.contains("\"revoked\":\"1\""), "{text}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


fn downgrade_run(budget: usize) -> Result<&'static str, Box<dyn std::error::Error>> {
    let fixture = fixture_over(LimitedWriter {
        operations_left: usize::MAX,
        bytes: Vec::new(),
    })?;
    let mut state = State::default();
    let mut pending = PendingMap::new();
    let first = prepare(&fixture, &mut pending)?;
    complete(&fixture, &mut state, &mut pending, &first, &spec())??;
    let second = prepare(&fixture, &mut pending)?;
    fixture.audit.state.lock().map_err(|_| "poisoned")?.writer.operations_left = budget;
    let unmapped = Spec {
        groups: json!(["nobody"]),
        ..spec()
    };
    let result = complete(&fixture, &mut state, &mut pending, &second, &unmapped)?;
    let account = state.accounts.get("oidc:user-1").ok_or("account missing")?;
    match &result {
        Err(AuthError::Audit(_)) => {
            assert!(!account.roles.is_empty() && state.sessions.len() == 1);
            Ok("audit")
        }
        Err(AuthError::InvalidCredentials) => {
            assert!(account.roles.is_empty() && state.sessions.is_empty());
            Ok("denied")
        }
        other => Err(format!("unexpected {other:?}").into()),
    }
}


#[test]
fn downgrade_is_committed_only_after_the_audit_append() -> TestResult {
    let labels = (0..=AUDIT_BUDGET).map(downgrade_run).collect::<Result<Vec<_>, _>>()?;
    assert!(labels.contains(&"denied") && labels.contains(&"audit"));
    Ok(())
}


#[test]
fn store_refuses_local_accounts_in_the_oidc_namespace() -> TestResult {
    let local =
        r#"{"version":1,"accounts":[{"username":"oidc:x","password_hash":"$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHQ$aGFzaA","roles":[],"totp":null}]}"#;
    assert!(matches!(load_accounts(local.as_bytes()), Err(AuthError::ReservedAccount(name)) if name == "oidc:x"));
    let external = local.replace("$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHQ$aGFzaA", "!external");
    assert_eq!(load_accounts(external.as_bytes())?.len(), 1);
    let ordinary = local.replace("oidc:x", "alice");
    assert_eq!(load_accounts(ordinary.as_bytes())?.len(), 1);
    Ok(())
}
