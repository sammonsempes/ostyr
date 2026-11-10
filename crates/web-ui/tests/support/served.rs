use crate::harness::{fire_body, post_form};
use crate::stub::{start_stub, Mode};
use crate::types::{TestError, TestResult};
use axum::body::Body;
use axum::http::StatusCode;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use core_api::types::ServerHandle;
use core_auth::random::os_random;
use core_config::reload::{reload, ReloadEngine, ReloadOutcome};
use rcgen::generate_simple_self_signed;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use web_ui::client::{client_tls, prepare};
use web_ui::config::{load_web_config, DEFAULT_LIMITS};
use web_ui::error::WebError;
use web_ui::model::{TlsSection, WebConfig};
use web_ui::routes::build_router;
use web_ui::server::{audit_into, build_engine, monotonic_seconds, new_state, reload_subscriber, serve_web};
use web_ui::types::PendingRuntime;


const OWNER_ONLY: u32 = 0o600;


const WORLD_READABLE: u32 = 0o644;


const TWO_LOGINS: usize = 2;


const LOGIN_FORM: &str = "csrf=abc&username=alice&password=secret";


struct Pki {
    certificate: PathBuf,
    key: PathBuf,
}


fn write_pki(dir: &TempDir, stem: &str) -> Result<Pki, TestError> {
    let generated = generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let certificate = dir.path().join(format!("{stem}.pem"));
    let key = dir.path().join(format!("{stem}.key"));
    fs::write(&certificate, generated.cert.pem())?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(OWNER_ONLY)
        .open(&key)?
        .write_all(generated.signing_key.serialize_pem().as_bytes())?;
    Ok(Pki { certificate, key })
}


fn settings(dir: &TempDir, listen: &str, base_url: &str, tls: Option<&Pki>, ca: Option<&Path>) -> Result<PathBuf, TestError> {
    let tls_text = tls.map_or_else(String::new, |pki| {
        format!("tls:\n  certificate: {}\n  key: {}\n", pki.certificate.display(), pki.key.display())
    });
    let ca_text = ca.map_or_else(String::new, |path| format!("  ca: {}\n", path.display()));
    let file = dir.path().join("web-ui.yaml");
    fs::write(
        &file,
        format!(
            "listen: {listen}\n{tls_text}api:\n  base_url: {base_url}\n  timeout_seconds: 5\n{ca_text}audit_file: {}\n",
            dir.path().join("audit.log").display()
        ),
    )?;
    Ok(file)
}


struct Engine {
    engine: Arc<ReloadEngine<WebConfig>>,
    router: Router,
    tls: Option<RustlsConfig>,
}


fn open_running(file: &Path) -> Result<Engine, TestError> {
    let config = load_web_config(file)?;
    let prepared = prepare(&config)?;
    let state = Arc::new(new_state(prepared.client, DEFAULT_LIMITS, Box::new(|| 0), os_random));
    let tls = prepared.tls.map(RustlsConfig::from_config);
    let subscriber = reload_subscriber(config.clone(), state.clone(), tls.clone(), PendingRuntime::default());
    let engine = Arc::new(build_engine(config.clone(), file, subscriber, audit_into(&config.audit_file)?));
    Ok(Engine {
        engine,
        router: build_router(state),
        tls,
    })
}


async fn login_through(router: &Router) -> Result<StatusCode, TestError> {
    let reply = fire_body(
        router,
        post_form("/login", vec!["__Host-ostyr_login=abc".to_owned()], LOGIN_FORM),
        Body::from(LOGIN_FORM),
    )
    .await?;
    Ok(reply.status)
}


#[tokio::test]
async fn a_reload_swaps_the_api_and_the_certificate_and_refuses_what_cannot_change() -> TestResult {
    let (first_api, second_api) = (start_stub(Mode::Normal).await?, start_stub(Mode::Normal).await?);
    let dir = tempdir()?;
    let pki = write_pki(&dir, "one")?;
    let base_one = format!("http://{}/", first_api.address);
    let file = settings(&dir, "127.0.0.1:0", &base_one, Some(&pki), None)?;
    let running = open_running(&file)?;
    assert_eq!(reload(&running.engine), ReloadOutcome::Unchanged);
    assert_eq!(login_through(&running.router).await?, StatusCode::SEE_OTHER);
    assert_eq!(first_api.state.logins.load(Ordering::SeqCst), 1);

    let second_pki = write_pki(&dir, "two")?;
    let before = running.tls.as_ref().ok_or("no tls")?.get_inner();
    let base_two = format!("http://{}/", second_api.address);
    settings(&dir, "127.0.0.1:0", &base_two, Some(&second_pki), None)?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(login_through(&running.router).await?, StatusCode::SEE_OTHER);
    assert_eq!(second_api.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(first_api.state.logins.load(Ordering::SeqCst), 1);
    assert!(!Arc::ptr_eq(&before, &running.tls.as_ref().ok_or("no tls")?.get_inner()));

    for (listen, tls, base) in [
        ("127.0.0.1:1", Some(&second_pki), base_two.as_str()),
        ("127.0.0.1:0", None, base_two.as_str()),
        ("127.0.0.1:0", Some(&second_pki), "http://example.test/"),
    ] {
        settings(&dir, listen, base, tls, None)?;
        assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { .. }), "{listen} {base}");
    }
    let missing_ca = dir.path().join("absent-ca.pem");
    settings(&dir, "127.0.0.1:0", &base_two, Some(&second_pki), Some(&missing_ca))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { .. }));
    assert_eq!(login_through(&running.router).await?, StatusCode::SEE_OTHER);
    assert_eq!(second_api.state.logins.load(Ordering::SeqCst), TWO_LOGINS);
    let audit = fs::read_to_string(dir.path().join("audit.log"))?;
    assert!(audit.contains("config.reload") && audit.contains("applied") && audit.contains("refused"));
    assert_eq!(
        first_api.state.logouts.load(Ordering::SeqCst) + first_api.state.details.load(Ordering::SeqCst),
        0
    );
    assert!(first_api.state.last_query.lock().map_err(|_| "poisoned")?.is_empty());
    assert!(matches!(*first_api.state.mode.lock().map_err(|_| "poisoned")?, Mode::Normal));
    Ok(())
}


#[tokio::test]
async fn the_server_runs_over_tls_and_stops_on_its_handle() -> TestResult {
    let api = start_stub(Mode::Normal).await?;
    let dir = tempdir()?;
    let pki = write_pki(&dir, "srv")?;
    let file = settings(&dir, "127.0.0.1:0", &format!("http://{}/", api.address), Some(&pki), None)?;
    let handle = ServerHandle::new();
    let serving = tokio::spawn({
        let stopping = handle.clone();
        async move { serve_web(&file, stopping).await }
    });
    let address = handle.listening().await.ok_or("not listening")?;
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(client_tls(Some(&pki.certificate))?)
        .resolve("localhost", address)
        .build()?;
    let response = client.get(format!("https://localhost:{}/login", address.port())).send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    let policy = response.headers().get("content-security-policy").ok_or("no csp")?;
    assert!(policy.to_str()?.contains("frame-ancestors 'none'"));
    let cookie = response.headers().get("set-cookie").ok_or("no cookie")?.to_str()?.to_owned();
    assert!(cookie.contains("Secure") && cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    handle.graceful_shutdown(None);
    serving.await??;
    assert!(fs::read_to_string(dir.path().join("audit.log"))?.is_empty());
    Ok(())
}


#[tokio::test]
async fn startup_refusals() -> TestResult {
    let dir = tempdir()?;
    let open_listen = settings(&dir, "0.0.0.0:0", "https://api.test/", None, None)?;
    assert!(matches!(serve_web(&open_listen, ServerHandle::new()).await, Err(WebError::Startup(_))));
    let absent = dir.path().join("absent.yaml");
    assert!(matches!(serve_web(&absent, ServerHandle::new()).await, Err(WebError::Config(_))));
    let busy = std::net::TcpListener::bind("127.0.0.1:0")?;
    let taken = settings(&dir, &busy.local_addr()?.to_string(), "https://api.test/", None, None)?;
    assert!(serve_web(&taken, ServerHandle::new()).await.is_err());
    let missing_ca = dir.path().join("none.pem");
    let bad_ca = settings(&dir, "127.0.0.1:0", "https://api.test/", None, Some(&missing_ca))?;
    assert!(matches!(serve_web(&bad_ca, ServerHandle::new()).await, Err(WebError::Io(_))));
    let blocked = dir.path().join("blocked");
    fs::create_dir(&blocked)?;
    assert!(audit_into(&blocked).is_err());
    let unauditable = dir.path().join("unauditable.yaml");
    fs::write(
        &unauditable,
        format!(
            "listen: 127.0.0.1:0\napi:\n  base_url: https://api.test/\n  timeout_seconds: 5\naudit_file: {}\n",
            blocked.display()
        ),
    )?;
    assert!(matches!(serve_web(&unauditable, ServerHandle::new()).await, Err(WebError::Audit(_))));
    let pki = write_pki(&dir, "open")?;
    let loose = dir.path().join("loose.key");
    fs::copy(&pki.key, &loose)?;
    fs::set_permissions(&loose, fs::Permissions::from_mode(WORLD_READABLE))?;
    let insecure = WebConfig {
        tls: Some(TlsSection {
            certificate: pki.certificate,
            key: loose,
        }),
        ..load_web_config(&open_listen)?
    };
    assert!(prepare(&insecure).is_err());
    let first = monotonic_seconds();
    assert!(monotonic_seconds() >= first);
    Ok(())
}
