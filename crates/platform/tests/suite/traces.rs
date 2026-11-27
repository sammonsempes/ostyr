use crate::fixture::config_in;
use crate::types::{TestError, TestResult};
use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, Response, StatusCode};
use axum::Router;
use core_api::model::Requirement;
use core_api::routes::build_router;
use core_api::server::new_listener;
use core_api::state::build_state_from_files;
use core_api::types::{SharedListener, SharedState};
use core_config::reload::{current_config, reload, ReloadOutcome};
use opentelemetry_proto::tonic::collector::trace::v1::{ExportTraceServiceRequest, ExportTraceServiceResponse};
use opentelemetry_proto::tonic::common::v1::{any_value::Value as AnyKind, AnyValue, KeyValue};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use platform::error::PlatformError;
use platform::merge::{module_of, module_parts, module_router, start_only_keys, ACTOR};
use platform::model::Module;
use platform::permits::module_semaphores;
use platform::traces::{
    context_of, joined, now_nanos, open_traces, push_senders, require_tls, response_of, sender_listed, traces_access, traces_document,
    traces_files_of, TracesFiles, TracesRuntime, SETTING_SENDERS_FILE, SETTING_TRACES_SAMPLING, SETTING_TRACES_SETTINGS, TRACES_PATH,
};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tower::ServiceExt;
use traces_ingest::receive::{fixed, Reply, STATUS_OK};
use traces_ingest::senders::senders_state;
use traces_ingest::types::SenderTable;


const SENDER: &str = "collector";


const OTHER_SENDER: &str = "second";


const TOKEN: &str = "abababababababababababababababababababababababababababababababab";


const OTHER_TOKEN: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";


const PASSWORD: &str = "TRACEPW-platform-marker";


const OK: &str = "200 OK";


const SERVER_ERROR: &str = "500 Internal Server Error";


const PROTOBUF: &str = "application/x-protobuf";


const NOW_NANOS: u64 = 1_700_000_000_000_000_000;


const SPAN_ID_BYTES: usize = 8;


const TRACE_ID_BYTES: usize = 16;


const CLIENT_PORT: u16 = 40_001;


const HANG_GUARD: Duration = Duration::from_secs(60);


const OWNER_ONLY: u32 = 0o600;


const BODY_LIMIT: usize = 1_048_576;


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 4096;


const MAX_READS: usize = 10_000;


const POOL_SIZE: u32 = 16;


const TWO_SPANS: u8 = 2;


const LOWERED_REQUEST_BYTES: usize = 8;


struct Stub {
    listener: TcpListener,
    port: u16,
    requests: Receiver<String>,
    release: Sender<()>,
    handle: JoinHandle<io::Result<()>>,
}


struct Site {
    _dir: TempDir,
    dir_path: std::path::PathBuf,
    router: Router,
    state: SharedState,
    runtime: TracesRuntime,
    listener: SharedListener,
    files: TracesFiles,
    stub: Stub,
}


fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut received = Vec::new();
    let mut chunk = [u8::MIN; CHUNK];
    let mut expected = usize::MAX;
    let mut reads = 0;
    while received.len() < expected && reads < MAX_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        received.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
        let text = String::from_utf8_lossy(&received).to_lowercase();
        expected = text.find(HEADER_END).map_or(usize::MAX, |end| {
            let length = text
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            end + HEADER_END.len() + length
        });
        if count == 0 {
            expected = 0;
        }
    }
    Ok(String::from_utf8_lossy(&received).into_owned())
}


fn stub(statuses: Vec<&'static str>, gated: bool) -> Result<Stub, TestError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let serving = listener.try_clone()?;
    let (seen, requests) = channel();
    let (release, gate) = channel::<()>();
    let handle = spawn(move || {
        statuses.into_iter().try_for_each(|status| {
            let (mut stream, _) = serving.accept()?;
            let request = read_request(&mut stream)?;
            seen.send(request).map_err(io::Error::other)?;
            if gated {
                gate.recv().map_err(io::Error::other)?;
            }
            stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())
        })
    });
    Ok(Stub {
        listener,
        port,
        requests,
        release,
        handle,
    })
}


fn digest_of(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}


fn senders_text(entries: &[(&str, &str)]) -> String {
    let body: String = entries
        .iter()
        .map(|(name, token)| format!("  - name: {name}\n    token_sha256: {}\n", digest_of(token)))
        .collect();
    format!("senders:\n{body}")
}


fn write_files(dir: &TempDir, port: u16) -> Result<TracesFiles, TestError> {
    let password = dir.path().join("ch.pass");
    fs::write(&password, format!("{PASSWORD}\n"))?;
    fs::set_permissions(&password, fs::Permissions::from_mode(OWNER_ONLY))?;
    let files = TracesFiles {
        settings: dir.path().join("traces.yaml"),
        sampling: dir.path().join("sampling.yaml"),
        senders: dir.path().join("senders.yaml"),
    };
    fs::write(
        &files.settings,
        format!(
            "url: http://127.0.0.1:{port}\nuser: ostyr\npassword_file: {}\ndatabase: ostyr\ntable: trace_spans\ntimeout_ms: 30000\nlimits:\n  max_batch_rows: 1\n",
            password.display()
        ),
    )?;
    fs::write(&files.sampling, "default_ratio: 1.0\n")?;
    fs::write(&files.senders, senders_text(&[(SENDER, TOKEN)]))?;
    Ok(files)
}


fn site(statuses: Vec<&'static str>, gated: bool) -> Result<Site, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    let started = stub(statuses, gated)?;
    let files = write_files(&dir, started.port)?;
    let pg_file = dir.path().join("pg.yaml");
    fs::write(
        &pg_file,
        "host: 127.0.0.1\nport: 1\ndatabase: ostyr\nuser: ostyr\npassword_file: /run/pg.pass\nca_file: /run/ca.pem\n",
    )?;
    let module_file = dir.path().join("platform.yaml");
    fs::write(
        &module_file,
        format!(
            "name: platform\nversion: \"1\"\ntenant: acme\nsettings:\n  modules: \"traces\"\n  pg_settings: {}\n",
            pg_file.display()
        ),
    )?;
    let listener = new_listener();
    let (opened, _pg) = alerts::settings::open_pg_engine_as(&module_file, listener.clone(), ACTOR)?;
    let runtime = open_traces(&files, "acme", "platform", &listener)?;
    let (extra, access, documents) = module_parts(
        &[Module::Traces],
        &Arc::new(opened),
        &module_semaphores(&[Module::Traces]),
        None,
        None,
        Some(&runtime),
    )?;
    let state: SharedState = Arc::new(build_state_from_files(&config, access, documents)?);
    listener.state.get_or_init(|| state.clone());
    push_senders(&listener, &current_config(&runtime.senders));
    let router = build_router(state.clone(), extra);
    let dir_path = dir.path().to_path_buf();
    Ok(Site {
        _dir: dir,
        dir_path,
        router,
        state,
        runtime,
        listener,
        files,
        stub: started,
    })
}


fn text(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(AnyKind::StringValue(value.to_string())),
        }),
        ..Default::default()
    }
}


fn span(seed: u8, start: u64) -> Span {
    Span {
        trace_id: vec![seed; TRACE_ID_BYTES],
        span_id: vec![seed; SPAN_ID_BYTES],
        name: "op".to_string(),
        start_time_unix_nano: start,
        end_time_unix_nano: start + 1,
        attributes: vec![text("tenant", "evil")],
        ..Default::default()
    }
}


fn export_body(count: u8) -> Vec<u8> {
    let start = now_nanos();
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: (1..=count).map(|seed| span(seed, start)).collect(),
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec()
}


async fn send(router: &Router, token: Option<&str>, content_type: &str, encoding: Option<&str>, body: Vec<u8>) -> Result<Response<Body>, TestError> {
    let mut builder = Request::builder().method("POST").uri(TRACES_PATH).header("content-type", content_type);
    if let Some(value) = token {
        builder = builder.header("authorization", format!("Bearer {value}"));
    }
    if let Some(value) = encoding {
        builder = builder.header("content-encoding", value);
    }
    let mut request = builder.body(Body::from(body))?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), CLIENT_PORT)));
    Ok(router.clone().oneshot(request).await?)
}


async fn export(site: &Site, token: &str, count: u8) -> Result<Response<Body>, TestError> {
    send(&site.router, Some(token), PROTOBUF, None, export_body(count)).await
}


fn untouched(listener: &TcpListener) -> Result<bool, TestError> {
    listener.set_nonblocking(true)?;
    Ok(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock))
}


async fn read_body(response: Response<Body>) -> Result<Vec<u8>, TestError> {
    Ok(to_bytes(response.into_body(), BODY_LIMIT).await?.to_vec())
}


fn finished(stub: Stub) -> TestResult {
    stub.handle.join().map_err(|_| "stub thread panicked")??;
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_valid_token_stores_under_the_process_tenant_whatever_the_payload_says() -> TestResult {
    let site = site(vec![OK, OK], false)?;
    let response = export(&site, TOKEN, TWO_SPANS).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").map(|value| value.as_bytes()),
        Some(PROTOBUF.as_bytes())
    );
    assert_eq!(
        ExportTraceServiceResponse::decode(read_body(response).await?.as_slice())?.partial_success,
        None
    );
    let first = site.stub.requests.recv_timeout(HANG_GUARD)?;
    let second = site.stub.requests.recv_timeout(HANG_GUARD)?;
    for request in [first, second] {
        let body = request.split(HEADER_END).nth(1).ok_or("no body")?.to_owned();
        assert!(body.contains("\"tenant\":\"acme\""), "{body}");
        assert!(body.contains("\"attributes\":{\"tenant\":\"evil\"}"), "{body}");
        assert!(!request.contains(&digest_of(TOKEN)) && !request.contains(TOKEN));
    }
    finished(site.stub)
}


#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_token_or_no_token_is_401_before_the_store_is_touched() -> TestResult {
    let site = site(Vec::new(), false)?;
    for token in [Some(OTHER_TOKEN), None] {
        let response = send(&site.router, token, PROTOBUF, None, export_body(1)).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert!(untouched(&site.stub.listener)?);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn json_and_a_content_encoding_are_415() -> TestResult {
    let site = site(Vec::new(), false)?;
    let json = send(&site.router, Some(TOKEN), "application/json", None, b"{}".to_vec()).await?;
    assert_eq!(json.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let gzip = send(&site.router, Some(TOKEN), PROTOBUF, Some("gzip"), export_body(1)).await?;
    assert_eq!(gzip.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(untouched(&site.stub.listener)?);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_unavailable_store_is_503_with_retry_after_and_a_lowered_snapshot_limit_is_413() -> TestResult {
    let site = site(vec![SERVER_ERROR], false)?;
    let down = export(&site, TOKEN, 1).await?;
    assert_eq!(down.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(down.headers().get("retry-after").map(|value| value.as_bytes()), Some(b"1".as_slice()));
    let body = String::from_utf8(read_body(down).await?)?;
    assert!(!body.contains(PASSWORD));
    fs::write(
        &site.files.settings,
        fs::read_to_string(&site.files.settings)?.replace("max_batch_rows: 1", &format!("max_request_bytes: {LOWERED_REQUEST_BYTES}")),
    )?;
    assert!(matches!(reload(&site.runtime.settings), ReloadOutcome::Applied { .. }));
    let big = export(&site, TOKEN, 1).await?;
    assert_eq!(big.status(), StatusCode::PAYLOAD_TOO_LARGE);
    finished(site.stub)
}


#[tokio::test(flavor = "multi_thread")]
async fn a_reload_that_removes_a_sender_makes_it_401_and_an_invalid_file_keeps_the_old_table() -> TestResult {
    let site = site(vec![OK], false)?;
    assert_eq!(export(&site, TOKEN, 1).await?.status(), StatusCode::OK);
    fs::write(&site.files.senders, "senders:\n  - name: x\n")?;
    assert!(matches!(reload(&site.runtime.senders), ReloadOutcome::Refused { .. }));
    assert!(current_config(&site.runtime.senders).contains_key(&digest_of(TOKEN)));
    fs::write(&site.files.senders, senders_text(&[(OTHER_SENDER, OTHER_TOKEN)]))?;
    assert!(matches!(reload(&site.runtime.senders), ReloadOutcome::Applied { .. }));
    assert_eq!(export(&site, TOKEN, 1).await?.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        site.state.senders.load().get(&digest_of(OTHER_TOKEN)).map(String::as_str),
        Some(OTHER_SENDER)
    );
    let audit = fs::read_to_string(site.dir_path.join("audit.log"))?;
    assert!(
        audit.contains("config.reload") && !audit.contains(&digest_of(TOKEN)) && !audit.contains(&digest_of(OTHER_TOKEN)),
        "{audit}"
    );
    finished(site.stub)
}


#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_leaves_keeps_its_slots_until_the_blocking_task_ends() -> TestResult {
    let site = site(vec![OK], true)?;
    let router = site.router.clone();
    let pending = tokio::spawn(async move {
        send(&router, Some(TOKEN), PROTOBUF, None, export_body(1))
            .await
            .map(|response| response.status())
            .map_err(|error| error.to_string())
    });
    let held = tokio::task::block_in_place(|| site.stub.requests.recv_timeout(HANG_GUARD))?;
    assert!(held.starts_with("POST /"));
    pending.abort();
    assert!(pending.await.is_err());
    assert_eq!(site.state.sender_slots.lock().map_err(|_| "poisoned")?.get(SENDER).copied(), Some(1));
    assert_eq!(site.state.sender_pool.permits.available_permits(), usize::try_from(POOL_SIZE)? - 1);
    site.stub.release.send(())?;
    let all = tokio::time::timeout(HANG_GUARD, site.state.sender_pool.permits.clone().acquire_many_owned(POOL_SIZE)).await??;
    assert!(site.state.sender_slots.lock().map_err(|_| "poisoned")?.is_empty());
    drop(all);
    finished(site.stub)
}


#[tokio::test(flavor = "multi_thread")]
async fn a_sender_removed_while_its_request_runs_stops_the_remaining_batches() -> TestResult {
    let site = site(vec![OK], true)?;
    let router = site.router.clone();
    let pending = tokio::spawn(async move {
        let response = send(&router, Some(TOKEN), PROTOBUF, None, export_body(TWO_SPANS))
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status();
        let body = read_body(response).await.map_err(|error| error.to_string())?;
        Ok::<_, String>((status, body))
    });
    let first = tokio::task::block_in_place(|| site.stub.requests.recv_timeout(HANG_GUARD))?;
    assert!(first.starts_with("POST /"));
    fs::write(&site.files.senders, senders_text(&[(OTHER_SENDER, OTHER_TOKEN)]))?;
    assert!(matches!(reload(&site.runtime.senders), ReloadOutcome::Applied { .. }));
    site.stub.release.send(())?;
    let (status, body) = pending.await??;
    assert_eq!(status, StatusCode::OK);
    let decoded = ExportTraceServiceResponse::decode(body.as_slice())?
        .partial_success
        .ok_or("no partial success")?;
    assert_eq!(decoded.rejected_spans, 1);
    assert!(decoded.error_message.contains("not stored 1"), "{}", decoded.error_message);
    assert!(untouched(&site.stub.listener)?);
    finished(site.stub)
}


#[tokio::test(flavor = "multi_thread")]
async fn the_route_is_documented_and_its_ceiling_is_the_sender_ceiling() -> TestResult {
    let access = traces_access();
    let rule = access.get("POST /v1/traces").ok_or("no rule")?;
    assert!(matches!(rule.requirement, Requirement::Sender(ceiling) if ceiling == traces_ingest::settings::ceiling_limits().max_request_bytes));
    assert!(!rule.sensitive);
    assert!(traces_document().paths.paths.contains_key(TRACES_PATH));
    Ok(())
}


#[test]
fn the_module_needs_its_three_files_and_tls() -> TestResult {
    let all: BTreeMap<String, String> = [SETTING_TRACES_SETTINGS, SETTING_TRACES_SAMPLING, SETTING_SENDERS_FILE]
        .into_iter()
        .map(|key| (key.to_owned(), format!("/etc/{key}")))
        .collect();
    assert_eq!(traces_files_of(&all, &[Module::Alerts])?, None);
    let found = traces_files_of(&all, &[Module::Traces])?.ok_or("no files")?;
    assert_eq!(found.senders.display().to_string(), "/etc/otlp.senders_file");
    let expectations = [
        (SETTING_TRACES_SETTINGS, PlatformError::MissingTracesSettings),
        (SETTING_TRACES_SAMPLING, PlatformError::MissingTracesSampling),
        (SETTING_SENDERS_FILE, PlatformError::MissingSendersFile),
    ];
    for (key, expected) in expectations {
        let mut partial = all.clone();
        partial.remove(key);
        assert_eq!(traces_files_of(&partial, &[Module::Traces]).err(), Some(expected));
    }
    let mut tls = BTreeMap::new();
    assert_eq!(require_tls(&tls, &[Module::Traces]), Err(PlatformError::TlsRequired));
    assert_eq!(require_tls(&tls, &[Module::Alerts]), Ok(()));
    tls.insert("tls_certificate".to_owned(), "c".to_owned());
    assert_eq!(require_tls(&tls, &[Module::Traces]), Err(PlatformError::TlsRequired));
    tls.insert("tls_key".to_owned(), "k".to_owned());
    assert_eq!(require_tls(&tls, &[Module::Traces]), Ok(()));
    Ok(())
}


#[test]
fn the_tls_settings_are_start_only_while_traces_are_served() -> TestResult {
    assert!(start_only_keys(false, true).contains(&"tls_key") && start_only_keys(false, true).contains(&"tls_certificate"));
    assert!(!start_only_keys(false, false).contains(&"tls_key"));
    for key in [SETTING_TRACES_SETTINGS, SETTING_TRACES_SAMPLING, SETTING_SENDERS_FILE] {
        assert!(start_only_keys(false, false).contains(&key), "{key}");
    }
    assert_eq!(module_of("traces"), Some(Module::Traces));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_router_without_its_runtime_and_a_missing_core_state_are_named() -> TestResult {
    let site = site(Vec::new(), false)?;
    let dir = tempdir()?;
    let pg_file = dir.path().join("pg.yaml");
    fs::write(
        &pg_file,
        "host: 127.0.0.1\nport: 1\ndatabase: ostyr\nuser: ostyr\npassword_file: /run/pg.pass\nca_file: /run/ca.pem\n",
    )?;
    let module_file = dir.path().join("platform.yaml");
    fs::write(
        &module_file,
        format!(
            "name: platform\nversion: \"1\"\nsettings:\n  modules: \"traces\"\n  pg_settings: {}\n",
            pg_file.display()
        ),
    )?;
    let (opened, _pg) = alerts::settings::open_pg_engine_as(&module_file, new_listener(), ACTOR)?;
    let permits = module_semaphores(&[Module::Traces]);
    let (_, held) = permits.first().ok_or("no permit")?.clone();
    let refused = module_router(Module::Traces, &Arc::new(opened), &held, None, None, None);
    assert_eq!(refused.err(), Some(PlatformError::MissingTracesRuntime));
    let bare = new_listener();
    push_senders(&bare, &SenderTable::new());
    assert!(bare.state.get().is_none());
    push_senders(&site.listener, &SenderTable::new());
    assert!(site.state.senders.load().is_empty());
    let context = context_of("acme", "platform", &site.files.senders);
    assert_eq!((context.actor_id.as_str(), context.request_id.as_str()), (ACTOR, "startup"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_bad_first_file_is_an_error_and_the_helpers_are_exact() -> TestResult {
    let site = site(Vec::new(), false)?;
    fs::write(&site.files.sampling, "default_ratio: 7.0\n")?;
    assert!(open_traces(&site.files, "acme", "platform", &site.listener).is_err());
    let table: SenderTable = [(digest_of(TOKEN), SENDER.to_owned())].into_iter().collect();
    assert!(sender_listed(&table, SENDER) && !sender_listed(&table, OTHER_SENDER));
    assert!(now_nanos() > NOW_NANOS);
    assert_eq!(senders_state(&table).len(), 1);
    let ended = tokio::spawn(std::future::pending::<Reply>());
    ended.abort();
    let reply = joined(ended.await).status();
    assert_eq!(reply, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_of(fixed(STATUS_OK, "x", false)).status(), StatusCode::OK);
    Ok(())
}
