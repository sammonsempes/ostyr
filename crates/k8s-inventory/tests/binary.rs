#![cfg(unix)]


#[path = "common/api.rs"]
mod api;
#[path = "common/api/types.rs"]
mod apitypes;
#[path = "common/types.rs"]
mod types;


use api::{answer, review_answer, review_of, rig, seen_of, Answer, Rig, Seen, BAD_REQUEST, CREATED, NOT_FOUND, OK, TOKEN};
use apitypes::Handler;
use core_pg::error::PgError;
use k8s_inventory::access::{NAMESPACES_PATH, REVIEW_PATH, RULES_PATH};
use k8s_inventory::error::{pg_category, FetchError};
use k8s_inventory::fetch::{NODES_PATH, PODS_PATH};
use k8s_inventory::round::{fault_class, one_round, RoundFault};
use k8s_inventory::serve::{exit_code, pause, run, serving_with, start, ServeError, Stop};
use k8s_inventory::service::{load_service_settings, LiveSettings};
use k8s_inventory::settings::load_settings;
use k8s_inventory::types::InterruptWait;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler as PgHandler;
use rcgen::SanType;
use serde_json::{json, Value};
use socket2::{Domain, Socket, Type};
use std::fs;
use std::future::{pending, poll_fn, ready};
use std::io::{self, BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, ExitCode, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::thread::spawn;
use std::time::Duration;
use tracing::debug;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-k8s-inventory");


const OWNER_ONLY: u32 = 0o600;


const WORLD_READABLE: u32 = 0o644;


const PG_PASSWORD: &str = "p";


const HANG_GUARD: Duration = Duration::from_secs(90);


const ROUND_DONE: &str = "k8s round done";


const ROUND_FAILED: &str = "k8s round failed";


const ONE_ROUND: u64 = 1;


const TWO_ROUNDS: u64 = 2;


const POD_UID: &str = "00000000-0000-4000-8000-000000000001";


struct Behaviour {
    writable: AtomicBool,
    with_pod: bool,
    pod_lists: AtomicUsize,
    hold: Mutex<Option<(Sender<()>, Receiver<()>)>>,
}


struct Site {
    settings_file: PathBuf,
    dir: PathBuf,
}


struct Running {
    child: Child,
    lines: Receiver<String>,
}


impl Drop for Running {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            debug!("child already gone: {error}");
        }
        if let Err(error) = self.child.wait() {
            debug!("child not reaped: {error}");
        }
    }
}


fn behaviour(writable: bool, with_pod: bool) -> Arc<Behaviour> {
    Arc::new(Behaviour {
        writable: AtomicBool::new(writable),
        with_pod,
        pod_lists: AtomicUsize::new(0),
        hold: Mutex::new(None),
    })
}


fn rules_status(writable: bool) -> Value {
    let mut rules = vec![
        json!({"verbs": ["create"], "apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectaccessreviews", "selfsubjectrulesreviews"]}),
        json!({"verbs": ["get", "list", "watch"], "apiGroups": [""], "resources": ["pods", "nodes"]}),
    ];
    if writable {
        rules.push(json!({"verbs": ["create"], "apiGroups": [""], "resources": ["pods"]}));
    }
    json!({"resourceRules": rules, "nonResourceRules": [], "incomplete": false})
}


fn pod_list(with_pod: bool) -> Answer {
    let pods = if with_pod {
        vec![json!({
            "metadata": {"name": "p1", "namespace": "default", "uid": POD_UID},
            "spec": {"nodeName": "n1", "containers": [{"image": "nginx:1"}]},
            "status": {"phase": "Running"}
        })]
    } else {
        Vec::new()
    };
    answer(OK, json!({"kind": "PodList", "metadata": {}, "items": pods}).to_string())
}


fn hold_if_asked(state: &Behaviour) -> Result<(), Box<dyn std::error::Error>> {
    let taken = state.hold.lock().map_err(|_poisoned| "poisoned")?.take();
    if let Some((held, release)) = taken {
        held.send(())?;
        release.recv_timeout(HANG_GUARD)?;
    }
    Ok(())
}


fn route(state: &Behaviour, seen: &Seen) -> Answer {
    if seen.method == "POST" && seen.target == RULES_PATH {
        answer(
            CREATED,
            json!({"status": rules_status(state.writable.load(Ordering::SeqCst))}).to_string(),
        )
    } else if seen.method == "POST" && seen.target == REVIEW_PATH {
        review_of(seen).map_or_else(|| answer(BAD_REQUEST, String::new()), |_verb_and_resource| review_answer(true))
    } else if seen.target.starts_with(NAMESPACES_PATH) {
        answer(
            OK,
            json!({"kind": "NamespaceList", "metadata": {}, "items": [{"metadata": {"name": "default"}}]}).to_string(),
        )
    } else if seen.target.starts_with(PODS_PATH) {
        state.pod_lists.fetch_add(1, Ordering::SeqCst);
        match hold_if_asked(state) {
            Ok(()) => pod_list(state.with_pod),
            Err(error) => answer(BAD_REQUEST, error.to_string()),
        }
    } else if seen.target.starts_with(NODES_PATH) {
        answer(OK, json!({"kind": "NodeList", "metadata": {}, "items": []}).to_string())
    } else {
        answer(NOT_FOUND, String::new())
    }
}


fn handler_of(state: &Arc<Behaviour>) -> Handler {
    let shared = Arc::clone(state);
    Arc::new(move |seen: &Seen| route(&shared, seen))
}


fn private_file(path: &Path, bytes: &[u8]) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


fn closed_socket() -> io::Result<(Socket, u16)> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
    let port = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("not an inet address"))?
        .port();
    Ok((socket, port))
}


fn write_site(rig: &Rig, pg_port: u16, ca_pem: &str) -> Result<Site, Box<dyn std::error::Error>> {
    let dir = rig.dir.path();
    private_file(&dir.join("pg.pass"), PG_PASSWORD.as_bytes())?;
    fs::write(dir.join("pgca.pem"), ca_pem)?;
    fs::write(
        dir.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: {pg_port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("pgca.pem").display()
        ),
    )?;
    fs::write(
        dir.join("fetch.yaml"),
        format!(
            "api_url: {}\nca_file: {}\ntoken_file: {}\ntenant: {}\ncluster: {}\ntimeout_ms: {}\n",
            rig.settings.api_url,
            rig.settings.ca_file.display(),
            rig.settings.token_file.display(),
            rig.settings.tenant,
            rig.settings.cluster,
            rig.settings.timeout_ms
        ),
    )?;
    let settings_file = dir.join("service.yaml");
    fs::write(
        &settings_file,
        format!(
            "fetch_settings: {}\npg_settings: {}\naudit_file: {}\ninterval_seconds: 60\n",
            dir.join("fetch.yaml").display(),
            dir.join("pg.yaml").display(),
            dir.join("audit.log").display(),
        ),
    )?;
    Ok(Site {
        settings_file,
        dir: dir.to_path_buf(),
    })
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


fn refused_with(output: &Output, marker: &str) -> TestResult {
    let text = String::from_utf8(output.stderr.clone())?;
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


async fn fake_with(handler: PgHandler) -> Result<(Fake, String), Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler).await?;
    Ok((fake, pki.ca_pem))
}


fn accepting() -> PgHandler {
    Arc::new(|_| Reply::Done)
}


fn counting(counter: &Arc<AtomicUsize>) -> PgHandler {
    let shared = Arc::clone(counter);
    Arc::new(move |_| {
        shared.fetch_add(1, Ordering::SeqCst);
        Reply::Done
    })
}


fn spawn_service(settings_file: &Path) -> Result<Running, Box<dyn std::error::Error>> {
    let mut child = Command::new(PROGRAM)
        .arg(settings_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let (sender, lines) = channel();
    spawn(move || {
        BufReader::new(stderr)
            .lines()
            .try_for_each(|line| sender.send(line?).map_err(io::Error::other))
    });
    Ok(Running { child, lines })
}


fn wait_for_line(running: &Running, marker: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut seen = Vec::new();
    let found = (0..usize::MAX)
        .map(|_| running.lines.recv_timeout(HANG_GUARD))
        .find_map(|received| match received {
            Ok(line) => {
                seen.push(line.clone());
                line.contains(marker).then_some(Ok(line))
            }
            Err(error) => Some(Err(error)),
        })
        .ok_or("no line")?;
    found.map_err(|error| format!("{error}: waiting for {marker}, saw {seen:?}").into())
}


fn signal(running: &Running, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(running.child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn exits_zero(running: &mut Running) -> TestResult {
    let status = running.child.wait()?;
    assert!(status.success(), "{status}");
    Ok(())
}


fn never() -> InterruptWait {
    Box::pin(pending())
}


fn at_once(_duration: Duration) -> Pin<Box<dyn std::future::Future<Output = ()>>> {
    Box::pin(ready(()))
}


async fn serve_one_round_then(name: &str) -> TestResult {
    let state = behaviour(false, false);
    let rig = rig(handler_of(&state))?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let mut running = spawn_service(&site.settings_file)?;
    let line = tokio::task::block_in_place(|| wait_for_line(&running, ROUND_DONE))?;
    assert!(line.contains("created=0"), "{line}");
    signal(&running, name)?;
    tokio::task::block_in_place(|| exits_zero(&mut running))?;
    assert_eq!(state.pod_lists.load(Ordering::SeqCst), 1);
    let seen = seen_of(&rig.stub)?;
    assert!(seen.iter().all(|request| request.authorization == format!("Bearer {TOKEN}")));
    assert!(site.dir.join("audit.log").exists());
    Ok(())
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-k8s-inventory <service.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-k8s-inventory")
}


#[test]
fn an_unreadable_or_invalid_settings_file_is_a_named_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")?;
    let settings_file = dir.path().join("service.yaml");
    fs::write(&settings_file, "interval_seconds: [\n")?;
    refused_with(&run_to_end(&[&settings_file])?, "service.yaml")
}


#[test]
fn a_settings_file_with_no_audit_path_is_refused_at_start() -> TestResult {
    let dir = tempfile::tempdir()?;
    let settings_file = dir.path().join("service.yaml");
    fs::write(&settings_file, "fetch_settings: /f\npg_settings: /p\ninterval_seconds: 60\n")?;
    refused_with(&run_to_end(&[&settings_file])?, "audit_file")?;
    assert!(!dir.path().join("audit.log").exists());
    Ok(())
}


#[test]
fn a_missing_pg_settings_file_or_a_refusing_database_fails_the_start() -> TestResult {
    let rig = rig(handler_of(&behaviour(false, false)))?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(&rig, port, "")?;
    let output = run_to_end(&[&site.settings_file])?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    fs::remove_file(site.dir.join("pg.yaml"))?;
    refused_with(&run_to_end(&[&site.settings_file])?, "pg.yaml")
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_migration_fails_the_start() -> TestResult {
    let rig = rig(handler_of(&behaviour(false, false)))?;
    let (fake, ca_pem) = fake_with(Arc::new(|sql| {
        if sql.contains("CREATE TABLE IF NOT EXISTS public.schema_migrations") {
            Reply::Error("XX000")
        } else {
            Reply::Done
        }
    }))
    .await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let output = tokio::task::block_in_place(|| run_to_end(&[&site.settings_file]))?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_a_round_and_exits_zero_on_sigint() -> TestResult {
    serve_one_round_then("-INT").await
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_exits_zero_on_sigterm() -> TestResult {
    serve_one_round_then("-TERM").await
}


#[tokio::test(flavor = "multi_thread")]
async fn a_stop_during_a_round_lets_the_round_finish_before_the_exit() -> TestResult {
    let state = behaviour(false, false);
    let (held, held_seen) = channel();
    let (release, released) = channel();
    *state.hold.lock().map_err(|_poisoned| "poisoned")? = Some((held, released));
    let rig = rig(handler_of(&state))?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let mut running = spawn_service(&site.settings_file)?;
    held_seen.recv_timeout(HANG_GUARD)?;
    signal(&running, "-TERM")?;
    release.send(())?;
    let line = tokio::task::block_in_place(|| wait_for_line(&running, ROUND_DONE))?;
    assert!(line.contains("unchanged=0"), "{line}");
    tokio::task::block_in_place(|| exits_zero(&mut running))?;
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_credential_that_can_write_is_a_named_round_result_and_the_cmdb_is_not_reached() -> TestResult {
    let state = behaviour(true, true);
    let rig = rig(handler_of(&state))?;
    let statements = Arc::new(AtomicUsize::new(0));
    let (fake, ca_pem) = fake_with(counting(&statements)).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let mut running = spawn_service(&site.settings_file)?;
    let line = tokio::task::block_in_place(|| wait_for_line(&running, ROUND_FAILED))?;
    assert!(line.contains("not_read_only"), "{line}");
    assert!(!line.contains(TOKEN), "{line}");
    let after_start = statements.load(Ordering::SeqCst);
    signal(&running, "-INT")?;
    tokio::task::block_in_place(|| exits_zero(&mut running))?;
    assert_eq!(statements.load(Ordering::SeqCst), after_start);
    assert_eq!(state.pod_lists.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_stop_asked_during_the_start_skips_the_first_round() -> TestResult {
    let state = behaviour(false, false);
    let rig = rig(handler_of(&state))?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    start(&site.settings_file, u64::MAX, pause, Box::pin(ready(Ok(())))).await?;
    assert_eq!(state.pod_lists.load(Ordering::SeqCst), 0);
    let failing: InterruptWait = Box::pin(ready(Err(io::Error::other("no signal"))));
    let error = start(&site.settings_file, u64::MAX, pause, failing)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(error.to_string().contains("no signal"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_round_cap_is_the_named_error_after_every_round_ran() -> TestResult {
    let state = behaviour(false, false);
    let rig = rig(handler_of(&state))?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let error = start(&site.settings_file, TWO_ROUNDS, at_once, never())
        .await
        .err()
        .ok_or("expected the cap")?;
    assert!(matches!(error, ServeError::RoundCap), "{error}");
    assert!(error.to_string().contains("round cap"));
    assert_eq!(state.pod_lists.load(Ordering::SeqCst), TWO_ROUNDS as usize);
    assert_eq!(exit_code(&Err(error)), ExitCode::from(k8s_inventory::serve::EXIT_ROUND_CAP));
    assert_eq!(exit_code(&Ok(())), ExitCode::SUCCESS);
    assert_eq!(exit_code(&Err(ServeError::Usage)), ExitCode::FAILURE);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_token_that_gains_a_write_verb_is_refused_before_any_list() -> TestResult {
    let state = behaviour(false, true);
    let rig = rig(handler_of(&state))?;
    let statements = Arc::new(AtomicUsize::new(0));
    let (fake, ca_pem) = fake_with(counting(&statements)).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let first = serving_with(load_service_settings, &site.settings_file, ONE_ROUND, at_once, never()).await?;
    assert_eq!(first, Stop::Capped(ONE_ROUND));
    assert_eq!(state.pod_lists.load(Ordering::SeqCst), 1);
    state.writable.store(true, Ordering::SeqCst);
    let before = statements.load(Ordering::SeqCst);
    let second = serving_with(load_service_settings, &site.settings_file, ONE_ROUND, at_once, never()).await?;
    assert_eq!(second, Stop::Capped(ONE_ROUND));
    assert_eq!(state.pod_lists.load(Ordering::SeqCst), 1);
    let migration_only = statements.load(Ordering::SeqCst) - before;
    assert!(migration_only > 0);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn each_failing_store_is_its_own_named_round_fault() -> TestResult {
    let state = behaviour(false, true);
    let rig = rig(handler_of(&state))?;
    let (fake, ca_pem) = fake_with(Arc::new(|_sql| Reply::Error("XX000"))).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let pg = core_pg::settings::load_settings(&site.dir.join("pg.yaml"))?;
    let live = LiveSettings {
        service: load_service_settings(&site.settings_file)?,
        fetch: load_settings(&site.dir.join("fetch.yaml"))?,
    };
    let refused = one_round(&pg, &live).await.err().ok_or("the sync was accepted")?;
    assert_eq!(fault_class(&refused), "cmdb_sync");
    let (_closed, port) = closed_socket()?;
    let site_down = write_site(&rig, port, "")?;
    let pg_down = core_pg::settings::load_settings(&site_down.dir.join("pg.yaml"))?;
    let unreachable = one_round(&pg_down, &live).await.err().ok_or("the connection was accepted")?;
    assert_eq!(fault_class(&unreachable), "cmdb_store");
    state.writable.store(true, Ordering::SeqCst);
    let writable = one_round(&pg_down, &live).await.err().ok_or("the token was accepted")?;
    assert_eq!(fault_class(&writable), "not_read_only");
    fs::remove_file(&live.fetch.token_file)?;
    let missing = one_round(&pg_down, &live).await.err().ok_or("the token was found")?;
    assert_eq!(fault_class(&missing), "fetch");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn run_refuses_a_bad_usage_and_installs_logging_once() -> TestResult {
    let usage = run(&[], never()).await.err().ok_or("expected the usage")?;
    assert!(matches!(usage, ServeError::Usage));
    let state = behaviour(false, false);
    let rig = rig(handler_of(&state))?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let arguments = [site.settings_file.display().to_string()];
    run(&arguments, Box::pin(ready(Ok(())))).await?;
    let again = run(&arguments, Box::pin(ready(Ok(()))))
        .await
        .err()
        .ok_or("expected a second install to fail")?;
    assert!(matches!(again, ServeError::Failed(_)));
    Ok(())
}


#[test]
fn every_refusal_that_says_the_credential_is_not_read_only_has_that_class() -> TestResult {
    let writable = FetchError::WritableCredential {
        verb: "create".to_owned(),
        group: String::new(),
        resource: "pods".to_owned(),
    };
    let unverifiable = FetchError::RulesUnverifiable {
        namespace: "default".to_owned(),
        reason: "incomplete",
    };
    let missing = FetchError::MissingRead { resource: "nodes" };
    [writable, unverifiable, missing]
        .into_iter()
        .for_each(|error| assert_eq!(fault_class(&RoundFault::Fetch(error)), "not_read_only"));
    assert_eq!(fault_class(&RoundFault::Fetch(FetchError::Deadline)), "fetch");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_or_credential_swap_in_the_fetch_file_of_a_running_process_is_refused_and_nothing_is_written() -> TestResult {
    let state = behaviour(false, false);
    let rig = rig(handler_of(&state))?;
    let statements = Arc::new(AtomicUsize::new(0));
    let (fake, ca_pem) = fake_with(counting(&statements)).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let mut running = spawn_service(&site.settings_file)?;
    tokio::task::block_in_place(|| wait_for_line(&running, ROUND_DONE))?;
    let original = fs::read_to_string(site.dir.join("fetch.yaml"))?;
    let after_round = statements.load(Ordering::SeqCst);
    let swaps = [
        (format!("tenant: {}", rig.settings.tenant), "tenant: victim".to_owned()),
        (
            format!("api_url: {}", rig.settings.api_url),
            "api_url: https://attacker.example:443".to_owned(),
        ),
        (
            format!("token_file: {}", rig.settings.token_file.display()),
            "token_file: /run/secrets/pg.pass".to_owned(),
        ),
    ];
    swaps.iter().try_for_each(|(from, to)| -> TestResult {
        fs::write(site.dir.join("fetch.yaml"), original.replace(from, to))?;
        let line = tokio::task::block_in_place(|| wait_for_line(&running, "configuration reload refused"))?;
        assert!(line.contains("start-only"), "{line}");
        Ok(())
    })?;
    signal(&running, "-TERM")?;
    tokio::task::block_in_place(|| exits_zero(&mut running))?;
    assert_eq!(statements.load(Ordering::SeqCst), after_round);
    let audit = fs::read_to_string(site.dir.join("audit.log"))?;
    assert_eq!(audit.matches("\"outcome\":\"denied\"").count(), swaps.len(), "{audit}");
    assert!(audit.contains(&format!("\"target\":\"{}\"", site.settings_file.display())), "{audit}");
    assert!(!audit.contains("victim") && !audit.contains("attacker"), "{audit}");
    assert_eq!(state.pod_lists.load(Ordering::SeqCst), 1);
    assert!(seen_of(&rig.stub)?
        .iter()
        .all(|request| request.authorization == format!("Bearer {TOKEN}")));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_token_refusal_names_its_fixed_category_and_never_the_token() -> TestResult {
    let rig = rig(handler_of(&behaviour(false, true)))?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    fs::set_permissions(&rig.settings.token_file, fs::Permissions::from_mode(WORLD_READABLE))?;
    let mut running = spawn_service(&site.settings_file)?;
    let line = tokio::task::block_in_place(|| wait_for_line(&running, ROUND_FAILED))?;
    assert!(line.contains("SecretMode"), "{line}");
    assert!(!line.contains(TOKEN), "{line}");
    signal(&running, "-TERM")?;
    tokio::task::block_in_place(|| exits_zero(&mut running))?;
    Ok(())
}


#[test]
fn a_fetch_settings_file_that_is_refused_at_start_fails_the_start() -> TestResult {
    let rig = rig(handler_of(&behaviour(false, false)))?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(&rig, port, "")?;
    fs::write(site.dir.join("fetch.yaml"), "surprise: 1\n")?;
    refused_with(&run_to_end(&[&site.settings_file])?, "fetch.yaml")
}


#[test]
fn every_credential_file_refusal_has_its_fixed_category() -> TestResult {
    let file = || "token".to_owned();
    let cases = [
        (
            PgError::Io {
                file: file(),
                source: io::Error::other("x"),
            },
            "Io",
        ),
        (PgError::NotRegular { file: file() }, "NotRegular"),
        (PgError::SecretSymlink { file: file() }, "SecretSymlink"),
        (PgError::SecretMode { file: file() }, "SecretMode"),
        (PgError::SecretOwner { file: file() }, "SecretOwner"),
        (PgError::TooLarge { file: file(), limit: 1 }, "TooLarge"),
        (PgError::EmptyPassword { file: file() }, "EmptyPassword"),
        (PgError::InvalidTenant, "Other"),
    ];
    cases.iter().for_each(|(error, category)| assert_eq!(pg_category(error), *category));
    let shown = FetchError::Token(PgError::SecretMode {
        file: "/secret/path".to_owned(),
    })
    .to_string();
    assert!(shown.contains("SecretMode") && !shown.contains("/secret/path"), "{shown}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_interrupt_that_fails_while_waiting_between_rounds_stops_the_service_with_its_error() -> TestResult {
    let rig = rig(handler_of(&behaviour(false, false)))?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let polls = AtomicUsize::new(0);
    let late_failure: InterruptWait = Box::pin(poll_fn(move |context| {
        if polls.fetch_add(1, Ordering::SeqCst) == 0 {
            context.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Err(io::Error::other("signal stream closed")))
        }
    }));
    let error = start(&site.settings_file, u64::MAX, pause, late_failure)
        .await
        .err()
        .ok_or("expected the signal error")?;
    assert!(error.to_string().contains("signal stream closed"), "{error}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_round_uses_the_snapshot_and_never_reads_the_fetch_file_again() -> TestResult {
    let state = behaviour(false, false);
    let rig = rig(handler_of(&state))?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let site = write_site(&rig, fake.port, &ca_pem)?;
    let pg = core_pg::settings::load_settings(&site.dir.join("pg.yaml"))?;
    let live = LiveSettings {
        service: load_service_settings(&site.settings_file)?,
        fetch: load_settings(&site.dir.join("fetch.yaml"))?,
    };
    fs::write(site.dir.join("fetch.yaml"), "surprise: 1\n")?;
    let report = one_round(&pg, &live).await?;
    assert_eq!(report.created, 0);
    assert_eq!(state.pod_lists.load(Ordering::SeqCst), 1);
    Ok(())
}
