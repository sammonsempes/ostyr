use crate::isolation::{exit, fake_denied, fake_nft, v4_settings};
use crate::support::scoped_logging;
use crate::types::TestResult;
use agent_channel::app::shared_log_audit;
use agent_channel::model::ExecuteRefusal;
use agent_command::model::{Action, Command, KeyClass, NONCE_LENGTH};
use agent_linux::cursor::open_state_dir;
use agent_linux::dispatch::{
    admin_execute_fn, admin_queue, channel_listed, command_entry, endpoint_socket, kind_name, order_of, read_settings, reason_of, run_admin_worker,
    run_order, run_with_admin, AdminEnv, AdminKind, AdminOrder, ADMIN_QUEUE,
};
use agent_linux::error::IsolationError;
use agent_linux::model::{Endpoint, IsolationSettings, StateDir};
use agent_linux::nft::run_nft_deadline;
use agent_linux::types::{NftFn, NftFuture};
use core_audit::log::open_file_log;
use core_config::types::SharedAuditFn;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::Notify;


const NFT: &str = "/usr/sbin/nft";


const GOOD: &str = "isolation:\n  endpoints:\n    - address: 192.168.102.196\n      port: 8080\n";


const PLATFORM_CHANNEL: &str = "192.168.102.196:8080";


const RELAY_CHANNEL: &str = "10.0.0.9:8443";


const PLATFORM_PORT: u16 = 8080;


const RELAY_PORT: u16 = 8443;


const FIRST: u64 = 1;


const SECOND: u64 = 2;


const THIRD: u64 = 3;


const SHORT_DEADLINE_MILLIS: u64 = 50;


const LONG_SLEEP_SECONDS: &str = "30";


struct Rig {
    dir: TempDir,
    settings: PathBuf,
    state: StateDir,
    audit: Box<SharedAuditFn>,
    restart: Notify,
}


fn rig(settings_text: &str) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let state = open_state_dir(&dir.path().join("cursor"))?;
    let log = Arc::new(open_file_log(&dir.path().join("audit"))?);
    fs::write(
        dir.path().join("linux.yaml"),
        format!(
            "agent_file: /a\nexport_path: /e\ncursor_file: {0}/cursor\naudit_file: {0}/audit\n{settings_text}",
            dir.path().display()
        ),
    )?;
    Ok(Rig {
        settings: dir.path().join("linux.yaml"),
        dir,
        state,
        audit: shared_log_audit(&log),
        restart: Notify::new(),
    })
}


fn env<'a>(rig: &'a Rig, run: NftFn, channel: &'a [SocketAddr]) -> AdminEnv<'a> {
    AdminEnv {
        run,
        nft: Path::new(NFT),
        state: &rig.state,
        tenant: "t1",
        audit: &*rig.audit,
        settings_file: &rig.settings,
        channel,
        restart: &rig.restart,
    }
}


fn addresses(texts: &[&str]) -> Result<Vec<SocketAddr>, std::net::AddrParseError> {
    texts.iter().map(|text| text.parse()).collect()
}


fn order(kind: AdminKind, sequence: u64) -> AdminOrder {
    AdminOrder { kind, sequence }
}


fn command(action: Action, sequence: u64) -> Command {
    Command {
        key_id: "k".to_owned(),
        key_class: KeyClass::Routine,
        agent_id: "a1".to_owned(),
        tenant: "t1".to_owned(),
        issued_at: 0,
        expires_at: 1,
        sequence,
        nonce: [0; NONCE_LENGTH],
        action,
    }
}


fn records(rig: &Rig) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    fs::read_to_string(rig.dir.path().join("audit"))?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}


fn commands_of(records: &[Value]) -> Vec<(String, String, String, String)> {
    let text = |value: Option<&Value>| value.and_then(Value::as_str).unwrap_or("-").to_owned();
    records
        .iter()
        .filter(|record| text(record.get("module")) == "agent_linux_command")
        .map(|record| {
            (
                text(record.get("action")),
                text(record.get("target")),
                text(record.get("parameters").and_then(|parameters| parameters.get("result"))),
                text(record.get("parameters").and_then(|parameters| parameters.get("reason"))),
            )
        })
        .collect()
}


async fn restart_pending(restart: &Notify) -> bool {
    tokio::time::timeout(Duration::ZERO, restart.notified()).await.is_ok()
}


#[test]
fn only_the_three_actions_become_orders_and_each_keeps_kind_and_sequence() -> TestResult {
    assert_eq!(order_of(&command(Action::Ping, FIRST)), Some(order(AdminKind::Ping, FIRST)));
    assert_eq!(
        order_of(&command(Action::CollectStatus, SECOND)),
        Some(order(AdminKind::CollectStatus, SECOND))
    );
    assert_eq!(order_of(&command(Action::Isolate, THIRD)), Some(order(AdminKind::Isolate, THIRD)));
    assert_eq!(order_of(&command(Action::Uninstall, FIRST)), None);
    assert_eq!(order_of(&command(Action::Kill { process_id: 1 }, FIRST)), None);
    assert_eq!(kind_name(AdminKind::Ping), "ping");
    assert_eq!(kind_name(AdminKind::CollectStatus), "collect_status");
    assert_eq!(kind_name(AdminKind::Isolate), "isolate");
    Ok(())
}


#[test]
fn the_executor_only_queues_and_refuses_what_it_cannot_take() -> TestResult {
    let _logging = scoped_logging();
    let (sender, mut receiver) = admin_queue();
    let execute = admin_execute_fn(sender);
    assert_eq!(execute(command(Action::Isolate, FIRST)), Ok(()));
    assert_eq!(receiver.try_recv()?, order(AdminKind::Isolate, FIRST));
    assert_eq!(
        execute(command(
            Action::Reboot {
                prompt_user: false,
                deadline: 1
            },
            SECOND
        )),
        Err(ExecuteRefusal::Invalid)
    );
    (0..ADMIN_QUEUE).for_each(|_slot| assert_eq!(execute(command(Action::Ping, FIRST)), Ok(())));
    assert_eq!(execute(command(Action::Ping, THIRD)), Err(ExecuteRefusal::Busy));
    drop(receiver);
    assert_eq!(execute(command(Action::Ping, THIRD)), Err(ExecuteRefusal::Busy));
    Ok(())
}


#[test]
fn the_channel_must_be_listed_on_exactly_the_address_the_ruleset_renders() -> TestResult {
    let both = IsolationSettings {
        endpoints: vec![
            Endpoint {
                address: "192.168.102.196".parse()?,
                port: PLATFORM_PORT,
            },
            Endpoint {
                address: "10.0.0.9".parse()?,
                port: RELAY_PORT,
            },
        ],
        dns: Vec::new(),
    };
    assert!(channel_listed(&both, &addresses(&[PLATFORM_CHANNEL, RELAY_CHANNEL])?));
    assert!(!channel_listed(&v4_settings()?, &addresses(&[PLATFORM_CHANNEL, RELAY_CHANNEL])?));
    assert!(!channel_listed(&v4_settings()?, &addresses(&["192.168.102.196:8081"])?));
    assert!(!channel_listed(&IsolationSettings::default(), &addresses(&[PLATFORM_CHANNEL])?));
    let mapped = IsolationSettings {
        endpoints: vec![Endpoint {
            address: "::ffff:10.0.0.9".parse()?,
            port: RELAY_PORT,
        }],
        dns: Vec::new(),
    };
    assert!(!channel_listed(&mapped, &addresses(&[RELAY_CHANNEL])?));
    let listed = mapped.endpoints.first().ok_or("missing endpoint")?;
    assert_eq!(endpoint_socket(listed), "[::ffff:10.0.0.9]:8443".parse()?);
    Ok(())
}


#[test]
fn the_settings_are_read_once_digested_and_validated() -> TestResult {
    let rig = rig(GOOD)?;
    let path = rig.dir.path().join("linux.yaml");
    let (file, digest) = read_settings(&path)?;
    assert_eq!(file.isolation.endpoints.len(), 1);
    assert_eq!(digest, format!("{:x}", Sha256::digest(fs::read(&path)?)));
    let bad = self::rig("isolation:\n  endpoints:\n    - address: 192.168.102.196\n      port: 0\n")?;
    assert!(matches!(
        read_settings(&bad.dir.path().join("linux.yaml")),
        Err(IsolationError::Settings(_))
    ));
    assert!(matches!(
        read_settings(&bad.dir.path().join("missing.yaml")),
        Err(IsolationError::Config(_))
    ));
    Ok(())
}


#[test]
fn every_failure_has_its_own_fixed_reason() -> TestResult {
    let reasons: Vec<&str> = [
        IsolationError::NoEndpoints,
        IsolationError::Settings("x".to_owned()),
        IsolationError::ChannelNotListed,
        IsolationError::Mismatch("x".to_owned()),
        IsolationError::Timeout,
        IsolationError::Usage,
    ]
    .iter()
    .map(reason_of)
    .collect();
    assert_eq!(
        reasons,
        vec![
            "settings_invalid",
            "settings_invalid",
            "channel_endpoint_not_listed",
            "table_mismatch",
            "nft_timeout",
            "failed"
        ]
    );
    let entry = command_entry("t1", order(AdminKind::Isolate, FIRST), &Err(IsolationError::Timeout));
    assert_eq!(entry.parameters.get("reason").map(String::as_str), Some("nft_timeout"));
    assert_eq!(entry.target, "sequence 1");
    Ok(())
}


#[tokio::test]
async fn an_isolate_that_keeps_the_channel_applies_audits_and_asks_for_a_redial() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig(GOOD)?;
    let channel = addresses(&[PLATFORM_CHANNEL])?;
    let (sender, receiver) = admin_queue();
    sender.try_send(order(AdminKind::Isolate, FIRST))?;
    sender.try_send(order(AdminKind::Ping, SECOND))?;
    sender.try_send(order(AdminKind::CollectStatus, THIRD))?;
    drop(sender);
    assert_eq!(
        run_admin_worker(receiver, &env(&rig, fake_nft, &channel), &AtomicBool::new(false)).await,
        THIRD
    );
    assert!(restart_pending(&rig.restart).await);
    let seen = commands_of(&records(&rig)?);
    assert_eq!(
        seen,
        vec![
            ("command.isolate".to_owned(), "sequence 1".to_owned(), "ok".to_owned(), "-".to_owned()),
            ("command.ping".to_owned(), "sequence 2".to_owned(), "ok".to_owned(), "-".to_owned()),
            (
                "command.collect_status".to_owned(),
                "sequence 3".to_owned(),
                "ok".to_owned(),
                "-".to_owned()
            ),
        ]
    );
    Ok(())
}


#[tokio::test]
async fn a_status_line_holds_the_isolation_status_the_version_and_the_digest_of_what_was_read() -> TestResult {
    let rig = rig(GOOD)?;
    let channel = addresses(&[PLATFORM_CHANNEL])?;
    let text = run_order(&env(&rig, fake_nft, &channel), order(AdminKind::CollectStatus, FIRST)).await?;
    let digest = format!("{:x}", Sha256::digest(fs::read(rig.dir.path().join("linux.yaml"))?));
    assert_eq!(
        text,
        format!(
            "isolation=Active version={} settings_sha256={digest}",
            agent_linux::dispatch::AGENT_LINUX_VERSION
        )
    );
    Ok(())
}


fn never_called(_program: PathBuf, _arguments: Vec<String>) -> NftFuture {
    Box::pin(async { Err(exit("nft must not run")) })
}


#[tokio::test]
async fn an_isolate_that_would_cut_the_channel_is_refused_before_any_nft_call() -> TestResult {
    let _logging = scoped_logging();
    let omits_relay = addresses(&[PLATFORM_CHANNEL, RELAY_CHANNEL])?;
    let empty_list = rig("isolation:\n  endpoints: []\n")?;
    let channel = addresses(&[PLATFORM_CHANNEL])?;
    let listed = rig(GOOD)?;
    let cases = [(&listed, &omits_relay), (&empty_list, &channel)];
    for (case, wanted) in cases {
        let outcome = run_order(&env(case, never_called, wanted), order(AdminKind::Isolate, FIRST)).await;
        assert!(matches!(outcome, Err(IsolationError::ChannelNotListed)));
        let (sender, receiver) = admin_queue();
        sender.try_send(order(AdminKind::Isolate, SECOND))?;
        drop(sender);
        run_admin_worker(receiver, &env(case, never_called, wanted), &AtomicBool::new(false)).await;
        assert!(!restart_pending(&case.restart).await);
        assert_eq!(
            commands_of(&records(case)?),
            vec![(
                "command.isolate".to_owned(),
                "sequence 2".to_owned(),
                "failed".to_owned(),
                "channel_endpoint_not_listed".to_owned()
            )]
        );
    }
    Ok(())
}


#[tokio::test]
async fn an_invalid_or_unreadable_settings_file_refuses_both_actions_by_name() -> TestResult {
    let _logging = scoped_logging();
    let invalid = rig("isolation:\n  endpoints:\n    - address: 192.168.102.196\n      port: 0\n")?;
    let channel = addresses(&[PLATFORM_CHANNEL])?;
    let (sender, receiver) = admin_queue();
    sender.try_send(order(AdminKind::Isolate, FIRST))?;
    sender.try_send(order(AdminKind::CollectStatus, SECOND))?;
    drop(sender);
    run_admin_worker(receiver, &env(&invalid, never_called, &channel), &AtomicBool::new(false)).await;
    fs::remove_file(invalid.dir.path().join("linux.yaml"))?;
    let unreadable = run_order(&env(&invalid, never_called, &channel), order(AdminKind::Isolate, THIRD)).await;
    assert!(matches!(unreadable, Err(ref error) if reason_of(error) == "settings_unreadable"));
    let seen = commands_of(&records(&invalid)?);
    assert_eq!(
        seen.iter().map(|entry| entry.3.as_str()).collect::<Vec<_>>(),
        vec!["settings_invalid", "settings_invalid"]
    );
    assert!(!restart_pending(&invalid.restart).await);
    Ok(())
}


#[tokio::test]
async fn a_failing_nft_is_audited_failed_and_never_asks_for_a_redial() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig(GOOD)?;
    let channel = addresses(&[PLATFORM_CHANNEL])?;
    let (sender, receiver) = admin_queue();
    sender.try_send(order(AdminKind::Isolate, FIRST))?;
    drop(sender);
    run_admin_worker(receiver, &env(&rig, fake_denied, &channel), &AtomicBool::new(false)).await;
    assert!(!restart_pending(&rig.restart).await);
    assert_eq!(
        commands_of(&records(&rig)?).iter().map(|entry| entry.2.as_str()).collect::<Vec<_>>(),
        vec!["failed"]
    );
    Ok(())
}


fn hung_nft(_program: PathBuf, _arguments: Vec<String>) -> NftFuture {
    Box::pin(run_nft_deadline(
        PathBuf::from("/bin/sleep"),
        vec![LONG_SLEEP_SECONDS.to_owned()],
        Duration::from_millis(SHORT_DEADLINE_MILLIS),
    ))
}


#[tokio::test]
async fn an_nft_that_never_completes_ends_in_a_timeout_and_the_next_order_still_runs() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig(GOOD)?;
    let channel = addresses(&[PLATFORM_CHANNEL])?;
    let (sender, receiver) = admin_queue();
    let execute = admin_execute_fn(sender);
    assert_eq!(execute(command(Action::Isolate, FIRST)), Ok(()));
    assert_eq!(execute(command(Action::Ping, SECOND)), Ok(()));
    drop(execute);
    assert_eq!(
        run_admin_worker(receiver, &env(&rig, hung_nft, &channel), &AtomicBool::new(false)).await,
        SECOND
    );
    let seen = commands_of(&records(&rig)?);
    assert_eq!(
        seen,
        vec![
            (
                "command.isolate".to_owned(),
                "sequence 1".to_owned(),
                "failed".to_owned(),
                "nft_timeout".to_owned()
            ),
            ("command.ping".to_owned(), "sequence 2".to_owned(), "ok".to_owned(), "-".to_owned()),
        ]
    );
    assert!(!restart_pending(&rig.restart).await);
    Ok(())
}


#[tokio::test]
async fn a_failing_audit_is_logged_and_never_undoes_the_order() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig(GOOD)?;
    let channel = addresses(&[PLATFORM_CHANNEL])?;
    let failing: Box<SharedAuditFn> = Box::new(|_| Err(core_audit::error::AuditError::LogPoisoned));
    let broken = AdminEnv {
        audit: &*failing,
        ..env(&rig, fake_nft, &channel)
    };
    let (sender, receiver) = admin_queue();
    sender.try_send(order(AdminKind::Isolate, FIRST))?;
    drop(sender);
    run_admin_worker(receiver, &broken, &AtomicBool::new(false)).await;
    assert!(restart_pending(&rig.restart).await);
    Ok(())
}


const HANG_GUARD_SECONDS: u64 = 120;


static IN_FLIGHT: LazyLock<Notify> = LazyLock::new(Notify::new);


static RELEASE: LazyLock<Notify> = LazyLock::new(Notify::new);


fn held_nft(program: PathBuf, arguments: Vec<String>) -> NftFuture {
    Box::pin(async move {
        if arguments.first().is_some_and(|first| first == "-f") {
            IN_FLIGHT.notify_one();
            RELEASE.notified().await;
        }
        fake_nft(program, arguments).await
    })
}


static TERMINATE_IN_FLIGHT: LazyLock<Notify> = LazyLock::new(Notify::new);


static TERMINATE_RELEASE: LazyLock<Notify> = LazyLock::new(Notify::new);


fn terminate_held_nft(program: PathBuf, arguments: Vec<String>) -> NftFuture {
    Box::pin(async move {
        if arguments.first().is_some_and(|first| first == "-f") {
            TERMINATE_IN_FLIGHT.notify_one();
            TERMINATE_RELEASE.notified().await;
        }
        fake_nft(program, arguments).await
    })
}


#[tokio::test]
async fn a_stop_during_an_isolate_still_settles_and_audits_it_and_logs_the_queued_order_lost() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig(GOOD)?;
    let channel = addresses(&[PLATFORM_CHANNEL])?;
    let (sender, receiver) = admin_queue();
    sender.try_send(order(AdminKind::Isolate, FIRST))?;
    sender.try_send(order(AdminKind::Ping, SECOND))?;
    drop(sender);
    let stopping = AtomicBool::new(false);
    let held = env(&rig, held_nft, &channel);
    let worker = run_admin_worker(receiver, &held, &stopping);
    let stopper = async {
        IN_FLIGHT.notified().await;
        stopping.store(true, Ordering::SeqCst);
        RELEASE.notify_one();
    };
    let (settled, ()) = tokio::time::timeout(Duration::from_secs(HANG_GUARD_SECONDS), async { tokio::join!(worker, stopper) }).await?;
    assert_eq!(settled, FIRST);
    assert!(restart_pending(&rig.restart).await);
    assert_eq!(
        commands_of(&records(&rig)?),
        vec![("command.isolate".to_owned(), "sequence 1".to_owned(), "ok".to_owned(), "-".to_owned())]
    );
    Ok(())
}


#[tokio::test]
async fn a_terminate_during_an_isolate_awaits_and_audits_it_before_the_run_returns() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig(GOOD)?;
    let channel = addresses(&[PLATFORM_CHANNEL])?;
    let (sender, receiver) = admin_queue();
    sender.try_send(order(AdminKind::Isolate, FIRST))?;
    sender.try_send(order(AdminKind::Ping, SECOND))?;
    let stopping = AtomicBool::new(false);
    let held = env(&rig, terminate_held_nft, &channel);
    let terminate = async {
        TERMINATE_IN_FLIGHT.notified().await;
        TERMINATE_RELEASE.notify_one();
    };
    let producers = async move {
        let _queue_open_until_dropped = sender;
        std::future::pending::<Result<(), ()>>().await
    };
    let admin = run_admin_worker(receiver, &held, &stopping);
    let ended = tokio::time::timeout(
        Duration::from_secs(HANG_GUARD_SECONDS),
        run_with_admin(producers, admin, terminate, &stopping),
    )
    .await;
    assert_eq!(ended?, None);
    assert!(restart_pending(&rig.restart).await);
    assert_eq!(
        commands_of(&records(&rig)?),
        vec![("command.isolate".to_owned(), "sequence 1".to_owned(), "ok".to_owned(), "-".to_owned())]
    );
    Ok(())
}
