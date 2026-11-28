use crate::support::{
    agent_path, capture, count_of, drain, failing_hook, issuer_of, issuer_with, locked, logged, names_in, ping, request, rig, Rig, AGENT, FOURTH,
    HANG_GUARD, KEY_ID, PERMISSIONS, SECOND, START, TENANT, THIRD,
};
use agent_channel::commands::MAX_COMMAND_FILES as MAX_COMMAND_FILES_USED;
use agent_command::codec::{decode_exact, signing_message};
use agent_command::model::{Action, Command, Envelope, KeyClass, MAX_SEQUENCE_ADVANCE};
use command_issue::error::{IssueError, KeyRefusal};
use command_issue::issue::{action_of, check_agent_id, issue_command, sign_envelope, IssueAction, IssueRequest, Issued};
use command_issue::limits::{Limits, LIFETIME_SECONDS};
use command_issue::queue::{envelope_name, open_agent_directory};
use core_pg::connect::connect;
use data_encoding::HEXLOWER;
use ed25519_dalek::Signature;
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use tokio::time::timeout;


const SKEW: u64 = 30;


const FILE_MODE: u32 = 0o640;


const OTHER_AGENT: &str = "agent2";


const TOTAL_ISSUES: u64 = 70;


const SMALL_GAP: u64 = 3;


const SMALL_AGENTS: u64 = 3;


const STEP_BACK: u64 = 1_000;


const QUEUED_AHEAD: u64 = 7;


const ROW_LAST: i64 = 3;


const WIDE_AGENT: usize = 200;


const SHORT: u64 = 5;


pub fn envelope_in(path: &Path) -> Result<(Vec<u8>, Envelope, Command), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let envelope = decode_exact::<Envelope>(&bytes)?;
    let command = decode_exact::<Command>(&envelope.command)?;
    Ok((bytes, envelope, command))
}


pub fn kinds(statements: &[String]) -> Vec<&'static str> {
    statements
        .iter()
        .filter(|statement| !statement.starts_with("SET statement_timeout"))
        .map(|statement| {
            if statement.starts_with("PARAMS") {
                "params"
            } else if statement.contains("pg_advisory_xact_lock(hashtextextended('command-issue/'") {
                "lock-agent"
            } else if statement.contains("command-issue-tenant/") {
                "lock-tenant"
            } else if statement.starts_with("SELECT last, confirmed") {
                "row"
            } else if statement.starts_with("SELECT count") {
                "count"
            } else if statement.starts_with("INSERT INTO agent_command_sequences") {
                "allocate"
            } else if statement == "BEGIN" {
                "begin"
            } else if statement == "COMMIT" {
                "commit"
            } else if statement == "ROLLBACK" {
                "rollback"
            } else {
                "other"
            }
        })
        .collect()
}


pub fn only_files(directory: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    names_in(directory)
}


pub fn plant_in(rig: &Rig, agent: &str, sequence: u64, expires_at: u64) -> Result<String, Box<dyn Error>> {
    let path = agent_path(rig, agent);
    fs::create_dir_all(&path)?;
    let name = envelope_name(sequence, expires_at);
    fs::write(path.join(&name), b"planted")?;
    Ok(name)
}


pub fn fail_sync(_directory: &OwnedFd) -> Result<(), Errno> {
    Err(Errno::IO)
}


pub fn fail_unlink(_directory: &OwnedFd, _name: &str) -> std::io::Result<()> {
    Err(std::io::Error::other("unlink failed"))
}


#[tokio::test]
async fn a_ping_is_signed_staged_published_and_committed_in_order() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    let issued = issue_command(&issuer_of(&rig), &ping(AGENT)).await?;
    assert_eq!(issued.sequence, 1);
    assert_eq!(issued.expires_at, START + LIFETIME_SECONDS);
    let name = envelope_name(issued.sequence, issued.expires_at);
    let path = agent_path(&rig, AGENT).join(&name);
    let (bytes, envelope, command) = envelope_in(&path)?;
    assert_eq!(issued.command_id, HEXLOWER.encode(&Sha256::digest(&bytes)));
    assert_eq!(fs::metadata(&path)?.permissions().mode() & PERMISSIONS, FILE_MODE);
    assert_eq!((command.tenant.as_str(), command.agent_id.as_str(), command.sequence), (TENANT, AGENT, 1));
    assert_eq!(
        (command.key_class, command.action.clone(), command.issued_at),
        (KeyClass::Routine, Action::Ping, START)
    );
    assert_eq!((command.key_id.as_str(), envelope.key_id.as_str()), (KEY_ID, KEY_ID));
    let signature = Signature::from_slice(&envelope.signature)?;
    rig.pairs
        .load()
        .public_key
        .verify_strict(&signing_message(&envelope.command), &signature)?;
    assert_eq!(only_files(&agent_path(&rig, AGENT))?, vec![name]);
    assert!(only_files(&rig.root.join(".staging"))?.is_empty());
    let statements = drain(&mut rig.fake.statements);
    assert_eq!(
        kinds(&statements),
        vec![
            "begin",
            "lock-agent",
            "params",
            "row",
            "params",
            "lock-tenant",
            "params",
            "count",
            "params",
            "allocate",
            "params",
            "commit"
        ]
    );
    assert!(statements.iter().any(|statement| statement == "PARAMS acme|agent1|0"));
    Ok(())
}


#[tokio::test]
async fn a_collect_status_and_successive_numbers_keep_the_name_order_equal_to_the_sequence_order() -> Result<(), Box<dyn Error>> {
    let rig = rig().await?;
    let first = issue_command(&issuer_of(&rig), &request(AGENT, IssueAction::CollectStatus)).await?;
    rig.now.store(START - STEP_BACK, Ordering::SeqCst);
    let second = issue_command(&issuer_of(&rig), &ping(AGENT)).await?;
    assert_eq!((first.sequence, second.sequence), (1, SECOND));
    let names = only_files(&agent_path(&rig, AGENT))?;
    assert_eq!(names, vec![envelope_name(1, first.expires_at), envelope_name(SECOND, second.expires_at)]);
    assert!(second.expires_at < first.expires_at);
    let first_name = names.first().ok_or("no file")?;
    let (_, _, command) = envelope_in(&agent_path(&rig, AGENT).join(first_name))?;
    assert_eq!(command.action, Action::CollectStatus);
    assert_eq!(action_of(IssueAction::Ping), Action::Ping);
    Ok(())
}


#[tokio::test]
async fn the_queue_cap_refuses_before_any_allocation_and_expiry_frees_it() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    let results = futures_issue(&rig, TOTAL_ISSUES).await;
    let accepted = results.iter().filter(|result| result.is_ok()).count();
    assert_eq!(
        accepted,
        MAX_COMMAND_FILES_USED,
        "{:?}",
        results.get(accepted).map(|result| result.as_ref().err().map(ToString::to_string))
    );
    assert!(results.iter().skip(accepted).all(|result| matches!(result, Err(IssueError::QueueFull))));
    assert_eq!(only_files(&agent_path(&rig, AGENT))?.len(), MAX_COMMAND_FILES_USED);
    let statements = drain(&mut rig.fake.statements);
    assert_eq!(count_of(&statements, "INSERT INTO agent_command_sequences"), MAX_COMMAND_FILES_USED);
    rig.now.store(START + LIFETIME_SECONDS + SKEW + 1, Ordering::SeqCst);
    let later = issue_command(&issuer_of(&rig), &ping(AGENT)).await?;
    assert_eq!(later.sequence, u64::try_from(MAX_COMMAND_FILES_USED)? + 1);
    assert_eq!(
        only_files(&agent_path(&rig, AGENT))?,
        vec![envelope_name(later.sequence, later.expires_at)]
    );
    Ok(())
}


pub async fn futures_issue(rig: &Rig, count: u64) -> Vec<Result<Issued, IssueError>> {
    let mut results = Vec::new();
    for _ in 0..count {
        let result = match connect(&rig.settings).await {
            Ok(client) => issue_command(&issuer_with(rig, &client, rig.hook.as_ref()), &ping(AGENT)).await,
            Err(error) => Err(IssueError::Pg(error)),
        };
        results.push(result);
    }
    results
}


#[tokio::test]
async fn a_gap_beyond_the_unconfirmed_cap_refuses_and_a_confirmation_reopens_it() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    rig.limits = Limits {
        max_unconfirmed: SMALL_GAP,
        ..Limits::default()
    };
    let results = futures_issue(&rig, SMALL_GAP + 1).await;
    assert!(results.iter().take(usize::try_from(SMALL_GAP)?).all(|result| result.is_ok()));
    assert!(matches!(results.last(), Some(Err(IssueError::SequenceGap))));
    let statements = drain(&mut rig.fake.statements);
    assert_eq!(count_of(&statements, "INSERT INTO agent_command_sequences"), usize::try_from(SMALL_GAP)?);
    *locked(&rig.script.row) = Some((ROW_LAST, ROW_LAST));
    let reopened = issue_command(&issuer_of(&rig), &ping(AGENT)).await?;
    assert_eq!(reopened.sequence, FOURTH);
    Ok(())
}


#[tokio::test]
async fn the_gap_counts_the_highest_queued_sequence_like_the_allocation() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    plant_in(&rig, AGENT, MAX_SEQUENCE_ADVANCE, START + LIFETIME_SECONDS)?;
    let refused = issue_command(&issuer_of(&rig), &ping(AGENT)).await.err().ok_or("issued")?;
    assert!(matches!(refused, IssueError::SequenceGap), "{refused}");
    assert_eq!(count_of(&drain(&mut rig.fake.statements), "INSERT INTO agent_command_sequences"), 0);
    Ok(())
}


#[tokio::test]
async fn a_queued_file_ahead_of_the_row_is_passed_to_the_allocation() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    plant_in(&rig, AGENT, QUEUED_AHEAD, START + LIFETIME_SECONDS)?;
    *locked(&rig.script.row) = Some((ROW_LAST, 0));
    rig.script.counter.store(i64::try_from(QUEUED_AHEAD)?, Ordering::SeqCst);
    let issued = issue_command(&issuer_of(&rig), &ping(AGENT)).await?;
    assert_eq!(issued.sequence, QUEUED_AHEAD + 1);
    assert!(drain(&mut rig.fake.statements)
        .iter()
        .any(|statement| statement == "PARAMS acme|agent1|7"));
    Ok(())
}


#[tokio::test]
async fn an_unusable_key_refuses_before_any_row_or_number_and_is_rechecked_at_every_issue() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    issue_command(&issuer_of(&rig), &ping(AGENT)).await?;
    drain(&mut rig.fake.statements);
    rig.keys.keys.iter_mut().for_each(|(_, key)| key.revoked = true);
    let refused = issue_command(&issuer_of(&rig), &ping(AGENT)).await.err().ok_or("issued")?;
    assert!(matches!(refused, IssueError::KeyUnusable(KeyRefusal::Revoked)), "{refused}");
    let statements = drain(&mut rig.fake.statements);
    assert_eq!(kinds(&statements), vec!["begin", "lock-agent", "params", "rollback"]);
    assert_eq!(only_files(&agent_path(&rig, AGENT))?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_new_agent_over_the_tenant_cap_is_refused_before_any_directory_or_row() -> Result<(), Box<dyn Error>> {
    let (dispatch, buffer) = capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let mut rig = rig().await?;
    rig.limits = Limits {
        max_agents: SMALL_AGENTS,
        ..Limits::default()
    };
    rig.script.count.store(i64::try_from(SMALL_AGENTS)?, Ordering::SeqCst);
    let warnings = {
        let mut counts = Vec::new();
        for index in 0..SMALL_AGENTS {
            let agent = format!("fake{index}");
            let refused = issue_command(&issuer_of(&rig), &ping(&agent)).await.err().ok_or("issued")?;
            assert!(matches!(refused, IssueError::AgentLimit), "{refused}");
            assert!(!agent_path(&rig, &agent).exists());
            counts.push(logged(&buffer).matches("tenant agent limit reached").count());
        }
        counts
    };
    assert_eq!(warnings, vec![1, usize::try_from(SECOND)?, usize::try_from(SECOND)?]);
    let statements = drain(&mut rig.fake.statements);
    assert_eq!(count_of(&statements, "command-issue-tenant/"), usize::try_from(THIRD)?);
    assert_eq!(count_of(&statements, "INSERT INTO agent_command_sequences"), 0);
    *locked(&rig.script.row) = Some((1, 0));
    issue_command(&issuer_of(&rig), &ping(OTHER_AGENT)).await?;
    assert_eq!(count_of(&drain(&mut rig.fake.statements), "SELECT count"), 0);
    Ok(())
}


#[tokio::test]
async fn hostile_agent_ids_and_tenants_are_refused_before_any_statement() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    let long = "a".repeat(WIDE_AGENT);
    let ids = [
        "",
        "a/b",
        "..",
        ".",
        "a@b",
        "a:b",
        "a\0b",
        "-x",
        ".hidden",
        "a b",
        "a\n",
        "é",
        long.as_str(),
    ];
    ids.iter().try_for_each(|agent| {
        assert!(matches!(check_agent_id(agent), Err(IssueError::InvalidAgent)), "{agent:?}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    check_agent_id("agent-1_a.b")?;
    for agent in ids {
        let refused = issue_command(&issuer_of(&rig), &ping(agent)).await.err().ok_or("issued")?;
        assert!(matches!(refused, IssueError::InvalidAgent), "{refused}");
    }
    let bad_tenant = IssueRequest {
        tenant: "Bad Tenant",
        agent_id: AGENT,
        action: IssueAction::Ping,
    };
    let tenant = issue_command(&issuer_of(&rig), &bad_tenant).await;
    assert!(matches!(tenant, Err(IssueError::Pg(_))));
    assert!(drain(&mut rig.fake.statements).is_empty());
    assert!(names_in(&rig.root)?.iter().all(|name| name == ".staging"));
    Ok(())
}


#[tokio::test]
async fn a_foreign_entry_in_the_agent_directory_refuses_and_nothing_is_deleted() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    let directory = agent_path(&rig, AGENT);
    fs::create_dir(&directory)?;
    symlink("elsewhere", directory.join("link"))?;
    let expired = plant_in(&rig, AGENT, 1, 1)?;
    let refused = issue_command(&issuer_of(&rig), &ping(AGENT)).await.err().ok_or("issued")?;
    assert!(matches!(refused, IssueError::QueueInvalid), "{refused}");
    assert_eq!(only_files(&directory)?, vec![expired, "link".to_owned()]);
    assert_eq!(count_of(&drain(&mut rig.fake.statements), "INSERT INTO agent_command_sequences"), 0);
    assert!(only_files(&rig.root.join(".staging"))?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failing_hook_removes_the_staged_file_and_the_number_stays_burnt() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    let refused = issue_command(&issuer_with(&rig, &rig.client, &failing_hook), &ping(AGENT))
        .await
        .err()
        .ok_or("issued")?;
    assert!(matches!(refused, IssueError::Hook(_)), "{refused}");
    assert!(only_files(&agent_path(&rig, AGENT))?.is_empty());
    assert!(only_files(&rig.root.join(".staging"))?.is_empty());
    let statements = drain(&mut rig.fake.statements);
    assert_eq!(kinds(&statements).last(), Some(&"rollback"));
    let next = issue_command(&issuer_of(&rig), &ping(AGENT)).await?;
    assert_eq!(next.sequence, SECOND);
    Ok(())
}


#[tokio::test]
async fn the_hook_sees_the_issued_record_before_the_file_is_published() -> Result<(), Box<dyn Error>> {
    let rig = rig().await?;
    let seen: Arc<Mutex<Vec<(Issued, bool)>>> = Arc::new(Mutex::new(Vec::new()));
    let directory = agent_path(&rig, AGENT);
    let witness = Arc::clone(&seen);
    let hook = move |issued: &Issued| -> Result<(), agent_command::types::BoxError> {
        let published = directory.join(envelope_name(issued.sequence, issued.expires_at)).exists();
        locked(&witness).push((issued.clone(), published));
        Ok(())
    };
    let issued = issue_command(&issuer_with(&rig, &rig.client, &hook), &ping(AGENT)).await?;
    assert_eq!(locked(&seen).as_slice(), &[(issued, false)]);
    Ok(())
}


#[tokio::test]
async fn a_name_collision_never_overwrites_and_removes_the_staged_file() -> Result<(), Box<dyn Error>> {
    let rig = rig().await?;
    let name = plant_in(&rig, AGENT, SHORT, START + LIFETIME_SECONDS)?;
    rig.script.counter.store(i64::try_from(SHORT)? - 1, Ordering::SeqCst);
    let refused = issue_command(&issuer_of(&rig), &ping(AGENT)).await.err().ok_or("issued")?;
    assert!(matches!(refused, IssueError::Fs(Errno::EXIST)), "{refused}");
    assert_eq!(fs::read(agent_path(&rig, AGENT).join(&name))?, b"planted");
    assert!(only_files(&rig.root.join(".staging"))?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failed_directory_sync_retracts_the_published_file() -> Result<(), Box<dyn Error>> {
    let rig = rig().await?;
    let mut issuer = issuer_of(&rig);
    issuer.sync = fail_sync;
    let refused = issue_command(&issuer, &ping(AGENT)).await.err().ok_or("issued")?;
    assert!(matches!(refused, IssueError::Fs(Errno::IO)), "{refused}");
    assert!(only_files(&agent_path(&rig, AGENT))?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failed_commit_retracts_the_published_file_and_rolls_back() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    locked(&rig.script.failing).push(("COMMIT", "40001"));
    let refused = issue_command(&issuer_of(&rig), &ping(AGENT)).await.err().ok_or("issued")?;
    assert!(matches!(refused, IssueError::Pg(_)), "{refused}");
    assert!(only_files(&agent_path(&rig, AGENT))?.is_empty());
    assert_eq!(kinds(&drain(&mut rig.fake.statements)).last(), Some(&"rollback"));
    Ok(())
}


#[tokio::test]
async fn a_file_replaced_or_gone_at_commit_failure_is_left_alone_and_a_failed_unlink_is_named() -> Result<(), Box<dyn Error>> {
    let (dispatch, buffer) = capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let rig = rig().await?;
    locked(&rig.script.failing).push(("COMMIT", "40001"));
    let directory = agent_path(&rig, AGENT);
    let failed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&failed);
    let target = directory.clone();
    *locked(&rig.script.on_commit) = Some(Arc::new(move || {
        let swapped = fs::read_dir(&target)
            .and_then(|mut entries| entries.next().transpose())
            .and_then(|entry| {
                entry.map_or(Ok(()), |found| {
                    let aside = found.path().with_extension("aside");
                    fs::write(&aside, b"other").and_then(|()| fs::rename(&aside, found.path()))
                })
            });
        flag.store(swapped.is_err(), Ordering::SeqCst);
    }));
    issue_command(&issuer_of(&rig), &ping(AGENT)).await.err().ok_or("issued")?;
    assert!(!failed.load(Ordering::SeqCst));
    assert_eq!(only_files(&directory)?.len(), 1);
    assert!(logged(&buffer).contains("replaced by another file"));
    let other = Arc::new(AtomicBool::new(false));
    let marker = Arc::clone(&other);
    let again = directory.clone();
    *locked(&rig.script.on_commit) = Some(Arc::new(move || {
        let removed = fs::read_dir(&again).and_then(|entries| {
            entries
                .map(|entry| entry.and_then(|found| fs::remove_file(found.path())))
                .collect::<Result<Vec<()>, _>>()
        });
        marker.store(removed.is_err(), Ordering::SeqCst);
    }));
    issue_command(&issuer_of(&rig), &ping(AGENT)).await.err().ok_or("issued")?;
    assert!(!other.load(Ordering::SeqCst));
    assert!(logged(&buffer).contains("already gone"));
    *locked(&rig.script.on_commit) = None;
    let mut issuer = issuer_of(&rig);
    issuer.unlink = fail_unlink;
    issue_command(&issuer, &ping(AGENT)).await.err().ok_or("issued")?;
    assert!(logged(&buffer).contains("cannot retract a published envelope"));
    assert_eq!(only_files(&directory)?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_failing_rollback_is_logged() -> Result<(), Box<dyn Error>> {
    let (dispatch, buffer) = capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let rig = rig().await?;
    locked(&rig.script.failing).push(("INSERT INTO agent_command_sequences", "40001"));
    locked(&rig.script.failing).push(("ROLLBACK", "40001"));
    let refused = issue_command(&issuer_of(&rig), &ping(AGENT)).await.err().ok_or("issued")?;
    assert!(matches!(refused, IssueError::Pg(_)), "{refused}");
    assert!(logged(&buffer).contains("command issue rollback failed"));
    assert!(only_files(&agent_path(&rig, AGENT))?.is_empty());
    Ok(())
}


#[tokio::test]
async fn the_envelope_expiry_overflow_is_a_range_error() -> Result<(), Box<dyn Error>> {
    let rig = rig().await?;
    let pair = rig.pairs.load_full();
    let refused = sign_envelope(&pair, &ping(AGENT), u64::MAX, 1).err().ok_or("signed")?;
    assert!(matches!(refused, IssueError::Range));
    let (envelope, expires_at) = sign_envelope(&pair, &ping(AGENT), START, 1)?;
    assert_eq!(expires_at, START + LIFETIME_SECONDS);
    assert!(!envelope.is_empty());
    Ok(())
}


#[tokio::test]
async fn the_agent_directory_is_created_under_the_trusted_root_only_when_needed() -> Result<(), Box<dyn Error>> {
    let rig = rig().await?;
    assert!(!agent_path(&rig, AGENT).exists());
    open_agent_directory(&rig.dirs, TENANT, AGENT)?;
    assert!(fs::metadata(agent_path(&rig, AGENT))?.is_dir());
    assert_ne!(fs::metadata(&rig.root)?.ino(), fs::metadata(agent_path(&rig, AGENT))?.ino());
    Ok(())
}


pub fn blocking_hook(
    reached: std::sync::mpsc::Sender<()>,
    go: Receiver<()>,
) -> impl Fn(&Issued) -> Result<(), agent_command::types::BoxError> + Send + Sync {
    let gate = Mutex::new(go);
    move |_issued: &Issued| {
        reached.send(())?;
        locked(&gate).recv_timeout(HANG_GUARD)?;
        Ok(())
    }
}


#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_second_issue_waits_for_the_agent_lock_and_the_numbers_are_distinct() -> Result<(), Box<dyn Error>> {
    let rig = Arc::new(rig().await?);
    let second_client = connect(&rig.settings).await?;
    let (reached_sender, reached) = channel::<()>();
    let (go, go_receiver) = channel::<()>();
    let first_rig = Arc::clone(&rig);
    let first = tokio::spawn(async move {
        let hook = blocking_hook(reached_sender, go_receiver);
        issue_command(&issuer_with(&first_rig, &first_rig.client, &hook), &ping(AGENT)).await
    });
    tokio::task::spawn_blocking(move || reached.recv_timeout(HANG_GUARD)).await??;
    let second_rig = Arc::clone(&rig);
    let mut second = tokio::spawn(async move { issue_command(&issuer_of_client(&second_rig, &second_client), &ping(AGENT)).await });
    let waited = tokio::select! {
        () = rig.script.waiting.notified() => true,
        _finished = &mut second => false,
        () = tokio::time::sleep(HANG_GUARD) => false,
    };
    assert!(waited, "the second issue did not wait for the lock");
    assert!(!second.is_finished());
    go.send(())?;
    let issued_first = timeout(HANG_GUARD, first).await???;
    let issued_second = timeout(HANG_GUARD, second).await???;
    assert_eq!((issued_first.sequence, issued_second.sequence), (1, SECOND));
    assert_eq!(only_files(&agent_path(&rig, AGENT))?.len(), usize::try_from(SECOND)?);
    Ok(())
}


pub fn issuer_of_client<'a>(rig: &'a Rig, client: &'a tokio_postgres::Client) -> command_issue::issue::Issuer<'a> {
    issuer_with(rig, client, rig.hook.as_ref())
}
