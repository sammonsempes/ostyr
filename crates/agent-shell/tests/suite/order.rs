use crate::support::{command_of, default_order, open_action, order_of, AGENT, IDLE_SECONDS, LIFETIME, MAX_SECONDS, NOW, SESSION};
use crate::types::TestResult;
use agent_command::error::ActionError;
use agent_command::model::{Action, KeyClass, CLOCK_SKEW_SECONDS, MAX_LIFETIME_SECONDS};
use agent_shell::banner::{printable, shell_banner};
use agent_shell::error::ShellError;
use agent_shell::model::VerifiedOpenShell;
use agent_shell::queue::{admit_shell, new_slot, shell_execute_fn};
use agent_shell::verified::{check_start, is_past, lifetime_ok};
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;


const CAPACITY: usize = 1;


const ESCAPE: u8 = 0x1b;


const ZERO_SECONDS: u32 = 0;


const OVER_MAX: u64 = MAX_LIFETIME_SECONDS + 1;


#[test]
fn a_valid_open_shell_command_becomes_a_verified_order() -> TestResult {
    let order = default_order()?;
    assert_eq!(order.session_id, SESSION);
    assert_eq!(order.asset, "asset-1");
    assert_eq!(order.ticket, "TCK-1");
    assert_eq!(order.requester, "alice@example.org");
    assert_eq!(order.approvers, vec!["bob@example.org".to_owned(), "carol@example.org".to_owned()]);
    assert_eq!(order.max_seconds, MAX_SECONDS);
    assert_eq!(order.idle_seconds, IDLE_SECONDS);
    assert_eq!(order.expires_at, NOW + LIFETIME);
    Ok(())
}


#[test]
fn a_command_that_is_not_open_shell_is_refused() -> TestResult {
    let refused = VerifiedOpenShell::try_from(command_of(Action::Ping));
    assert!(matches!(refused, Err(ShellError::NotOpenShell)));
    Ok(())
}


#[test]
fn the_grammars_run_again_on_every_field() -> TestResult {
    let mut bad_session = command_of(open_action("../escape", MAX_SECONDS, IDLE_SECONDS));
    assert!(matches!(
        VerifiedOpenShell::try_from(bad_session.clone()),
        Err(ShellError::Invalid(ActionError::ShellSessionId))
    ));
    bad_session.action = open_action(SESSION, ZERO_SECONDS, IDLE_SECONDS);
    assert!(matches!(
        VerifiedOpenShell::try_from(bad_session.clone()),
        Err(ShellError::Invalid(ActionError::ShellMaxSeconds))
    ));
    bad_session.action = open_action(SESSION, MAX_SECONDS, ZERO_SECONDS);
    assert!(matches!(
        VerifiedOpenShell::try_from(bad_session),
        Err(ShellError::Invalid(ActionError::ShellIdleSeconds))
    ));
    Ok(())
}


#[test]
fn a_routine_key_is_refused() -> TestResult {
    let mut command = command_of(open_action(SESSION, MAX_SECONDS, IDLE_SECONDS));
    command.key_class = KeyClass::Routine;
    assert!(matches!(VerifiedOpenShell::try_from(command), Err(ShellError::NotSensitive)));
    Ok(())
}


#[test]
fn a_lifetime_that_is_negative_or_over_the_maximum_is_refused() -> TestResult {
    let mut command = command_of(open_action(SESSION, MAX_SECONDS, IDLE_SECONDS));
    command.expires_at = command.issued_at - 1;
    assert!(matches!(VerifiedOpenShell::try_from(command.clone()), Err(ShellError::Lifetime)));
    command.expires_at = command.issued_at + OVER_MAX;
    assert!(matches!(VerifiedOpenShell::try_from(command.clone()), Err(ShellError::Lifetime)));
    command.expires_at = command.issued_at + MAX_LIFETIME_SECONDS;
    assert!(VerifiedOpenShell::try_from(command).is_ok());
    assert!(lifetime_ok(NOW, NOW));
    Ok(())
}


#[test]
fn the_start_is_refused_only_after_the_expiry_and_the_skew() -> TestResult {
    let order = default_order()?;
    let last_good = order.expires_at + CLOCK_SKEW_SECONDS;
    assert!(check_start(&order, last_good).is_ok());
    assert!(matches!(check_start(&order, last_good + 1), Err(ShellError::Expired)));
    assert!(!is_past(order.expires_at, last_good));
    assert!(is_past(order.expires_at, last_good + 1));
    assert!(!is_past(u64::MAX, u64::MAX));
    Ok(())
}


fn waiting(order_count: usize) -> (mpsc::Sender<VerifiedOpenShell>, mpsc::Receiver<VerifiedOpenShell>) {
    mpsc::channel(order_count)
}


#[test]
fn a_second_open_shell_is_refused_by_name_while_the_slot_is_held() -> TestResult {
    let slot = new_slot();
    let (queue, mut receiver) = waiting(CAPACITY);
    admit_shell(&slot, &queue, command_of(open_action(SESSION, MAX_SECONDS, IDLE_SECONDS)))?;
    assert!(slot.load(Ordering::SeqCst));
    let second = admit_shell(&slot, &queue, command_of(open_action("session-2", MAX_SECONDS, IDLE_SECONDS)));
    assert!(matches!(second, Err(ShellError::Busy)));
    assert_eq!(receiver.try_recv()?.session_id, SESSION);
    assert!(receiver.try_recv().is_err());
    Ok(())
}


#[test]
fn a_full_queue_gives_the_slot_back_and_is_busy() -> TestResult {
    let slot = new_slot();
    let (queue, _receiver) = waiting(CAPACITY);
    queue.try_send(default_order()?)?;
    let refused = admit_shell(&slot, &queue, command_of(open_action("session-2", MAX_SECONDS, IDLE_SECONDS)));
    assert!(matches!(refused, Err(ShellError::Busy)));
    assert!(!slot.load(Ordering::SeqCst));
    Ok(())
}


#[test]
fn a_closed_queue_gives_the_slot_back() -> TestResult {
    let slot = new_slot();
    let (queue, receiver) = waiting(CAPACITY);
    drop(receiver);
    let refused = admit_shell(&slot, &queue, command_of(open_action(SESSION, MAX_SECONDS, IDLE_SECONDS)));
    assert!(matches!(refused, Err(ShellError::QueueClosed)));
    assert!(!slot.load(Ordering::SeqCst));
    Ok(())
}


#[test]
fn an_invalid_command_never_takes_the_slot() -> TestResult {
    let slot = new_slot();
    let (queue, _receiver) = waiting(CAPACITY);
    let refused = admit_shell(&slot, &queue, command_of(Action::Ping));
    assert!(matches!(refused, Err(ShellError::NotOpenShell)));
    assert!(!slot.load(Ordering::SeqCst));
    Ok(())
}


#[test]
fn the_execute_adapter_only_queues_and_reports_a_refusal_as_false() -> TestResult {
    let slot = new_slot();
    let (queue, mut receiver) = waiting(CAPACITY);
    let execute = shell_execute_fn(slot, queue);
    assert!(execute(command_of(open_action(SESSION, MAX_SECONDS, IDLE_SECONDS))));
    assert!(!execute(command_of(open_action("session-2", MAX_SECONDS, IDLE_SECONDS))));
    assert!(!execute(command_of(Action::Ping)));
    assert!(receiver.try_recv().is_ok());
    assert!(receiver.try_recv().is_err());
    Ok(())
}


#[test]
fn the_banner_holds_the_session_as_signed_and_the_configured_agent() -> TestResult {
    let order = order_of(SESSION, MAX_SECONDS, IDLE_SECONDS)?;
    let banner = String::from_utf8(shell_banner(&order, AGENT))?;
    assert_eq!(
        banner,
        "OSTYR REMOTE SHELL SESSION\r\nsession: session-1\r\nagent: agent-1\r\nasset: asset-1\r\nticket: TCK-1\r\n\
         requester: alice@example.org\r\napprovers: bob@example.org, carol@example.org\r\n"
    );
    Ok(())
}


#[test]
fn a_configured_name_never_writes_a_terminal_escape() -> TestResult {
    assert_eq!(printable("agent 1~"), "agent 1~");
    assert_eq!(printable("a\x1b[2Jb\r\n"), "a?[2Jb??");
    let banner = shell_banner(&default_order()?, "evil\x1b]0;x\x07");
    assert!(!banner.contains(&ESCAPE));
    Ok(())
}
