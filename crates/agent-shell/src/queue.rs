use crate::error::ShellError;
use crate::model::VerifiedOpenShell;
use crate::types::{EnabledFn, ShellSlot};
use agent_channel::model::ExecuteRefusal;
use agent_channel::types::ExecuteFn;
use agent_command::model::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;


pub fn new_slot() -> ShellSlot {
    std::sync::Arc::new(AtomicBool::new(false))
}


pub fn release_slot(slot: &AtomicBool) {
    slot.store(false, Ordering::SeqCst);
}


pub fn queue_refusal(refused: TrySendError<VerifiedOpenShell>) -> ShellError {
    match refused {
        TrySendError::Full(_order) => ShellError::Busy,
        TrySendError::Closed(_order) => ShellError::QueueClosed,
    }
}


/// Verifies again, takes the busy slot and queues the order; a refused queue gives the slot back.
pub fn admit_shell(slot: &AtomicBool, queue: &Sender<VerifiedOpenShell>, command: Command) -> Result<(), ShellError> {
    let order = VerifiedOpenShell::try_from(command)?;
    slot.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .map_err(|_taken| ShellError::Busy)?;
    queue.try_send(order).map_err(|refused| {
        release_slot(slot);
        queue_refusal(refused)
    })
}


pub fn shell_refusal(error: &ShellError) -> ExecuteRefusal {
    match error {
        ShellError::Busy | ShellError::QueueClosed => ExecuteRefusal::Busy,
        ShellError::Disabled => ExecuteRefusal::ShellDisabled,
        ShellError::NotOpenShell
        | ShellError::Invalid(_)
        | ShellError::NotSensitive
        | ShellError::Lifetime
        | ShellError::Expired
        | ShellError::Cleanup(_)
        | ShellError::Leftover(_)
        | ShellError::Store(_)
        | ShellError::Dial(_)
        | ShellError::Spawn(_)
        | ShellError::PreviousUidStillRunning(_)
        | ShellError::Account(_) => ExecuteRefusal::Invalid,
    }
}


/// The executor of `OpenShell` commands: it only queues, never spawns, and refuses (busy or invalid, fixed reasons) what it cannot take.
pub fn shell_execute_fn(slot: ShellSlot, queue: Sender<VerifiedOpenShell>) -> Box<ExecuteFn<'static>> {
    Box::new(move |command| {
        admit_shell(&slot, &queue, command)
            .inspect_err(|error| tracing::warn!(%error, "open-shell command refused"))
            .map_err(|error| shell_refusal(&error))
    })
}


/// Puts the enable switch in front of an executor: a disabled switch refuses by name before anything is queued.
pub fn gated_execute_fn(enabled: Arc<EnabledFn>, inner: Box<ExecuteFn<'static>>) -> Box<ExecuteFn<'static>> {
    Box::new(move |command| {
        if enabled() {
            inner(command)
        } else {
            tracing::warn!("open-shell command refused: the shell is disabled");
            Err(ExecuteRefusal::ShellDisabled)
        }
    })
}
