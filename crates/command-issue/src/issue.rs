use crate::error::IssueError;
use crate::key::{check_key, Pair};
use crate::limits::{Limits, LIFETIME_SECONDS};
use crate::queue::{discard, envelope_name, list_queue, open_agent_directory, prune, rename_staged, retract, stage, CommandDirs, Staged};
use crate::sequence::{allocate, check_agent_cap, check_gap, count_agents, lock_agent, lock_tenant, read_row, RowState};
use crate::types::{ClockFn, HookFn, SyncFn, UnlinkFn};
use agent_channel::identity::valid_component;
use agent_command::model::{Action, Command, KeyClass, TrustedKeys};
use agent_command::sign::{memory_signer, new_nonce, os_random, sign_command};
use arc_swap::ArcSwap;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use core_pg::transaction::{begin, commit, rollback};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use std::os::fd::OwnedFd;
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use tokio_postgres::Client;
use tracing::warn;


/// The only two actions a routine key may sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueAction {
    Ping,
    CollectStatus,
}


pub struct IssueRequest<'a> {
    pub tenant: &'a str,
    pub agent_id: &'a str,
    pub action: IssueAction,
}


/// Everything one issue works through; `keys` is one snapshot of the keys file and `pairs` the swappable signing pair.
pub struct Issuer<'a> {
    pub client: &'a Client,
    pub dirs: &'a CommandDirs,
    pub keys: &'a TrustedKeys,
    pub pairs: &'a ArcSwap<Pair>,
    pub limits: Limits,
    pub deadline: Duration,
    pub clock: &'a ClockFn,
    pub before_publish: &'a HookFn,
    pub sync: SyncFn,
    pub unlink: UnlinkFn,
    pub agent_limit_refusals: &'a AtomicU64,
}


/// The result of an issue and the argument of the publish hook; `command_id` is the hex SHA-256 of the envelope, never the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub tenant: String,
    pub agent_id: String,
    pub action: IssueAction,
    pub command_id: String,
    pub sequence: u64,
    pub expires_at: u64,
}


pub struct Published {
    pub issued: Issued,
    pub directory: OwnedFd,
    pub name: String,
    pub staged: Staged,
}


pub fn action_of(action: IssueAction) -> Action {
    match action {
        IssueAction::Ping => Action::Ping,
        IssueAction::CollectStatus => Action::CollectStatus,
    }
}


/// The gateway's identity grammar, called and never copied, minus a leading `-` or `.`: such an enrolled agent cannot be commanded.
pub fn check_agent_id(agent: &str) -> Result<(), IssueError> {
    if valid_component(agent) && !agent.starts_with(['-', '.']) {
        Ok(())
    } else {
        Err(IssueError::InvalidAgent)
    }
}


pub fn sign_envelope(pair: &Pair, request: &IssueRequest<'_>, now: u64, sequence: u64) -> Result<(Vec<u8>, u64), IssueError> {
    let expires_at = now.checked_add(LIFETIME_SECONDS).ok_or(IssueError::Range)?;
    let command = Command {
        key_id: pair.key_id.clone(),
        key_class: KeyClass::Routine,
        agent_id: request.agent_id.to_owned(),
        tenant: request.tenant.to_owned(),
        issued_at: now,
        expires_at,
        sequence,
        nonce: new_nonce(os_random)?,
        action: action_of(request.action),
    };
    let signer = memory_signer(pair.signing_key.clone());
    Ok((sign_command(&command, &pair.key_id, signer.as_ref())?, expires_at))
}


/// A tenant refusal needs the tenant lock and a count before any directory or row exists.
pub async fn guard_new_agent(issuer: &Issuer<'_>, scope: &TenantScope, row: Option<RowState>) -> Result<(), IssueError> {
    match row {
        Some(_) => Ok(()),
        None => {
            lock_tenant(issuer.client, scope, issuer.deadline).await?;
            let count = count_agents(issuer.client, scope, issuer.deadline).await?;
            check_agent_cap(tenant_of(scope), count, issuer.limits.max_agents, issuer.agent_limit_refusals)
        }
    }
}


/// The queue rules: prune, refuse a full queue, and return the highest sequence ever seen in the directory.
pub fn queue_state(issuer: &Issuer<'_>, directory: &OwnedFd, request: &IssueRequest<'_>, now: u64) -> Result<u64, IssueError> {
    let listing = list_queue(directory, request.tenant, request.agent_id)?;
    let highest = listing.iter().map(|entry| entry.sequence).max().unwrap_or(0);
    let remaining = prune(directory, listing, now)?;
    if remaining.len() >= issuer.limits.max_queue_files {
        Err(IssueError::QueueFull)
    } else {
        Ok(highest)
    }
}


/// The hook, the no-replace rename and the directory sync; a failure removes the staged file or the published one.
pub fn publish_staged(issuer: &Issuer<'_>, directory: &OwnedFd, staged: &Staged, issued: &Issued, name: &str) -> Result<(), IssueError> {
    (issuer.before_publish)(issued)
        .map_err(IssueError::Hook)
        .inspect_err(|_| discard(issuer.dirs, &staged.name))?;
    rename_staged(issuer.dirs, directory, staged, name)
        .map_err(IssueError::from)
        .inspect_err(|_| discard(issuer.dirs, &staged.name))?;
    (issuer.sync)(directory)
        .map_err(IssueError::from)
        .inspect_err(|_| retract(directory, name, staged.identity, issuer.unlink))
}


/// Everything between the lock and the commit; every refusal is decided before the allocation, and a failure removes its own file.
pub async fn locked_issue(issuer: &Issuer<'_>, scope: &TenantScope, request: &IssueRequest<'_>, now: u64) -> Result<Published, IssueError> {
    lock_agent(issuer.client, scope, request.agent_id, issuer.deadline).await?;
    let pair = issuer.pairs.load_full();
    check_key(issuer.keys, &pair, now).map_err(IssueError::KeyUnusable)?;
    let row = read_row(issuer.client, scope, request.agent_id, issuer.deadline).await?;
    guard_new_agent(issuer, scope, row).await?;
    let state = row.unwrap_or(RowState { last: 0, confirmed: 0 });
    let directory = open_agent_directory(issuer.dirs, request.tenant, request.agent_id)?;
    let highest_queued = queue_state(issuer, &directory, request, now)?;
    check_gap(state.last.max(highest_queued), state.confirmed, issuer.limits.max_unconfirmed)?;
    let sequence = allocate(issuer.client, scope, request.agent_id, highest_queued, issuer.deadline).await?;
    let (envelope, expires_at) = sign_envelope(&pair, request, now, sequence)?;
    let staged = stage(issuer.dirs, &envelope)?;
    let issued = Issued {
        tenant: request.tenant.to_owned(),
        agent_id: request.agent_id.to_owned(),
        action: request.action,
        command_id: HEXLOWER.encode(&Sha256::digest(&envelope)),
        sequence,
        expires_at,
    };
    let name = envelope_name(sequence, expires_at);
    publish_staged(issuer, &directory, &staged, &issued, &name)?;
    Ok(Published {
        issued,
        directory,
        name,
        staged,
    })
}


pub async fn rollback_logged(issuer: &Issuer<'_>) {
    if let Err(error) = rollback(issuer.client, issuer.deadline).await {
        warn!(%error, "command issue rollback failed");
    }
}


/// The commit is the last step: a failure retracts the published file (same inode only) and rolls back.
pub async fn seal(issuer: &Issuer<'_>, published: Published) -> Result<Issued, IssueError> {
    match commit(issuer.client, issuer.deadline).await {
        Ok(()) => Ok(published.issued),
        Err(error) => {
            retract(&published.directory, &published.name, published.staged.identity, issuer.unlink);
            rollback_logged(issuer).await;
            Err(IssueError::Pg(error))
        }
    }
}


/// Signs a routine command for one agent and publishes it; a refusal burns no number, and a failure after the allocation burns one.
pub async fn issue_command(issuer: &Issuer<'_>, request: &IssueRequest<'_>) -> Result<Issued, IssueError> {
    check_agent_id(request.agent_id)?;
    let scope = tenant_scope(request.tenant)?;
    let now = (issuer.clock)();
    begin(issuer.client, issuer.deadline).await?;
    match locked_issue(issuer, &scope, request, now).await {
        Ok(published) => seal(issuer, published).await,
        Err(error) => {
            rollback_logged(issuer).await;
            Err(error)
        }
    }
}
