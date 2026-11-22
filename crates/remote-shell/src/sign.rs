use crate::agent_map::{resolve_agent, AgentMap};
use crate::error::{SignError, StoreError};
use crate::grammar::{valid_reference, valid_subject};
use crate::open::{age_of, decide_open, OpenDecision, OpenRequest};
use crate::sign_model::{SignInputs, SignPlan, SignedShell, Signing};
use crate::store::{cell, int_of, optional_int, required, run, text_of, to_i64};
use crate::store_model::{Param, SessionRow, Statement};
use crate::types::{Row, Seconds};
use agent_channel::shell_gate::gate_add;
use agent_command::action::validate_action;
use agent_command::model::{Action, Command, KeyClass};
use agent_command::sign::{new_nonce, sign_command};
use core_pg::scope::{tenant_of, TenantScope};
use std::future::Future;


/// A register row older than this is never signed: the evidence behind its decision has aged out.
pub const MAX_SIGN_DELAY_SECONDS: u64 = 120;


/// The agent may start the shell within this many seconds of the signature; `max_seconds` and `idle_seconds` then run from its start.
pub const SIGN_LIFETIME_SECONDS: Seconds = 60;


/// Signed shells of one tenant that have not expired; the same number as the gate's per-tenant cap.
pub const MAX_PENDING_SHELLS_PER_TENANT: u32 = 16;


pub const APPROVER_SEPARATOR: &str = ",";


pub const COL_SIGN_CLOSED_AT: usize = 0;


pub const COL_SIGN_OPENED_AT: usize = 1;


pub const COL_SIGN_REQUESTER: usize = 2;


pub const COL_SIGN_ASSET: usize = 3;


pub const COL_SIGN_TICKET: usize = 4;


pub const COL_SIGN_SIGNED: usize = 5;


pub const COL_SIGN_PENDING: usize = 6;


/// Params `$2` to `$14`: session id, requester, asset, ticket, opened_at, agent id, approvers, max, idle, issued_at, expires_at, key id, cap.
pub const CLAIM_SQL: &str = "SELECT out_session FROM remote_shell_sign_claim($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)";


/// Params `$2` session id, `$3` the sequence; fills the sequence once.
pub const SEQUENCE_SQL: &str =
    "UPDATE remote_shell_signed SET sequence = $3 WHERE tenant = $1 AND session_id = $2 AND sequence IS NULL RETURNING session_id";


/// Params `$2` session id, `$3` issued_at; read only after a refused claim, to name the refusal.
pub const SIGN_STATE_SQL: &str = "SELECT s.closed_at, s.opened_at, s.requester, s.asset, s.ticket, g.session_id, \
    (SELECT count(*) FROM remote_shell_signed c WHERE c.tenant = $1 AND c.expires_at >= $3) \
    FROM remote_shell_sessions s LEFT JOIN remote_shell_signed g ON g.tenant = s.tenant AND g.session_id = s.session_id \
    WHERE s.tenant = $1 AND s.session_id = $2";


pub fn check_field(field: &'static str, valid: bool) -> Result<(), SignError> {
    valid.then_some(()).ok_or(SignError::Invalid { field })
}


/// The pure checks on the row: grammars (no leading `-` on the requester), age, still open.
pub fn check_row(row: &SessionRow, now: Seconds) -> Result<(), SignError> {
    check_field("session_id", valid_reference(&row.session_id))?;
    check_field("asset", valid_reference(&row.asset))?;
    check_field("ticket", valid_reference(&row.ticket))?;
    check_field("requester", valid_subject(&row.requester) && !row.requester.starts_with('-'))?;
    age_of(row.opened_at, now)
        .filter(|age| *age <= MAX_SIGN_DELAY_SECONDS)
        .ok_or(SignError::Stale)?;
    row.closed_at.is_none().then_some(()).ok_or(SignError::Closed)
}


pub fn open_request(scope: &TenantScope, row: &SessionRow) -> OpenRequest {
    OpenRequest {
        request_id: row.session_id.clone(),
        tenant: tenant_of(scope).to_owned(),
        requester: row.requester.clone(),
        asset: row.asset.clone(),
        ticket: row.ticket.clone(),
        created_at: row.opened_at,
    }
}


/// The decision is recomputed here from the row and the inputs; the caller never hands one over.
pub fn recompute(inputs: &SignInputs, request: &OpenRequest, now: Seconds) -> Result<(u64, u64, Vec<String>), SignError> {
    match decide_open(
        inputs.policy,
        inputs.catalog,
        request,
        inputs.requester_roles,
        inputs.criticality,
        inputs.evidence,
        now,
    ) {
        OpenDecision::Allowed {
            idle_timeout,
            max_duration,
            approved_by,
        } => Ok((idle_timeout, max_duration, approved_by)),
        OpenDecision::Refused(reason) => Err(SignError::Refused(reason)),
    }
}


/// A value above `u32::MAX` saturates, and `validate_action` then refuses it by its ceiling.
pub fn clamp_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}


pub fn open_shell_action(row: &SessionRow, plan: &SignPlan) -> Action {
    Action::OpenShell {
        session_id: row.session_id.clone(),
        asset: row.asset.clone(),
        ticket: row.ticket.clone(),
        requester: row.requester.clone(),
        approvers: plan.approvers.clone(),
        max_seconds: plan.max_seconds,
        idle_seconds: plan.idle_seconds,
    }
}


/// Every pure check, the recomputed decision, the mapping and `validate_action` on the action to sign; nothing is recorded yet.
pub fn plan_of(scope: &TenantScope, row: &SessionRow, inputs: &SignInputs, agents: &AgentMap, now: Seconds) -> Result<SignPlan, SignError> {
    (now >= 0).then_some(()).ok_or(SignError::Clock)?;
    check_row(row, now)?;
    let expires_at = now.checked_add(SIGN_LIFETIME_SECONDS).ok_or(SignError::Clock)?;
    let (idle_timeout, max_duration, approvers) = recompute(inputs, &open_request(scope, row), now)?;
    let identity = resolve_agent(agents, tenant_of(scope), &row.asset).ok_or(SignError::UnknownAsset)?;
    let plan = SignPlan {
        identity,
        approvers,
        max_seconds: clamp_u32(max_duration),
        idle_seconds: clamp_u32(idle_timeout),
        issued_at: now,
        expires_at,
    };
    validate_action(&open_shell_action(row, &plan))?;
    Ok(plan)
}


pub fn claim_params(row: &SessionRow, plan: &SignPlan, key_id: &str) -> Vec<Param> {
    vec![
        Param::Text(row.session_id.clone()),
        Param::Text(row.requester.clone()),
        Param::Text(row.asset.clone()),
        Param::Text(row.ticket.clone()),
        Param::Int(row.opened_at),
        Param::Text(plan.identity.agent_id.clone()),
        Param::Text(plan.approvers.join(APPROVER_SEPARATOR)),
        Param::Int(i64::from(plan.max_seconds)),
        Param::Int(i64::from(plan.idle_seconds)),
        Param::Int(plan.issued_at),
        Param::Int(plan.expires_at),
        Param::Text(key_id.to_owned()),
        Param::Int(i64::from(MAX_PENDING_SHELLS_PER_TENANT)),
    ]
}


/// Names why a claim returned no row, from one read made after the refusal and never written.
pub fn state_refusal(state: &Row, row: &SessionRow) -> Result<SignError, StoreError> {
    let closed_at = optional_int(state, COL_SIGN_CLOSED_AT, "closed_at")?;
    let opened_at = int_of(required(cell(state, COL_SIGN_OPENED_AT, "opened_at")?, "opened_at")?, "opened_at")?;
    let requester = text_of(required(cell(state, COL_SIGN_REQUESTER, "requester")?, "requester")?, "requester")?;
    let asset = text_of(required(cell(state, COL_SIGN_ASSET, "asset")?, "asset")?, "asset")?;
    let ticket = text_of(required(cell(state, COL_SIGN_TICKET, "ticket")?, "ticket")?, "ticket")?;
    let signed = cell(state, COL_SIGN_SIGNED, "signed")?;
    let pending = int_of(required(cell(state, COL_SIGN_PENDING, "pending")?, "pending")?, "pending")?;
    let same_row = opened_at == row.opened_at && requester == row.requester && asset == row.asset && ticket == row.ticket;
    Ok(if !same_row {
        SignError::RowMismatch
    } else if closed_at.is_some() {
        SignError::Closed
    } else if signed.is_some() {
        SignError::AlreadySigned
    } else if pending >= i64::from(MAX_PENDING_SHELLS_PER_TENANT) {
        SignError::TenantFull
    } else {
        SignError::Unclaimed
    })
}


pub async fn refusal_of_claim<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    row: &SessionRow,
    issued_at: Seconds,
) -> Result<SignError, SignError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let params = vec![Param::Text(row.session_id.clone()), Param::Int(issued_at)];
    let rows = run(exec, scope, SIGN_STATE_SQL, params).await?;
    match rows.first() {
        None => Ok(SignError::RowMismatch),
        Some(state) => Ok(state_refusal(state, row)?),
    }
}


/// Records the claim from the live open row in one statement; any refusal is named and nothing is signed.
pub async fn claim<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    row: &SessionRow,
    plan: &SignPlan,
    key_id: &str,
) -> Result<(), SignError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let rows = run(exec, scope, CLAIM_SQL, claim_params(row, plan, key_id)).await?;
    if rows.is_empty() {
        Err(refusal_of_claim(exec, scope, row, plan.issued_at).await?)
    } else {
        Ok(())
    }
}


/// Draws the nonce, takes the next sensitive sequence of the agent and signs; returns the envelope and the sequence it holds.
pub fn sign_envelope(row: &SessionRow, plan: &SignPlan, tenant: &str, signing: &mut Signing) -> Result<(Vec<u8>, u64), SignError> {
    let nonce = new_nonce(signing.fill).map_err(|error| SignError::Nonce(Box::new(error)))?;
    let sequence = (signing.next_sequence)(&plan.identity.agent_id, KeyClass::Sensitive).map_err(SignError::Sequence)?;
    let command = Command {
        key_id: signing.key_id.to_owned(),
        key_class: KeyClass::Sensitive,
        agent_id: plan.identity.agent_id.clone(),
        tenant: tenant.to_owned(),
        issued_at: plan.issued_at.unsigned_abs(),
        expires_at: plan.expires_at.unsigned_abs(),
        sequence,
        nonce,
        action: open_shell_action(row, plan),
    };
    Ok((sign_command(&command, signing.key_id, signing.signer)?, sequence))
}


pub async fn record_sequence<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, session_id: &str, sequence: u64) -> Result<(), SignError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let params = vec![Param::Text(session_id.to_owned()), Param::Int(to_i64("sequence", sequence)?)];
    let rows = run(exec, scope, SEQUENCE_SQL, params).await?;
    if rows.is_empty() {
        Err(SignError::SequenceRecord)
    } else {
        Ok(())
    }
}


/// Signs `OpenShell` for a register row; the order is fixed and each refusal is named.
pub async fn sign_open_shell<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    row: &SessionRow,
    inputs: &SignInputs<'_>,
    agents: &AgentMap,
    signing: &mut Signing<'_>,
    now: Seconds,
) -> Result<SignedShell, SignError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let plan = plan_of(scope, row, inputs, agents, now)?;
    claim(exec, scope, row, &plan, signing.key_id).await?;
    gate_add(
        signing.gate,
        tenant_of(scope),
        &plan.identity.agent_id,
        &row.session_id,
        plan.expires_at.unsigned_abs(),
        u64::from(plan.max_seconds),
    )?;
    let (envelope, sequence) = sign_envelope(row, &plan, tenant_of(scope), signing)?;
    record_sequence(exec, scope, &row.session_id, sequence).await?;
    Ok(SignedShell {
        identity: plan.identity,
        envelope,
    })
}
