use crate::grammar::{valid_reference, valid_subject};
use crate::policy::ShellPolicy;
use crate::types::{ApproverRoles, Seconds};
use cmdb::model::Criticality;
use core_auth::rbac::is_allowed;
use core_auth::types::{RoleCatalog, RoleSet};
use core_pg::scope::tenant_scope;
use serde::Deserialize;
use thiserror::Error;


pub const PERMISSION_REMOTE_SHELL_OPEN: &str = "remote_shell.open";


pub const PERMISSION_REMOTE_SHELL_APPROVE: &str = "remote_shell.approve";


pub const MAX_APPROVALS: usize = 16;


pub const MAX_CLOCK_SKEW_SECONDS: i64 = 5;


pub const UNKNOWN_ASSET_CRITICALITY: Criticality = Criticality::Critical;


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenRequest {
    pub request_id: String,
    pub tenant: String,
    pub requester: String,
    pub asset: String,
    pub ticket: String,
    pub created_at: Seconds,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MfaProof {
    pub request_id: String,
    pub verified_at: Seconds,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub request_id: String,
    pub tenant: String,
    pub approver: String,
    pub approved_at: Seconds,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub mfa: Option<MfaProof>,
    pub approvals: Vec<Approval>,
    pub approver_roles: ApproverRoles,
}


/// The reason names are the audit values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenRefusal {
    #[error("tenant")]
    Tenant,
    #[error("requester")]
    Requester,
    #[error("request_id")]
    RequestId,
    #[error("role")]
    Role,
    #[error("ticket")]
    Ticket,
    #[error("mfa_missing")]
    MfaMissing,
    #[error("mfa_other_request")]
    MfaOtherRequest,
    #[error("mfa_not_fresh")]
    MfaNotFresh,
    #[error("mfa_expired")]
    MfaExpired,
    #[error("too_many_approvals")]
    TooManyApprovals,
    #[error("approval_required")]
    ApprovalRequired,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenDecision {
    Allowed {
        idle_timeout: u64,
        max_duration: u64,
        approved_by: Vec<String>,
    },
    Refused(OpenRefusal),
}


/// Age of `then` at `now` in seconds: `None` when `then` is later than `now` plus `MAX_CLOCK_SKEW_SECONDS` or the arithmetic overflows.
pub fn age_of(then: Seconds, now: Seconds) -> Option<u64> {
    let latest = now.checked_add(MAX_CLOCK_SKEW_SECONDS)?;
    (then <= latest).then_some(())?;
    now.checked_sub(then).map(|age| age.max(0).unsigned_abs())
}


pub fn check_identity(request: &OpenRequest) -> Result<(), OpenRefusal> {
    tenant_scope(&request.tenant).map(|_| ()).map_err(|_| OpenRefusal::Tenant)?;
    valid_subject(&request.requester).then_some(()).ok_or(OpenRefusal::Requester)?;
    valid_reference(&request.request_id).then_some(()).ok_or(OpenRefusal::RequestId)
}


pub fn check_role(catalog: &RoleCatalog, roles: &RoleSet) -> Result<(), OpenRefusal> {
    is_allowed(catalog, roles, PERMISSION_REMOTE_SHELL_OPEN)
        .then_some(())
        .ok_or(OpenRefusal::Role)
}


pub fn check_mfa(policy: &ShellPolicy, request: &OpenRequest, mfa: Option<&MfaProof>, now: Seconds) -> Result<(), OpenRefusal> {
    let proof = mfa.ok_or(OpenRefusal::MfaMissing)?;
    (proof.request_id == request.request_id)
        .then_some(())
        .ok_or(OpenRefusal::MfaOtherRequest)?;
    let age = age_of(proof.verified_at, now)
        .filter(|_| proof.verified_at >= request.created_at)
        .ok_or(OpenRefusal::MfaNotFresh)?;
    (age <= policy.mfa_max_age_seconds).then_some(()).ok_or(OpenRefusal::MfaExpired)
}


pub fn approval_valid(
    policy: &ShellPolicy,
    catalog: &RoleCatalog,
    request: &OpenRequest,
    evidence: &Evidence,
    approval: &Approval,
    now: Seconds,
) -> bool {
    let holds_role = evidence
        .approver_roles
        .get(&approval.approver)
        .is_some_and(|roles| is_allowed(catalog, roles, PERMISSION_REMOTE_SHELL_APPROVE));
    let fresh = age_of(approval.approved_at, now).is_some_and(|age| age <= policy.approval_max_age_seconds);
    [
        approval.request_id == request.request_id,
        approval.tenant == request.tenant,
        valid_subject(&approval.approver),
        approval.approver != request.requester,
        holds_role,
        fresh,
    ]
    .into_iter()
    .all(|passed| passed)
}


/// The cap is checked first, before any approval is read, and whatever the criticality; one valid approval is the second person.
pub fn check_approvals(
    policy: &ShellPolicy,
    catalog: &RoleCatalog,
    request: &OpenRequest,
    criticality: Option<Criticality>,
    evidence: &Evidence,
    now: Seconds,
) -> Result<Vec<String>, OpenRefusal> {
    (evidence.approvals.len() <= MAX_APPROVALS)
        .then_some(())
        .ok_or(OpenRefusal::TooManyApprovals)?;
    match criticality.unwrap_or(UNKNOWN_ASSET_CRITICALITY) >= policy.dual_approval_from {
        true => evidence
            .approvals
            .iter()
            .find(|approval| approval_valid(policy, catalog, request, evidence, approval, now))
            .map(|approval| vec![approval.approver.clone()])
            .ok_or(OpenRefusal::ApprovalRequired),
        false => Ok(Vec::new()),
    }
}


/// Checks run in this order and the first failure is the one reason: tenant, requester, request id, role, ticket, MFA, approval.
pub fn check_open(
    policy: &ShellPolicy,
    catalog: &RoleCatalog,
    request: &OpenRequest,
    requester_roles: &RoleSet,
    asset_criticality: Option<Criticality>,
    evidence: &Evidence,
    now: Seconds,
) -> Result<Vec<String>, OpenRefusal> {
    check_identity(request)?;
    check_role(catalog, requester_roles)?;
    valid_reference(&request.ticket).then_some(()).ok_or(OpenRefusal::Ticket)?;
    check_mfa(policy, request, evidence.mfa.as_ref(), now)?;
    check_approvals(policy, catalog, request, asset_criticality, evidence, now)
}


pub fn decide_open(
    policy: &ShellPolicy,
    catalog: &RoleCatalog,
    request: &OpenRequest,
    requester_roles: &RoleSet,
    asset_criticality: Option<Criticality>,
    evidence: &Evidence,
    now: Seconds,
) -> OpenDecision {
    match check_open(policy, catalog, request, requester_roles, asset_criticality, evidence, now) {
        Ok(approved_by) => OpenDecision::Allowed {
            idle_timeout: policy.idle_timeout_seconds,
            max_duration: policy.max_duration_seconds,
            approved_by,
        },
        Err(refusal) => OpenDecision::Refused(refusal),
    }
}
