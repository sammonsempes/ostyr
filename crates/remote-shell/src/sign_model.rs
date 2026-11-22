use crate::open::Evidence;
use crate::policy::ValidatedPolicy;
use crate::types::{Seconds, SequenceFn};
use agent_channel::model::{Identity, ShellGate};
use agent_command::types::{FillFn, SignerFn};
use cmdb::model::Criticality;
use core_auth::types::{RoleCatalog, RoleSet};


/// What `decide_open` needs besides the row: the caller never hands over a decision, only these inputs.
pub struct SignInputs<'injected> {
    pub policy: &'injected ValidatedPolicy,
    pub catalog: &'injected RoleCatalog,
    pub requester_roles: &'injected RoleSet,
    pub criticality: Option<Criticality>,
    pub evidence: &'injected Evidence,
}


/// The injected ends of the signature: the `[open_shell]` signer, the shared sequence allocator, the nonce source and the shared gate.
pub struct Signing<'injected> {
    pub key_id: &'injected str,
    pub next_sequence: &'injected mut SequenceFn<'injected>,
    pub fill: FillFn,
    pub signer: &'injected SignerFn,
    pub gate: &'injected ShellGate,
}


/// What the recomputed `Allowed` and the mapping fix, before anything is recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignPlan {
    pub identity: Identity,
    pub approvers: Vec<String>,
    pub max_seconds: u32,
    pub idle_seconds: u32,
    pub issued_at: Seconds,
    pub expires_at: Seconds,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedShell {
    pub identity: Identity,
    pub envelope: Vec<u8>,
}
