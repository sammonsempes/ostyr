use crate::model::{Decision, Proposal, Verdict};
use crate::policy::LoadedPolicy;
use crate::rules::validate;
use core_audit::error::AuditError;
use core_audit::model::{Actor, NewEntry, Outcome};
use core_audit::types::ParameterMap;
use core_config::reload::{current_config, ReloadEngine};
use thiserror::Error;
use time::OffsetDateTime;


pub const VALIDATE_ACTION: &str = "policy.validate";


pub const AUDIT_MODULE: &str = "policy-validator";


#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub actor: Actor,
    pub tenant: String,
    pub request_id: String,
}


/// An error means the proposal is refused: no verdict leaves without its audit record.
#[derive(Debug, Error)]
pub enum ValidateError {
    #[error("cannot audit the verdict, the proposal is refused: {0}")]
    Audit(#[from] AuditError),
}


/// What was proposed, as enum names only: selector text may hold a secret (a command line) and never reaches the audit.
pub fn audit_parameters(proposal: &Proposal, verdict: &Verdict) -> ParameterMap {
    let reasons: Vec<String> = verdict.reasons.iter().map(ToString::to_string).collect();
    let subject = match proposal {
        Proposal::Exclusion(exclusion) => [
            ("engine", format!("{:?}", exclusion.engine)),
            ("scope", format!("{:?}", exclusion.scope)),
            ("selector_kind", format!("{:?}", exclusion.selector.kind)),
        ]
        .to_vec(),
        Proposal::AsrChange(change) => vec![("new_state", format!("{:?}", change.new_state))],
    };
    [
        ("decision", format!("{:?}", verdict.decision)),
        ("reasons", reasons.join("; ")),
        ("version", verdict.version.clone()),
    ]
    .into_iter()
    .chain(subject)
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn audit_entry(context: &ValidationContext, proposal: &Proposal, verdict: &Verdict) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: context.actor.clone(),
        tenant: context.tenant.clone(),
        module: AUDIT_MODULE.to_owned(),
        action: VALIDATE_ACTION.to_owned(),
        target: match proposal {
            Proposal::Exclusion(_) => "exclusion".to_owned(),
            Proposal::AsrChange(_) => "asr_change".to_owned(),
        },
        outcome: if verdict.decision == Decision::Accepted {
            Outcome::Success
        } else {
            Outcome::Denied
        },
        request_id: context.request_id.clone(),
        justification: None,
        parameters: audit_parameters(proposal, verdict),
    }
}


/// Validates against one configuration snapshot and audits the verdict through the engine's audit sink (fail closed).
pub fn validate_audited(engine: &ReloadEngine<LoadedPolicy>, context: &ValidationContext, proposal: &Proposal) -> Result<Verdict, ValidateError> {
    let snapshot = current_config(engine);
    let verdict = validate(&snapshot, proposal);
    (engine.audit)(audit_entry(context, proposal, &verdict))?;
    Ok(verdict)
}
