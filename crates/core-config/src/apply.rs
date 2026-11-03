use crate::error::ApplyError;
use crate::plan::{action_name, plan, Change};
use crate::types::{ApplierFn, AuditFn, ConfigState, Plan, ReaderFn};
use core_audit::model::{Actor, NewEntry, Outcome};
use time::OffsetDateTime;


#[derive(Debug, Clone)]
pub struct ApplyContext {
    pub actor: Actor,
    pub tenant: String,
    pub module: String,
    pub request_id: String,
    pub justification: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    pub applied: Vec<String>,
}


pub fn audit_entry(context: &ApplyContext, change: &Change) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: context.actor.clone(),
        tenant: context.tenant.clone(),
        module: context.module.clone(),
        action: action_name(change.kind).to_owned(),
        target: change.key.clone(),
        outcome: Outcome::Success,
        request_id: context.request_id.clone(),
        justification: Some(context.justification.clone()),
        parameters: [("diff".to_owned(), change.diff.clone())].into(),
    }
}


pub fn compare_read_back(desired: &ConfigState, actual: &ConfigState, applied: Vec<String>) -> Result<ApplyReport, ApplyError> {
    let remaining: Vec<String> = plan(desired, actual).into_iter().map(|change| change.key).collect();
    if remaining.is_empty() {
        Ok(ApplyReport { applied })
    } else {
        Err(ApplyError::Mismatch { keys: remaining })
    }
}


/// Applies each change in order, stops at the first failure, audits every applied change, then reads the state back and compares it with `desired`.
pub fn apply(
    changes: &Plan,
    desired: &ConfigState,
    context: &ApplyContext,
    audit: &mut AuditFn,
    applier: &mut ApplierFn,
    reader: &mut ReaderFn,
) -> Result<ApplyReport, ApplyError> {
    let applied = changes.iter().try_fold(Vec::new(), |mut done: Vec<String>, change| {
        applier(change).map_err(|source| ApplyError::Applier {
            key: change.key.clone(),
            applied: done.clone(),
            source,
        })?;
        audit(audit_entry(context, change)).map_err(|source| ApplyError::Audit {
            applied: done.clone(),
            source,
        })?;
        done.push(change.key.clone());
        Ok::<_, ApplyError>(done)
    })?;
    let actual = reader().map_err(ApplyError::ReadBack)?;
    compare_read_back(desired, &actual, applied)
}
