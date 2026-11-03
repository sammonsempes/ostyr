use crate::breakers::{Breakers, MODULE};
use crate::error::BreakerError;
use crate::model::{limit_label, LimitName};
use crate::store::{persist, prune, Override};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use std::collections::BTreeMap;
use std::sync::PoisonError;
use time::OffsetDateTime;


pub const OVERRIDE_ACTION: &str = "breaker.override";


#[derive(Debug, Clone)]
pub struct OverrideGrant {
    pub admin: String,
    pub tenant: String,
    pub limit: LimitName,
    pub until: OffsetDateTime,
    pub justification: String,
    pub request_id: String,
}


pub fn grant_entry(grant: &OverrideGrant, now: OffsetDateTime) -> NewEntry {
    NewEntry {
        timestamp: now,
        actor: Actor {
            kind: ActorKind::User,
            id: grant.admin.clone(),
        },
        tenant: grant.tenant.clone(),
        module: MODULE.to_owned(),
        action: OVERRIDE_ACTION.to_owned(),
        target: limit_label(grant.limit).to_owned(),
        outcome: Outcome::Success,
        request_id: grant.request_id.clone(),
        justification: Some(grant.justification.clone()),
        parameters: BTreeMap::from([("until".to_owned(), grant.until.to_string())]),
    }
}


/// Audit first, then the durable write: an override that cannot be audited is never in force.
pub fn commit_override(breakers: &Breakers, grant: &OverrideGrant, now: OffsetDateTime) -> Result<(), BreakerError> {
    (breakers.audit)(grant_entry(grant, now))?;
    let mut state = breakers.store.state.lock().unwrap_or_else(PoisonError::into_inner);
    let mut next = prune(&state, now.unix_timestamp());
    next.overrides.push(Override {
        tenant: grant.tenant.clone(),
        limit: grant.limit,
        until: grant.until.unix_timestamp(),
    });
    persist(&breakers.store.path, &next, breakers.store.sync)?;
    *state = next;
    Ok(())
}


/// Lifts one limit of one tenant until `grant.until`; protected targets stay protected.
pub fn grant_override(breakers: &Breakers, grant: &OverrideGrant) -> Result<(), BreakerError> {
    let now = (breakers.clock)();
    if grant.until <= now {
        Err(BreakerError::AlreadyExpired)
    } else {
        commit_override(breakers, grant, now)
    }
}
