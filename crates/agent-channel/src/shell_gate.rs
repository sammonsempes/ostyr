use crate::model::{
    ActiveShell, GateError, GateTable, Identity, PendingShell, ShellGate, ShellTake, MAX_SHELL_SESSIONS, MAX_SHELL_SESSIONS_PER_TENANT,
};
use crate::types::ClockFn;
use agent_command::action::valid_session_id;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};


pub fn new_gate(clock: Box<ClockFn>) -> Arc<ShellGate> {
    Arc::new(ShellGate {
        table: Mutex::new(GateTable::default()),
        clock,
    })
}


/// No code holding the lock can panic, so a poisoned lock still guards consistent data.
pub fn lock_gate(gate: &ShellGate) -> MutexGuard<'_, GateTable> {
    gate.table.lock().unwrap_or_else(PoisonError::into_inner)
}


/// Drops every pending session whose start deadline has passed.
pub fn prune(table: &mut GateTable, now: u64) {
    table.pending.retain(|_key, entry| entry.start_deadline >= now);
}


/// Pending and running sessions of one tenant.
pub fn tenant_sessions(table: &GateTable, tenant: &str) -> usize {
    let pending = table.pending.keys().filter(|(owner, _session)| owner.tenant == tenant).count();
    pending.saturating_add(table.active_by_tenant.get(tenant).copied().unwrap_or(0))
}


/// Approves one session for one agent; refused when the gate or the tenant is full, the id is not valid or the session is already pending.
pub fn gate_add(gate: &ShellGate, tenant: &str, agent_id: &str, session_id: &str, start_deadline: u64, max_seconds: u64) -> Result<(), GateError> {
    let now = (gate.clock)();
    let key = (
        Identity {
            tenant: tenant.to_owned(),
            agent_id: agent_id.to_owned(),
        },
        session_id.to_owned(),
    );
    let mut table = lock_gate(gate);
    prune(&mut table, now);
    if !valid_session_id(session_id) {
        Err(GateError::InvalidSessionId)
    } else if table.pending.len().saturating_add(table.active) >= MAX_SHELL_SESSIONS {
        Err(GateError::Full)
    } else if tenant_sessions(&table, tenant) >= MAX_SHELL_SESSIONS_PER_TENANT {
        Err(GateError::TenantFull)
    } else {
        match table.pending.entry(key) {
            Entry::Occupied(_taken) => Err(GateError::Duplicate),
            Entry::Vacant(slot) => {
                slot.insert(PendingShell { start_deadline, max_seconds });
                Ok(())
            }
        }
    }
}


/// Whether the agent has any session still allowed to start.
pub fn gate_has_pending(gate: &ShellGate, identity: &Identity) -> bool {
    let now = (gate.clock)();
    lock_gate(gate)
        .pending
        .iter()
        .any(|((owner, _session), entry)| owner == identity && entry.start_deadline >= now)
}


/// Removes the session of this exact identity in one step, under one lock; a second call finds nothing.
pub fn gate_take(gate: &Arc<ShellGate>, identity: &Identity, session_id: &str) -> Option<ShellTake> {
    let now = (gate.clock)();
    let mut table = lock_gate(gate);
    prune(&mut table, now);
    let entry = table.pending.remove(&(identity.clone(), session_id.to_owned()))?;
    table.active = table.active.saturating_add(1);
    let running = table.active_by_tenant.entry(identity.tenant.clone()).or_insert(0);
    *running = running.saturating_add(1);
    Some(ShellTake {
        max_seconds: entry.max_seconds,
        active: ActiveShell {
            gate: Arc::clone(gate),
            tenant: identity.tenant.clone(),
        },
    })
}


impl Drop for ActiveShell {
    fn drop(&mut self) {
        let mut table = lock_gate(&self.gate);
        table.active = table.active.saturating_sub(1);
        let remaining = table.active_by_tenant.get(&self.tenant).copied().unwrap_or(0).saturating_sub(1);
        if remaining == 0 {
            table.active_by_tenant.remove(&self.tenant);
        } else {
            table.active_by_tenant.insert(self.tenant.clone(), remaining);
        }
    }
}
