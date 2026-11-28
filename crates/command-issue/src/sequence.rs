use crate::error::IssueError;
use core_pg::error::{reduce, PgError};
use core_pg::migrate::Migration;
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio_postgres::{Client, Row};
use tracing::warn;


pub const MIGRATION_NAMESPACE: &str = "command_issue";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "command_issue_0001",
    sql: include_str!("../migrations/command_issue_0001.sql"),
}];


/// Params: `$1` tenant, `$2` agent. The 64-bit key keeps two tenants from sharing a lock.
pub const LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(hashtextextended('command-issue/' || $1::text || '@' || $2::text, 0::bigint))";


/// Param: `$1` tenant. Taken after the agent lock, only when the agent has no row.
pub const TENANT_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(hashtextextended('command-issue-tenant/' || $1::text, 0::bigint))";


/// Params: `$1` tenant, `$2` agent.
pub const ROW_SQL: &str = "SELECT last, confirmed FROM agent_command_sequences WHERE tenant = $1 AND agent_id = $2 AND class = 'routine'";


/// Param: `$1` tenant. The plan is an index range on the primary key prefix (proved by `PREPARE`/`EXECUTE` before any ANALYZE).
pub const COUNT_SQL: &str = "SELECT count(*) FROM agent_command_sequences WHERE tenant = $1 AND class = 'routine'";


/// Params: `$1` tenant, `$2` agent, `$3` the highest queued sequence: `GREATEST` heals a crash after the rename.
pub const ALLOCATE_SQL: &str = "INSERT INTO agent_command_sequences (tenant, agent_id, class, last) VALUES ($1, $2, 'routine', $3::bigint + 1) \
    ON CONFLICT (tenant, agent_id, class) DO UPDATE SET last = GREATEST(agent_command_sequences.last, $3::bigint) + 1 RETURNING last";


/// What the row holds for one agent; an absent row is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowState {
    pub last: u64,
    pub confirmed: u64,
}


pub fn column_number(row: &Row, index: usize) -> Result<u64, IssueError> {
    let value = row.try_get::<usize, i64>(index).map_err(reduce)?;
    u64::try_from(value).map_err(|_negative| IssueError::Range)
}


pub async fn lock_agent(client: &Client, scope: &TenantScope, agent: &str, deadline: Duration) -> Result<(), PgError> {
    scoped_query(client, scope, LOCK_SQL, &[&agent], deadline).await.map(|_rows| ())
}


pub async fn lock_tenant(client: &Client, scope: &TenantScope, deadline: Duration) -> Result<(), PgError> {
    scoped_query(client, scope, TENANT_LOCK_SQL, &[], deadline).await.map(|_rows| ())
}


pub async fn read_row(client: &Client, scope: &TenantScope, agent: &str, deadline: Duration) -> Result<Option<RowState>, IssueError> {
    let rows = scoped_query(client, scope, ROW_SQL, &[&agent], deadline).await?;
    rows.first()
        .map(|row| {
            Ok(RowState {
                last: column_number(row, 0)?,
                confirmed: column_number(row, 1)?,
            })
        })
        .transpose()
}


pub async fn count_agents(client: &Client, scope: &TenantScope, deadline: Duration) -> Result<u64, IssueError> {
    let rows = scoped_query(client, scope, COUNT_SQL, &[], deadline).await?;
    rows.first().map_or(Ok(0), |row| column_number(row, 0))
}


/// Refuses when the tenant already holds `max_agents` agents; the refusals counter warns on the first and on each power of two.
pub fn check_agent_cap(tenant: &str, count: u64, max_agents: u64, refusals: &AtomicU64) -> Result<(), IssueError> {
    if count >= max_agents {
        let refused = refusals.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if refused.is_power_of_two() {
            warn!(tenant, count, refused, "tenant agent limit reached, a new agent id is refused");
        }
        Err(IssueError::AgentLimit)
    } else {
        Ok(())
    }
}


/// `base` is the larger of the row and the highest queued sequence, the same value the allocation starts from.
pub fn check_gap(base: u64, confirmed: u64, max_unconfirmed: u64) -> Result<(), IssueError> {
    if base.saturating_add(1).saturating_sub(confirmed) > max_unconfirmed {
        Err(IssueError::SequenceGap)
    } else {
        Ok(())
    }
}


pub async fn allocate(client: &Client, scope: &TenantScope, agent: &str, highest_queued: u64, deadline: Duration) -> Result<u64, IssueError> {
    let queued = i64::try_from(highest_queued).map_err(|_large| IssueError::Range)?;
    let rows = scoped_query(client, scope, ALLOCATE_SQL, &[&agent, &queued], deadline).await?;
    rows.first().ok_or(IssueError::Range).and_then(|row| column_number(row, 0))
}
