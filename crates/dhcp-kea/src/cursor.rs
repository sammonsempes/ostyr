//! The per-tenant position of the already-alerted lookup, kept in PostgreSQL so that it moves with the runs, not with a clock.

use alerts::types::Executor;
use core_pg::migrate::Migration;
use core_pg::scope::TenantScope;


pub const MIGRATION_NAMESPACE: &str = "dhcp_kea";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "001_dhcp_lookup_cursor",
    sql: include_str!("../migrations/001_dhcp_lookup_cursor.sql"),
}];


pub const READ_SQL: &str = "SELECT next_chunk::text FROM dhcp_lookup_cursor WHERE tenant = $1";


pub const WRITE_SQL: &str = "INSERT INTO dhcp_lookup_cursor (tenant, next_chunk, updated_at) VALUES ($1, $2::text::bigint, now()) \
                             ON CONFLICT (tenant) DO UPDATE SET next_chunk = EXCLUDED.next_chunk, updated_at = now() RETURNING next_chunk::text";


/// The stored chunk position of the tenant; 0 when there is no row, and 0 with one `warn!` when the read fails or the value is not a number.
pub async fn read_cursor(exec: Executor<'_, '_>, scope: &TenantScope) -> usize {
    let answer = exec(scope.clone(), READ_SQL, Vec::new()).await.map_err(|error| error.to_string());
    let parsed = answer.and_then(|rows| {
        rows.first()
            .and_then(|row| row.first())
            .map_or(Ok(0), |text| text.parse::<usize>().map_err(|error| error.to_string()))
    });
    match parsed {
        Ok(position) => position,
        Err(reason) => {
            tracing::warn!(reason, "dhcp lookup cursor unreadable, start at chunk 0");
            0
        }
    }
}


/// Stores the position; a failure is one `warn!` and the next run starts from the old position (progress may repeat, never skip).
pub async fn write_cursor(exec: Executor<'_, '_>, scope: &TenantScope, next_chunk: usize) {
    let written = exec(scope.clone(), WRITE_SQL, vec![next_chunk.to_string()]).await;
    if let Err(error) = written {
        let reason = error.to_string();
        tracing::warn!(reason, "dhcp lookup cursor not stored, the next run repeats");
    }
}
