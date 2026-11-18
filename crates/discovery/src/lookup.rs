//! The already-alerted lookup: which devices of a run have no stored alert yet, a bounded number of chunks per run from a per-tenant cursor.

use crate::cursor::read_cursor;
use crate::model::{Lookup, LOOKUP_CHUNK, MAX_LOOKUP_CHUNKS, MAX_UNMANAGED_PER_RUN};
use alerts::types::Executor;
use core_pg::scope::TenantScope;
use serde_json::json;
use std::collections::BTreeSet;
use tracing::warn;


pub const ALERTED_SQL: &str = "SELECT id FROM alerts WHERE tenant = $1 AND rule_id = 'discovery.unmanaged_device' \
                               AND id = ANY(ARRAY(SELECT jsonb_array_elements_text($2::text::jsonb)))";


/// The ids of the chunk already holding a stored alert of the tenant (one query); the error text when the query fails.
pub async fn alerted_ids(exec: Executor<'_, '_>, scope: &TenantScope, ids: &[String]) -> Result<BTreeSet<String>, String> {
    let document = json!(ids).to_string();
    let rows = exec(scope.clone(), ALERTED_SQL, vec![document])
        .await
        .map_err(|error| error.to_string())?;
    Ok(rows.into_iter().filter_map(|row| row.into_iter().next()).collect())
}


/// The chunk to store after a run that scanned `scanned` chunks from `start`: the last one again when it held more fresh ids than the run alerts, else the one after it.
pub fn next_chunk_of(start: usize, scanned: usize, chunk_count: usize, fresh: usize) -> usize {
    let stay = usize::from(fresh > MAX_UNMANAGED_PER_RUN);
    (start + scanned - stay) % chunk_count.max(1)
}


/// The ids to alert: at most `MAX_LOOKUP_CHUNKS` chunk lookups from the tenant's cursor, wrapping around, until a run's worth of fresh ids is seen; a failed query makes the run alert nothing.
pub async fn scan(exec: Executor<'_, '_>, scope: &TenantScope, ids: &[String]) -> Lookup {
    let chunks: Vec<&[String]> = ids.chunks(LOOKUP_CHUNK).collect();
    let chunk_count = chunks.len();
    let start = read_cursor(exec, scope).await % chunk_count.max(1);
    let order: Vec<&[String]> = chunks
        .iter()
        .cycle()
        .skip(start)
        .take(chunk_count.min(MAX_LOOKUP_CHUNKS))
        .copied()
        .collect();
    let mut fresh: Vec<String> = Vec::new();
    let mut scanned = 0;
    let mut failure: Option<String> = None;
    while let Some(chunk) = order
        .get(scanned)
        .filter(|_chunk| failure.is_none() && fresh.len() < MAX_UNMANAGED_PER_RUN)
    {
        match alerted_ids(exec, scope, chunk).await {
            Ok(found) => {
                fresh.extend(chunk.iter().filter(|id| !found.contains(*id)).cloned());
                scanned += 1;
            }
            Err(reason) => failure = Some(reason),
        }
    }
    if let Some(reason) = failure {
        warn!(reason, "discovery already-alerted lookup failed, run alerts nothing");
        Lookup {
            fresh: Vec::new(),
            next_chunk: start,
            failed: true,
            deferred: 0,
        }
    } else {
        let next_chunk = next_chunk_of(start, scanned, chunk_count, fresh.len());
        let scanned_ids: usize = order.iter().take(scanned).map(|chunk| chunk.len()).sum();
        let deferred = ids.len().saturating_sub(scanned_ids);
        if deferred > 0 && fresh.len() < MAX_UNMANAGED_PER_RUN {
            warn!(deferred, scanned, "discovery lookup cap reached");
        }
        Lookup {
            fresh,
            next_chunk,
            failed: false,
            deferred,
        }
    }
}
