use crate::bounds::validate_graph;
use crate::choke::{choke_points, recommendations};
use crate::error::StoreError;
use crate::model::{ChokePoint, Graph, Path, PathSet, Recommendation, Unsearched};
use crate::types::{Executor, Row};
use core_pg::migrate::Migration;
use core_pg::scope::tenant_scope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset};


pub const MIGRATION_NAMESPACE: &str = "attack_paths";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "attack_paths_0001",
    sql: include_str!("../migrations/attack_paths_0001.sql"),
}];


/// Largest stored report body, in bytes of the JSON document; a larger one is refused, never cut.
pub const MAX_REPORT_BYTES: usize = 1_048_576;


/// Reports of one tenant; a store that would pass it is refused and nothing is deleted.
pub const MAX_REPORTS_PER_TENANT: i64 = 1_000;


/// Largest page of `list_reports`.
pub const MAX_LIST_LIMIT: usize = 100;


/// Quotes and a comma around one node id in the JSON document: a lower bound of what a node costs.
pub const NODE_JSON_OVERHEAD: usize = 3;


/// The first and last year of a UTC time that PostgreSQL holds and RFC 3339 writes back.
pub const MIN_YEAR: i32 = 1;


pub const MAX_YEAR: i32 = 9999;


pub const OUTCOME_STORED: &str = "stored";


pub const OUTCOME_ALREADY: &str = "already_stored";


pub const OUTCOME_REFUSED: &str = "refused";


/// Params: `$2` graph digest, `$3` generated (UTC RFC 3339), `$4` digest, `$5` body, `$6` truncated, `$7` budget reached, `$8` unsearched, `$9` cap.
pub const STORE_SQL: &str = "SELECT outcome, report_id FROM attack_path_report_store($1, $2, $3, $4, $5, $6::text::boolean, $7::text::boolean, \
$8::text::bigint, $9::text::bigint)";


/// Params: `$2` limit.
pub const LIST_SQL: &str = "SELECT id::text, graph_digest, to_char(generated AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), digest, \
octet_length(body)::text, truncated::text, budget_reached::text, unsearched_count::text, extract(epoch from stored_at)::bigint::text \
FROM attack_path_report WHERE tenant = $1 ORDER BY attack_path_report.id DESC LIMIT $2::text::bigint";


/// Params: `$2` id.
pub const GET_SQL: &str = "SELECT graph_digest, to_char(generated AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), digest, truncated::text, \
budget_reached::text, unsearched_count::text, body FROM attack_path_report WHERE tenant = $1 AND id = $2::text::bigint";


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOutcome {
    Stored { id: i64 },
    AlreadyStored { id: i64 },
}


/// The stored JSON document. The incompleteness fields are never skipped: a stored report says when its search was cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportBody {
    pub graph_digest: String,
    pub truncated: bool,
    pub budget_reached: bool,
    pub unsearched: Vec<Unsearched>,
    pub paths: Vec<Path>,
    pub choke_points: Vec<ChokePoint>,
    pub recommendations: Vec<Recommendation>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportMeta {
    pub id: i64,
    pub graph_digest: String,
    pub generated: String,
    pub digest: String,
    pub bytes: u64,
    pub truncated: bool,
    pub budget_reached: bool,
    pub unsearched_count: u64,
    pub stored_epoch: i64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReport {
    pub id: i64,
    pub generated: String,
    pub digest: String,
    pub body: String,
    pub report: ReportBody,
}


/// SHA-256 of the graph as serialised by serde (struct fields in order, so the same graph always gives the same digest).
pub fn graph_digest(graph: &Graph) -> Result<String, StoreError> {
    let text = serde_json::to_string(graph).map_err(StoreError::Render)?;
    Ok(digest_hex(&text))
}


pub fn digest_hex(body: &str) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}


/// The UTC second written as RFC 3339; a time whose UTC date leaves years 1 to 9999 is refused (`to_offset` would panic on it).
pub fn generated_text(generated: OffsetDateTime) -> Result<String, StoreError> {
    let utc = generated
        .checked_to_offset(UtcOffset::UTC)
        .filter(|moment| (MIN_YEAR..=MAX_YEAR).contains(&moment.year()))
        .ok_or(StoreError::BadGenerated)?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    ))
}


/// What the paths alone cost in the document, computed before anything is serialised.
pub fn paths_lower_bound(found: &PathSet) -> usize {
    found
        .paths
        .iter()
        .flat_map(|path| path.nodes.iter())
        .map(|node| node.len() + NODE_JSON_OVERHEAD)
        .sum()
}


pub fn build_body(graph_digest: String, found: &PathSet) -> ReportBody {
    ReportBody {
        graph_digest,
        truncated: found.truncated,
        budget_reached: found.budget_reached,
        unsearched: found.unsearched.clone(),
        paths: found.paths.clone(),
        choke_points: choke_points(&found.paths),
        recommendations: recommendations(&found.paths),
    }
}


pub fn render_body(report: &ReportBody) -> Result<String, StoreError> {
    serde_json::to_string(report).map_err(StoreError::Render)
}


fn number<Parsed: std::str::FromStr>(text: &str) -> Result<Parsed, StoreError> {
    text.parse().map_err(|_error| StoreError::BadRow)
}


pub fn decode_store_row(rows: &[Row], cap: i64) -> Result<StoreOutcome, StoreError> {
    let cells = match rows {
        [row] => row.as_slice(),
        _ => &[],
    };
    match cells {
        [outcome, id] if outcome == OUTCOME_STORED => Ok(StoreOutcome::Stored { id: number(id)? }),
        [outcome, id] if outcome == OUTCOME_ALREADY => Ok(StoreOutcome::AlreadyStored { id: number(id)? }),
        [outcome, _id] if outcome == OUTCOME_REFUSED => Err(StoreError::CapReached { max: cap }),
        _ => Err(StoreError::BadRow),
    }
}


/// `store_report` with an explicit cap (the example lowers it for the live proof); a cap above `MAX_REPORTS_PER_TENANT` is lowered to it; every refusal happens before the executor is called.
pub async fn store_report_with_cap(
    exec: Executor<'_, '_>,
    tenant: &str,
    graph: &Graph,
    found: &PathSet,
    generated: OffsetDateTime,
    cap: i64,
) -> Result<StoreOutcome, StoreError> {
    let scope = tenant_scope(tenant)?;
    validate_graph(graph)?;
    let moment = generated_text(generated)?;
    let lower = paths_lower_bound(found);
    (lower <= MAX_REPORT_BYTES).then_some(()).ok_or(StoreError::TooLarge {
        bytes: lower,
        max: MAX_REPORT_BYTES,
    })?;
    let input_digest = graph_digest(graph)?;
    let body = render_body(&build_body(input_digest.clone(), found))?;
    (body.len() <= MAX_REPORT_BYTES).then_some(()).ok_or(StoreError::TooLarge {
        bytes: body.len(),
        max: MAX_REPORT_BYTES,
    })?;
    let effective = cap.min(MAX_REPORTS_PER_TENANT);
    let params = vec![
        input_digest,
        moment,
        digest_hex(&body),
        body,
        found.truncated.to_string(),
        found.budget_reached.to_string(),
        found.unsearched.len().to_string(),
        effective.to_string(),
    ];
    let rows = exec(scope, STORE_SQL, params).await.map_err(StoreError::Store)?;
    decode_store_row(&rows, effective)
}


/// Stores one report for the tenant; the same graph and result stored twice answer `AlreadyStored`.
pub async fn store_report(
    exec: Executor<'_, '_>,
    tenant: &str,
    graph: &Graph,
    found: &PathSet,
    generated: OffsetDateTime,
) -> Result<StoreOutcome, StoreError> {
    store_report_with_cap(exec, tenant, graph, found, generated, MAX_REPORTS_PER_TENANT).await
}


pub fn decode_meta(row: &Row) -> Result<ReportMeta, StoreError> {
    match row.as_slice() {
        [id, graph, generated, digest, bytes, truncated, budget, unsearched, stored] => Ok(ReportMeta {
            id: number(id)?,
            graph_digest: graph.clone(),
            generated: generated.clone(),
            digest: digest.clone(),
            bytes: number(bytes)?,
            truncated: number(truncated)?,
            budget_reached: number(budget)?,
            unsearched_count: number(unsearched)?,
            stored_epoch: number(stored)?,
        }),
        _ => Err(StoreError::BadRow),
    }
}


/// Newest first, metadata and the three incompleteness fields only, at most `limit` (1 to `MAX_LIST_LIMIT`) rows.
pub async fn list_reports(exec: Executor<'_, '_>, tenant: &str, limit: usize) -> Result<Vec<ReportMeta>, StoreError> {
    let scope = tenant_scope(tenant)?;
    (1..=MAX_LIST_LIMIT)
        .contains(&limit)
        .then_some(())
        .ok_or(StoreError::BadLimit { max: MAX_LIST_LIMIT })?;
    let rows = exec(scope, LIST_SQL, vec![limit.to_string()]).await.map_err(StoreError::Store)?;
    (rows.len() <= limit).then_some(()).ok_or(StoreError::BadRow)?;
    rows.iter().map(decode_meta).collect()
}


pub fn decode_stored(id: i64, row: &Row) -> Result<StoredReport, StoreError> {
    match row.as_slice() {
        [graph, generated, digest, truncated, budget, unsearched, body] => {
            (digest_hex(body) == *digest).then_some(()).ok_or(StoreError::DigestMismatch)?;
            let report: ReportBody = serde_json::from_str(body).map_err(|_error| StoreError::BadBody)?;
            let columns: (&str, bool, bool, usize) = (graph, number(truncated)?, number(budget)?, number(unsearched)?);
            let document = (
                report.graph_digest.as_str(),
                report.truncated,
                report.budget_reached,
                report.unsearched.len(),
            );
            (columns == document).then_some(()).ok_or(StoreError::MetadataMismatch)?;
            Ok(StoredReport {
                id,
                generated: generated.clone(),
                digest: digest.clone(),
                body: body.clone(),
                report,
            })
        }
        _ => Err(StoreError::BadRow),
    }
}


/// One report of the tenant by id; the body is digested again, parsed, and its incompleteness fields must equal the columns. Another tenant's id is `None`.
pub async fn get_report(exec: Executor<'_, '_>, tenant: &str, id: i64) -> Result<Option<StoredReport>, StoreError> {
    let scope = tenant_scope(tenant)?;
    let rows = exec(scope, GET_SQL, vec![id.to_string()]).await.map_err(StoreError::Store)?;
    match rows.as_slice() {
        [] => Ok(None),
        [row] => decode_stored(id, row).map(Some),
        _ => Err(StoreError::BadRow),
    }
}
