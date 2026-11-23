use crate::error::StoreError;
use crate::export::to_json;
use crate::report::ComplianceReport;
use crate::types::{Executor, Row};
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_of, tenant_scope};
use sha2::{Digest, Sha256};


pub const MIGRATION_NAMESPACE: &str = "grc";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "grc_0001",
    sql: include_str!("../migrations/grc_0001.sql"),
}];


/// Largest stored report body, in bytes of `to_json`; a larger one is refused, never cut.
pub const MAX_REPORT_BYTES: usize = 1_048_576;


/// Reports of one tenant; a store that would pass it is refused and nothing is deleted.
pub const MAX_REPORTS_PER_TENANT: i64 = 1_000;


/// Largest page of `list_reports`.
pub const MAX_LIST_LIMIT: usize = 100;


/// Framework names are identifiers of at most 64 characters; the table allows 256 bytes.
pub const MAX_FRAMEWORK_BYTES: usize = 256;


pub const OUTCOME_STORED: &str = "stored";


pub const OUTCOME_ALREADY: &str = "already_stored";


pub const OUTCOME_REFUSED: &str = "refused";


/// Params: `$2` framework, `$3` version, `$4` generated date, `$5` digest, `$6` body, `$7` cap.
pub const STORE_SQL: &str = "SELECT outcome, report_id FROM grc_report_store($1, $2, $3::text::bigint, $4, $5, $6, $7::text::bigint)";


/// Params: `$2` limit.
pub const LIST_SQL: &str = "SELECT id::text, framework, framework_version::text, generated::text, digest, octet_length(body)::text, \
extract(epoch from stored_at)::bigint::text FROM grc_report WHERE tenant = $1 ORDER BY grc_report.id DESC LIMIT $2::text::bigint";


/// Params: `$2` framework, `$3` limit.
pub const LIST_FRAMEWORK_SQL: &str = "SELECT id::text, framework, framework_version::text, generated::text, digest, octet_length(body)::text, \
extract(epoch from stored_at)::bigint::text FROM grc_report WHERE tenant = $1 AND framework = $2 ORDER BY grc_report.id DESC LIMIT $3::text::bigint";


/// Params: `$2` id.
pub const GET_SQL: &str = "SELECT framework, framework_version::text, generated::text, digest, body FROM grc_report \
WHERE tenant = $1 AND id = $2::text::bigint";


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOutcome {
    Stored { id: i64 },
    AlreadyStored { id: i64 },
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportMeta {
    pub id: i64,
    pub framework: String,
    pub version: u32,
    pub generated: String,
    pub digest: String,
    pub bytes: u64,
    pub stored_epoch: i64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReport {
    pub id: i64,
    pub framework: String,
    pub version: u32,
    pub generated: String,
    pub digest: String,
    pub body: String,
}


pub fn render_body(report: &ComplianceReport) -> Result<String, StoreError> {
    let mut bytes = Vec::new();
    to_json(report, &mut bytes).map_err(StoreError::Render)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}


pub fn digest_hex(body: &str) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
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


/// `store_report` with an explicit cap (the example lowers it for the live proof); a cap above `MAX_REPORTS_PER_TENANT` is lowered to it.
pub async fn store_report_with_cap(exec: Executor<'_, '_>, tenant: &str, report: &ComplianceReport, cap: i64) -> Result<StoreOutcome, StoreError> {
    let scope = tenant_scope(tenant)?;
    (tenant_of(&scope) == report.tenant).then_some(()).ok_or(StoreError::TenantMismatch)?;
    (report.framework.len() <= MAX_FRAMEWORK_BYTES)
        .then_some(())
        .ok_or(StoreError::FrameworkTooLong {
            bytes: report.framework.len(),
            max: MAX_FRAMEWORK_BYTES,
        })?;
    let body = render_body(report)?;
    (body.len() <= MAX_REPORT_BYTES).then_some(()).ok_or(StoreError::TooLarge {
        bytes: body.len(),
        max: MAX_REPORT_BYTES,
    })?;
    let effective = cap.min(MAX_REPORTS_PER_TENANT);
    let params = vec![
        report.framework.clone(),
        report.version.to_string(),
        report.generated.clone(),
        digest_hex(&body),
        body,
        effective.to_string(),
    ];
    let rows = exec(scope, STORE_SQL, params).await.map_err(StoreError::Store)?;
    decode_store_row(&rows, effective)
}


/// Stores one report for the tenant; the same inputs stored twice answer `AlreadyStored`.
pub async fn store_report(exec: Executor<'_, '_>, tenant: &str, report: &ComplianceReport) -> Result<StoreOutcome, StoreError> {
    store_report_with_cap(exec, tenant, report, MAX_REPORTS_PER_TENANT).await
}


pub fn decode_meta(row: &Row) -> Result<ReportMeta, StoreError> {
    match row.as_slice() {
        [id, framework, version, generated, digest, bytes, stored] => Ok(ReportMeta {
            id: number(id)?,
            framework: framework.clone(),
            version: number(version)?,
            generated: generated.clone(),
            digest: digest.clone(),
            bytes: number(bytes)?,
            stored_epoch: number(stored)?,
        }),
        _ => Err(StoreError::BadRow),
    }
}


/// Newest first, metadata only, at most `limit` (1 to `MAX_LIST_LIMIT`) rows, of one framework when given.
pub async fn list_reports(exec: Executor<'_, '_>, tenant: &str, framework: Option<&str>, limit: usize) -> Result<Vec<ReportMeta>, StoreError> {
    let scope = tenant_scope(tenant)?;
    (1..=MAX_LIST_LIMIT)
        .contains(&limit)
        .then_some(())
        .ok_or(StoreError::BadLimit { max: MAX_LIST_LIMIT })?;
    let (sql, params) = match framework {
        Some(name) => (LIST_FRAMEWORK_SQL, vec![name.to_owned(), limit.to_string()]),
        None => (LIST_SQL, vec![limit.to_string()]),
    };
    let rows = exec(scope, sql, params).await.map_err(StoreError::Store)?;
    (rows.len() <= limit).then_some(()).ok_or(StoreError::BadRow)?;
    rows.iter().map(decode_meta).collect()
}


pub fn decode_stored(id: i64, row: &Row) -> Result<StoredReport, StoreError> {
    match row.as_slice() {
        [framework, version, generated, digest, body] => {
            (digest_hex(body) == *digest).then_some(()).ok_or(StoreError::DigestMismatch)?;
            Ok(StoredReport {
                id,
                framework: framework.clone(),
                version: number(version)?,
                generated: generated.clone(),
                digest: digest.clone(),
                body: body.clone(),
            })
        }
        _ => Err(StoreError::BadRow),
    }
}


/// One report of the tenant by id; the body is digested again and a mismatch is `DigestMismatch`. Another tenant's id is `None`.
pub async fn get_report(exec: Executor<'_, '_>, tenant: &str, id: i64) -> Result<Option<StoredReport>, StoreError> {
    let scope = tenant_scope(tenant)?;
    let rows = exec(scope, GET_SQL, vec![id.to_string()]).await.map_err(StoreError::Store)?;
    match rows.as_slice() {
        [] => Ok(None),
        [row] => decode_stored(id, row).map(Some),
        _ => Err(StoreError::BadRow),
    }
}
