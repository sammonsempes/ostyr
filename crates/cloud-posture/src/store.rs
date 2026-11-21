//! Per-tenant findings store: one run of one account replaces that account's findings (spec section 23).

use crate::error::StoreError;
use crate::model::{Admitted, Finding, Findings, RunOutcome, Skipped, Status};
use crate::prowler::identity_of;
use crate::text::{
    severity_rank, severity_text, status_text, valid_provider, valid_reference, valid_spaced_reference, MAX_ACCOUNT_BYTES, MAX_CHECK_ID_BYTES,
    MAX_FINDING_UID_BYTES, MAX_REGION_BYTES, MAX_RESOURCE_TYPE_BYTES, MAX_RESOURCE_UID_BYTES,
};
use crate::types::Executor;
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::{json, Value};
use std::collections::hash_map::Entry;
use std::time::Duration;


pub const MIGRATION_NAMESPACE: &str = "posture";


pub const MIGRATIONS: [Migration; 2] = [
    Migration {
        version: "posture_0001",
        sql: include_str!("../migrations/posture_0001.sql"),
    },
    Migration {
        version: "posture_0002",
        sql: include_str!("../migrations/posture_0002.sql"),
    },
];


/// Rows of one tenant, findings and run rows together: the cap the function enforces at commit.
pub const MAX_FINDINGS_PER_TENANT: usize = 200_000;


pub const MAX_STORED_TEXT_BYTES: usize = 1_024;


/// Below jsonb's 255 MB limit.
pub const MAX_RUN_DOC_BYTES: usize = 134_217_728;


pub const MAX_RUN_ID_BYTES: usize = 128;


pub const MIN_TIME_UNIX: i64 = -62_167_219_200;


pub const MAX_TIME_UNIX: i64 = 253_402_300_799;


/// The deadline a caller gives the executor of `replace_run`: a run of 100 000 rows is one statement.
pub const STORE_DEADLINE: Duration = Duration::from_secs(120);


pub const REFERENCE_PATTERN: &str = "^[A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*$";


pub const SPACED_PATTERN: &str = "^[A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*( [A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*)*$";


pub const PROVIDER_PATTERN: &str = "^[a-z0-9_]+$";


pub const OUTCOME_STORED: &str = "stored";


pub const OUTCOME_REFUSED_CAP: &str = "refused_cap";


/// `$1` tenant, `$2` account, `$3` run id, `$4` findings JSON, `$5` finish time, `$6` counters JSON, `$7` row cap.
pub const REPLACE_SQL: &str = "SELECT outcome, others::text, stored::text \
                               FROM posture_replace_run($1, $2, $3, $4::text::jsonb, $5::text::bigint, $6::text::jsonb, $7::text::bigint)";


/// `$1` tenant, `$2` account, `$3` finish time, `$4` items the refused run held, `$5` row cap: writes the refusal marker of a run too large to send.
pub const REFUSE_SQL: &str = "SELECT others::text FROM posture_refuse_run($1, $2, $3::text::bigint, $4::text::bigint, $5::text::bigint)";


/// True when the store can hold the finding of the run's `account`: every identity field in its grammar, no NUL, texts and times in range.
pub fn finding_fits(finding: &Finding, account: &str) -> bool {
    finding.account == account
        && valid_reference(&finding.check_id, MAX_CHECK_ID_BYTES)
        && valid_provider(&finding.provider)
        && valid_reference(&finding.region, MAX_REGION_BYTES)
        && valid_spaced_reference(&finding.resource_uid, MAX_RESOURCE_UID_BYTES)
        && valid_spaced_reference(&finding.resource_type, MAX_RESOURCE_TYPE_BYTES)
        && !finding.uid.is_empty()
        && finding.uid.len() <= MAX_FINDING_UID_BYTES
        && !finding.uid.contains('\0')
        && !finding.title.contains('\0')
        && !finding.detail.contains('\0')
        && finding.title.len() <= MAX_STORED_TEXT_BYTES
        && finding.detail.len() <= MAX_STORED_TEXT_BYTES
        && (MIN_TIME_UNIX..=MAX_TIME_UNIX).contains(&finding.time_unix)
        && i64::try_from(finding.title_cut).is_ok()
        && i64::try_from(finding.detail_cut).is_ok()
}


/// Adds a finding that fits, or merges it into the repeat of its identity keeping the more serious status; a finding that does not fit is counted by status.
pub fn admit<'a>(admitted: &mut Admitted<'a>, account: &str, finding: &'a Finding) {
    if !finding_fits(finding, account) {
        *admitted.refused.entry(finding.status).or_insert(0) += 1;
    } else {
        match admitted.positions.entry(identity_of(finding)) {
            Entry::Vacant(slot) => {
                slot.insert(admitted.kept.len());
                admitted.kept.push(finding);
            }
            Entry::Occupied(slot) => {
                admitted.duplicate += 1;
                if let Some(kept) = admitted.kept.get_mut(*slot.get()).filter(|kept| finding.status > kept.status) {
                    *kept = finding;
                }
            }
        }
    }
}


/// The findings of the run the store accepts, in input order.
pub fn admit_all<'a>(account: &str, items: &'a [Finding]) -> Admitted<'a> {
    let mut admitted = Admitted::default();
    items.iter().for_each(|finding| admit(&mut admitted, account, finding));
    admitted
}


/// The JSON object of one finding: the identity is the lowercase hex of the SHA-256 recomputed here, never taken from the caller.
pub fn finding_doc(finding: &Finding) -> Value {
    json!({
        "identity": format!("{:x}", identity_of(finding)),
        "severity_rank": severity_rank(finding.severity),
        "uid": finding.uid,
        "check_id": finding.check_id,
        "status": status_text(finding.status),
        "severity": severity_text(finding.severity),
        "provider": finding.provider,
        "region": finding.region,
        "resource_uid": finding.resource_uid,
        "resource_type": finding.resource_type,
        "time_unix": finding.time_unix,
        "title": finding.title,
        "title_cut": finding.title_cut,
        "detail": finding.detail,
        "detail_cut": finding.detail_cut,
    })
}


/// The findings array as one JSON text, refused as soon as it passes `max_bytes` so a run never holds more than that plus one finding.
pub fn document_of(findings: &[&Finding], max_bytes: usize) -> Result<String, StoreError> {
    let document = findings.iter().try_fold(String::from("["), |mut document, finding| {
        let text = finding_doc(finding).to_string();
        if document.len() + text.len() + 1 > max_bytes {
            Err(StoreError::RunTooLarge {
                items: findings.len(),
                max_items: MAX_FINDINGS_PER_TENANT,
                max_bytes,
            })
        } else {
            if document.len() > 1 {
                document.push(',');
            }
            document.push_str(&text);
            Ok(document)
        }
    })?;
    Ok(document + "]")
}


/// The counters of a run: the parser's plus the store's own refusals, per status.
pub fn stats_doc(skipped: &Skipped, admitted: &Admitted) -> Value {
    let by_status =
        |status: Status| skipped.refused_by_status.get(&status).copied().unwrap_or(0) + admitted.refused.get(&status).copied().unwrap_or(0);
    json!({
        "unparsable": skipped.unparsable,
        "bad_field": skipped.bad_field,
        "duplicate": skipped.duplicate + admitted.duplicate,
        "foreign_account": skipped.foreign_account,
        "refused_pass": by_status(Status::Pass),
        "refused_muted": by_status(Status::Muted),
        "refused_manual": by_status(Status::Manual),
        "refused_fail": by_status(Status::Fail),
        "store_refused": admitted.refused.values().sum::<usize>(),
    })
}


/// Every check that needs no I/O: tenant, account, run id and the item count.
pub fn check_run(scope: &TenantScope, findings: &Findings, run_id: &str) -> Result<(), StoreError> {
    if tenant_of(&findings.tenant) != tenant_of(scope) {
        Err(StoreError::TenantMismatch)
    } else if !valid_reference(&findings.account, MAX_ACCOUNT_BYTES) {
        Err(StoreError::BadAccount)
    } else if !valid_reference(run_id, MAX_RUN_ID_BYTES) {
        Err(StoreError::BadRunId)
    } else {
        Ok(())
    }
}


/// The run is refused as too large when it holds more findings than the tenant cap, before any finding is looked at.
pub fn check_size(findings: &Findings) -> Result<(), StoreError> {
    if findings.items.len() > MAX_FINDINGS_PER_TENANT {
        Err(StoreError::RunTooLarge {
            items: findings.items.len(),
            max_items: MAX_FINDINGS_PER_TENANT,
            max_bytes: MAX_RUN_DOC_BYTES,
        })
    } else {
        Ok(())
    }
}


/// Writes the refusal marker of a run refused as too large (no run row is written otherwise) and gives back the refusal; a failing marker is logged, the refusal stays the answer.
pub async fn refuse_run(exec: Executor<'_, '_>, scope: &TenantScope, account: &str, finished: i64, items: usize, refusal: StoreError) -> StoreError {
    let params = vec![
        account.to_owned(),
        finished.to_string(),
        items.to_string(),
        MAX_FINDINGS_PER_TENANT.to_string(),
    ];
    if let Err(error) = exec(scope.clone(), REFUSE_SQL, params).await {
        let category = error.to_string();
        tracing::warn!(category, "posture refusal marker not written");
    }
    refusal
}


/// The answer row: (stored, others, rows written).
pub fn parse_answer(rows: &[Vec<String>]) -> Result<(bool, usize, usize), StoreError> {
    match rows.first().map(Vec::as_slice) {
        Some([outcome, others, written]) => {
            let stored = match outcome.as_str() {
                OUTCOME_STORED => Ok(true),
                OUTCOME_REFUSED_CAP => Ok(false),
                _other => Err(StoreError::BadAnswer),
            }?;
            let others_count = others.parse::<usize>().map_err(|_bad| StoreError::BadAnswer)?;
            let written_count = written.parse::<usize>().map_err(|_bad| StoreError::BadAnswer)?;
            Ok((stored, others_count, written_count))
        }
        _other => Err(StoreError::BadAnswer),
    }
}


/// Replaces the stored findings of the run's account with this run's, under the scope's tenant, with the default document limit.
pub async fn replace_run(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    findings: &Findings,
    run_id: &str,
    finished_micros: u64,
) -> Result<RunOutcome, StoreError> {
    replace_run_limited(exec, scope, findings, run_id, finished_micros, MAX_RUN_DOC_BYTES).await
}


/// As `replace_run` with an explicit document limit; every bound is checked before any I/O.
pub async fn replace_run_limited(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    findings: &Findings,
    run_id: &str,
    finished_micros: u64,
    max_doc_bytes: usize,
) -> Result<RunOutcome, StoreError> {
    check_run(scope, findings, run_id)?;
    let finished = i64::try_from(finished_micros).map_err(|_bad| StoreError::BadTime)?;
    let sized = check_size(findings).and_then(|()| {
        let admitted = admit_all(&findings.account, &findings.items);
        document_of(&admitted.kept, max_doc_bytes).map(|document| (admitted, document))
    });
    let prepared = match sized {
        Ok(pair) => Ok(pair),
        Err(refusal) => Err(refuse_run(exec, scope, &findings.account, finished, findings.items.len(), refusal).await),
    };
    let (admitted, document) = prepared?;
    let params = vec![
        findings.account.clone(),
        run_id.to_owned(),
        document,
        finished.to_string(),
        stats_doc(&findings.skipped, &admitted).to_string(),
        MAX_FINDINGS_PER_TENANT.to_string(),
    ];
    let rows = exec(scope.clone(), REPLACE_SQL, params).await?;
    let (stored, others, written) = parse_answer(&rows)?;
    let items = admitted.kept.len();
    let store_refused = admitted.refused.values().sum::<usize>();
    let duplicate = admitted.duplicate;
    if !stored {
        let cap = MAX_FINDINGS_PER_TENANT;
        tracing::warn!(cap, items, others, "posture run refused by the row cap");
        Err(StoreError::TenantCap { cap, items, others })
    } else {
        if store_refused + duplicate > 0 {
            tracing::warn!(store_refused, duplicate, "posture findings refused or merged by the store");
        }
        Ok(RunOutcome {
            stored: written,
            store_refused,
            duplicate,
        })
    }
}
