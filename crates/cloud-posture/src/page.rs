//! Paged read of one account's stored run: the run header and the findings by severity then identity, from one snapshot.

use crate::error::StoreError;
use crate::model::{Finding, FindingsPage, PageCursor, RunHeader};
use crate::prowler::identity_of;
use crate::store::{finding_fits, MAX_RUN_ID_BYTES};
use crate::text::{severity_of, severity_rank, status_of, valid_reference, MAX_ACCOUNT_BYTES, RANK_FATAL};
use crate::types::Executor;
use core_pg::scope::TenantScope;


pub const MAX_PAGE_LIMIT: usize = 500;


/// A run id, a finish time, a rank and a 64 character identity fit well inside this.
pub const MAX_CURSOR_BYTES: usize = 512;


pub const CURSOR_FIELDS: usize = 4;


pub const CURSOR_SEPARATOR: char = ' ';


pub const IDENTITY_HEX_CHARACTERS: usize = 64;


/// Above every stored rank: the first page has no row "at" the cursor rank, every row is "below" it.
pub const RANK_BEFORE_FIRST: u8 = RANK_FATAL + 1;


pub const ROW_COLUMNS: usize = 29;


pub const COL_RUN_ID: usize = 0;


pub const COL_FINISHED: usize = 1;


pub const COL_ITEMS: usize = 2;


pub const COL_UNPARSABLE: usize = 3;


pub const COL_BAD_FIELD: usize = 4;


pub const COL_DUPLICATE: usize = 5;


pub const COL_FOREIGN: usize = 6;


pub const COL_REFUSED_PASS: usize = 7;


pub const COL_REFUSED_MUTED: usize = 8;


pub const COL_REFUSED_MANUAL: usize = 9;


pub const COL_REFUSED_FAIL: usize = 10;


pub const COL_STORE_REFUSED: usize = 11;


pub const COL_REFUSED_MICROS: usize = 12;


pub const COL_REFUSED_ITEMS: usize = 13;


pub const COL_IDENTITY: usize = 14;


pub const COL_RANK: usize = 15;


pub const COL_UID: usize = 16;


pub const COL_CHECK: usize = 17;


pub const COL_STATUS: usize = 18;


pub const COL_SEVERITY: usize = 19;


pub const COL_PROVIDER: usize = 20;


pub const COL_REGION: usize = 21;


pub const COL_RESOURCE_UID: usize = 22;


pub const COL_RESOURCE_TYPE: usize = 23;


pub const COL_TIME: usize = 24;


pub const COL_TITLE: usize = 25;


pub const COL_TITLE_CUT: usize = 26;


pub const COL_DETAIL: usize = 27;


pub const COL_DETAIL_CUT: usize = 28;


/// One statement and snapshot: `$1` tenant, `$2` account, `$3` cursor rank and `$4` identity hex (8 and empty on the first page), `$5` rows to fetch.
pub const PAGE_SQL: &str = "SELECT coalesce(r.run_id, ''), coalesce(r.finished_micros::text, ''), r.items::text, r.unparsable::text, r.bad_field::text, \
    r.duplicate::text, r.foreign_account::text, r.refused_pass::text, r.refused_muted::text, r.refused_manual::text, r.refused_fail::text, \
    r.store_refused::text, coalesce(r.refused_micros::text, ''), r.refused_items::text, \
    coalesce(encode(p.identity, 'hex'), ''), coalesce(p.severity_rank::text, ''), coalesce(p.uid, ''), coalesce(p.check_id, ''), coalesce(p.status, ''), \
    coalesce(p.severity, ''), coalesce(p.provider, ''), coalesce(p.region, ''), coalesce(p.resource_uid, ''), coalesce(p.resource_type, ''), \
    coalesce(p.time_unix::text, ''), coalesce(p.title, ''), coalesce(p.title_cut::text, ''), coalesce(p.detail, ''), coalesce(p.detail_cut::text, '') \
    FROM cloud_posture_runs r LEFT JOIN ( \
        SELECT * FROM ( \
            (SELECT f.* FROM cloud_posture_findings f WHERE f.tenant = $1 AND f.account = $2 AND f.severity_rank = $3::text::smallint \
                AND f.identity > decode($4::text, 'hex') ORDER BY f.identity LIMIT $5::text::bigint) \
            UNION ALL \
            (SELECT f.* FROM cloud_posture_findings f WHERE f.tenant = $1 AND f.account = $2 AND f.severity_rank < $3::text::smallint \
                ORDER BY f.severity_rank DESC, f.identity LIMIT $5::text::bigint) \
        ) u ORDER BY u.severity_rank DESC, u.identity LIMIT $5::text::bigint \
    ) p ON true \
    WHERE r.tenant = $1 AND r.account = $2 ORDER BY p.severity_rank DESC NULLS LAST, p.identity";


/// A stored rank: decimal text of 0 to `RANK_FATAL`, with no sign or leading zero.
pub fn rank_of(text: &str) -> Option<u8> {
    text.parse::<u8>().ok().filter(|rank| *rank <= RANK_FATAL && rank.to_string() == text)
}


/// The lowercase hex of a SHA-256, the form the store prints identities in.
pub fn is_identity_hex(text: &str) -> bool {
    text.len() == IDENTITY_HEX_CHARACTERS && text.chars().all(|next| next.is_ascii_digit() || ('a'..='f').contains(&next))
}


/// A non-negative decimal with no sign or leading zero.
pub fn micros_of(text: &str) -> Option<i64> {
    text.parse::<i64>().ok().filter(|micros| *micros >= 0 && micros.to_string() == text)
}


/// `<run id> <finish micros> <rank> <identity hex>`: no field holds a space.
pub fn cursor_text(run_id: &str, finished_micros: i64, rank: &str, identity: &str) -> String {
    [run_id, &finished_micros.to_string(), rank, identity].join(&CURSOR_SEPARATOR.to_string())
}


/// A cursor as this store prints it; a longer text is refused before it is split.
pub fn parse_cursor(text: &str) -> Result<PageCursor, StoreError> {
    if text.len() > MAX_CURSOR_BYTES {
        Err(StoreError::BadCursor)
    } else {
        match text.splitn(CURSOR_FIELDS + 1, CURSOR_SEPARATOR).collect::<Vec<_>>().as_slice() {
            [run_id, finished, rank, identity] => {
                let named = valid_reference(run_id, MAX_RUN_ID_BYTES) && is_identity_hex(identity);
                micros_of(finished)
                    .zip(rank_of(rank))
                    .filter(|_pair| named)
                    .map(|(finished_micros, rank_value)| PageCursor {
                        run_id: (*run_id).to_owned(),
                        finished_micros,
                        rank: rank_value,
                        identity: (*identity).to_owned(),
                    })
                    .ok_or(StoreError::BadCursor)
            }
            _other => Err(StoreError::BadCursor),
        }
    }
}


fn column(row: &[String], index: usize) -> Result<&str, StoreError> {
    row.get(index).map(String::as_str).ok_or(StoreError::BadAnswer)
}


fn count(row: &[String], index: usize) -> Result<u64, StoreError> {
    column(row, index)?.parse::<u64>().map_err(|_bad| StoreError::BadAnswer)
}


fn optional_micros(row: &[String], index: usize) -> Result<Option<i64>, StoreError> {
    let text = column(row, index)?;
    if text.is_empty() {
        Ok(None)
    } else {
        micros_of(text).map(Some).ok_or(StoreError::BadAnswer)
    }
}


fn run_id_of(row: &[String]) -> Result<Option<String>, StoreError> {
    let text = column(row, COL_RUN_ID)?;
    if text.is_empty() {
        Ok(None)
    } else if valid_reference(text, MAX_RUN_ID_BYTES) {
        Ok(Some(text.to_owned()))
    } else {
        Err(StoreError::StoredValue)
    }
}


/// The run header carried by every row of a page.
pub fn header_of(row: &[String]) -> Result<RunHeader, StoreError> {
    Ok(RunHeader {
        run_id: run_id_of(row)?,
        finished_micros: optional_micros(row, COL_FINISHED)?,
        items: count(row, COL_ITEMS)?,
        unparsable: count(row, COL_UNPARSABLE)?,
        bad_field: count(row, COL_BAD_FIELD)?,
        duplicate: count(row, COL_DUPLICATE)?,
        foreign_account: count(row, COL_FOREIGN)?,
        refused_pass: count(row, COL_REFUSED_PASS)?,
        refused_muted: count(row, COL_REFUSED_MUTED)?,
        refused_manual: count(row, COL_REFUSED_MANUAL)?,
        refused_fail: count(row, COL_REFUSED_FAIL)?,
        store_refused: count(row, COL_STORE_REFUSED)?,
        refused_micros: optional_micros(row, COL_REFUSED_MICROS)?,
        refused_items: count(row, COL_REFUSED_ITEMS)?,
    })
}


/// True when a run was refused after the stored one finished (or when none was ever stored): the reader must be told the data is not the newest run.
pub fn refusal_pending(run: &RunHeader) -> bool {
    run.refused_micros
        .is_some_and(|refused| run.finished_micros.is_none_or(|finished| refused > finished))
}


/// The finding a row holds, parsed only; the serving check is `served_of`.
pub fn finding_of(row: &[String], account: &str) -> Option<Finding> {
    let text = |index: usize| row.get(index).cloned();
    Some(Finding {
        uid: text(COL_UID)?,
        check_id: text(COL_CHECK)?,
        status: status_of(&text(COL_STATUS)?)?,
        severity: severity_of(&text(COL_SEVERITY)?)?,
        provider: text(COL_PROVIDER)?,
        account: account.to_owned(),
        region: text(COL_REGION)?,
        resource_uid: text(COL_RESOURCE_UID)?,
        resource_type: text(COL_RESOURCE_TYPE)?,
        time_unix: text(COL_TIME)?.parse().ok()?,
        title: text(COL_TITLE)?,
        title_cut: text(COL_TITLE_CUT)?.parse().ok()?,
        detail: text(COL_DETAIL)?,
        detail_cut: text(COL_DETAIL_CUT)?.parse().ok()?,
    })
}


/// The serving check: the row parses, every field passes the grammar and the caps the writer applies, and the stored rank and identity are the ones recomputed.
pub fn served_of(row: &[String], account: &str) -> Option<Finding> {
    finding_of(row, account).filter(|finding| {
        let rank = severity_rank(finding.severity).to_string();
        let identity = format!("{:x}", identity_of(finding));
        finding_fits(finding, account)
            && row.get(COL_RANK).is_some_and(|stored| *stored == rank)
            && row.get(COL_IDENTITY).is_some_and(|stored| *stored == identity)
    })
}


/// The cursor text of a row served or skipped: its raw key, with the run the page belongs to; `StoredValue` when the key or the run cannot be printed.
pub fn next_cursor(run: &RunHeader, row: &[String]) -> Result<String, StoreError> {
    let rank = column(row, COL_RANK)?;
    let identity = column(row, COL_IDENTITY)?;
    let printable = rank_of(rank).is_some() && is_identity_hex(identity);
    run.run_id
        .as_deref()
        .zip(run.finished_micros)
        .filter(|_run| printable)
        .map(|(run_id, finished_micros)| cursor_text(run_id, finished_micros, rank, identity))
        .ok_or(StoreError::StoredValue)
}


/// `RunChanged` when the cursor names another run than the one the snapshot holds (another id or another finish time).
pub fn check_cursor(run: &RunHeader, cursor: Option<&PageCursor>) -> Result<(), StoreError> {
    let changed =
        cursor.is_some_and(|named| run.run_id.as_deref() != Some(named.run_id.as_str()) || run.finished_micros != Some(named.finished_micros));
    if changed {
        Err(StoreError::RunChanged)
    } else {
        Ok(())
    }
}


/// The page of `rows` (at most `limit + 1` of them): findings failing the serving check are skipped and counted, the next cursor is the raw key of the last of the first `limit`.
pub fn page_of(account: &str, rows: &[Vec<String>], limit: usize, cursor: Option<&PageCursor>) -> Result<FindingsPage, StoreError> {
    if rows.iter().any(|row| row.len() != ROW_COLUMNS) {
        Err(StoreError::BadAnswer)
    } else {
        match rows.first() {
            None => cursor.map_or_else(
                || {
                    Ok(FindingsPage {
                        run: None,
                        items: Vec::new(),
                        unservable: 0,
                        next: None,
                    })
                },
                |_named| Err(StoreError::RunChanged),
            ),
            Some(first) => {
                let run = header_of(first)?;
                check_cursor(&run, cursor)?;
                let data: Vec<&Vec<String>> = rows
                    .iter()
                    .filter(|row| row.get(COL_IDENTITY).is_some_and(|identity| !identity.is_empty()))
                    .collect();
                let items: Vec<Finding> = data.iter().take(limit).filter_map(|row| served_of(row, account)).collect();
                let unservable = data.len().min(limit) - items.len();
                let next = data
                    .get(limit.saturating_sub(1))
                    .filter(|_last| data.len() > limit)
                    .map(|row| next_cursor(&run, row))
                    .transpose()?;
                Ok(FindingsPage {
                    run: Some(run),
                    items,
                    unservable,
                    next,
                })
            }
        }
    }
}


/// Every check that needs no I/O: account, limit (1 to `MAX_PAGE_LIMIT`) and cursor.
pub fn check_read(account: &str, cursor: Option<&str>, limit: usize) -> Result<Option<PageCursor>, StoreError> {
    if !valid_reference(account, MAX_ACCOUNT_BYTES) {
        Err(StoreError::BadAccount)
    } else if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        Err(StoreError::BadLimit { max: MAX_PAGE_LIMIT })
    } else {
        cursor.map(parse_cursor).transpose()
    }
}


/// The parameters of `PAGE_SQL` after the tenant.
pub fn page_params(account: &str, cursor: Option<&PageCursor>, limit: usize) -> Vec<String> {
    let (rank, identity) = cursor.map_or((RANK_BEFORE_FIRST, String::new()), |named| (named.rank, named.identity.clone()));
    vec![account.to_owned(), rank.to_string(), identity, (limit + 1).to_string()]
}


/// One page of the account's stored run under the scope's tenant, highest severity first then by identity; `limit` is 1 to `MAX_PAGE_LIMIT`.
pub async fn read_findings(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    account: &str,
    cursor: Option<&str>,
    limit: usize,
) -> Result<FindingsPage, StoreError> {
    let parsed = check_read(account, cursor, limit)?;
    let rows = exec(scope.clone(), PAGE_SQL, page_params(account, parsed.as_ref(), limit)).await?;
    let page = page_of(account, &rows, limit, parsed.as_ref())?;
    let unservable = page.unservable;
    if unservable > 0 {
        tracing::warn!(unservable, "stored posture findings that cannot be served were skipped");
    }
    Ok(page)
}
