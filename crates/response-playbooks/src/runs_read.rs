use crate::api_model::{RunDetail, RunList, RunMeta, RunPage};
use crate::error::ReadError;
use crate::runs::{MAX_TRACE_BYTES, UNKNOWN_KIND};
use alerts::store::MAX_PAGE_SIZE;
use alerts::types::{Executor, Row};
use core_pg::scope::tenant_scope;
use serde_json::{Map, Value};


/// Params: `$2` size.
pub const LIST_FIRST_SQL: &str = "SELECT id, alert_id, playbook, mode, outcome, steps::text, created::text, run_seq::text \
FROM playbook_runs WHERE tenant = $1 ORDER BY run_seq DESC LIMIT $2::text::bigint";


/// Params: `$2` run sequence to continue below, `$3` size.
pub const LIST_NEXT_SQL: &str = "SELECT id, alert_id, playbook, mode, outcome, steps::text, created::text, run_seq::text \
FROM playbook_runs WHERE tenant = $1 AND run_seq < $2::text::bigint ORDER BY run_seq DESC LIMIT $3::text::bigint";


/// Params: `$2` run id.
pub const GET_SQL: &str = "SELECT id, alert_id, playbook, mode, outcome, steps::text, created::text, run_seq::text, trace::text \
FROM playbook_runs WHERE tenant = $1 AND id = $2";


pub const MAX_CURSOR_DIGITS: usize = 19;


pub const ID_CHARS: usize = 64;


/// jsonb prints a space after each colon and comma, so its text can pass twice the compact size the writer bounded.
pub const TRACE_TEXT_LIMIT: usize = MAX_TRACE_BYTES * 2;


pub const TRACE_TEXT_KEYS: [&str; 6] = ["kind", "outcome", "path", "action", "connector", "step"];


pub const KIND_WORDS: [&str; 6] = ["string", "integer", "boolean", "ip", "domain", "duration"];


/// A cursor is the decimal run sequence number: a forged one only moves inside the caller's own tenant, a malformed one is refused.
pub fn parse_cursor(text: &str) -> Result<i64, ReadError> {
    (text.len() <= MAX_CURSOR_DIGITS && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse::<i64>().ok())
        .flatten()
        .ok_or(ReadError::BadCursor)
}


pub fn parse_limit(text: Option<&str>, default: usize) -> Result<usize, ReadError> {
    text.map_or(Ok(default), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<usize>().ok())
            .flatten()
            .filter(|size| (1..=MAX_PAGE_SIZE).contains(size))
            .ok_or(ReadError::BadLimit { limit: MAX_PAGE_SIZE })
    })
}


/// A run id is 64 lowercase hexadecimal characters (a SHA-256 digest).
pub fn is_run_id(text: &str) -> bool {
    text.len() == ID_CHARS && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}


fn number<Parsed: std::str::FromStr>(text: &str) -> Result<Parsed, ReadError> {
    text.parse().map_err(|_error| ReadError::BadRow)
}


pub fn decode_meta(cells: &[String]) -> Result<RunMeta, ReadError> {
    match cells {
        [id, alert_id, playbook, mode, outcome, steps, created, seq] => Ok(RunMeta {
            id: id.clone(),
            alert_id: alert_id.clone(),
            playbook: playbook.clone(),
            mode: mode.clone(),
            outcome: outcome.clone(),
            steps: number(steps)?,
            created: number(created)?,
            seq: number(seq)?,
        }),
        _ => Err(ReadError::BadRow),
    }
}


/// Newest first, at most `size` runs; the store is asked for one more, which only tells that a next page exists.
pub async fn list_runs(exec: Executor<'_, '_>, tenant: &str, page: RunPage) -> Result<RunList, ReadError> {
    let scope = tenant_scope(tenant)?;
    (1..=MAX_PAGE_SIZE)
        .contains(&page.size)
        .then_some(())
        .ok_or(ReadError::BadLimit { limit: MAX_PAGE_SIZE })?;
    let fetch = (page.size + 1).to_string();
    let (sql, params) = match page.after {
        Some(after) => (LIST_NEXT_SQL, vec![after.to_string(), fetch]),
        None => (LIST_FIRST_SQL, vec![fetch]),
    };
    let rows: Vec<Row> = exec(scope, sql, params).await?;
    (rows.len() <= page.size + 1).then_some(()).ok_or(ReadError::BadRow)?;
    let runs = rows.iter().map(|row| decode_meta(row)).collect::<Result<Vec<RunMeta>, ReadError>>()?;
    let kept: Vec<RunMeta> = runs.iter().take(page.size).cloned().collect();
    let next = (runs.len() > page.size).then(|| kept.last().map(|last| last.seq)).flatten();
    Ok(RunList { runs: kept, next })
}


/// Parameters keep their name and a catalogue kind word; any other stored value reads as `unknown`, so a value can never come out.
pub fn clean_params(params: &Map<String, Value>) -> Value {
    Value::Object(
        params
            .iter()
            .map(|(name, kind)| {
                let word = kind.as_str().filter(|text| KIND_WORDS.contains(text)).unwrap_or(UNKNOWN_KIND);
                (name.clone(), Value::String(word.to_owned()))
            })
            .collect(),
    )
}


/// An element is rebuilt from the fixed keys the writer produces; anything else in the stored JSON is dropped.
pub fn clean_element(element: &Value) -> Result<Value, ReadError> {
    let fields = element.as_object().ok_or(ReadError::BadRow)?;
    let texts = TRACE_TEXT_KEYS.iter().filter_map(|key| {
        fields
            .get(*key)
            .filter(|found| found.is_string())
            .map(|found| ((*key).to_owned(), found.clone()))
    });
    let events = fields
        .get("events")
        .filter(|found| found.is_u64())
        .map(|found| ("events".to_owned(), found.clone()));
    let params = fields
        .get("params")
        .and_then(Value::as_object)
        .map(|found| ("params".to_owned(), clean_params(found)));
    Ok(Value::Object(texts.chain(events).chain(params).collect()))
}


pub fn clean_trace(text: &str) -> Result<Value, ReadError> {
    (text.len() <= TRACE_TEXT_LIMIT).then_some(()).ok_or(ReadError::BadRow)?;
    let parsed: Value = serde_json::from_str(text).map_err(|_error| ReadError::BadRow)?;
    let elements = parsed.as_array().ok_or(ReadError::BadRow)?;
    Ok(Value::Array(
        elements.iter().map(clean_element).collect::<Result<Vec<Value>, ReadError>>()?,
    ))
}


pub fn decode_detail(id: &str, cells: &[String]) -> Result<RunDetail, ReadError> {
    let (trace, head) = cells.split_last().ok_or(ReadError::BadRow)?;
    let meta = decode_meta(head)?;
    (meta.id == id).then_some(()).ok_or(ReadError::BadRow)?;
    Ok(RunDetail {
        meta,
        trace: clean_trace(trace)?,
    })
}


/// One run of the tenant by id; another tenant's id and a malformed id are `None`, the malformed one without a store call.
pub async fn get_run(exec: Executor<'_, '_>, tenant: &str, id: &str) -> Result<Option<RunDetail>, ReadError> {
    let scope = tenant_scope(tenant)?;
    if is_run_id(id) {
        let rows = exec(scope, GET_SQL, vec![id.to_owned()]).await?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => decode_detail(id, row).map(Some),
            _ => Err(ReadError::BadRow),
        }
    } else {
        Ok(None)
    }
}
