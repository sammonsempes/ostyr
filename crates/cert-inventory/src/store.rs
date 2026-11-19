//! Per-tenant certificate inventory in PostgreSQL: sightings of scans and CT logs, rows capped at commit by the store (spec section 23).

use crate::alerting::{is_fingerprint, MAX_DNS_NAME_BYTES};
use crate::error::InventoryStoreError;
use crate::model::{
    CertDetail, CertFilter, CertPage, CertRecord, KeyType, Sighting, SightingPage, Source, SourceKind, StoreCounts, StoreLimits, StoredCert,
};
use crate::parse::MAX_DNS_NAMES;
use alerts::types::{Executor, Row};
use core_pg::migrate::Migration;
use core_pg::scope::TenantScope;
use serde_json::{json, Value};
use std::collections::HashSet;
use time::OffsetDateTime;


pub const MIGRATION_NAMESPACE: &str = "cert_inventory";


pub const MIGRATIONS: [Migration; 2] = [
    Migration {
        version: "001_cert_inventory",
        sql: include_str!("../migrations/001_cert_inventory.sql"),
    },
    Migration {
        version: "002_cert_inventory_lock_64",
        sql: include_str!("../migrations/002_cert_inventory_lock_64.sql"),
    },
];


/// One statement: `$1` tenant, `$2` records JSON, `$3` kind, `$4` reference, `$5` now, `$6` and `$7` caps; answers (inserted, seen again, refused).
pub const STORE_SQL: &str = include_str!("../migrations/store.sql");


pub const LIST_FIRST_SQL: &str = "SELECT fingerprint, subject, issuer, array_to_json(dns_names)::text, not_before::text, not_after::text, key_type, \
                                  COALESCE(key_bits::text, ''), self_signed::text, first_seen::text, last_seen::text FROM cert_inventory \
                                  WHERE tenant = $1 AND not_after < $2::text::bigint ORDER BY not_after, fingerprint LIMIT $3::text::bigint";


pub const LIST_NEXT_SQL: &str = "SELECT fingerprint, subject, issuer, array_to_json(dns_names)::text, not_before::text, not_after::text, key_type, \
                                 COALESCE(key_bits::text, ''), self_signed::text, first_seen::text, last_seen::text FROM cert_inventory \
                                 WHERE tenant = $1 AND not_after < $2::text::bigint AND (not_after, fingerprint) > ($4::text::bigint, $5::text) \
                                 ORDER BY not_after, fingerprint LIMIT $3::text::bigint";


pub const GET_SQL: &str = "SELECT fingerprint, subject, issuer, array_to_json(dns_names)::text, not_before::text, not_after::text, key_type, \
                           COALESCE(key_bits::text, ''), self_signed::text, first_seen::text, last_seen::text FROM cert_inventory \
                           WHERE tenant = $1 AND fingerprint = $2::text";


pub const SIGHTINGS_SQL: &str = "SELECT source_kind, source_ref, last_seen::text FROM cert_sightings WHERE tenant = $1 AND fingerprint = $2::text \
                                 ORDER BY source_kind, source_ref LIMIT $3::text::bigint";


pub const DEFAULT_LIMITS: StoreLimits = StoreLimits {
    max_certs: 200_000,
    max_sightings: 1_000_000,
};


pub const MAX_STORE_BATCH: usize = 1_000;


pub const MAX_PAGE: usize = 500;


pub const MAX_SIGHTINGS_READ: usize = 500;


pub const MAX_SOURCE_BYTES: usize = 512;


pub const MAX_TEXT_BYTES: usize = 1_024;


pub const MIN_YEAR: i32 = 0;


pub const MAX_YEAR: i32 = 9_999;


pub const SOURCE_EXTRA_BYTES: &[u8] = b"._-/:@+=,~%";


pub const CURSOR_SEPARATOR: char = ':';


pub const SCAN_KIND: &str = "scan";


pub const CT_KIND: &str = "ct";


pub const COL_FINGERPRINT: usize = 0;


pub const COL_SUBJECT: usize = 1;


pub const COL_ISSUER: usize = 2;


pub const COL_DNS_NAMES: usize = 3;


pub const COL_NOT_BEFORE: usize = 4;


pub const COL_NOT_AFTER: usize = 5;


pub const COL_KEY_TYPE: usize = 6;


pub const COL_KEY_BITS: usize = 7;


pub const COL_SELF_SIGNED: usize = 8;


pub const COL_FIRST_SEEN: usize = 9;


pub const COL_LAST_SEEN: usize = 10;


pub const COL_SIGHTING_KIND: usize = 0;


pub const COL_SIGHTING_REF: usize = 1;


pub const COL_SIGHTING_LAST: usize = 2;


pub const COL_REFUSED: usize = 2;


/// True when the time can be written as an RFC 3339 date (year 0 to 9999).
pub fn time_in_range(seconds: i64) -> bool {
    OffsetDateTime::from_unix_timestamp(seconds).is_ok_and(|moment| (MIN_YEAR..=MAX_YEAR).contains(&moment.year()))
}


/// A non-empty ASCII reference of letters, digits and `._-/:@+=,~%`, at most `MAX_SOURCE_BYTES` bytes.
pub fn source_ok(source: &Source) -> bool {
    !source.reference.is_empty()
        && source.reference.len() <= MAX_SOURCE_BYTES
        && source
            .reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || SOURCE_EXTRA_BYTES.contains(&byte))
}


pub fn kind_text(kind: SourceKind) -> &'static str {
    match kind {
        SourceKind::Scan => SCAN_KIND,
        SourceKind::Ct => CT_KIND,
    }
}


pub fn key_type_text(key_type: KeyType) -> &'static str {
    match key_type {
        KeyType::Rsa => "rsa",
        KeyType::Ec => "ec",
        KeyType::Other => "other",
    }
}


/// The text itself up to `MAX_TEXT_BYTES` bytes, else its head (cut on a character boundary) and `...[N bytes omitted]`.
pub fn cut_text(text: &str) -> String {
    let end = (0..=MAX_TEXT_BYTES).rev().find(|index| text.is_char_boundary(*index)).unwrap_or(0);
    if text.len() <= MAX_TEXT_BYTES {
        text.to_owned()
    } else {
        format!("{}\u{2026}[{} bytes omitted]", text.get(..end).unwrap_or(""), text.len() - end)
    }
}


/// A record the store can hold: lowercase hex fingerprint, times a date can write, no NUL (jsonb refuses it), bounded DNS names.
pub fn record_ok(record: &CertRecord) -> bool {
    is_fingerprint(&record.fingerprint_sha256)
        && time_in_range(record.not_before)
        && time_in_range(record.not_after)
        && !record.subject.contains('\0')
        && !record.issuer.contains('\0')
        && record.dns_names.len() <= MAX_DNS_NAMES
        && record
            .dns_names
            .iter()
            .all(|name| name.len() <= MAX_DNS_NAME_BYTES && !name.contains('\0'))
}


pub fn doc_of(record: &CertRecord) -> Value {
    json!({
        "fingerprint": record.fingerprint_sha256,
        "subject": cut_text(&record.subject),
        "issuer": cut_text(&record.issuer),
        "dns_names": record.dns_names,
        "not_before": record.not_before,
        "not_after": record.not_after,
        "key_type": key_type_text(record.key_type),
        "key_bits": record.key_bits,
        "self_signed": record.self_signed,
    })
}


pub fn text_at(row: &Row, column: usize) -> Result<&str, InventoryStoreError> {
    row.get(column).map(String::as_str).ok_or(InventoryStoreError::BadRow { column })
}


pub fn number_at(row: &Row, column: usize) -> Result<i64, InventoryStoreError> {
    text_at(row, column)?.parse().map_err(|_bad| InventoryStoreError::BadRow { column })
}


pub fn count_at(row: &Row, column: usize) -> Result<usize, InventoryStoreError> {
    text_at(row, column)?.parse().map_err(|_bad| InventoryStoreError::BadRow { column })
}


pub fn limit_text(limit: usize) -> Result<String, InventoryStoreError> {
    i64::try_from(limit)
        .map(|number| number.to_string())
        .map_err(|_big| InventoryStoreError::BadLimit)
}


/// One statement for at most `MAX_STORE_BATCH` valid records; answers (inserted, seen again, refused for room).
pub async fn store_batch(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    source: &Source,
    batch: &[&CertRecord],
    now: i64,
    limits: &StoreLimits,
) -> Result<(usize, usize, usize), InventoryStoreError> {
    let docs: Vec<Value> = batch.iter().map(|record| doc_of(record)).collect();
    let params = vec![
        Value::Array(docs).to_string(),
        kind_text(source.kind).to_owned(),
        source.reference.clone(),
        now.to_string(),
        limit_text(limits.max_certs)?,
        limit_text(limits.max_sightings)?,
    ];
    let rows = exec(scope.clone(), STORE_SQL, params).await?;
    let row = rows.first().ok_or(InventoryStoreError::BadRow { column: 0 })?;
    Ok((count_at(row, 0)?, count_at(row, 1)?, count_at(row, COL_REFUSED)?))
}


/// Stores the records seen at `now`; a bad source, a bad record or a record over the caps is refused alone and counted.
pub async fn store_records(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    source: &Source,
    records: &[CertRecord],
    now: i64,
    limits: &StoreLimits,
) -> Result<StoreCounts, InventoryStoreError> {
    if !time_in_range(now) {
        Err(InventoryStoreError::BadNow)
    } else if !source_ok(source) {
        Ok(StoreCounts {
            refused_source: records.len(),
            ..StoreCounts::default()
        })
    } else {
        let good: Vec<&CertRecord> = records.iter().filter(|record| record_ok(record)).collect();
        let mut seen: HashSet<&str> = HashSet::new();
        let valid: Vec<&CertRecord> = good
            .iter()
            .copied()
            .filter(|record| seen.insert(record.fingerprint_sha256.as_str()))
            .collect();
        let mut counts = StoreCounts {
            refused_record: records.len() - good.len(),
            duplicate_in_batch: good.len() - valid.len(),
            ..StoreCounts::default()
        };
        for batch in valid.chunks(MAX_STORE_BATCH) {
            let (inserted, seen_again, refused_full) = store_batch(exec, scope, source, batch, now, limits).await?;
            counts.inserted += inserted;
            counts.seen_again += seen_again;
            counts.refused_full += refused_full;
            if refused_full > 0 {
                tracing::warn!(refused_full, "tenant certificate caps reached, records not stored");
            }
        }
        Ok(counts)
    }
}


pub fn encode_cursor(not_after: i64, fingerprint: &str) -> String {
    format!("{not_after}{CURSOR_SEPARATOR}{fingerprint}")
}


/// The canonical form only: a number that `encode_cursor` would not print back, or a fingerprint outside the grammar, is refused.
pub fn decode_cursor(text: &str) -> Result<(i64, String), InventoryStoreError> {
    let (number, fingerprint) = text.split_once(CURSOR_SEPARATOR).ok_or(InventoryStoreError::BadCursor)?;
    let not_after: i64 = number.parse().map_err(|_bad| InventoryStoreError::BadCursor)?;
    if is_fingerprint(fingerprint) && encode_cursor(not_after, fingerprint) == text {
        Ok((not_after, fingerprint.to_owned()))
    } else {
        Err(InventoryStoreError::BadCursor)
    }
}


pub fn key_type_of(text: &str, column: usize) -> Result<KeyType, InventoryStoreError> {
    match text {
        "rsa" => Ok(KeyType::Rsa),
        "ec" => Ok(KeyType::Ec),
        "other" => Ok(KeyType::Other),
        _unknown => Err(InventoryStoreError::BadRow { column }),
    }
}


pub fn stored_cert_of(row: &Row) -> Result<StoredCert, InventoryStoreError> {
    let dns_names: Vec<String> =
        serde_json::from_str(text_at(row, COL_DNS_NAMES)?).map_err(|_bad| InventoryStoreError::BadRow { column: COL_DNS_NAMES })?;
    let key_bits_text = text_at(row, COL_KEY_BITS)?;
    let key_bits = if key_bits_text.is_empty() {
        None
    } else {
        Some(count_at(row, COL_KEY_BITS)?)
    };
    let self_signed = match text_at(row, COL_SELF_SIGNED)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _other => Err(InventoryStoreError::BadRow { column: COL_SELF_SIGNED }),
    }?;
    Ok(StoredCert {
        record: CertRecord {
            fingerprint_sha256: text_at(row, COL_FINGERPRINT)?.to_owned(),
            subject: text_at(row, COL_SUBJECT)?.to_owned(),
            issuer: text_at(row, COL_ISSUER)?.to_owned(),
            dns_names,
            not_before: number_at(row, COL_NOT_BEFORE)?,
            not_after: number_at(row, COL_NOT_AFTER)?,
            key_type: key_type_of(text_at(row, COL_KEY_TYPE)?, COL_KEY_TYPE)?,
            key_bits,
            self_signed,
        },
        first_seen: number_at(row, COL_FIRST_SEEN)?,
        last_seen: number_at(row, COL_LAST_SEEN)?,
    })
}


/// One page ordered by `(not_after, fingerprint)` of the tenant's certificates; `limit` is 1 to `MAX_PAGE`, the cursor is the one a page gave.
pub async fn list_certificates(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    filter: &CertFilter,
    cursor: Option<&str>,
    limit: usize,
) -> Result<CertPage, InventoryStoreError> {
    if !(1..=MAX_PAGE).contains(&limit) {
        Err(InventoryStoreError::BadPageSize { limit: MAX_PAGE })
    } else {
        let before = filter.expiring_before.unwrap_or(i64::MAX).to_string();
        let fetch = limit_text(limit + 1)?;
        let rows = match cursor {
            None => exec(scope.clone(), LIST_FIRST_SQL, vec![before, fetch]).await?,
            Some(text) => {
                let (not_after, fingerprint) = decode_cursor(text)?;
                exec(scope.clone(), LIST_NEXT_SQL, vec![before, fetch, not_after.to_string(), fingerprint]).await?
            }
        };
        let (certs, failed): (Vec<_>, Vec<_>) = rows.iter().take(limit).map(stored_cert_of).partition(Result::is_ok);
        let skipped = failed.len();
        if skipped > 0 {
            tracing::warn!(skipped, "stored certificate rows refused and skipped");
        }
        let next_cursor = rows
            .get(limit.saturating_sub(1))
            .filter(|_last| rows.len() > limit)
            .map(cursor_of_row)
            .transpose()?;
        Ok(CertPage {
            certs: certs.into_iter().flatten().collect(),
            skipped,
            next_cursor,
        })
    }
}


/// The cursor of a raw row, so a page of refused rows still moves the client forward.
pub fn cursor_of_row(row: &Row) -> Result<String, InventoryStoreError> {
    Ok(encode_cursor(number_at(row, COL_NOT_AFTER)?, text_at(row, COL_FINGERPRINT)?))
}


/// One certificate of the tenant, or `None`; a stored row that cannot be parsed is an error.
pub async fn get_certificate(exec: Executor<'_, '_>, scope: &TenantScope, fingerprint: &str) -> Result<Option<StoredCert>, InventoryStoreError> {
    if is_fingerprint(fingerprint) {
        let rows = exec(scope.clone(), GET_SQL, vec![fingerprint.to_owned()]).await?;
        rows.first().map(stored_cert_of).transpose()
    } else {
        Err(InventoryStoreError::BadFingerprint)
    }
}


/// The certificate and its sightings: two statements at most, the second only when the first found the certificate.
pub async fn get_detail(exec: Executor<'_, '_>, scope: &TenantScope, fingerprint: &str) -> Result<Option<CertDetail>, InventoryStoreError> {
    match get_certificate(exec, scope, fingerprint).await? {
        None => Ok(None),
        Some(cert) => Ok(Some(CertDetail {
            cert,
            sightings: sightings_of(exec, scope, fingerprint).await?,
        })),
    }
}


pub fn sighting_of(row: &Row) -> Result<Sighting, InventoryStoreError> {
    let kind = match text_at(row, COL_SIGHTING_KIND)? {
        SCAN_KIND => Ok(SourceKind::Scan),
        CT_KIND => Ok(SourceKind::Ct),
        _other => Err(InventoryStoreError::BadRow { column: COL_SIGHTING_KIND }),
    }?;
    Ok(Sighting {
        kind,
        reference: text_at(row, COL_SIGHTING_REF)?.to_owned(),
        last_seen: number_at(row, COL_SIGHTING_LAST)?,
    })
}


/// At most `MAX_SIGHTINGS_READ` sightings of one certificate of the tenant, ordered by kind and reference; a bad row is skipped and counted.
pub async fn sightings_of(exec: Executor<'_, '_>, scope: &TenantScope, fingerprint: &str) -> Result<SightingPage, InventoryStoreError> {
    if is_fingerprint(fingerprint) {
        let rows = exec(
            scope.clone(),
            SIGHTINGS_SQL,
            vec![fingerprint.to_owned(), limit_text(MAX_SIGHTINGS_READ)?],
        )
        .await?;
        let (good, failed): (Vec<_>, Vec<_>) = rows.iter().map(sighting_of).partition(Result::is_ok);
        let skipped = failed.len();
        if skipped > 0 {
            tracing::warn!(skipped, "stored sighting rows refused and skipped");
        }
        Ok(SightingPage {
            sightings: good.into_iter().flatten().collect(),
            skipped,
            truncated: rows.len() >= MAX_SIGHTINGS_READ,
        })
    } else {
        Err(InventoryStoreError::BadFingerprint)
    }
}
