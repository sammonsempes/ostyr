use thiserror::Error;


#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Pg(#[from] core_pg::error::PgError),
    #[error("at most {limit} alerts per insert")]
    TooManyAlerts { limit: usize },
    #[error("alert tenant differs from the scope")]
    TenantMismatch,
    #[error("alert id is not the one derived from its tenant, rule and events")]
    IdMismatch,
    #[error("field `{field}` is empty")]
    FieldEmpty { field: &'static str },
    #[error("field `{field}` exceeds {limit}")]
    FieldTooLong { field: &'static str, limit: usize },
    #[error("field `{field}` holds a NUL character")]
    NulByte { field: &'static str },
    #[error("an alert names between 1 and {limit} events")]
    BadEventCount { limit: usize },
    #[error("created time does not fit the column")]
    BadCreated,
    #[error("triage time does not fit the `updated_at` column")]
    BadUpdatedAt,
    #[error("summary original size does not fit the column")]
    BadOriginalBytes,
    #[error("summary size fields are inconsistent")]
    BadSummary,
    #[error("alert id must be 64 lowercase hexadecimal characters")]
    BadId,
    #[error("page size must be between 1 and {limit}")]
    BadPageSize { limit: usize },
    #[error("cursor is malformed")]
    BadCursor,
    #[error("the store returned a malformed value in column {column}")]
    BadRow { column: usize },
    #[error("column {column} is not a number")]
    BadNumber {
        column: usize,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("the alert document cannot be built")]
    Document(#[source] serde_json::Error),
    #[error("the stored event list is malformed")]
    BadEvents(#[source] serde_json::Error),
    #[error("the triage version changed or a triage already exists")]
    Conflict,
    #[error("no such alert in this tenant")]
    NotFound,
    #[error("too many concurrent database requests")]
    Busy,
}
