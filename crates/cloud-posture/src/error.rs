use crate::model::KubeconfigFault;
#[cfg(unix)]
use core_config::trusted_dir::TrustedDirError;
use core_pg::error::PgError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid tenant: {0}")]
    Tenant(#[source] PgError),
    #[error("the declared account id is not a valid reference")]
    Account,
    #[error("cannot read the document: {0}")]
    Read(#[source] std::io::Error),
    #[error("document is above the {max} byte limit")]
    TooLarge { max: u64 },
    #[error("document is not a JSON array ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("document holds {count} findings, above the {max} limit")]
    TooManyFindings { count: usize, max: usize },
}


#[derive(Debug, Error)]
pub enum DeclarationError {
    #[error("cannot read the declarations: {0}")]
    Read(#[source] std::io::Error),
    #[error("declarations are above the {max} byte limit")]
    TooLarge { max: u64 },
    #[error("declarations are not the expected YAML document")]
    Malformed,
    #[error("invalid tenant: {0}")]
    Tenant(#[source] PgError),
    #[error("declarations hold {count} clusters, above the {max} limit")]
    TooManyClusters { count: usize, max: usize },
}


/// Why one cluster scan gave no findings; fixed text, never Prowler output, a path or a credential.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("the kubeconfig was refused ({fault:?})")]
    Kubeconfig { fault: KubeconfigFault },
    #[error("cannot prepare the work directory: {0}")]
    Workdir(#[source] std::io::Error),
    #[cfg(unix)]
    #[error("the work directory is not trusted: {0}")]
    UntrustedWorkdir(#[source] TrustedDirError),
    #[error("prowler could not be started")]
    Spawn,
    #[error("prowler ran past its deadline")]
    Timeout,
    #[error("prowler failed with code {code:?}")]
    Failed { code: Option<i32> },
    #[error("prowler wrote no output file")]
    NoOutput,
    #[error("the output file is not a regular file of this user")]
    BadOutputFile,
    #[error("cluster declaration {index} was refused")]
    BadDeclaration { index: usize },
    #[error("the output cannot be parsed: {0}")]
    Parse(#[from] ParseError),
}


#[derive(Debug, Error)]
pub enum StoreError {
    #[error("the findings belong to another tenant than the scope")]
    TenantMismatch,
    #[error("the account is not a valid reference")]
    BadAccount,
    #[error("the run id is not a valid reference")]
    BadRunId,
    #[error("the finish time does not fit the store")]
    BadTime,
    #[error("the run holds {items} findings (limit {max_items}) or more than {max_bytes} bytes of document")]
    RunTooLarge { items: usize, max_items: usize, max_bytes: usize },
    #[error("the tenant cap of {cap} rows is reached: this run holds {items} findings, the tenant's other accounts {others} rows")]
    TenantCap { cap: usize, items: usize, others: usize },
    #[error("the store answered a shape this build does not know")]
    BadAnswer,
    #[error("the page limit must be 1 to {max}")]
    BadLimit { max: usize },
    #[error("the cursor is not one this store prints")]
    BadCursor,
    #[error("the run changed since the cursor was printed: restart from the first page")]
    RunChanged,
    #[error("a stored key or run id is outside its grammar")]
    StoredValue,
    #[error("database: {0}")]
    Pg(#[from] PgError),
}
