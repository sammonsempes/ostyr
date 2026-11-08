use thiserror::Error;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum CmdbError {
    #[error("observation from `{source_name}` carries no identity key")]
    NoIdentity { source_name: String },
}
