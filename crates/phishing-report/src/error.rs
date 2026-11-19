use thiserror::Error;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TriageError {
    #[error("the message is larger than the size limit")]
    TooLarge,
    #[error("the bytes are not a message")]
    Unparsable,
}
