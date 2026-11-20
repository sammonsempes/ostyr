use thiserror::Error;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TriageError {
    #[error("the message is larger than the size limit")]
    TooLarge,
    #[error("the bytes are not a message")]
    Unparsable,
    #[error("the isolated parse ran out of memory")]
    ChildMemory,
    #[error("the isolated parse passed its deadline")]
    ChildDeadline,
    #[error("the isolated parse failed")]
    ChildFailed,
    #[error("the isolated parse returned an unusable record")]
    ChildOutput,
    #[error("the isolation program is not trusted")]
    ChildProgram,
    #[error("the isolation limits are outside their bounds")]
    LimitsRefused,
}
