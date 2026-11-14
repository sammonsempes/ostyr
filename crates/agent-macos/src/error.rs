use thiserror::Error;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("the tool output is {length} bytes, over the limit of {limit}")]
    TooLarge { length: usize, limit: usize },
}
