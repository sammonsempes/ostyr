use crate::types::BoxError;
use std::io;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum CodecError {
    #[error("cannot decode: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("trailing bytes after the encoded value")]
    TrailingBytes,
}


/// Fixed texts: no variant carries claims, peer identifiers or subjects.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("token is too large")]
    TooLarge,
    #[error("token is not base64url")]
    BadEncoding(#[source] data_encoding::DecodeError),
    #[error("malformed token: {0}")]
    Malformed(#[from] CodecError),
    #[error("unknown signing key")]
    UnknownKey,
    #[error("signing key is revoked")]
    KeyRevoked,
    #[error("signing key is outside its validity period")]
    KeyOutsideValidity,
    #[error("bad signature")]
    BadSignature,
    #[error("token is bound to another signing key")]
    KeyIdMismatch,
    #[error("token expires at or before its start")]
    InvalidLifetime,
    #[error("token lifetime is longer than the maximum")]
    LifetimeTooLong,
    #[error("token is expired")]
    Expired,
    #[error("token starts in the future beyond the clock skew")]
    NotYetValid,
    #[error("token is for another device")]
    WrongPeer,
    #[error("token is for another tenant")]
    WrongTenant,
    #[error("token was already used")]
    Replayed,
    #[error("too many live tokens, token refused")]
    ReplayFull,
}


#[derive(Debug, Error)]
pub enum IssueError {
    #[error("cannot encode: {0}")]
    Encode(#[from] postcard::Error),
    #[error("the signer failed: {0}")]
    Signer(#[source] BoxError),
    #[error("the token would be larger than the maximum")]
    TooLarge,
}


#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifierError {
    #[error("the live token cap must be between 1 and the ceiling")]
    LiveTokens,
}


#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShareError {
    #[error("key id `{id}` is also an agent-command key id")]
    SharedId { id: String },
    #[error("the public key of `{id}` is also an agent-command key")]
    SharedPublicKey { id: String },
}


#[derive(Debug, Error)]
pub enum CliError {
    #[error("usage: {0}")]
    Usage(&'static str),
    #[error("invalid hexadecimal: {0}")]
    Hex(#[from] data_encoding::DecodeError),
    #[error("seed must be 32 bytes")]
    Seed,
    #[error("invalid claims: {0}")]
    Request(#[from] serde_json::Error),
    #[error(transparent)]
    Issue(#[from] IssueError),
    #[error("cannot draw random bytes: {0}")]
    Random(#[from] getrandom::Error),
    #[error("cannot write: {0}")]
    Io(#[from] io::Error),
}
