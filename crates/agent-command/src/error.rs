use crate::types::BoxError;
use core_audit::error::AuditError;
use ed25519_dalek::SignatureError;
use std::io;
use std::num::ParseIntError;
use std::path::PathBuf;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum CodecError {
    #[error("cannot decode: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("trailing bytes after the encoded value")]
    TrailingBytes,
}


/// Fixed texts: a refused package name is never echoed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ActionError {
    #[error("a named package selection must not be empty")]
    NoPackages,
    #[error("too many packages")]
    TooManyPackages,
    #[error("a package name is empty")]
    EmptyPackageName,
    #[error("a package name is too long")]
    PackageNameTooLong,
    #[error("a package name starts with a dash")]
    PackageNameLeadingDash,
    #[error("a package name holds a forbidden character")]
    PackageNameCharacter,
}


/// Every variant is a distinct refusal reason; none carries command parameters.
#[derive(Debug, Error)]
pub enum CommandError {
    #[error("malformed envelope or command: {0}")]
    Malformed(#[from] CodecError),
    #[error("unknown signing key")]
    UnknownKey,
    #[error("signing key is revoked")]
    KeyRevoked,
    #[error("signing key is outside its validity period")]
    KeyOutsideValidity,
    #[error("bad signature")]
    BadSignature,
    #[error("command is bound to another signing key")]
    KeyIdMismatch,
    #[error("command is bound to another key class")]
    KeyClassMismatch,
    #[error("command addressed to another agent")]
    WrongAgent,
    #[error("command addressed to another tenant")]
    WrongTenant,
    #[error("command expires at or before the time it is issued")]
    InvalidLifetime,
    #[error("command lifetime is longer than the maximum")]
    LifetimeTooLong,
    #[error("command is expired")]
    Expired,
    #[error("command is issued in the future beyond the clock skew")]
    IssuedInFuture,
    #[error("invalid action: {0}")]
    InvalidAction(#[from] ActionError),
    #[error("sensitive action signed by a routine key")]
    SensitiveActionNeedsSensitiveKey,
    #[error("sequence number is not greater than the last accepted one")]
    ReplayedSequence,
    #[error("sequence number jumps further than the allowed advance")]
    SequenceJump,
    #[error("cannot store the sequence number, command refused: {0}")]
    Store(#[source] io::Error),
}


#[derive(Debug, Error)]
pub enum SignError {
    #[error("cannot encode: {0}")]
    Encode(#[from] postcard::Error),
    #[error("the signer failed: {0}")]
    Signer(#[source] BoxError),
    #[error("invalid action: {0}")]
    Action(#[from] ActionError),
}


#[derive(Debug, Error)]
pub enum StoreError {
    #[error("{path}: cannot read the sequence: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{path}: the stored sequence is corrupt: {source}")]
    Corrupt {
        path: PathBuf,
        #[source]
        source: ParseIntError,
    },
    #[error("{path}: the state file has an unknown layout")]
    Layout { path: PathBuf },
    #[error("{path}: the state file is not private: {source}")]
    Insecure {
        path: PathBuf,
        #[source]
        source: AuditError,
    },
}


#[derive(Debug, Error)]
pub enum KeyFileError {
    #[error("key `{id}`: public key is not hexadecimal: {source}")]
    Hex {
        id: String,
        #[source]
        source: data_encoding::DecodeError,
    },
    #[error("key `{id}`: public key must be 32 bytes")]
    Length { id: String },
    #[error("key `{id}`: invalid public key: {source}")]
    PublicKey {
        id: String,
        #[source]
        source: SignatureError,
    },
    #[error("key `{id}` appears twice")]
    Duplicate { id: String },
    #[error("public key of `{id}` is already listed under `{first}`")]
    DuplicatePublicKey { id: String, first: String },
    #[error("key `{id}`: not_before is after not_after")]
    Validity { id: String },
}


#[derive(Debug, Error)]
pub enum CliError {
    #[error("usage: {0}")]
    Usage(&'static str),
    #[error("unknown action `{0}`")]
    UnknownAction(String),
    #[error("unknown key class `{0}`")]
    Class(String),
    #[error("invalid number")]
    Number,
    #[error("invalid hexadecimal: {0}")]
    Hex(#[from] data_encoding::DecodeError),
    #[error("invalid parameter: {0}")]
    Parameter(&'static str),
    #[error("invalid action: {0}")]
    Action(#[from] ActionError),
    #[error("seed must be 32 bytes")]
    Seed,
    #[error(transparent)]
    Sign(#[from] SignError),
    #[error("cannot draw random bytes: {0}")]
    Random(#[from] getrandom::Error),
    #[error("cannot write: {0}")]
    Io(#[from] io::Error),
}
