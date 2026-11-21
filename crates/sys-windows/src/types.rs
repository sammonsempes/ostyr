use std::path::PathBuf;
use thiserror::Error;


/// One access control entry reduced to what the judge reads: type byte, flag byte, SID string and access mask (deny and unknown types carry no SID).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ace {
    pub kind: u8,
    pub flags: u8,
    pub sid: String,
    pub mask: u32,
}


/// A security descriptor reduced to its owner SID string and its DACL (`None` is a NULL DACL).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedDescriptor {
    pub owner: String,
    pub dacl: Option<Vec<Ace>>,
}


/// The SID strings the agent trusts to hold rights on its directories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principals {
    pub trusted: Vec<String>,
}


/// An absolute local path split into its volume root (`C:\`) and its components, every one checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumePath {
    pub root: String,
    pub components: Vec<String>,
}


/// The identity of an opened file: volume serial number and 64-bit file index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub volume: u32,
    pub index: u64,
}


#[derive(Debug, Error)]
pub enum DirAclError {
    #[error("{} has a NULL DACL: everyone has full access", .path.display())]
    NullDacl { path: PathBuf },
    #[error("{} has an access control entry of unknown type {kind:#x}", .path.display())]
    UnknownAceType { path: PathBuf, kind: u8 },
    #[error("{} grants {bits:#010x} to {sid}, which is not a trusted principal", .path.display())]
    UntrustedAce { path: PathBuf, sid: String, bits: u32 },
    #[error("{} is owned by {sid}, which is not a trusted principal", .path.display())]
    UntrustedOwner { path: PathBuf, sid: String },
    #[error("{path} is not an absolute local path: {reason}")]
    BadPath { path: String, reason: &'static str },
    #[error("{} is a reparse point (junction, symbolic link or mount point)", .path.display())]
    ReparsePoint { path: PathBuf },
    #[error("{} exists and is not a regular file", .path.display())]
    NotRegularFile { path: PathBuf },
    #[error("{} is not the directory the walk judged", .path.display())]
    IdentityMismatch { path: PathBuf },
    #[error("cannot open {} for the walk: {kind:?}", .path.display())]
    Open { path: PathBuf, kind: std::io::ErrorKind },
    #[error("invalid SID: {0}")]
    InvalidSid(&'static str),
    #[error("malformed security descriptor: {0}")]
    Malformed(&'static str),
    #[error("{operation} failed with code {code:#010x}")]
    Windows { operation: &'static str, code: u32 },
}
